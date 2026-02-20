#include "taint_analyze.h"

#include <cassert>


#include "taint_utils.h"

std::string default_taint_file = ".asm";
std::string default_trace_file = "trace.asm";

bool TaintTrace::SetOutputPath(const std::string *path) {
    std::string def_path = std::string(BLANK);
    if (path == nullptr) {
        path = &def_path;
    }
    if (log.is_open()){
        log.close();
        log.clear();
    }

    if (all_log.is_open()){
        all_log.close();
        all_log.clear();
    }


    log.open(*path+ModeName[mode]+default_taint_file, std::ios::out | std::ios::trunc);
    if (log.is_open()&&IsAsmMode()){
        log << ASM_START_STR << ENTER;
    }
    if (IsDebugMode()||IsTraceMode())
    {
        all_log.open(*path + default_trace_file, std::ios::out | std::ios::trunc);
    }
    return log.is_open()&&all_log.is_open();
}

TaintTrace::TaintTrace(const uint64_t base,
                       const PrintMode mode,const std::string* path): reg_name()
{

    this->base = base;
    this->mode = mode;
    reg_name.SetGPRArray(QBDI::GPR_NAMES, state);
    SetOutputPath(path);

}







void TaintTrace::PrintMemoryOp(QBDI::GPRState* gpr,uint64_t offset,QBDI::MemoryAccess *memoryAccess,int reg_w,int rRegIdx){
    std::ostringstream log_str;

    std::string mem_op = "[" + ToHex(memoryAccess->accessAddress) + "] ";
    std::string tmp;
    if (IsAddrMode()||IsDebugMode())
    {
        tmp +=  PRINT_OFFSET(offset);
    }
    tmp += MOV;
    if (IsValid(reg_w)){
        tmp += RegName(reg_w);
        tmp += ", ";
        tmp += mem_op;

        tmp += ASM_NOTE;
        log_str << std::left << std::setw(STR_ALIGN) << tmp;
        log_str << SPLIT;
        log_str << TName(reg_w) << EQ << ToHex(memoryAccess->value);
        log_str << PRINT_SIZE(memoryAccess->size);
        log_str << ENTER;
    } else {
        tmp += mem_op;
        tmp += ", ";
        tmp += RegName(rRegIdx);

        tmp += ASM_NOTE;
        log_str << std::left << std::setw(STR_ALIGN) << tmp;
        log_str << TName(rRegIdx)  << EQ << ToHex(memoryAccess->value);
        log_str << PRINT_SIZE(memoryAccess->size);
        log_str << SPLIT ENTER;
    }
    log << log_str.str();
    if (NeedFlush()) log.flush();


}



template<auto M>
struct Tunnel;

template<class T, class U, T U::*M>
struct Tunnel<M> {
    friend T& GetPrivate(U& u) {
        return u.*M;
    }
};

// Separate accessor name to avoid GetPrivate overload conflicts.
template<auto M>
struct TunnelRunning;
template<class T, class U, T U::*M>
struct TunnelRunning<M> {
    friend T& GetPrivateRunning(U& u) {
        return u.*M;
    }
};

template struct Tunnel<&QBDI::VM::engine>;           // T = std::unique_ptr<QBDI::Engine>
template struct Tunnel<&QBDI::Engine::execBroker>;    // T = QBDI::ExecBroker*
template struct Tunnel<&QBDI::ExecBroker::transferBlock>; // T = std::unique_ptr<QBDI::ExecBlock>
template struct TunnelRunning<&QBDI::Engine::running>;       // T = bool

std::unique_ptr<QBDI::Engine>& GetPrivate(QBDI::VM&);
QBDI::ExecBroker*& GetPrivate(QBDI::Engine&);  // 注意：返回的是指针的引用
std::unique_ptr<QBDI::ExecBlock>& GetPrivate(QBDI::ExecBroker&);

// Use a dedicated name to avoid overload collisions on GetPrivate.
bool& GetPrivateRunning(QBDI::Engine&);


QBDI::VMAction TaintTrace::InstTrace(QBDI::VM *vm,
                                     const QBDI::GPRState *gpr, QBDI::FPRState *fpr) {

    const QBDI::InstAnalysis *inst = vm->getInstAnalysis(
            QBDI::ANALYSIS_INSTRUCTION | QBDI::ANALYSIS_SYMBOL |
                 QBDI::ANALYSIS_DISASSEMBLY | QBDI::ANALYSIS_OPERANDS );


    if (!inst) return QBDI::CONTINUE;

    if (inst->address == trace_end|| IsBreakAddr(inst->address)) {
        auto& engine_ptr = GetPrivate(*vm);                    // std::unique_ptr<Engine>&
        GetPrivateRunning(*engine_ptr) = false;
        auto& execBroker_ptr = GetPrivate(*engine_ptr);       // QBDI::ExecBroker*&
        auto& transferBlock = GetPrivate(*execBroker_ptr); // std::unique_ptr<ExecBlock>&

        // auto transferBlock = reinterpret_cast<QBDI::ExecBlock*>(*reinterpret_cast<uint64_t *>(block_addr));
        transferBlock->getContext()->gprState = *gpr;
        transferBlock->getContext()->fprState = *fpr;
        transferBlock->getContext()->hostState.selector = inst->address;
        guest_stack.RestoreStack();
        transferBlock->run();
        // end
        // Read transfer result
        // *gpr = transferBlock->getContext()->gprState;
        // *fpr = transferBlock->getContext()->fprState;
    }
    uint64_t offset = inst->address - base;
//    triton.UpdateRegister(gpr,fpr);
//    triton.Procces(inst->address, inst->instSize);
    // triton.
    // analyse operands
    anal.reset();
    for(int idx = 0;idx < inst->numOperands;idx++){
        QBDI::OperandAnalysis &operand =  inst->operands[idx];
        switch (operand.regAccess) {
            case QBDI::REGISTER_WRITE:
                anal.SetReg(operand.regCtxIdx,WRITE);
                break;
            case QBDI::REGISTER_READ:
                anal.SetReg(operand.regCtxIdx,READ);
                break;
            case QBDI::REGISTER_READ_WRITE:
                anal.SetReg(operand.regCtxIdx,READ_WRITE);
                break;

            case QBDI::REGISTER_UNUSED:
                // assert(false);
                break;
        }
    }
    int Tr_idx=anal.Tr_idx,Tw_idx=anal.Tw_idx,Trw_idx=anal.Trw_idx;
    int Cr_idx=anal.Cr_idx,Cw_idx=anal.Cw_idx,Crw_idx=anal.Crw_idx;

    // trace
    AnalysisInstType(inst);

    if (IsDebugMode()||IsTraceMode())
    {

        std::ostringstream log_str1;
        if (IsDebugMode()&&inst->moduleName) {
          offset = inst->address - GetAndSaveBase(inst->moduleName);
          log_str1 << inst->moduleName << ":";
        }
        log_str1 << PRINT_OFFSET(offset) << inst->disassembly;
        all_log  << std::left << std::setw(STR_ALIGN) << log_str1.str();
        anal.PrintReg(all_log,gpr, true);
        // allLog << ENTER;
        all_log << SPLIT;
        SetPostInstFlag();
        if (IsTraceMode()) {
          return QBDI::CONTINUE;
        }
    }

    // taint process
    if (!IsValid(Tr_idx) && !IsValid(Tw_idx)&&!IsValid(Trw_idx)){
        return QBDI::CONTINUE;
    }
    if (!IsValid(Trw_idx)&&!IsValid(Crw_idx)){
        // no rwReg

        if (IsValid(Tr_idx) && !IsValid(Tw_idx)){
            if (IsValid(Cw_idx)){
                // ldr x0, [*reg]
                // ldp x0, x1, [*reg]
                while (IsValid(Cw_idx))
                    SetTaintReg(anal.Cw[Cw_idx--],0);
            } else {
                // CMP REG, *REG
                // mov	[mem], *rax
                if (!inst->isCompare) return QBDI::CONTINUE;
            }
        } else if (!IsValid(Tr_idx) && IsValid(Tw_idx)){
            while (IsValid(Tw_idx))
                ClearTaintReg(anal.Tw[Tw_idx--]);

            return QBDI::CONTINUE;
        }
    } else {
//        if (!IsValid(anal.Trw_idx)){
            if (IsValid(Trw_idx)&& IsValid(Crw_idx)){
                // XCHG REG,*REG
                ClearTaintReg(anal.Trw[0]);
                SetTaintReg(anal.Crw[0],0);
            } else if (!IsValid(Trw_idx)&&IsValid(Crw_idx)){
                /*
                 * PUSH *REG
                 */
                if (anal.Crw[0] == QBDI::REG_SP) {
                    return QBDI::CONTINUE;
                }
                //  XOR  REG,*REG
                if(IsValid(Tr_idx)){
                    SetTaintReg(anal.Crw[0],0);
                }


            } else if (IsValid(Trw_idx)&& !IsValid(Crw_idx)){
                // INC *REG
                // XOR *REG,REG
            } else {
                return  QBDI::CONTINUE;
            }
    }


    SetPostInstFlag();
    if (IsValid(Cr_idx))
    {
      // for asm
      if (IsAddrMode()||IsDebugMode()) log << PRINT_OFFSET(offset);
        while (IsValid(Cr_idx))
            log << MOV << RegName(anal.Cr[Cr_idx]) << ", "<< PRINT_GPR(anal.Cr[Cr_idx--]) <<ENTER;
    }
    std::ostringstream log_str;
    // if (inst->symbolName) logStr << inst->symbolName << "!";
    if (IsAddrMode()||IsDebugMode()) log_str << PRINT_OFFSET(offset);
    log_str << inst->disassembly;
    log_str << ASM_NOTE;
    log  << std::left << std::setw(STR_ALIGN) << log_str.str();
    anal.PrintReg(log,gpr, true);
    log << SPLIT;
    return QBDI::CONTINUE;



}
void TaintTrace::PostInstTrace(QBDI::VM *vm, const QBDI::GPRState *gpr, QBDI::FPRState *fpr)
{
    if (!enable_post_inst)return;
    CleanPostInstFlag();
    if (IsTraceMode()||IsDebugMode()) {
        if (IsDebugMode())log << ENTER;
        anal.PrintReg(all_log,gpr, false);
        all_log << ENTER;
        if (inst_type == CALL) all_log << ENTER;
        if(NeedFlush()) all_log.flush();
        return;
    }

    // todo... fix:debug mode taint.asm will lose post reg value
    anal.PrintReg(log,gpr, false);

    log << ENTER;
    if (inst_type == CALL) log << ENTER;
    // if(needFlush()) log.flush();
}
void TaintTrace::MemoryTrace(const QBDI::VM *vm, QBDI::GPRState *gpr, QBDI::FPRState *fpr) {
    int taint_r[4] = { -1,-1,-1},taint_w[4] = {-1,-1,-1};
    int taint_rw = -1,clear_rw = -1;
    int clear_r[4] = { -1,-1,-1},clear_w[4] = {-1,-1,-1};
    int taint_r_idx = -1,taint_w_idx = -1,clear_r_idx = -1,clear_w_idx = -1;


    const QBDI::InstAnalysis *inst = vm->getInstAnalysis(
        QBDI::ANALYSIS_INSTRUCTION |
        QBDI::ANALYSIS_DISASSEMBLY | QBDI::ANALYSIS_OPERANDS);
    if (!inst) return;
    // int16_t rOpIdx = -1,wOpIdx = -1;
    std::vector<QBDI::MemoryAccess> access_list = vm->getInstMemoryAccess();

    char flag = 0;
    QBDI::MemoryAccess* access_p=nullptr;


    for (QBDI::MemoryAccess &access:access_list){
        switch (access.type){
            case QBDI::MEMORY_READ:
                flag |= QBDI::MEMORY_READ;
                // for taint str
                if (IsTraceMode()){
                    if(IsPrintable((unsigned char*)access.accessAddress,printable_size)){
                        all_log << "PrintableRead:[" << (char*) access.accessAddress << "]" << ENTER;
                        return;
                    } else {
                        all_log << "MemoryRead:" << PRINT_ADDR(access.accessAddress) << PRINT_SIZE(access.size) << ENTER;
                    }
                }
                CheckTaintedStr(access.accessAddress);
                break;
            case QBDI::MEMORY_WRITE:
                flag |= QBDI::MEMORY_WRITE;
                if (IsTraceMode()){
                    if(IsPrintable((unsigned char*)access.accessAddress,printable_size)){
                        all_log << "PrintableWrite:[" << (char*) access.accessAddress << "]" << ENTER;
                        return;
                    } else {
                        all_log << "MemoryWrite:" << PRINT_ADDR(access.accessAddress) << PRINT_SIZE(access.size) << ENTER;
                    }
                }
                break;
            case QBDI::MEMORY_READ_WRITE:
                if (IsTraceMode()){
                    if(IsPrintable((unsigned char*)access.accessAddress,printable_size)){
                        all_log << "PrintableRead:[" << (char*) access.accessAddress << "]"  << ENTER;
                        return;
                    } else {
                        all_log << "MemoryReadWrite:" << PRINT_ADDR(access.accessAddress) << PRINT_SIZE(access.size) << ENTER;
                    }
                }
                flag |= QBDI::MEMORY_READ_WRITE;
                CheckTaintedStr(access.accessAddress);
                break;
        }
        access_p = &access;
    }

    if (!access_p||IsTraceMode())return;





    const uint64_t offset = inst->address - base;

    // analyse operands
    for(int16_t idx = 0;idx < inst->numOperands;idx++) {
        const QBDI::OperandAnalysis &operand = inst->operands[idx];
        if(operand.regAccess == QBDI::REGISTER_READ ){
            if (IsTaint(operand.regCtxIdx)){
                taint_r[++taint_r_idx] = operand.regCtxIdx;
            } else {
                clear_r[++clear_r_idx] = operand.regCtxIdx;
            }
        }else if (operand.regAccess == QBDI::REGISTER_WRITE ){
            if (IsTaint(operand.regCtxIdx)){
                taint_w[++taint_w_idx] = operand.regCtxIdx;
            } else {
                clear_w[++clear_w_idx] = operand.regCtxIdx;
            }
        }else if (operand.regAccess == QBDI::REGISTER_READ_WRITE){
            if (IsTaint(operand.regCtxIdx)){
                taint_rw = operand.regCtxIdx;
            } else {
                clear_rw = operand.regCtxIdx;
            }
        }
    }




    QBDI::MemoryAccess& access=*access_p;
    switch (flag) {
        case QBDI::MEMORY_READ:
            {
             /*     POP REG
              *     MOV REG, [MEM]
              *
              *     XOR REG, [MEM]
              *     ADD REG, [MEM]
              *     SUB REG, [MEM]
              *     AND REG, [MEM]
              *     OR  REG, [MEM] */
                const auto range = memory.find(access.accessAddress);
                if (range){
                    // ldp x1, x2, *[mem]
                    // ldp x1, *x2, *[mem]
                    // mov eax, dword ptr [rbp - 0x18]
                    if (IsValid(clear_w_idx)||IsValid(taint_w_idx)){
                        while (IsValid(clear_w_idx)) {
                            PrintMemoryOp(gpr,offset,&access,clear_w[clear_w_idx],-1);
                            SetTaintReg(clear_w[clear_w_idx--],0);
                        }
                        while (IsValid(taint_w_idx)) {
                            PrintMemoryOp(gpr, offset, &access, taint_w[taint_w_idx], -1);
                            SetTaintReg(taint_w[taint_w_idx--], 0);
                        }
                    } else if(IsValid(clear_rw)||IsValid(taint_rw)){

                        /*      XOR REG, *[MEM]
                                ADD REG, *[MEM]
                                SUB REG, *[MEM]
                                XOR *REG, [MEM]*/
                        int rw = IsValid(clear_rw)?clear_rw:taint_rw;
                        SetTaintReg(rw,0);
                        if (IsAddrMode()||IsDebugMode()) log << PRINT_OFFSET(offset);
                        log << MOV<< RegName(rw) << ", "<< ToHex(UNKNOWN_CONST) <<ENTER;
                        std::ostringstream log_str;

                        if (IsAddrMode()||IsDebugMode()) log_str << PRINT_OFFSET(offset);
                        log_str << TAB << disassembler.AnalyzeInst(inst->address)->mnemonic<<SPACE;
                        log_str << RegName(rw) << ", " << PRINT_ADDR(access.accessAddress);
                        log_str << ASM_NOTE;
                        log << std::left << std::setw(STR_ALIGN) << log_str.str();
                        log << SPLIT << TName(rw) << EQ <<ToHex(access.value);
                        log << PRINT_SIZE(access.size);
                        log << ENTER;

                    };
                } else {

                    if (!IsValid(taint_r_idx)&&IsValid(taint_w_idx)) {
                        // ldp *x1, *x2, [reg]
                        // MOV *RAX, [MEM]
                        while (IsValid(taint_w_idx))
                            ClearTaintReg(taint_w[taint_w_idx--]);
                    } else if (IsValid(taint_r_idx)){
                        if (IsValid(clear_w_idx)) {
                            // MOV RAX,[*RDX]
                            // ldp x1, x2, [*reg] (print by InstTrace)
                            while (IsValid(clear_w_idx))
                                SetTaintReg(clear_w[clear_w_idx--],0);
                        } else if (IsValid(clear_rw)) {
                            SetTaintReg(clear_rw,0);
                        }
                    }
                }
            }
            break;
        case QBDI::MEMORY_WRITE:
            /* MOV [MEM], REG
             * PUSH REG
             * stp *x1 *x2 ,[mem]
             **/
            if(IsValid(taint_r_idx)){
                // todo: str x1, [x2,x3]
                while (IsValid(taint_r_idx)&&taint_r[taint_r_idx])
                    PrintMemoryOp(gpr, offset, &access, -1, taint_r[taint_r_idx--]);
                // question: is stp case access.size = 16 ?
                AddTaintMemory(access.accessAddress, access.size);
                if (IsDebugMode())
                {
                    log <<  "[--> add " << ToHex(offset) +
                        " range:" << ToHex(access.accessAddress) +
                        "->"+ ToHex(access.accessAddress+access.size)+ "] " << ENTER;
                }
            } else {
                if (IsDebugMode()) {
                    const auto del = memory.find(access.accessAddress);
                    if (del!=nullptr) {
                        log << "[-->remove " << ToHex(offset) +
                            " range:" << ToHex(del->min) +
                            "->"+ ToHex(del->max) + "]" ENTER;
                    }
                }
                memory.erase(access.accessAddress);
            }
            break;
        case QBDI::MEMORY_READ_WRITE:
            /*  XOR [MEM], REG
             *  XCHG [MEM], REG
             *  ADD [MEM], REG
             *  SUB [MEM], REG
             *  AND [MEM], REG
             **/
            // only x86 sure ?
            const auto range = memory.find(access.accessAddress);
            if (!range && !IsValid(taint_r_idx)) return;

            if (range && !IsValid(taint_r_idx)) {
              // XOR *[MEM], REG
              if (IsAddrMode() || IsDebugMode()) log << PRINT_OFFSET(offset);
              log << MOV << RegName(clear_r[0]) << ", "
                  <<  PRINT_GPR(clear_r[0]) << ENTER;
            } else if (!range && IsValid(taint_r_idx)) {
              // XOR [MEM], *REG
              AddTaintMemory(access.accessAddress, access.size);
            }
            std::ostringstream log_str2;
            if (IsAddrMode()||IsDebugMode()) log_str2 << PRINT_OFFSET(offset);
            log_str2 << TAB << disassembler.AnalyzeInst(inst->address)->mnemonic << SPACE;
            log_str2 << PRINT_ADDR(access.accessAddress) << ", "
            <<  RegName(IsValid(taint_r_idx)?taint_r[0]:clear_r[0]) ;
            log_str2 << ASM_NOTE;
            log << std::left << std::setw(STR_ALIGN) << log_str2.str();
            log << SPLIT <<  PRINT_ADDR(access.accessAddress) << EQ <<ToHex(access.value);
            log << PRINT_SIZE(access.size);
            log << ENTER;
            break;
    }
    if(NeedFlush()) log.flush();

}
