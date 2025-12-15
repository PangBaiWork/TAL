
#include "taint_analyze.h"

#include <cassert>

#include "taint_utils.h"
#define UNKNOWN_CONST 0xdeadbeef
#define TAB "\t"
#define ENTER std::endl
std::string default_taint_file = ".asm";
std::string default_trace_file = "trace.asm";
TaintTrace::TaintTrace(const std::string* path, const uint64_t base,
                       const PrintMode mode=ADDR_MODE): reg_name()
{
    if (path == nullptr) {
        path =new std::string("");
    }
    log.open(*path+ModeName[mode]+default_taint_file, std::ios::out | std::ios::trunc);
    this->base = base;
    this->mode = mode;
    reg_name.SetGPRArray(QBDI::GPR_NAMES, state);
    if (IsAsmMode())
    {
        log << ASM_START_STR << ENTER;
    }
    if (IsDebugMode()||IsTraceMode())
    {
        all_log.open(*path + default_trace_file, std::ios::out | std::ios::trunc);
    }
}







void TaintTrace::PrintMemoryOp(QBDI::GPRState* gpr,uint64_t offset,QBDI::MemoryAccess *memoryAccess,int reg_w,int rRegIdx){
    std::ostringstream log_str;

    std::string mem_op = "[" + ToHex(memoryAccess->accessAddress) + "] ";
    std::string tmp;
    if (IsAddrMode()||IsDebugMode())
    {
        tmp +=  ToHex(offset) + ":";
    }
    tmp += TAB "mov ";
    if (IsValid(reg_w)){
        tmp += reg_name.get(reg_w);

        tmp += ", ";
        tmp += mem_op;
        if (IsAsmMode()) tmp += ";";
        log_str << std::left << std::setw(STR_ALIGN) << tmp;
        log_str << " | ";
        log_str << reg_name[reg_w] << "=" << ToHex(memoryAccess->value);
        log_str << " <" << memoryAccess->size;
        log_str << ">\n";
    } else {
        tmp += mem_op;
        tmp += ", ";
        tmp += reg_name.get(rRegIdx);

        if (IsAsmMode()) tmp += ";";
        log_str << std::left << std::setw(STR_ALIGN) << tmp;
        log_str << reg_name[rRegIdx]  << "=" << ToHex(memoryAccess->value);
        log_str << " <" << memoryAccess->size;
        log_str << "> | \n";
    }
    log << log_str.str();
    if (NeedFlush()) log.flush();


}

#define PRINT_QBDI_REG(reg) (all_log<<#reg<<":"<<ToHex(state->reg)<<ENTER)
// LOGE(#reg"_org:%llx,",state->reg)
QBDI::rword gs=0;
void TaintTrace::PrintReg(const QBDI::GPRState *state) {
    // PRINT_QBDI_REG(r8);
    // PRINT_QBDI_REG(r9);
    // PRINT_QBDI_REG(r10);
    // PRINT_QBDI_REG(r11);
    // PRINT_QBDI_REG(r12);
    // PRINT_QBDI_REG(r13);
    // PRINT_QBDI_REG(r14);
    // PRINT_QBDI_REG(r15);
    //
    // PRINT_QBDI_REG(rax);
    // PRINT_QBDI_REG(rcx);
    // PRINT_QBDI_REG(rdx);
    // PRINT_QBDI_REG(rbx);
    // PRINT_QBDI_REG(rsp);
    // PRINT_QBDI_REG(rbp);
    // PRINT_QBDI_REG(rsi);
    // PRINT_QBDI_REG(rdi);
    PRINT_QBDI_REG(gs);
    // if (!gs) {
    //   gs=state->gs;
    // }else {
    //   state->gs=gs;
    // }
    // PRINT_QBDI_REG(rax);

    // PRINT_QBDI_REG();


}

QBDI::VMAction TaintTrace::InstTrace(const QBDI::VM *vm,
                                     const QBDI::GPRState *gpr, QBDI::FPRState *fpr) {
    reg_w=-1;
    reg_r=-1;
    reg_rw[0]=-1;
    reg_rw[1]=-1;

    const QBDI::InstAnalysis *inst = vm->getInstAnalysis(
            QBDI::ANALYSIS_INSTRUCTION | QBDI::ANALYSIS_SYMBOL |
                 QBDI::ANALYSIS_DISASSEMBLY | QBDI::ANALYSIS_OPERANDS);


    if (!inst) return QBDI::CONTINUE;
    const uint64_t offset = inst->address - base;

    // analyse operands
    for(int idx = 0;idx < inst->numOperands;idx++){
        QBDI::OperandAnalysis &operand =  inst->operands[idx];
        switch (operand.regAccess) {
            case QBDI::REGISTER_WRITE:
                reg_w = operand.regCtxIdx;
                break;
            case QBDI::REGISTER_READ:
                if( !IsValid(reg_r) || !state.IsTaintReg(reg_r)){
                    reg_r = operand.regCtxIdx;
                }
                break;
            case QBDI::REGISTER_READ_WRITE:
                if (!IsValid((reg_rw[0]))){
                    reg_rw[0] = operand.regCtxIdx;
                } else {
                    reg_rw[1] = operand.regCtxIdx;
                }
                break;

            case QBDI::REGISTER_UNUSED:
                assert(false);
                break;
        }
    }


    // trace
    if (IsDebugMode()||IsTraceMode())
    {

        std::ostringstream log_str1;
        log_str1 << ToHex(offset) << ":" << inst->disassembly;
        all_log  << std::left << std::setw(STR_ALIGN) << log_str1.str();
        if (IsValid(reg_w))
            all_log <<"  "<< reg_name[reg_w] <<
                   "=" <<ToHex(QBDI_GPR_GET(gpr,reg_w)) + " ";
        if (IsValid(reg_rw[0]))
            all_log <<"  "<< reg_name[reg_rw[0]] <<
                   "=" << ToHex(QBDI_GPR_GET(gpr,reg_rw[0])) + " ";
        if (IsValid(reg_r))
            all_log <<"  "<< reg_name[reg_r] <<
                   "=" <<ToHex(QBDI_GPR_GET(gpr,reg_r)) ;
        // allLog << ENTER;
        all_log << " | ";
        // printReg(gprState);
        SetPostInstFlag();
        if (IsTraceMode()) {
          return QBDI::CONTINUE;
        }
    }

    // taint process
    if (!IsValid( reg_rw[0])){
        // no rwReg
        if (!IsTaint(reg_r) && !IsTaint(reg_w)){
            return QBDI::CONTINUE;
        }
        if (IsTaint(reg_r) && !IsTaint(reg_w)){
            if (IsValid(reg_w)){
                SetTaintReg(reg_w,0);
            } else {
                // CMP REG, *REG
                // mov	mem, *rax
                if (!inst->isCompare) return QBDI::CONTINUE;
            }
        } else if (!IsTaint(reg_r) && IsTaint(reg_w)){
            state.ClearReg(reg_w);
            return QBDI::CONTINUE;
        }
    } else {
        if (!IsTaint(reg_rw[0])){
            if (IsTaint(reg_rw[1])){
                // XCHG REG,*REG
                state.ClearReg(reg_rw[1]);
                SetTaintReg(reg_rw[0],0);
            } else if (IsTaint(reg_r)){
                /*
                 * XOR  REG,*REG
                 * PUSH *REG
                 */
                if (reg_rw[0] == QBDI::REG_SP) {
                  return QBDI::CONTINUE;
                }
                SetTaintReg(reg_rw[0],0);
            } else {
                   return QBDI::CONTINUE;;
            }
        } else if (IsValid(reg_rw[1])&&!IsTaint(reg_rw[1])){
            // XCHG *REG1, REG2
            state.ClearReg(reg_rw[0]);
            SetTaintReg(reg_rw[1],0);
        }
        /* INC *REG
         * XCHG *REG,REG
         * XOR *REG,REG
         * */
    }
    //log process
//    std::ostringstream logStr;
//    logStr << std::left << std::setw(STR_ALIGN)
//      << "0x" <<ToHex(offset) << ":" << inst->disassembly;
//    if (isValid(wRegIdx))
//        logStr <<"  "<< regNames[wRegIdx] <<
//        "=" <<ToHex(QBDI_GPR_GET(gprState,wRegIdx)) + " ";
//    if (isValid(rwRegIdx[0]))
//        logStr <<"  "<< regNames[rwRegIdx[0]] <<
//        "=" << ToHex(QBDI_GPR_GET(gprState,rwRegIdx[0])) + " ";
//    if (isValid(rRegIdx))
//        logStr <<"  "<< regNames[rRegIdx] <<
//        "=" <<ToHex(QBDI_GPR_GET(gprState,rRegIdx)) + "\n";
//    log << logStr.str();
    //isAsmMode()&&


    SetPostInstFlag();

    if (!IsTaint(reg_r)&&IsValid(reg_r))
    {
      // for asm
      if (IsAddrMode()||IsDebugMode()) log << ToHex(offset) << ":";
      log << TAB "mov "<< QBDI::GPR_NAMES[reg_r] << ", "<< ToHex(QBDI_GPR_GET(gpr,reg_r)) <<ENTER;
    }
    std::ostringstream log_str;
    // if (inst->symbolName) logStr << inst->symbolName << "!";
    if (IsAddrMode()||IsDebugMode()) log_str << ToHex(offset) << ":";
    log_str << inst->disassembly;
    if (IsAsmMode()) log_str << ";";
    log  << std::left << std::setw(STR_ALIGN) << log_str.str();
    if (IsValid(reg_w))
        log <<"  "<< reg_name[reg_w] <<
            "=" <<ToHex(QBDI_GPR_GET(gpr,reg_w)) + " ";
    if (IsValid(reg_rw[0]))
        log <<"  "<< reg_name[reg_rw[0]] <<
            "=" << ToHex(QBDI_GPR_GET(gpr,reg_rw[0])) + " ";
    if (IsValid(reg_r))
        log <<"  "<< reg_name[reg_r] <<
            "=" <<ToHex(QBDI_GPR_GET(gpr,reg_r));
    log << " | ";
    return QBDI::CONTINUE;

}
void TaintTrace::PostInstTrace(QBDI::VM *vm, QBDI::GPRState *gprState, QBDI::FPRState *fprState)
{
    if (!enable_post_inst)return;
    CleanPostInstFlag();
    if (IsTraceMode()||IsDebugMode()) {
      std::ofstream &log= all_log;
      // printReg(gprState);
      if (IsValid(reg_w))
        log <<"  "<< reg_name[reg_w] <<
            "=" <<ToHex(QBDI_GPR_GET(gprState,reg_w)) + " ";
      if (IsValid(reg_rw[0]))
        log <<"  "<< reg_name[reg_rw[0]] <<
            "=" << ToHex(QBDI_GPR_GET(gprState,reg_rw[0])) + " ";
      if (IsValid(reg_r))
        log <<"  "<< reg_name[reg_r] <<
            "=" <<ToHex(QBDI_GPR_GET(gprState,reg_r));
      log << ENTER;
      if(NeedFlush()) log.flush();

      return;

    }
    // todo... fix:debug mode taint.asm will lose post reg value
    if (IsValid(reg_w))
        log <<"  "<< reg_name[reg_w] <<
            "=" <<ToHex(QBDI_GPR_GET(gprState,reg_w)) + " ";
    if (IsValid(reg_rw[0]))
        log <<"  "<< reg_name[reg_rw[0]] <<
            "=" << ToHex(QBDI_GPR_GET(gprState,reg_rw[0])) + " ";
    if (IsValid(reg_r))
        log <<"  "<< reg_name[reg_r] <<
            "=" <<ToHex(QBDI_GPR_GET(gprState,reg_r));
    log << ENTER;
    // if(needFlush()) log.flush();
}
void TaintTrace::MemoryTrace(QBDI::VM *vm, QBDI::GPRState *gprState, QBDI::FPRState *fprState) {
    int16_t reg_r = -1,reg_w = -1,reg_rw=-1;
    // int16_t rOpIdx = -1,wOpIdx = -1;
    std::vector<QBDI::MemoryAccess> access_list = vm->getInstMemoryAccess();
    const QBDI::InstAnalysis *inst = vm->getInstAnalysis(
            QBDI::ANALYSIS_INSTRUCTION | QBDI::ANALYSIS_SYMBOL |
            QBDI::ANALYSIS_DISASSEMBLY | QBDI::ANALYSIS_OPERANDS);
    if (!inst) return;

    const uint64_t offset = inst->address - base;
    // analyse operands
    for(int16_t idx = 0;idx < inst->numOperands;idx++) {
        const QBDI::OperandAnalysis &operand = inst->operands[idx];
        if(operand.regAccess == QBDI::REGISTER_READ ){
            if ( !IsValid(reg_r)||!IsTaint(reg_r)){
                // only tainted reg
                reg_r = operand.regCtxIdx;
                // rOpIdx = idx;
            }
        }else if (operand.regAccess == QBDI::REGISTER_WRITE ){
            reg_w = operand.regCtxIdx;
            // wOpIdx = idx;
        }else if (operand.regAccess == QBDI::REGISTER_READ_WRITE){
            reg_rw = operand.regCtxIdx;
        }
    }

    char flag = 0;
    QBDI::MemoryAccess* access_p=nullptr;
    for (QBDI::MemoryAccess &access:access_list){
        switch (access.type){
            case QBDI::MEMORY_READ:
                flag |= QBDI::MEMORY_READ;
                // for taint str
                CheckTaintedStr(access.accessAddress);

            break;
            case QBDI::MEMORY_WRITE:
                flag |= QBDI::MEMORY_WRITE;
            break;
            case QBDI::MEMORY_READ_WRITE:
                flag |= QBDI::MEMORY_READ_WRITE;
                CheckTaintedStr(access.accessAddress);
            break;
        }
        access_p = &access;
    }
    if (!access_p)return;
    QBDI::MemoryAccess& access=*access_p;
    switch (flag) {
        case QBDI::MEMORY_READ:
            {
             /*     POP REG
           *     MOV REG, [MEM]
           *
                 XOR REG, [MEM]
                 ADD REG, [MEM]
                 SUB REG, [MEM]
                 AND REG, [MEM]
                 OR  REG, [MEM] */
                const auto range = memory.find(access.accessAddress);
                if (range){
                    if (IsValid(reg_w)){
                        SetTaintReg(reg_w,0);
                        PrintMemoryOp(gprState,offset,&access,reg_w,-1);

                    }else if(IsValid(reg_rw)){

                        /*      XOR REG, *[MEM]
                                ADD REG, *[MEM]
                                SUB REG, *[MEM] */

                        SetTaintReg(reg_rw,0);

                        if (IsAddrMode()||IsDebugMode()) log << ToHex(offset) << ":";
                        log << TAB "mov "<< QBDI::GPR_NAMES[reg_rw] << ", "<< ToHex(UNKNOWN_CONST) <<ENTER;
                        std::ostringstream log_str;

                        if (IsAddrMode()||IsDebugMode()) log_str << ToHex(offset) << ":";
                        log_str << TAB << disassembler.AnalyzeInst(inst->address)->mnemonic<<" "<<QBDI::GPR_NAMES[reg_rw]
                        <<", ["<< ToHex(access.accessAddress) <<"]";
                            // inst->disassembly;
                        if (IsAsmMode()) log_str << ";";
                        log  << std::left << std::setw(STR_ALIGN) << log_str.str();
                        log <<" | "<< reg_name[reg_rw] <<
                        "=" <<ToHex(access.value);
                        log << " <" << access.size;
                        log << ">\n";

                    };
                } else if(IsValid(reg_w)){
                    // MOV RAX,[*RDX]
                    if (!IsTaint(reg_r))
                        state.ClearReg(reg_w);
                }
            }
            break;
        case QBDI::MEMORY_WRITE:
            /* MOV [MEM], REG
             * PUSH REG
             *
             **/
            if(IsTaint(reg_r)){
                PrintMemoryOp(gprState, offset, &access, -1, reg_r);
                const bool result = memory.InsertBySize(access.accessAddress,access.size);
                if (IsDebugMode())
                {
                    log <<  "[--> add " << ToHex(offset) +
                        " range:" << ToHex(access.accessAddress) +
                        "->"+ ToHex(access.accessAddress+access.size)+ "] "<< result <<"\n";
                }
            } else {
                if (IsDebugMode()) {
                    const auto del = memory.find(access.accessAddress);
                    if (del!=nullptr) {
                        log << "[-->remove " << ToHex(offset) +
                            " range:" << ToHex(del->min) +
                            "->"+ ToHex(del->max) + "]\n";
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
            const auto range = memory.find(access.accessAddress);
            if (!range&&!IsTaint(reg_r))return;

            if (range&&!IsTaint(reg_r)){
                // XOR *[MEM], REG
                if (IsAddrMode()||IsDebugMode()) log << ToHex(offset) << ":";
                log << TAB "mov "<< QBDI::GPR_NAMES[reg_r] << ", "<< ToHex(QBDI_GPR_GET(gprState,reg_r)) << ENTER;
            }else if (!range&&IsTaint(reg_r)){
                // XOR [MEM], *REG
                memory.InsertBySize(access.accessAddress,access.size);
            }
            std::ostringstream log_str2;
            if (IsAddrMode()||IsDebugMode()) log_str2 << ToHex(offset) << ":";
            log_str2 << TAB << disassembler.AnalyzeInst(inst->address)->mnemonic << " ["<< ToHex(access.accessAddress) <<"], "
                            <<  QBDI::GPR_NAMES[reg_r] ;
            if (IsAsmMode()) log_str2 << ";";
            log  << std::left << std::setw(STR_ALIGN) << log_str2.str();
            log <<" | ["<< ToHex(access.accessAddress) <<
                "]=" <<ToHex(access.value);
            log << " <" << access.size;
            log << ">\n";
            break;
    }
    if(NeedFlush()) log.flush();

}
