#include "taint_analyze.h"

#include <cassert>

#include "trace_utils.h"






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

        log_str << std::left << std::setw(STR_ALIGN) << tmp;
        log_str << SPLIT;
        log_str << TName(reg_w) << EQ << ToHex(memoryAccess->value);
        log_str << PRINT_SIZE(memoryAccess->size);
        log_str << ENTER;
    } else {
        tmp += mem_op;
        tmp += ", ";
        tmp += RegName(rRegIdx);
        log_str << std::left << std::setw(STR_ALIGN) << tmp;
        log_str << TName(rRegIdx)  << EQ << ToHex(memoryAccess->value);
        log_str << PRINT_SIZE(memoryAccess->size);
        log_str << SPLIT ENTER;
    }
    log << log_str.str();
    if (NeedFlush()) log.flush();


}




QBDI::VMAction TaintTrace::InstTrace(QBDI::VM *vm,QBDI::GPRState *gpr, QBDI::FPRState *fpr) {

    const QBDI::InstAnalysis *inst = vm->getInstAnalysis(
            QBDI::ANALYSIS_INSTRUCTION | QBDI::ANALYSIS_SYMBOL |
                 QBDI::ANALYSIS_DISASSEMBLY | QBDI::ANALYSIS_OPERANDS );


    if (!inst) return QBDI::CONTINUE;

    CheckAndBreak(inst->address,gpr,fpr);
    uint64_t offset = inst->address - base;
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
    log  << std::left << std::setw(STR_ALIGN) << log_str.str();
    anal.PrintReg(log,gpr, true);
    log << SPLIT;
    return QBDI::CONTINUE;



}
void TaintTrace::PostInstTrace(QBDI::VM *vm,QBDI::GPRState *gpr, QBDI::FPRState *fpr)
{
    if (!enable_post_inst)return;
    CleanPostInstFlag();

    // todo... fix:debug mode taint.asm will lose post reg value
    anal.PrintReg(log,gpr, false);

    log << ENTER;
    if (inst_type == CALL) log << ENTER;
    // if(needFlush()) log.flush();
}
void TaintTrace::MemoryTrace(QBDI::VM *vm, QBDI::GPRState *gpr, QBDI::FPRState *fpr) {
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
                CheckTaintedStr(access.accessAddress,log);
                break;
            case QBDI::MEMORY_WRITE:
                flag |= QBDI::MEMORY_WRITE;
                break;
            case QBDI::MEMORY_READ_WRITE:
                flag |= QBDI::MEMORY_READ_WRITE;
                CheckTaintedStr(access.accessAddress,log);
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
                        // log_str << ASM_NOTE;
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
            // log_str2 << ASM_NOTE;
            log << std::left << std::setw(STR_ALIGN) << log_str2.str();
            log << SPLIT <<  PRINT_ADDR(access.accessAddress) << EQ <<ToHex(access.value);
            log << PRINT_SIZE(access.size);
            log << ENTER;
            break;
    }
    if(NeedFlush()) log.flush();

}
