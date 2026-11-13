#include "taint_analyze.h"

#include <cassert>

#include "trace_utils.h"






void TaintTrace::PrintMemoryOp(QBDI::GPRState* gpr,uint64_t offset,QBDI::MemoryAccess *memoryAccess,int reg_w,int rRegIdx){
    std::ostringstream log_str;

    std::string mem_op = "[" + ToHex(memoryAccess->accessAddress) + "] ";
    std::ostringstream tmp;
    if (IsAddrMode()||IsDebugMode())
    {
        tmp <<  PRINT_OFFSET(offset);
    }
    tmp << MOV;
    if (IsValid(reg_w)){
        tmp << RegName(reg_w);
        tmp << ", ";
        tmp << mem_op;

        log_str << std::left << std::setw(STR_ALIGN) << tmp.str();
        log_str << SPLIT;
        log_str << TName(reg_w) << EQ << ToHex(memoryAccess->value);
        log_str << PRINT_SIZE(memoryAccess->size);
        log_str << ENTER;
    } else {
        tmp << mem_op;
        tmp << ", ";
        tmp << RegName(rRegIdx);
        log_str << std::left << std::setw(STR_ALIGN) << tmp.str();
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
        anal.SetReg(operand.regCtxIdx, operand.regAccess, operand.flag);
    }
    int Tr_idx=anal.Tr_idx,Tw_idx=anal.Tw_idx,Trw_idx=anal.Trw_idx;
    int Cr_idx=anal.Cr_idx,Cw_idx=anal.Cw_idx,Crw_idx=anal.Crw_idx;
    // A tainted address register counts as a tainted read for propagation
    // decisions, but it is never a data source.
    const bool has_tainted_read =
        IsValid(Tr_idx) || anal.HasTaintedAddrReg();

    // trace
    AnalysisInstType(inst);

    // taint process
    if (!has_tainted_read && !IsValid(Tw_idx)&&!IsValid(Trw_idx)){
        return QBDI::CONTINUE;
    }
    if (!IsValid(Trw_idx)&&!IsValid(Crw_idx)){
        // no rwReg

        if (has_tainted_read && !IsValid(Tw_idx)){
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
        } else if (!has_tainted_read && IsValid(Tw_idx)){
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
                if (has_tainted_read) {
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
    if (!GetPostInstFlag())return;
    CleanPostInstFlag();

    // todo... fix:debug mode taint.asm will lose post reg value
    anal.PrintReg(log,gpr, false);

    log << ENTER;
    if (inst_type == CALL) log << ENTER;
    // if(needFlush()) log.flush();
}
void TaintTrace::MemoryTrace(QBDI::VM *vm, QBDI::GPRState *gpr, QBDI::FPRState *fpr) {
    RegAnalysis analysis(this);


    const QBDI::InstAnalysis *inst = vm->getInstAnalysis(
        QBDI::ANALYSIS_INSTRUCTION |
        QBDI::ANALYSIS_DISASSEMBLY | QBDI::ANALYSIS_OPERANDS);
    if (!inst) return;
    // int16_t rOpIdx = -1,wOpIdx = -1;
    std::vector<QBDI::MemoryAccess> access_list = vm->getInstMemoryAccess();


    // analyse operands
    for(int16_t idx = 0;idx < inst->numOperands;idx++) {
        const QBDI::OperandAnalysis &operand = inst->operands[idx];
        if (operand.type==QBDI::OPERAND_SEG) {
            // fs/gs not support
            if ((operand.regName[0]=='F'&&operand.regName[1]=='S')||
                (operand.regName[0]=='G'&&operand.regName[1]=='S')) {
                return;
                }
        } else {
            analysis.SetReg(operand.regCtxIdx, operand.regAccess,
                            operand.flag);
        }
    }
    // A tainted address register counts as a tainted read for propagation
    // decisions, but it is never a data source.
    const bool has_tainted_read =
        IsValid(analysis.Tr_idx) || analysis.HasTaintedAddrReg();

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
                    if (IsValid(analysis.Cw_idx)||IsValid(analysis.Tw_idx)){
                        while (IsValid(analysis.Cw_idx)) {
                            PrintMemoryOp(gpr,offset,&access,
                                          analysis.Cw[analysis.Cw_idx],-1);
                            SetTaintReg(analysis.Cw[analysis.Cw_idx--],0);
                        }
                        while (IsValid(analysis.Tw_idx)) {
                            PrintMemoryOp(gpr, offset, &access,
                                          analysis.Tw[analysis.Tw_idx], -1);
                            SetTaintReg(analysis.Tw[analysis.Tw_idx--], 0);
                        }
                    } else if(IsValid(analysis.Crw_idx)||
                              IsValid(analysis.Trw_idx)){

                        /*      XOR REG, *[MEM]
                                ADD REG, *[MEM]
                                SUB REG, *[MEM]
                                XOR *REG, [MEM]*/
                        int rw = IsValid(analysis.Crw_idx)
                                     ? analysis.Crw[analysis.Crw_idx]
                                     : analysis.Trw[analysis.Trw_idx];
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

                    if (!has_tainted_read &&
                        IsValid(analysis.Tw_idx)) {
                        // ldp *x1, *x2, [reg]
                        // MOV *RAX, [MEM]
                        while (IsValid(analysis.Tw_idx))
                            ClearTaintReg(analysis.Tw[analysis.Tw_idx--]);
                    } else if (has_tainted_read) {
                        if (IsValid(analysis.Cw_idx)) {
                            // MOV RAX,[*RDX]
                            // ldp x1, x2, [*reg] (print by InstTrace)
                            while (IsValid(analysis.Cw_idx))
                                SetTaintReg(analysis.Cw[analysis.Cw_idx--],0);
                        } else if (IsValid(analysis.Crw_idx)) {
                            SetTaintReg(analysis.Crw[analysis.Crw_idx],0);
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
            if (has_tainted_read) {
                // todo: str x1, [x2,x3]
                while (IsValid(analysis.Tr_idx)) {
                    PrintMemoryOp(gpr, offset, &access, -1,
                                  analysis.Tr[analysis.Tr_idx--]);
                }
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
            if (!range && !has_tainted_read) return;

            if (range && !has_tainted_read) {
              // XOR *[MEM], REG
              // The source register is a data register: address registers
              // (base/index) are kept out of Cr, so Cr[0] is the source.
              // The source value is auxiliary info, not an instruction, so
              // print it as a comment instead of a mov line.
              if (IsValid(analysis.Cr_idx)) {
                log << TAB << "; src " << RegName(analysis.Cr[0]) << " = "
                    << PRINT_GPR(analysis.Cr[0]) << ENTER;
              }
            } else if (!range && has_tainted_read) {
              // XOR [MEM], *REG
              AddTaintMemory(access.accessAddress, access.size);
            }
            std::ostringstream log_str2;
            if (IsAddrMode()||IsDebugMode()) log_str2 << PRINT_OFFSET(offset);
            log_str2 << TAB << disassembler.AnalyzeInst(inst->address)->mnemonic << SPACE;
            log_str2 << PRINT_ADDR(access.accessAddress) << ", ";
            if (IsValid(analysis.Tr_idx)) {
              log_str2 << RegName(analysis.Tr[0]);
            } else if (IsValid(analysis.Cr_idx)) {
              log_str2 << RegName(analysis.Cr[0]);
            } else {
              // xor [mem], imm: there is no source register.
              log_str2 << "imm";
            }
            log << std::left << std::setw(STR_ALIGN) << log_str2.str();
            log << SPLIT <<  PRINT_ADDR(access.accessAddress) << EQ <<ToHex(access.value);
            log << PRINT_SIZE(access.size);
            log << ENTER;
            break;
    }
    if(NeedFlush()) log.flush();

}
