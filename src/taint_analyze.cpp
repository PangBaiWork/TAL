
#include "taint_analyze.h"


#include "taint_utils.h"
#define UNKNOWN_CONST 0xdeadbeef
string default_taint_file = "taint.asm";
string default_trace_file = "trace.asm";
TaintTrace::TaintTrace(std::string* path, uint64_t base,PrintMode printMode=ADDR_MODE): regNames()
{
    if (path == nullptr) {
        path =new std::string("");
    }
    log.open(*path+default_taint_file, ios::out | ios::trunc);
    this->base = base;
    this->printMode = printMode;
    regNames.setGPRArray(QBDI::GPR_NAMES, regsState);
    if (isAsmMode())
    {
        log << ASM_START_STR << endl;
    }
    if (isDebugMode()||isTraceMode())
    {
        allLog.open(*path + default_trace_file, ios::out | ios::trunc);
    }
}







void TaintTrace::printMemoryOp(QBDI::GPRState* gpr,uint64_t offset,QBDI::MemoryAccess *memoryAccess,int wRegIdx,int rRegIdx){
    std::ostringstream logStr;

    std::string memOp = "[" + toHex(memoryAccess->accessAddress) + "] ";
    std::string tmp;
    if (isAddrMode()||isDebugMode())
    {
        tmp +=  toHex(offset) + ":";
    }
    tmp += "    mov ";
    if (isValid(wRegIdx)){
        tmp += regNames.get(wRegIdx);

        tmp += ", ";
        tmp += memOp;
        if (isAsmMode()) tmp += ";";
        logStr << std::left << std::setw(STR_ALIGN) << tmp;
        logStr << " | ";
        logStr << regNames[wRegIdx] <<" idx:" << wRegIdx << "=" << toHex(memoryAccess->value);
        logStr << " <" << memoryAccess->size;
        logStr << ">\n";
    } else {
        tmp += memOp;
        tmp += ", ";
        tmp += regNames.get(rRegIdx);

        if (isAsmMode()) tmp += ";";
        logStr << std::left << std::setw(STR_ALIGN) << tmp;
        logStr << regNames[rRegIdx] <<" idx:" << rRegIdx << "=" << toHex(memoryAccess->value);
        logStr << " <" << memoryAccess->size;
        logStr << "> | \n";
        // logStr << "\n";
    }
    log << logStr.str();
    log.flush();


}

#define PRINT_QBDI_REG(reg) (allLog<<#reg<<":"<<toHex(state->reg)<<endl)
// LOGE(#reg"_org:%llx,",state->reg)
void TaintTrace::printReg(QBDI::GPRState *state) {
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
    PRINT_QBDI_REG(rax);

    // PRINT_QBDI_REG();


}

QBDI::VMAction TaintTrace::instTrace(QBDI::VM *vm, QBDI::GPRState *gprState, QBDI::FPRState *fprState) {
    wRegIdx=-1;
    rRegIdx=-1;
    rwRegIdx[0]=-1;
    rwRegIdx[1]=-1;

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
                wRegIdx = operand.regCtxIdx;
                break;
            case QBDI::REGISTER_READ:
                if( !isValid(rRegIdx) || !regsState.isTaintReg(rRegIdx)){
                    rRegIdx = operand.regCtxIdx;
                }
                break;
            case QBDI::REGISTER_READ_WRITE:
                if (!isValid((rwRegIdx[0]))){
                    rwRegIdx[0] = operand.regCtxIdx;
                } else {
                    rwRegIdx[1] = operand.regCtxIdx;
                }
                break;

            case QBDI::REGISTER_UNUSED:
                // LOGE("unused reg");
                break;
        }
    }


    // trace
    if (isDebugMode()||isTraceMode())
    {

        std::ostringstream logStr1;
        logStr1 << toHex(offset) << ":" << inst->disassembly;
        allLog  << std::left << std::setw(STR_ALIGN) << logStr1.str();
        if (isValid(wRegIdx))
            allLog <<"  "<< regNames[wRegIdx] <<
                   "=" <<toHex(QBDI_GPR_GET(gprState,wRegIdx)) + " ";
        if (isValid(rwRegIdx[0]))
            allLog <<"  "<< regNames[rwRegIdx[0]] <<
                   "=" << toHex(QBDI_GPR_GET(gprState,rwRegIdx[0])) + " ";
        if (isValid(rRegIdx))
            allLog <<"  "<< regNames[rRegIdx] <<
                   "=" <<toHex(QBDI_GPR_GET(gprState,rRegIdx)) ;
        // allLog << endl;
        allLog << " | ";
        // printReg(gprState);
        setPostInstFlag();
        if (isTraceMode()) {
          return QBDI::CONTINUE;
        }
    }

    // taint process
    if (!isValid( rwRegIdx[0])){
        // no rwReg
        if (!isTaintReg(rRegIdx) && !isTaintReg(wRegIdx)){
            return QBDI::CONTINUE;
        }
        if (isTaintReg(rRegIdx) && !isTaintReg(wRegIdx)){
            if (isValid(wRegIdx)){
                regsState.setTaintReg(wRegIdx,0);
            } else {
                // CMP REG, REG
                return QBDI::CONTINUE;
            }
        } else if (!isTaintReg(rRegIdx) && isTaintReg(wRegIdx)){
            regsState.clearReg(wRegIdx);
            return QBDI::CONTINUE;
        }
    } else {
        if (!isTaintReg(rwRegIdx[0])){
            if (isTaintReg(rwRegIdx[1])){
                // XCHG REG,*REG
                regsState.clearReg(rwRegIdx[1]);
                regsState.setTaintReg(rwRegIdx[0],0);
            } else if (isTaintReg(rRegIdx)){
                /*
                 * XOR  REG,*REG
                 */
                regsState.setTaintReg(rwRegIdx[0],0);
            } else {
                   return QBDI::CONTINUE;;
            }
        } else if (isValid(rwRegIdx[1])&&!isTaintReg(rwRegIdx[1])){
            // XCHG *REG1, REG2
            regsState.clearReg(rwRegIdx[0]);
            regsState.setTaintReg(rwRegIdx[1],0);
        }
        /* INC *REG
         * XCHG *REG,REG
         * XOR *REG,REG
         * */
    }
    //log process
//    std::ostringstream logStr;
//    logStr << std::left << std::setw(STR_ALIGN)
//      << "0x" <<toHex(offset) << ":" << inst->disassembly;
//    if (isValid(wRegIdx))
//        logStr <<"  "<< regNames[wRegIdx] <<
//        "=" <<toHex(QBDI_GPR_GET(gprState,wRegIdx)) + " ";
//    if (isValid(rwRegIdx[0]))
//        logStr <<"  "<< regNames[rwRegIdx[0]] <<
//        "=" << toHex(QBDI_GPR_GET(gprState,rwRegIdx[0])) + " ";
//    if (isValid(rRegIdx))
//        logStr <<"  "<< regNames[rRegIdx] <<
//        "=" <<toHex(QBDI_GPR_GET(gprState,rRegIdx)) + "\n";
//    log << logStr.str();
    //isAsmMode()&&
    if (!isTaintReg(rRegIdx)&&isValid(rRegIdx))
    {
        log << "  mov "<< QBDI::GPR_NAMES[rRegIdx] << ", "<< toHex(QBDI_GPR_GET(gprState,rRegIdx)) <<endl;
    }

    setPostInstFlag();
    std::ostringstream logStr;
    if (isAddrMode()||isDebugMode()) logStr << toHex(offset) << ":";
    logStr << inst->disassembly;
    if (isAsmMode()) logStr << ";";
    log  << std::left << std::setw(STR_ALIGN) << logStr.str();
    if (isValid(wRegIdx))
        log <<"  "<< regNames[wRegIdx] <<
            "=" <<toHex(QBDI_GPR_GET(gprState,wRegIdx)) + " ";
    if (isValid(rwRegIdx[0]))
        log <<"  "<< regNames[rwRegIdx[0]] <<
            "=" << toHex(QBDI_GPR_GET(gprState,rwRegIdx[0])) + " ";
    if (isValid(rRegIdx))
        log <<"  "<< regNames[rRegIdx] <<
            "=" <<toHex(QBDI_GPR_GET(gprState,rRegIdx));
    log << " | ";

    // LOGE("log:%s",logStr.str().c_str());
    return QBDI::CONTINUE;

}
void TaintTrace::postInstTrace(QBDI::VM *vm, QBDI::GPRState *gprState, QBDI::FPRState *fprState)
{
    if (!postInstFlag)return;
    cleanPostInstFlag();
    if (isTraceMode()||isDebugMode()) {
      ofstream &log= allLog;
      if (isValid(wRegIdx))
        log <<"  "<< regNames[wRegIdx] <<
            "=" <<toHex(QBDI_GPR_GET(gprState,wRegIdx)) + " ";
      if (isValid(rwRegIdx[0]))
        log <<"  "<< regNames[rwRegIdx[0]] <<
            "=" << toHex(QBDI_GPR_GET(gprState,rwRegIdx[0])) + " ";
      if (isValid(rRegIdx))
        log <<"  "<< regNames[rRegIdx] <<
            "=" <<toHex(QBDI_GPR_GET(gprState,rRegIdx));
      log << endl;
      log.flush();

      return;

    }
    // todo... fix:debug mode taint.asm will lose post reg value
    if (isValid(wRegIdx))
        log <<"  "<< regNames[wRegIdx] <<
            "=" <<toHex(QBDI_GPR_GET(gprState,wRegIdx)) + " ";
    if (isValid(rwRegIdx[0]))
        log <<"  "<< regNames[rwRegIdx[0]] <<
            "=" << toHex(QBDI_GPR_GET(gprState,rwRegIdx[0])) + " ";
    if (isValid(rRegIdx))
        log <<"  "<< regNames[rRegIdx] <<
            "=" <<toHex(QBDI_GPR_GET(gprState,rRegIdx));
    log << endl;
    log.flush();
}
void TaintTrace::memoryTrace(QBDI::VM *vm, QBDI::GPRState *gprState, QBDI::FPRState *fprState) {
    int16_t rRegIdx = -1,wRegIdx = -1,rwRegIdx=-1;
    int16_t rOpIdx = -1,wOpIdx = -1;
    std::vector<QBDI::MemoryAccess> memoryAccessList = vm->getInstMemoryAccess();
    const QBDI::InstAnalysis *inst = vm->getInstAnalysis(
            QBDI::ANALYSIS_INSTRUCTION | QBDI::ANALYSIS_SYMBOL |
            QBDI::ANALYSIS_DISASSEMBLY | QBDI::ANALYSIS_OPERANDS);
    if (!inst)return;



    uint64_t offset = inst->address - base;
    // analyse operands
    for(int16_t idx = 0;idx < inst->numOperands;idx++) {
        QBDI::OperandAnalysis &operand = inst->operands[idx];
        if(operand.regAccess == QBDI::REGISTER_READ ){
            if ( !isValid(rRegIdx)||!isTaintReg(rRegIdx)){
                // only tainted reg
                rRegIdx = operand.regCtxIdx;
                rOpIdx = idx;
            }
        }else if (operand.regAccess == QBDI::REGISTER_WRITE ){
            wRegIdx = operand.regCtxIdx;
            wOpIdx = idx;
        }else if (operand.regAccess == QBDI::REGISTER_READ_WRITE){
            rwRegIdx = operand.regCtxIdx;
        }
    }

    char flag = 0;
    QBDI::MemoryAccess* memory_access_p=nullptr;
    for (QBDI::MemoryAccess &memoryAccess_item:memoryAccessList){
        switch (memoryAccess_item.type){
            case QBDI::MEMORY_READ:
                flag |= QBDI::MEMORY_READ;

                // for taint str
                checkTaintedStr(memoryAccess_item.accessAddress);

            break;
            case QBDI::MEMORY_WRITE:
                flag |= QBDI::MEMORY_WRITE;
            break;
            case QBDI::MEMORY_READ_WRITE:
                flag |= QBDI::MEMORY_READ_WRITE;
                checkTaintedStr(memoryAccess_item.accessAddress);
            break;
        }
        memory_access_p = &memoryAccess_item;
    }
    if (!memory_access_p)return;
    QBDI::MemoryAccess& memoryAccess=*memory_access_p;
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
                auto memoryRange = taintMemory.find(memoryAccess.accessAddress);
                if (memoryRange){
                    if (isValid(wRegIdx)){
                        regsState.setTaintReg(wRegIdx,0);
                        printMemoryOp(gprState,offset,&memoryAccess,wRegIdx,-1);

                    }else if(isValid(rwRegIdx)){

                        /*      XOR REG, *[MEM]
                                ADD REG, *[MEM]
                                SUB REG, *[MEM] */

                        regsState.setTaintReg(rwRegIdx,0);

                        log << "    mov "<< QBDI::GPR_NAMES[rwRegIdx] << ", "<< toHex(UNKNOWN_CONST) <<endl;
                        std::ostringstream logStr;

                        if (isAddrMode()||isDebugMode()) logStr << toHex(offset) << ":";
                        logStr << "	"<< disasmer.analyzeInst(inst->address)->mnemonic<<" "<<QBDI::GPR_NAMES[rwRegIdx]
                        <<", ["<< toHex(memoryAccess.accessAddress) <<"]";
                            // inst->disassembly;
                        if (isAsmMode()) logStr << ";";
                        log  << std::left << std::setw(STR_ALIGN) << logStr.str();
                        log <<" | "<< regNames[rwRegIdx] <<
                        "=" <<toHex(memoryAccess.value);
                        log << " <" << memoryAccess.size;
                        log << ">\n";

                    };
                } else if(isValid(wRegIdx)){
                    // MOV RAX,[*RDX]
                    if (!isTaintReg(rRegIdx))
                        regsState.clearReg(wRegIdx);
                }
            }
            break;
        case QBDI::MEMORY_WRITE:
            /* MOV [MEM], REG
             * PUSH REG
             *
             **/
            if(isTaintReg(rRegIdx)){
                printMemoryOp(gprState,offset,&memoryAccess,-1,rRegIdx);
                bool result = taintMemory.insertBySize(memoryAccess.accessAddress,memoryAccess.size);
                if (isDebugMode())
                {
                    log << flag<< "[--> add " << toHex(offset) +
                        " range:" << toHex(memoryAccess.accessAddress) +
                        "->"+ toHex(memoryAccess.accessAddress+memoryAccess.size)+ "] "<< result <<"\n";
                }
            } else {
                if (isDebugMode()){
                    auto deleteRange = taintMemory.find(memoryAccess.accessAddress);
                    if (deleteRange!=nullptr) {
                        log << "[-->remove " << toHex(offset) +
                            " range:" << toHex(deleteRange->minAddr) +
                            "->"+ toHex(deleteRange->maxAddr) + "]\n";
                    }
                }
                taintMemory.erase(memoryAccess.accessAddress);
            }
            break;
        case QBDI::MEMORY_READ_WRITE:
            /*  XOR [MEM], REG
             *  XCHG [MEM], REG
             *  ADD [MEM], REG
             *  SUB [MEM], REG
             *  AND [MEM], REG
             **/
            auto memoryRange = taintMemory.find(memoryAccess.accessAddress);
            if (!memoryRange&&!isTaintReg(rRegIdx))return;

            if (memoryRange&&!isTaintReg(rRegIdx)){
                // XOR *[MEM], REG
                log << "    mov "<< QBDI::GPR_NAMES[rRegIdx] << ", "<< toHex(UNKNOWN_CONST) << endl;
            }else if (!memoryRange&&isTaintReg(rRegIdx)){
                // XOR [MEM], *REG
                taintMemory.insertBySize(memoryAccess.accessAddress,memoryAccess.size);
            }
            std::ostringstream logStr2;
            if (isAddrMode()||isDebugMode()) logStr2 << toHex(offset) << ":";
            logStr2 << "  " << disasmer.analyzeInst(inst->address)->mnemonic << " ["<< toHex(memoryAccess.accessAddress) <<"], "
                            <<  QBDI::GPR_NAMES[rRegIdx] ;
            if (isAsmMode()) logStr2 << ";";
            log  << std::left << std::setw(STR_ALIGN) << logStr2.str();
            log <<" | ["<< toHex(memoryAccess.accessAddress) <<
                "]=" <<toHex(memoryAccess.value);
            log << " <" << memoryAccess.size;
            log << ">\n";
            break;
    }

    log.flush();

}
