
#include "taint_analyze.h"

#include <cassert>

#include "taint_utils.h"
#define UNKNOWN_CONST 0xdeadbeef
#define TAB "\t"
#define SPLIT " | "
#define ENTER "\n"
#define SPACE " "
#define EQ "="
#define MOV (TAB "mov ")
#define BLANK ""
// std::endl

#define ASM_NOTE (IsAsmMode() ? ";" : BLANK)
#define PRINT_OFFSET(OFFSET) (ToHex(OFFSET) + ":")
#define PRINT_ADDR(VALUE) ("[" + ToHex(VALUE) + "]")
#define PRINT_SIZE(SIZE) (" <" + ToHex(SIZE) + "> ")
#define PRINT_GPR(REG)  ToHex(QBDI_GPR_GET(gpr,REG))
#define PRINT_QBDI_REG(reg) (all_log << #reg << ":" << ToHex(state->reg) << ENTER)

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



QBDI::VMAction TaintTrace::InstTrace(const QBDI::VM *vm,
                                     const QBDI::GPRState *gpr, QBDI::FPRState *fpr) {
    wreg=-1,rreg=-1,rwreg[0]=-1,rwreg[1]=-1;

    const QBDI::InstAnalysis *inst = vm->getInstAnalysis(
            QBDI::ANALYSIS_INSTRUCTION | QBDI::ANALYSIS_SYMBOL |
                 QBDI::ANALYSIS_DISASSEMBLY | QBDI::ANALYSIS_OPERANDS);


    if (!inst) return QBDI::CONTINUE;
    uint64_t offset = inst->address - base;

    // analyse operands
    for(int idx = 0;idx < inst->numOperands;idx++){
        QBDI::OperandAnalysis &operand =  inst->operands[idx];
        switch (operand.regAccess) {
            case QBDI::REGISTER_WRITE:
                wreg = operand.regCtxIdx;
                break;
            case QBDI::REGISTER_READ:
                if( !IsValid(rreg) || !state.IsTaintReg(rreg)){
                    rreg = operand.regCtxIdx;
                }
                break;
            case QBDI::REGISTER_READ_WRITE:
                if (!IsValid((rwreg[0]))){
                    rwreg[0] = operand.regCtxIdx;
                } else {
                    rwreg[1] = operand.regCtxIdx;
                }
                break;

            case QBDI::REGISTER_UNUSED:
                // assert(false);
                break;
        }
    }


    // trace
    if (IsDebugMode()||IsTraceMode())
    {

        std::ostringstream log_str1;
        if (IsDebugMode()&&inst->moduleName) {
          offset = inst->address - GetAndSaveBase(inst->moduleName);
          log_str1 << inst->moduleName << ":";
        }
        log_str1 << PRINT_OFFSET(offset) << inst->disassembly;
        all_log  << std::left << std::setw(STR_ALIGN) << log_str1.str();
        if (IsValid(wreg))
            all_log << SPACE << TName(wreg) <<     EQ << PRINT_GPR(wreg) + SPACE;
        if (IsValid(rwreg[0]))
            all_log << SPACE << TName(rwreg[0]) << EQ << PRINT_GPR(rwreg[0]) + SPACE;
        if (IsValid(rreg))
            all_log << SPACE << TName(rreg) <<     EQ << PRINT_GPR(rreg) ;
        // allLog << ENTER;
        all_log << SPLIT;
        SetPostInstFlag();
        if (IsTraceMode()) {
          return QBDI::CONTINUE;
        }
    }

    // taint process
    if (!IsValid( rwreg[0])){
        // no rwReg
        if (!IsTaint(rreg) && !IsTaint(wreg)){
            return QBDI::CONTINUE;
        }
        if (IsTaint(rreg) && !IsTaint(wreg)){
            if (IsValid(wreg)){
                SetTaintReg(wreg,0);
            } else {
                // CMP REG, *REG
                // mov	mem, *rax
                if (!inst->isCompare) return QBDI::CONTINUE;
            }
        } else if (!IsTaint(rreg) && IsTaint(wreg)){
            state.ClearReg(wreg);
            return QBDI::CONTINUE;
        }
    } else {
        if (!IsTaint(rwreg[0])){
            if (IsTaint(rwreg[1])){
                // XCHG REG,*REG
                state.ClearReg(rwreg[1]);
                SetTaintReg(rwreg[0],0);
            } else if (IsTaint(rreg)){
                /*
                 * XOR  REG,*REG
                 * PUSH *REG
                 */
                if (rwreg[0] == QBDI::REG_SP) {
                  return QBDI::CONTINUE;
                }
                SetTaintReg(rwreg[0],0);
            } else {
                   return QBDI::CONTINUE;;
            }
        } else if (IsValid(rwreg[1])&&!IsTaint(rwreg[1])){
            // XCHG *REG1, REG2
            state.ClearReg(rwreg[0]);
            SetTaintReg(rwreg[1],0);
        }
        /* INC *REG
         * XCHG *REG,REG
         * XOR *REG,REG
         * */
    }

    SetPostInstFlag();
    if (!IsTaint(rreg)&&IsValid(rreg))
    {
      // for asm
      if (IsAddrMode()||IsDebugMode()) log << PRINT_OFFSET(offset);
      log << MOV << RegName(rreg) << ", "<< PRINT_GPR(rreg) <<ENTER;
    }
    std::ostringstream log_str;
    // if (inst->symbolName) logStr << inst->symbolName << "!";
    if (IsAddrMode()||IsDebugMode()) log_str << PRINT_OFFSET(offset);
    log_str << inst->disassembly;
    log_str << ASM_NOTE;
    log  << std::left << std::setw(STR_ALIGN) << log_str.str();
    if (IsValid(wreg))
        log << SPACE << TName(wreg)     << EQ << PRINT_GPR(wreg) + SPACE;
    if (IsValid(rwreg[0]))
        log << SPACE << TName(rwreg[0]) << EQ << PRINT_GPR(rwreg[0]) + SPACE;
    if (IsValid(rreg))
        log << SPACE << TName(rreg)     << EQ << PRINT_GPR(rreg);
    log << SPLIT;
    return QBDI::CONTINUE;

}
void TaintTrace::PostInstTrace(QBDI::VM *vm, const QBDI::GPRState *gpr, QBDI::FPRState *fpr)
{
    if (!enable_post_inst)return;
    CleanPostInstFlag();
    if (IsTraceMode()||IsDebugMode()) {
      std::ofstream &log= all_log;
      // printReg(gprState);
      if (IsValid(wreg))
          log << SPACE << TName(wreg) << EQ << PRINT_GPR(wreg) << " ";
      if (IsValid(rwreg[0]))
          log << SPACE << TName(rwreg[0]) << EQ << PRINT_GPR(rwreg[0]) << " ";
      if (IsValid(rreg))
          log << SPACE << TName(rreg) << EQ << PRINT_GPR(rreg);
      log << ENTER;
      if(NeedFlush()) log.flush();

      return;

    }
    // todo... fix:debug mode taint.asm will lose post reg value
    if (IsValid(wreg))
        log << SPACE << TName(wreg) << EQ << PRINT_GPR(wreg) << SPACE;
    if (IsValid(rwreg[0]))
        log << SPACE << TName(rwreg[0]) << EQ << PRINT_GPR(rwreg[0]) << SPACE;
    if (IsValid(rreg))
        log << SPACE << TName(rreg) << EQ << PRINT_GPR(rreg);
    log << ENTER;
    // if(needFlush()) log.flush();
}
void TaintTrace::MemoryTrace(const QBDI::VM *vm, QBDI::GPRState *gpr, QBDI::FPRState *fpr) {
    int16_t rreg = -1,wreg = -1,rwreg=-1;
    // int16_t rOpIdx = -1,wOpIdx = -1;
    std::vector<QBDI::MemoryAccess> access_list = vm->getInstMemoryAccess();
    const QBDI::InstAnalysis *inst = vm->getInstAnalysis(
            QBDI::ANALYSIS_INSTRUCTION |
            QBDI::ANALYSIS_DISASSEMBLY | QBDI::ANALYSIS_OPERANDS);
    if (!inst) return;

    const uint64_t offset = inst->address - base;
    // analyse operands
    for(int16_t idx = 0;idx < inst->numOperands;idx++) {
        const QBDI::OperandAnalysis &operand = inst->operands[idx];
        if(operand.regAccess == QBDI::REGISTER_READ ){
            if ( !IsValid(rreg)||!IsTaint(rreg)){
                // only tainted reg
                rreg = operand.regCtxIdx;
                // rOpIdx = idx;
            }
        }else if (operand.regAccess == QBDI::REGISTER_WRITE ){
            wreg = operand.regCtxIdx;
            // wOpIdx = idx;
        }else if (operand.regAccess == QBDI::REGISTER_READ_WRITE){
            rwreg = operand.regCtxIdx;
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
              *     XOR REG, [MEM]
              *     ADD REG, [MEM]
              *     SUB REG, [MEM]
              *     AND REG, [MEM]
              *     OR  REG, [MEM] */
                const auto range = memory.find(access.accessAddress);
                if (range){
                    if (IsValid(wreg)){
                        SetTaintReg(wreg,0);
                        PrintMemoryOp(gpr,offset,&access,wreg,-1);

                    }else if(IsValid(rwreg)){

                        /*      XOR REG, *[MEM]
                                ADD REG, *[MEM]
                                SUB REG, *[MEM] */

                        SetTaintReg(rwreg,0);

                        if (IsAddrMode()||IsDebugMode()) log << PRINT_OFFSET(offset);
                        log << MOV<< RegName(rwreg) << ", "<< ToHex(UNKNOWN_CONST) <<ENTER;
                        std::ostringstream log_str;

                        if (IsAddrMode()||IsDebugMode()) log_str << PRINT_OFFSET(offset);
                        log_str << TAB << disassembler.AnalyzeInst(inst->address)->mnemonic<<SPACE;
                        log_str << RegName(rwreg) << ", " << PRINT_ADDR(access.accessAddress);
                        log_str << ASM_NOTE;
                        log << std::left << std::setw(STR_ALIGN) << log_str.str();
                        log << SPLIT << TName(rwreg) << EQ <<ToHex(access.value);
                        log << PRINT_SIZE(access.size);
                        log << ENTER;

                    };
                } else if(IsValid(wreg)){
                    // MOV RAX,[*RDX]
                    if (!IsTaint(rreg))
                        state.ClearReg(wreg);
                }
            }
            break;
        case QBDI::MEMORY_WRITE:
            /* MOV [MEM], REG
             * PUSH REG
             *
             **/
            if(IsTaint(rreg)){
                PrintMemoryOp(gpr, offset, &access, -1, rreg);
                const bool result = memory.InsertBySize(access.accessAddress, access.size);
                if (IsDebugMode())
                {
                    log <<  "[--> add " << ToHex(offset) +
                        " range:" << ToHex(access.accessAddress) +
                        "->"+ ToHex(access.accessAddress+access.size)+ "] "<< result << ENTER;
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
            const auto range = memory.find(access.accessAddress);
            if (!range && !IsTaint(rreg)) return;

            if (range && !IsTaint(rreg)) {
              // XOR *[MEM], REG
              if (IsAddrMode() || IsDebugMode()) log << PRINT_OFFSET(offset);
              log << MOV << RegName(rreg) << ", "
                  <<  PRINT_GPR(rreg) << ENTER;
            } else if (!range && IsTaint(rreg)) {
              // XOR [MEM], *REG
              memory.InsertBySize(access.accessAddress, access.size);
            }
            std::ostringstream log_str2;
            if (IsAddrMode()||IsDebugMode()) log_str2 << PRINT_OFFSET(offset);
            log_str2 << TAB << disassembler.AnalyzeInst(inst->address)->mnemonic << SPACE;
            log_str2 << PRINT_ADDR(access.accessAddress) << ", " <<  RegName(rreg) ;
            log_str2 << ASM_NOTE;
            log << std::left << std::setw(STR_ALIGN) << log_str2.str();
            log << SPLIT <<  PRINT_ADDR(access.accessAddress) << EQ <<ToHex(access.value);
            log << PRINT_SIZE(access.size);
            log << ENTER;
            break;
    }
    if(NeedFlush()) log.flush();

}
