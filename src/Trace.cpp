//
// Created by pangb on 26-2-23.
//

#include "trace.h"

Trace::Trace(const uint64_t base, const PrintMode mode,
             const std::string *path) {
    this->base = base;
    this->mode = mode;
    reg_name.SetGPRArray(QBDI::GPR_NAMES, state);
    if (IsBinMode()) {
        printable_size = 0;
    }
    SetOutputPath(path);
}

QBDI::VMAction Trace::InstTrace(QBDI::VM *vm, QBDI::GPRState *gpr,
                                 QBDI::FPRState *fpr) {
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
    AnalysisInstType(inst);
    log << std::endl;
    if (inst->moduleName) {
        offset = inst->address - GetAndSaveBase(inst->moduleName);
        log << inst->moduleName << ":";
    }
    if (IsBinMode()) {
        log << PRINT_DATA(reinterpret_cast<uint8_t*>(inst->address),inst->instSize);
    }
    log << BASE_LOG;
    anal.PrintReg(log,gpr,true);

    SetPostInstFlag();
    return QBDI::CONTINUE;
}

void Trace::PostInstTrace(QBDI::VM *vm, QBDI::GPRState *gpr, QBDI::FPRState *fpr) {
    if (enable_post_inst) {
        anal.PrintReg(log,gpr,false);

        if (inst_type == CALL&&!IsBinMode()) log << ENTER;
        CleanPostInstFlag();
    }
}

void Trace::MemoryTrace(QBDI::VM *vm, QBDI::GPRState *gpr, QBDI::FPRState *fpr) {
    if (IsBinMode()||inst_type==CALL)return;
    std::vector<QBDI::MemoryAccess> access_list = vm->getInstMemoryAccess();
    char flag = 0;
    std::string printable;
    for (QBDI::MemoryAccess &access:access_list){
        switch (access.type){
            case QBDI::MEMORY_READ:
                flag |= QBDI::MEMORY_READ;
                if(IsPrintable(access.accessAddress,printable_size)){
                    printable = PrintStr(access.accessAddress);
                }
                PrintMemoryOp(access,printable);
                CheckTaintedStr(access.accessAddress,log);
                break;
            case QBDI::MEMORY_WRITE:
                flag |= QBDI::MEMORY_WRITE;
                if(IsPrintable(access.accessAddress,printable_size)){
                    printable = PrintStr(access.accessAddress);
                }
                PrintMemoryOp(access,printable);
                break;
            case QBDI::MEMORY_READ_WRITE:
                flag |= QBDI::MEMORY_READ_WRITE;
                if(IsPrintable(access.accessAddress,printable_size)){
                    printable = PrintStr(access.accessAddress);
                }
                PrintMemoryOp(access,printable);
                CheckTaintedStr(access.accessAddress,log);
                break;
        }
    }

}

bool Trace::SetOutputPath(const std::string *path) {
    std::string def_path = std::string(BLANK);
    if (path == nullptr) {
        path = &def_path;
    }
    if (log.is_open()) {
        log.close();
        log.clear();
    }
    log.open(*path + ModeName[mode] + ".asm", std::ios::out | std::ios::trunc);
    return log.is_open();
}

void Trace::AnalysisInstType(const QBDI::InstAnalysis *inst) {
    if (inst->isCall) {
        inst_type = CALL;
    } else if (inst->isReturn) {
        inst_type = RET;
    } else if (inst->isPredicable && inst->isBranch) {
        inst_type = IF_JMP;
    } else {
        inst_type = NONE;
    }
}

uint64_t Trace::GetAndSaveBase(const char *module_name) {
    uint64_t bais = 0;
    const auto iter = base_map.find(module_name);
    if (iter == base_map.end()) {
        GumModule *mod = gum_process_find_module_by_name(module_name);
        if (mod) {
            bais = gum_module_get_range(mod)->base_address;
            log << "base:" << module_name << "=" << ToHex(bais)
                    << std::endl;
            base_map[module_name] = bais;
        }
    } else {
        bais = iter->second;
    }
    return bais;
}

bool Trace::IsTaint(const int reg) {
    if (!IsValid(reg)) return false;
    return state.IsTaintReg(reg);
}

bool Trace::CheckAndBreak(uint64_t addr, const QBDI::GPRState *gpr,
                                     QBDI::FPRState *fpr) {
    bool need_break = false;
    need_break =  addr == trace_end;
    if (!need_break) {
        for (auto& range : escape_execute) {
            if (range.min == addr) {
                need_break = true;
                break;
            }
        }
    }
    if (need_break) {
        LOGI("vm break on %llx",addr);
        auto& engine_ptr = GetPrivate(*qvm);
        auto& execBroker_ptr = GetPrivate(*engine_ptr);
        auto& transferBlock = GetPrivate(*execBroker_ptr);
        transferBlock->getContext()->gprState = *gpr;
        transferBlock->getContext()->fprState = *fpr;
        transferBlock->getContext()->hostState.selector = addr;
        guest_stack.RestoreStack();
        transferBlock->run();
    }
    return need_break;
}

bool Trace::SetTaintReg(const int reg, const uint64_t ref) {
    if (reg < 0) return false;
    state.SetTaintReg(reg, ref);
    return true;
}

void Trace::ClearTaintReg(const int reg) {
    if (reg < 0) return;
    state.ClearReg(reg);
}

void Trace::SetTaintStr(char *str) {
    if (str) {
        taint_str = new char[strlen(str) + 1];
        strcpy(taint_str, str);
        LOGE("TaintStr set: %s %s", taint_str, str);
    }
}

bool Trace::CheckTaintedStr(const uint64_t addr,std::ofstream& log) {
    if (taint_str && READABLE_ADDR < addr) {
        if (auto ptr = reinterpret_cast<char *>(addr);
            ptr[0] == taint_str[0] && ptr[1] == taint_str[1] &&
            ptr[2] == taint_str[2] && ptr[3] == taint_str[3]) {
            const int len = GetSameStrLen(ptr, taint_str);
            LOGE("Insert Taint Memory: %s %d", ptr, len);
            log << std::endl << "Insert Taint Memory: " << ptr << std::endl;
            AddTaintMemory(reinterpret_cast<uint64_t>(ptr), len);
            taint_str = nullptr;
            return true;
        }
    }
    return false;
}
void Trace::RegAnalysis::SetReg(int reg, RegAccess access) {
    if (!IsValid(reg) || reg >= std::size(QBDI::GPR_NAMES)) return;
    switch (access) {
        case READ:
            if (tracer->IsTaint(reg)) {
                Tr[++Tr_idx] = reg;
            } else {
                Cr[++Cr_idx] = reg;
            }
            break;
        case WRITE:
            if (tracer->IsTaint(reg)) {
                Tw[++Tw_idx] = reg;
            } else {
                Cw[++Cw_idx] = reg;
            }
            break;
        case READ_WRITE:
            if (tracer->IsTaint(reg)) {
                Trw[++Trw_idx] = reg;
            } else {
                Crw[++Crw_idx] = reg;
            }
            break;
    }
}

void Trace::RegAnalysis::PrintReg(std::ofstream &log, const QBDI::GPRState *gpr,
                                  bool before) const {
    int Tr_idx = this->Tr_idx, Tw_idx = this->Tw_idx, Trw_idx = this->Trw_idx;
    int Cr_idx = this->Cr_idx, Cw_idx = this->Cw_idx, Crw_idx = this->Crw_idx;

    if (before) {
        while (IsValid(Tr_idx))
            log << SPACE << tracer->TName(Tr[Tr_idx]) << EQ
                << PRINT_GPR(Tr[Tr_idx--]);
        // + SPACE;
        while (IsValid(Cr_idx))
            log << SPACE << tracer->TName(Cr[Cr_idx]) << EQ
                << PRINT_GPR(Cr[Cr_idx--]);
        // + SPACE;
    }
    while (IsValid(Tw_idx))
        log << SPACE << tracer->TName(Tw[Tw_idx]) << EQ
            << PRINT_GPR(Tw[Tw_idx--]);
    // + SPACE;
    while (IsValid(Cw_idx))
        log << SPACE << tracer->TName(Cw[Cw_idx]) << EQ
            << PRINT_GPR(Cw[Cw_idx--]);
    // + SPACE;
    while (IsValid(Trw_idx))
        log << SPACE << tracer->TName(Trw[Trw_idx]) << EQ
            << PRINT_GPR(Trw[Trw_idx--]);
    // + SPACE;
    while (IsValid(Crw_idx))
        log << SPACE << tracer->TName(Crw[Crw_idx]) << EQ
            << PRINT_GPR(Crw[Crw_idx--]);
    // + SPACE;
    log << SPACE << SPLIT;
}
