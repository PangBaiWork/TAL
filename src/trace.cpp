//
// Created by pangb on 26-2-23.
//

#include "trace.h"
#include "function_utils.h"
Trace::Trace(const uint64_t base, const PrintMode mode,
             const std::string *path) {
    this->base = base;
    this->mode = mode;
    reg_name.SetGPRArray(QBDI::GPR_NAMES, state);
    if (IsBinMode()) {
        printable_size = 0;
    }
    LOGI("Mode %s Init", ModeName[mode].c_str());

}

QBDI::VMAction Trace::InstTrace(QBDI::VM *vm, QBDI::GPRState *gpr,
                                 QBDI::FPRState *fpr) {
    const QBDI::InstAnalysis *inst = vm->getInstAnalysis(
        QBDI::ANALYSIS_INSTRUCTION |
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

    log << ENTER;
        // std::endl;
    if (modules) {
        if (const auto module = gum_module_map_find(modules, inst->address);
            module&&gum_module_get_name(module)) {
            offset = inst->address - gum_module_get_range(module)->base_address;

            log << gum_module_get_name(module) << ":";
            }
    }

    AnalysisInstType(inst);





    if (IsBinMode()) {
        log << PRINT_DATA(reinterpret_cast<uint8_t*>(inst->address),inst->instSize);
    }
    log << BASE_LOG;
    anal.PrintReg(log,gpr,true);
    // log .flush();
    return QBDI::CONTINUE;
}
struct Ctx {
    const char* needle;
    GumAddress found;
};
const char*  invalid_symbol = "invalid_symbol";
void Trace::PostInstTrace(QBDI::VM *vm, QBDI::GPRState *gpr, QBDI::FPRState *fpr) {
    // if (enable_post_inst) {
    anal.PrintReg(log,gpr,false);

    if ((inst_type == CALL || inst_type == JMP)
        &&!IsBinMode()&&modules) {

        uint64_t addr = QBDI_GPR_GET(gpr,QBDI::REG_PC);
        // bool removed = qvm->removeInstrumentedModuleFromAddr(addr);
        // if (removed) {
        //     qvm->addInstrumentedModuleFromAddr(addr);
        // }
        const char* symbol_name = symbols[addr];
        if (symbol_name==invalid_symbol) return;
        // gum_module_map_find(modules, addr);
        GumModule* module = gum_module_map_find(modules,addr);
        if (!module) {
            symbols[addr] = invalid_symbol;
            return;
        }

        if (inst_type == JMP&& !symbol_name) {
            // is plt jmp ? check jmp address module, if not will return
            const QBDI::InstAnalysis *inst = vm->getInstAnalysis(QBDI::ANALYSIS_INSTRUCTION |
                                            QBDI::ANALYSIS_DISASSEMBLY | QBDI::ANALYSIS_OPERANDS );
            GumModule* module_org = gum_module_map_find(modules,inst->address);
            if (module == module_org) {
                symbols[addr] = invalid_symbol;
                return;
            }
        }
        if (mode==DEBUG_MODE) {
            log << std::endl;
        }else {
            log << ENTER;
        }
        if (gum_module_get_name(module)) {
            log << "call "<< gum_module_get_name(module) << ":";
        }else {
            return;
        }
        if (module_cache[module].empty()) {
            struct Ctx {
                GumAddress pc;
                const char* name;
                std::ofstream* log;
                decltype(module_cache)& cache;  // 添加 cache 引用
                decltype(module)& mod;           // 添加 module 引用
            } ctx { addr, nullptr, &log, module_cache, module };

            // search symbol table
            gum_module_enumerate_symbols(
              module,
              +[](const GumSymbolDetails* e, gpointer user_data) -> gboolean {
                auto* ctx = (Ctx*) user_data;
                ctx->cache[ctx->mod][(void*)e->address] = e->name;
                if (e->name != nullptr && e->address == ctx->pc) {
                  ctx->name = e->name;
                }
                return TRUE;
              },
              &ctx);


            // search export table
            gum_module_enumerate_exports(
              module,
              +[](const GumExportDetails* e, gpointer user_data) -> gboolean {
                auto* ctx = (Ctx*) user_data;
                ctx->cache[ctx->mod][(void*)e->address] = e->name;
                if (e->name != nullptr && e->address == ctx->pc) {
                  ctx->name = e->name;
                }
                return TRUE;
              },
              &ctx);
            LOGI("module: %s symbols size: %lu",gum_module_get_name(module),module_cache[module].size());
        }
        symbol_name = module_cache[module][(void*)addr];


        // no symbol feedback to offset
        if (!symbol_name) {
            auto offset_str = new char [20];
            sprintf(offset_str,"0x%llx",addr - gum_module_get_range(module)->base_address);
            symbol_name = offset_str;
        }
        symbols[addr]=symbol_name;

        log << symbol_name;
        if (mode==TRACE_ARGS_MODE) {

            PrintFunctionArgs(log,gpr,symbol_name);
        }
        log.flush();

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
    auto log_file = *path + ModeName[mode] + ".asm";
    LOGI("set log path: %s", log_file.c_str());
    log.open(log_file.c_str(), std::ios::out | std::ios::trunc);
    return log.is_open();
}
#include "vm.h"
void Trace::AnalysisInstType(const QBDI::InstAnalysis *inst) {

    if (inst->isCall) {
        inst_type = CALL;

    } else if (inst->isReturn) {
        inst_type = RET;
    } else if ( inst->isBranch) {
        inst_type = JMP;
        if (inst->isPredicable) {
            inst_type = IF_JMP;
        }
    } else {
        inst_type = NONE;
    }
}

uint64_t Trace::GetAndSaveBase(const char *module_name) {
    // uint64_t bais = 0;
    // const auto iter = base_map.find(module_name);
    // if (iter == base_map.end()) {
    //     GumModule *mod = gum_process_find_module_by_name(module_name);
    //     if (mod) {
    //         bais = gum_module_get_range(mod)->base_address;
    //         log << "base:" << module_name << "=" << ToHex(bais)
    //                 << std::endl;
    //         base_map[module_name] = bais;
    //     }
    // } else {
    //     bais = iter->second;
    // }
    // return bais;
    return 0;
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
        log.flush();
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
            delete [] taint_str;
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
