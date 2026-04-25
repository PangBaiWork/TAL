//
// Created by pangb on 26-2-23.
//

#ifndef TRACE_H
#define TRACE_H

#include <fstream>
#include <iomanip>
#include <string>

#include "QBDI.h"
#include "QBDI/State.h"
#include "str_format.h"
#include "trace_utils.h"
#include "utils.h"

#if defined(_M_X64)
#define NOMINMAX
#include <windows.h>

#include <cstdint>
#endif

#define READABLE_ADDR 0x3000
#define PRINT_GPR(REG) ToHex(QBDI_GPR_GET(gpr, REG))
#define PRINT_QBDI_REG(reg) \
    (all_log << #reg << ":" << ToHex(state->reg) << ENTER)
#define BASE_LOG std::left << std::setw(STR_ALIGN) << PRINT_OFFSET(offset) + inst->disassembly;


class Trace {
   public:
    int printable_size = 4;
    std::shared_ptr<BorrowedStackAllocator> stack;
    StackInfo guest_stack;
    StackInfo host_stack;
    std::shared_ptr<QBDI::VM> qvm;
    bool trace_all = false;
    uint64_t trace_end = 0;
    std::vector<MemoryRange> escape_execute;
    std::vector<MemoryRange> avoid_range;
    std::map<std::string, uint64_t> base_map;
    RegsState state;
    uint64_t base;
    PrintMode mode = ADDR_MODE;
    std::ofstream log;
    std::ofstream all_log;
    Instruction disassembler;
    InstOprandType inst_type = NONE;
    bool enable_post_inst = false;
    RegArray reg_name;
    char *taint_str = nullptr;
    Trace(uint64_t base, PrintMode mode = ADDR_MODE,const std::string *path = nullptr);
    virtual ~Trace() { log.close(); }
    bool SetOutputPath(const std::string *path);
    void SetPostInstFlag() { enable_post_inst = true; }
    void SetPrivateRunning(const bool running) const {
        GetPrivateRunning(*GetPrivate(*qvm)) = running;
    }
    bool SetTaintReg(const int reg, const uint64_t ref);
    void ClearTaintReg(const int reg);
    void CleanPostInstFlag() { enable_post_inst = false; }
    bool NeedFlush() const { return true; }

    QBDI::VMAction virtual InstTrace(QBDI::VM *vm,QBDI::GPRState *gpr,
                                     QBDI::FPRState *fpr);
    void virtual PostInstTrace(QBDI::VM *vm, QBDI::GPRState *gpr,
                               QBDI::FPRState *fpr);
    void virtual MemoryTrace(QBDI::VM *vm, QBDI::GPRState *gpr,
                             QBDI::FPRState *fpr);
    void virtual AddTaintMemory(const uint64_t addr, const uint64_t size){}


    const char *TName(const int reg) const { return reg_name[reg]; }
    const char *RegName(const int idx) const { return reg_name.get(idx); }

    PrintMode GetPrintMode() const { return mode; }
    bool IsAddrMode() const { return mode == ADDR_MODE; }
    bool IsBinMode() const { return mode == BIN_MODE; }
    bool IsDebugMode() const { return mode == DEBUG_MODE; }
    bool IsTraceMode() const { return mode == TRACE_MODE; }

    void PrintMemoryOp(QBDI::MemoryAccess& access,std::string& printable) {
        const char *op_str = nullptr;
        if (access.type==QBDI::MEMORY_READ) {
            op_str = " R";
        }else if (access.type==QBDI::MEMORY_WRITE) {
            op_str = " W";
        }else if (access.type==QBDI::MEMORY_READ_WRITE) {
            op_str = " RW";
        }
        log << op_str << PRINT_ADDR(access.accessAddress) << "=";
        if (printable.empty()) {
            log << ToHex(access.value);
        }else {
            log << "\""<<printable << "\"";
        }
        log << PRINT_SIZE(access.size);
    }


    bool CheckAndBreak(uint64_t addr, const QBDI::GPRState *gpr,
                                         QBDI::FPRState *fpr);
    void AnalysisInstType(const QBDI::InstAnalysis *inst);
    bool CheckTaintedStr(const uint64_t addr,std::ofstream& log);
    uint64_t GetAndSaveBase(const char *module_name);
    static bool IsValid(const int input) { return input >= 0; }
    bool IsTaint(const int reg);
    void SetTaintStr(char *str);


    class RegAnalysis {
    public:
        RegAnalysis(Trace *tracer) { this->tracer = tracer; }
        Trace *tracer;
        int Tr[4] = {}, Tw[4] = {}, Trw[2] = {}, Cr[4] = {}, Cw[4] = {},
            Crw[2] = {};
        int Tr_idx = -1, Tw_idx = -1, Trw_idx = -1, Cr_idx = -1, Cw_idx = -1,
            Crw_idx = -1;
        void reset() {
            Tr_idx = -1, Tw_idx = -1, Trw_idx = -1;
            Cr_idx = -1, Cw_idx = -1, Crw_idx = -1;
        }
        static bool IsValid(const int input) { return input >= 0; }
        void SetReg(int reg, RegAccess access);
        void PrintReg(std::ofstream &log, const QBDI::GPRState *gpr,
                      bool before) const;
    };
    RegAnalysis anal = RegAnalysis(this);
};

#endif  // TRACE_H
