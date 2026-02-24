//
// Created by pangbai on 2025/10/12.
//

#ifndef EZMYDROID_TAINTANALYZE_H
#define EZMYDROID_TAINTANALYZE_H

#include <exception>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>

#include "QBDI.h"
#include "QBDI/State.h"
#include "Trace.h"
#include "trace_utils.h"
#include "utils.h"
class TaintTrace:public Trace{
   public:

    TaintTrace(const uint64_t base, const PrintMode mode,
             const std::string *path=nullptr):Trace(base, mode, path){};
    TaintMemory memory;
    QBDI::VMAction InstTrace(QBDI::VM *vm,QBDI::GPRState *gpr,
                             QBDI::FPRState *fpr) override;
    void PostInstTrace(QBDI::VM *vm,QBDI::GPRState *gpr,
                       QBDI::FPRState *fpr) override;
    void MemoryTrace(QBDI::VM *vm, QBDI::GPRState *gpr,
                     QBDI::FPRState *fpr) override;
    void PrintMemoryOp(QBDI::GPRState *gpr, uint64_t offset,
                       QBDI::MemoryAccess *access, int reg_w = -1,
                       int reg_r = -1);
    // Taint reg name
    void AddTaintMemory(const uint64_t addr, const uint64_t size) override {
        memory.InsertBySize(addr, size);
    }
    void  AddTaintMemory(const MemoryRange &range) {
        memory.insert(range.min, range.max);
    }
};
#endif  // EZMYDROID_TAINTANALYZE_H
