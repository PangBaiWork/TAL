//
// Created by pangb on 26-2-6.
//

#ifndef TRITONTAINT_H
#define TRITONTAINT_H
#include "QBDI.h"
#include "taint_analyze.h"
#include "triton/context.hpp"
#include "unordered_map"
class TritonTaint final : public TaintTrace{
   public:
    enum LiftMode {
        NONE = 0,
        PYTHON = 1,
        LLVM = 2
    };
    LiftMode lift_mode = NONE;
    triton::Context ctx;
    const static  QBDI::GPRState* gpr_state;
    const static  QBDI::FPRState* fpr_state;
//    static int tq_map[300];
//    static int qt_map[300];
    static std::unordered_map<int,int> qt_map;
    static std::unordered_map<int,int> tq_map;
    TritonTaint(uint64_t base, PrintMode mode = ADDR_MODE,
               const std::string *path = nullptr);
    QBDI::VMAction virtual InstTrace(const QBDI::VM *vm, const QBDI::GPRState *gpr,
                             QBDI::FPRState *fpr);
    void virtual PostInstTrace(QBDI::VM *vm, const QBDI::GPRState *gpr,
                       QBDI::FPRState *fpr);
    void virtual MemoryTrace(const QBDI::VM *vm, QBDI::GPRState *gpr,
                     QBDI::FPRState *fpr);
    static void NeedConcreteRegisterValueCB(triton::Context& tritonCtx,
                                            const triton::arch::Register& reg);
    static void NeedConcreteMemoryValueCB(
        triton::Context& tritonCtx, const triton::arch::MemoryAccess& mem);
    static void UpdateRegister(const QBDI::GPRState *gpr_state,
                               const QBDI::FPRState *fpr_state) {
        TritonTaint::gpr_state = gpr_state;
        TritonTaint::fpr_state = fpr_state;
    }
    bool Process(triton::arch::Instruction &inst);
    void virtual AddTaintMemory(const uint64_t addr, const uint64_t size) {
        // memory.InsertBySize(addr, size);
        const auto mem = triton::arch::MemoryAccess(addr, size);
        ctx.setTaintMemory(mem,true);
    }
    static int GetQRegIdx(int id){
        auto it = qt_map.find(id);
        int value = (it != qt_map.end()) ? it->second : -1;
        return value;
    }
    void SetLiftMode(const LiftMode mode) {
        this->lift_mode = mode;
        if (lift_mode != NONE){
            ctx.setMode(triton::modes::ONLY_ON_TAINTED, false);
            ctx.setMode(triton::modes::CONSTANT_FOLDING, true);
            ctx.setMode(triton::modes::AST_OPTIMIZATIONS, true);
        }
    }




    #define QBDI_REG_IDX(reg) offsetof(QBDI::GPRState, reg)/sizeof(uint64_t)
    #define SET_MAPS(t_reg,q_reg) \
            tq_map[q_reg] = t_reg;    \
            qt_map[t_reg] = q_reg
    void InitMap() {
//        memset(qt_map, 0xff, sizeof(qt_map));
//        memset(tq_map, 0xff, sizeof(tq_map));
#if defined(__x86_64__) || defined(_M_X64)
        SET_MAPS(triton::arch::register_e::ID_REG_X86_RAX,QBDI_REG_IDX(rax));
        SET_MAPS(triton::arch::register_e::ID_REG_X86_RBX,QBDI_REG_IDX(rbx));
        SET_MAPS(triton::arch::register_e::ID_REG_X86_RCX,QBDI_REG_IDX(rcx));
        SET_MAPS(triton::arch::register_e::ID_REG_X86_RDX,QBDI_REG_IDX(rdx));
        SET_MAPS(triton::arch::register_e::ID_REG_X86_RSI,QBDI_REG_IDX(rsi));
        SET_MAPS(triton::arch::register_e::ID_REG_X86_RDI,QBDI_REG_IDX(rdi));
        SET_MAPS(triton::arch::register_e::ID_REG_X86_R8,QBDI_REG_IDX(r8));
        SET_MAPS(triton::arch::register_e::ID_REG_X86_R9,QBDI_REG_IDX(r9));
        SET_MAPS(triton::arch::register_e::ID_REG_X86_R10,QBDI_REG_IDX(r10));
        SET_MAPS(triton::arch::register_e::ID_REG_X86_R11,QBDI_REG_IDX(r11));
        SET_MAPS(triton::arch::register_e::ID_REG_X86_R12,QBDI_REG_IDX(r12));
        SET_MAPS(triton::arch::register_e::ID_REG_X86_R13,QBDI_REG_IDX(r13));
        SET_MAPS(triton::arch::register_e::ID_REG_X86_R14,QBDI_REG_IDX(r14));
        SET_MAPS(triton::arch::register_e::ID_REG_X86_R15,QBDI_REG_IDX(r15));
        SET_MAPS(triton::arch::register_e::ID_REG_X86_RBP,QBDI_REG_IDX(rbp));
        SET_MAPS(triton::arch::register_e::ID_REG_X86_RSP,QBDI_REG_IDX(rsp));
        SET_MAPS(triton::arch::register_e::ID_REG_X86_RIP,QBDI_REG_IDX(rip));
        SET_MAPS(triton::arch::register_e::ID_REG_X86_EFLAGS,QBDI_REG_IDX(eflags));
#elif defined(__aarch64__)
        SET_MAPS(triton::arch::register_e::ID_REG_AARCH64_X0,QBDI_REG_IDX(x0));
        SET_MAPS(triton::arch::register_e::ID_REG_AARCH64_X1,QBDI_REG_IDX(x1));
        SET_MAPS(triton::arch::register_e::ID_REG_AARCH64_X2,QBDI_REG_IDX(x2));
        SET_MAPS(triton::arch::register_e::ID_REG_AARCH64_X3,QBDI_REG_IDX(x3));
        SET_MAPS(triton::arch::register_e::ID_REG_AARCH64_X4,QBDI_REG_IDX(x4));
        SET_MAPS(triton::arch::register_e::ID_REG_AARCH64_X5,QBDI_REG_IDX(x5));
        SET_MAPS(triton::arch::register_e::ID_REG_AARCH64_X6,QBDI_REG_IDX(x6));
        SET_MAPS(triton::arch::register_e::ID_REG_AARCH64_X7,QBDI_REG_IDX(x7));
        SET_MAPS(triton::arch::register_e::ID_REG_AARCH64_X8,QBDI_REG_IDX(x8));
        SET_MAPS(triton::arch::register_e::ID_REG_AARCH64_X9,QBDI_REG_IDX(x9));
        SET_MAPS(triton::arch::register_e::ID_REG_AARCH64_X10,QBDI_REG_IDX(x10));
        SET_MAPS(triton::arch::register_e::ID_REG_AARCH64_X11,QBDI_REG_IDX(x11));
        SET_MAPS(triton::arch::register_e::ID_REG_AARCH64_X12,QBDI_REG_IDX(x12));
        SET_MAPS(triton::arch::register_e::ID_REG_AARCH64_X13,QBDI_REG_IDX(x13));
        SET_MAPS(triton::arch::register_e::ID_REG_AARCH64_X14,QBDI_REG_IDX(x14));
        SET_MAPS(triton::arch::register_e::ID_REG_AARCH64_X15,QBDI_REG_IDX(x15));
        SET_MAPS(triton::arch::register_e::ID_REG_AARCH64_X16,QBDI_REG_IDX(x16));
        SET_MAPS(triton::arch::register_e::ID_REG_AARCH64_X17,QBDI_REG_IDX(x17));
        SET_MAPS(triton::arch::register_e::ID_REG_AARCH64_X18,QBDI_REG_IDX(x18));
        SET_MAPS(triton::arch::register_e::ID_REG_AARCH64_X19,QBDI_REG_IDX(x19));
        SET_MAPS(triton::arch::register_e::ID_REG_AARCH64_X20,QBDI_REG_IDX(x20));
        SET_MAPS(triton::arch::register_e::ID_REG_AARCH64_X21,QBDI_REG_IDX(x21));
        SET_MAPS(triton::arch::register_e::ID_REG_AARCH64_X22,QBDI_REG_IDX(x22));
        SET_MAPS(triton::arch::register_e::ID_REG_AARCH64_X23,QBDI_REG_IDX(x23));
        SET_MAPS(triton::arch::register_e::ID_REG_AARCH64_X24,QBDI_REG_IDX(x24));
        SET_MAPS(triton::arch::register_e::ID_REG_AARCH64_X25,QBDI_REG_IDX(x25));
        SET_MAPS(triton::arch::register_e::ID_REG_AARCH64_X26,QBDI_REG_IDX(x26));
        SET_MAPS(triton::arch::register_e::ID_REG_AARCH64_X27,QBDI_REG_IDX(x27));
        SET_MAPS(triton::arch::register_e::ID_REG_AARCH64_X28,QBDI_REG_IDX(x28));
        SET_MAPS(triton::arch::register_e::ID_REG_AARCH64_X29,QBDI_REG_IDX(x29));
        SET_MAPS(triton::arch::register_e::ID_REG_AARCH64_X30,QBDI_REG_IDX(lr));
        SET_MAPS(triton::arch::register_e::ID_REG_AARCH64_SP,QBDI_REG_IDX(sp));
        SET_MAPS(triton::arch::register_e::ID_REG_AARCH64_NZCV,QBDI_REG_IDX(nzcv));
        SET_MAPS(triton::arch::register_e::ID_REG_AARCH64_PC,QBDI_REG_IDX(pc));
#endif
            // State.h
    }


};

#endif  // TRITONTAINT_H
