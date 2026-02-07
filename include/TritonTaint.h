//
// Created by pangb on 26-2-6.
//

#ifndef TRITONTAINT_H
#define TRITONTAINT_H
#include "../qbdi-src/src/Patch/Register.h"
#include "QBDI/State.h"
#include "taint_analyze.h"
#include "triton/context.hpp"
#include "utils.h"

class TritonTaint :public TaintTrace{
   public:
    triton::Context ctx;
    const static  QBDI::GPRState* gpr_state;
    const static  QBDI::FPRState* fpr_state;
    static int tq_map[100];
    static int qt_map[100];
    TritonTaint();
    static void NeedConcreteRegisterValueCB(triton::Context& tritonCtx,
                                            const triton::arch::Register& reg);
    static void NeedConcreteMemoryValueCB(
        triton::Context& tritonCtx, const triton::arch::MemoryAccess& mem);
    static void UpdateRegister(const QBDI::GPRState* gpr_state,
                        const QBDI::FPRState* fpr_state) {
        TritonTaint::gpr_state = gpr_state;
        TritonTaint::fpr_state = fpr_state;
    }
    void Procces(uint64_t addr, uint32_t size,TaintTrace& tracer);
    #define QBDI_REG_IDX(reg) offsetof(QBDI::GPRState, reg)/sizeof(uint64_t)
    #define SET_MAPS(t_reg,q_reg) \
        tq_map[q_reg] = t_reg;    \
        qt_map[t_reg] = q_reg;
    void InitMap() {
        memset(qt_map, 0xff, sizeof(qt_map));
        memset(tq_map, 0xff, sizeof(tq_map));
        if(ctx.getArchitecture()==triton::arch::architecture_e::ARCH_X86_64) {
            // State.h
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
        }
    }

    void PreInstTrace(const QBDI::VM *vm,const QBDI::GPRState *gpr, QBDI::FPRState *fpr);
    void PostInstTrace(QBDI::VM *vm, const QBDI::GPRState *gpr, QBDI::FPRState *fpr);

};

#endif  // TRITONTAINT_H
