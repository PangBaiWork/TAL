//
// Created by pangb on 26-2-6.
//

#include "taint_analyze.h"
#include "triton_taint.h"

const QBDI::GPRState* TritonTaint::gpr_state = nullptr;
const QBDI::FPRState* TritonTaint::fpr_state = nullptr;

std::unordered_map<int,int> TritonTaint::qt_map;
std::unordered_map<int,int> TritonTaint::tq_map;


TritonTaint::TritonTaint(const uint64_t base,
                       const PrintMode mode,const std::string* path) : Trace(base,mode,path) {
#if defined(__x86_64__) || defined(_M_X64)
    cs_arch_register_x86();
    ctx.setArchitecture(triton::arch::architecture_e::ARCH_X86_64);
#elif defined(__aarch64__)
    cs_arch_register_arm64();
    ctx.setArchitecture(triton::arch::architecture_e::ARCH_AARCH64);
#endif
    InitMap();
    ctx.addCallback(triton::callbacks::callback_e::GET_CONCRETE_MEMORY_VALUE,
                    NeedConcreteMemoryValueCB);
    ctx.addCallback(triton::callbacks::callback_e::GET_CONCRETE_REGISTER_VALUE,
                    NeedConcreteRegisterValueCB);
    // These modes cannot be configured by the user. They are allways on
    ctx.setMode(triton::modes::ALIGNED_MEMORY, true);

    ctx.setMode(triton::modes::ONLY_ON_TAINTED, true);

    ctx.setMode(triton::modes::TAINT_THROUGH_POINTERS, true);
}


void TritonTaint::NeedConcreteMemoryValueCB(triton::Context& ctx, const triton::arch::MemoryAccess& mem) {
    // if (mem.getAddress()<READABLE_ADDR) return;
        // ctx.setConcreteMemoryAreaValue(mem.getAddress(), reinterpret_cast<const void*>(mem.getAddress()),mem.getSize());
 }


void TritonTaint::NeedConcreteRegisterValueCB(
     triton::Context& ctx, const triton::arch::Register& reg) {
     auto id = reg.getParent();

#if defined(__x86_64__) || defined(_M_X64)
     if (id >= triton::arch::ID_REG_X86_AC &&id <= triton::arch::ID_REG_X86_ZF) {
         id = triton::arch::ID_REG_X86_EFLAGS;
     }
#elif defined(__aarch64__)
     if (id >= triton::arch::ID_REG_AARCH64_C &&id <= triton::arch::ID_REG_AARCH64_Z) {
        id = triton::arch::ID_REG_AARCH64_NZCV;
     }
#endif

     if (qt_map[id] < 0) {
         LOGE("no map for reg:%s id:%d",reg.getName().c_str(),id);
         return;
     }
     uint64_t value = QBDI_GPR_GET(gpr_state,GetQRegIdx(id));
     ctx.setConcreteRegisterValue(ctx.getRegister(id),value);
     // LOGI("need %s  pid:%d qid:%d ret %llx",reg.getName().c_str(),id,qt_map[id],value);
     // LOGI("get %s id: %d",gpr_state.,reg.getId());
 }

QBDI::VMAction TritonTaint::InstTrace(QBDI::VM *vm,QBDI::GPRState *gpr, QBDI::FPRState *fpr) {

    const QBDI::InstAnalysis *inst = vm->getInstAnalysis(
            QBDI::ANALYSIS_INSTRUCTION | QBDI::ANALYSIS_SYMBOL |
                 QBDI::ANALYSIS_DISASSEMBLY | QBDI::ANALYSIS_OPERANDS );
    CheckAndBreak(inst->address,gpr,fpr);
    uint64_t offset = inst->address - base;
    // LOGI("triton");
    AnalysisInstType(inst);
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


    UpdateRegister(gpr,fpr);
    auto instruction = triton::arch::Instruction(inst->address, reinterpret_cast<void*>(inst->address), inst->instSize);
    // Procces(inst->address, inst->instSize);
    // ctx.getSymbolicMemory();
    // ctx.getSymbolicRegister();
    // ctx.liftToPython()
    ctx.disassembly(instruction);
    for (auto& operand:instruction.operands) {
        if (operand.getType() == triton::arch::operand_e::OP_REG
               && !ctx.isRegisterTainted(operand.getRegister())) {
                    ClearTaintReg(GetQRegIdx(operand.getRegister().getParent()));
                }
    }
    bool tainted = Process(instruction);
    if (taint_str) {
        for (auto& operand:instruction.operands) {
            if (operand.getType() == triton::arch::operand_e::OP_MEM) {
                if (CheckTaintedStr(operand.getMemory().getAddress(),log)) {
                    tainted = Process(instruction);
                    break;
                }
            }
        }
    }
    if (tainted) {

        log << std::left << std::setw(STR_ALIGN) << PRINT_OFFSET(offset) + inst->disassembly;
        anal.PrintReg(log, gpr, true);
        SetPostInstFlag();
        for (auto& operand:instruction.operands) {
            switch (operand.getType()) {
                case triton::arch::operand_e::OP_REG:
                    if(ctx.isRegisterTainted(operand.getRegister())) {
                        SetTaintReg(GetQRegIdx(operand.getRegister().getParent()),0);
                    }else {
                        ClearTaintReg(GetQRegIdx(operand.getRegister().getParent()));
                    }
                    break;
                case triton::arch::operand_e::OP_MEM:
                    if(ctx.isMemoryTainted(operand.getMemory())) {
                        log << SPACE << PRINT_ADDR(operand.getMemory().getAddress());
                        log << PRINT_SIZE(operand.getMemory().getSize()) << SPLIT;
                    }
                    CheckTaintedStr(operand.getMemory().getAddress(),log);
                    break;
                default:
                    break;
            }
        }
    }

    return QBDI::CONTINUE;
}

void TritonTaint::PostInstTrace(QBDI::VM *vm,QBDI::GPRState *gpr, QBDI::FPRState *fpr) {
    if (enable_post_inst) {
        anal.PrintReg(log,gpr, false);
        log << ENTER;
        if (inst_type == CALL) log << ENTER;
        if(NeedFlush()) log.flush();
        CleanPostInstFlag();
    }

}


void TritonTaint::MemoryTrace(QBDI::VM *vm, QBDI::GPRState *gpr,
                              QBDI::FPRState *fpr) {}

bool TritonTaint::Process(triton::arch::Instruction &inst) {

     switch (ctx.buildSemantics(inst))
     {
         case triton::arch::NO_FAULT:

             break;
         case triton::arch::FAULT_UD:
             LOGW("[!] Instruction at %lx not supported by Triton: %s\n",
                 inst.getAddress(), inst.getDisassembly().c_str());
             break;
         case triton::arch::FAULT_DE:
         case triton::arch::FAULT_BP:
         case triton::arch::FAULT_GP:
             LOGW("[!] Some error happend at %lx processing instruction: %s\n",
                 inst.getAddress(), inst.getDisassembly().c_str());
             break;
     }


    return inst.isTainted();
 }


