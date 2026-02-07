//
// Created by pangb on 26-2-6.
//

#include "TritonTaint.h"

#include "taint_analyze.h"
const QBDI::GPRState* TritonTaint::gpr_state = nullptr;
const QBDI::FPRState* TritonTaint::fpr_state = nullptr;
int TritonTaint::tq_map[100];
int TritonTaint::qt_map[100];
 TritonTaint::TritonTaint() {
#if defined(__x86_64__) || defined(_M_X64)
     cs_arch_register_x86();
     ctx.setArchitecture(triton::arch::architecture_e::ARCH_X86_64);
#elif defined(__aarch64__)
     cs_arch_register_arm64();
     ctx.setArchitecture(triton::arch::architecture_e::ARCH_AARCH64);
#endif
     InitMap();
     ctx.addCallback(triton::callbacks::callback_e::GET_CONCRETE_MEMORY_VALUE,NeedConcreteMemoryValueCB);
     ctx.addCallback(triton::callbacks::callback_e::GET_CONCRETE_REGISTER_VALUE,NeedConcreteRegisterValueCB);
     // These modes cannot be configured by the user. They are allways on
     ctx.setMode(triton::modes::ALIGNED_MEMORY, true);
     ctx.setMode(triton::modes::ONLY_ON_TAINTED, true);
     ctx.setMode(triton::modes::TAINT_THROUGH_POINTERS, true);

 }
void TritonTaint::NeedConcreteMemoryValueCB(triton::Context& ctx, const triton::arch::MemoryAccess& mem) {
    ctx.setConcreteMemoryAreaValue(mem.getAddress(), reinterpret_cast<const void*>(mem.getAddress()),mem.getSize());
 }
void TritonTaint::NeedConcreteRegisterValueCB(
     triton::Context& ctx, const triton::arch::Register& reg) {
     auto id = reg.getParent();

#if defined(__x86_64__) || defined(_M_X64)
     if ( id >= triton::arch::ID_REG_X86_AC &&id <= triton::arch::ID_REG_X86_ZF) {
         id = triton::arch::ID_REG_X86_EFLAGS;
     }
#elif defined(__aarch64__)

#endif

     if (qt_map[id] < 0) {
         LOGE("no map for reg:%s id:%d",reg.getName().c_str(),id);
         return;
     }
     uint64_t value = QBDI_GPR_GET(gpr_state,qt_map[id]);
     ctx.setConcreteRegisterValue(ctx.getRegister(id),value);
     // LOGI("need %s  pid:%d qid:%d ret %llx",reg.getName().c_str(),id,qt_map[id],value);
     // LOGI("get %s id: %d",gpr_state.,reg.getId());
 }
void TritonTaint::Procces(uint64_t addr, uint32_t size,TaintTrace& tracer) {
     auto inst = triton::arch::Instruction(addr, reinterpret_cast<void*>(addr),size);
     switch (ctx.processing(inst))
     {
         case triton::arch::NO_FAULT:

             break;
         case triton::arch::FAULT_UD:
             LOGW("[!] Instruction at %llx not supported by Triton: %s\n",
                 addr, inst.getDisassembly().c_str());
             break;
         case triton::arch::FAULT_DE:
         case triton::arch::FAULT_BP:
         case triton::arch::FAULT_GP:
             LOGW("[!] Some error happend at %llx processing instruction: %s\n",
                 addr, inst.getDisassembly().c_str());
             break;
     }
     if (inst.isTainted()) {
         // Check if it is a conditional jump
         // We only color with a different color the symbolic conditions, to show the user he could do additional actions like solve
         // LOGI("tainted:%llx %s",inst.getAddress(),inst.getDisassembly().c_str());
         for (auto& operand:inst.operands) {
            switch (operand.getType()) {
                case triton::arch::operand_e::OP_REG:
                    if(ctx.isRegisterTainted(operand.getRegister())) {
                        tracer.SetTaintReg(tq_map[operand.getRegister().getParent()],0);
                    }
                    break;
                case triton::arch::operand_e::OP_MEM:
                    if(ctx.isMemoryTainted(operand.getMemory())) {
                        // operand.getMemory()
                    }
                    break;
                default:
                    break;
            }
        }
     }
 }


