
#include "library.h"

#include <string>

#include "QBDI.h"
#include "fs_gs.h"
#include "hook_utils.h"
#include "utils.h"
#include "vm.h"
#define SET_QBDI(reg) (state->reg = cpu->reg);LOGE(#reg":%llx,",cpu->reg)
#define SET_FRIDA(reg) (cpu->reg = state->reg)
#define PRINT_REG(reg) LOGE(#reg"_org:%llx,",cpu->reg)
#define PRINT_QBDI_REG(reg) LOGE(#reg"_org:%llx,",state->reg)
void print_reg(GumCpuContext *cpu) {
    PRINT_REG(r8);
    PRINT_REG(r9);
    PRINT_REG(r10);
    PRINT_REG(r11);
    PRINT_REG(r12);
    PRINT_REG(r13);
    PRINT_REG(r14);
    PRINT_REG(r15);

    PRINT_REG(rax);
    PRINT_REG(rcx);
    PRINT_REG(rdx);
    PRINT_REG(rbx);
    PRINT_REG(rsp);
    LOGE("frida str rsp:%p %s",cpu->rsp,cpu->rsp);
    PRINT_REG(rbp);
    PRINT_REG(rsi);
    PRINT_REG(rdi);

}
void print_qbdi_reg(QBDI::GPRState *state) {
    PRINT_QBDI_REG(r8);
    PRINT_QBDI_REG(r9);
    PRINT_QBDI_REG(r10);
    PRINT_QBDI_REG(r11);
    PRINT_QBDI_REG(r12);
    PRINT_QBDI_REG(r13);
    PRINT_QBDI_REG(r14);
    PRINT_QBDI_REG(r15);

    PRINT_QBDI_REG(rax);
    PRINT_QBDI_REG(rcx);
    PRINT_QBDI_REG(rdx);
    PRINT_QBDI_REG(rbx);
    PRINT_QBDI_REG(rsp);

    PRINT_QBDI_REG(rbp);
    PRINT_QBDI_REG(rsi);
    PRINT_QBDI_REG(rdi);

}
void syn_reg_gum(GumCpuContext *cpu, QBDI::GPRState *state, bool F2Q) {
    if (F2Q) {

        SET_QBDI(r8);
        SET_QBDI(r9);
        SET_QBDI(r10);
        SET_QBDI(r11);
        SET_QBDI(r12);
        SET_QBDI(r13);
        SET_QBDI(r14);
        SET_QBDI(r15);

        SET_QBDI(rax);
        SET_QBDI(rcx);
        SET_QBDI(rdx);
        SET_QBDI(rbx);
        SET_QBDI(rsp);
        SET_QBDI(rbp);
        SET_QBDI(rsi);
        SET_QBDI(rdi);


    } else {
        SET_FRIDA(r8);
        SET_FRIDA(r9);
        SET_FRIDA(r10);
        SET_FRIDA(r11);
        SET_FRIDA(r12);
        SET_FRIDA(r13);
        SET_FRIDA(r14);
        SET_FRIDA(r15);

        SET_FRIDA(rax);
        SET_FRIDA(rcx);
        SET_FRIDA(rdx);
        SET_FRIDA(rbx);
        SET_FRIDA(rsp);
        SET_FRIDA(rbp);
        SET_FRIDA(rsi);
        SET_FRIDA(rdi);

    }

}

bool isTraceAll = false;

MemoryRange *taintMemory=nullptr;
PrintMode g_print_mode=ADDR_MODE;
std::string *log_path=nullptr;
uint64_t g_base=0;
GumCpuContext g_cpu_context;
void* g_function;
GumInvocationListener *g_listener=nullptr;
GumInterceptor  *g_interceptor=nullptr;

char * g_taint_str=nullptr;

#define FAKE_RET_ADDR 42
// HOOK_DEF(QBDI::rword, taint_gum_handle) {
//     unsigned long long rspvalue;
//     auto context = gum_interceptor_get_current_invocation();
//     print_reg(context->cpu_context);
//     auto interceptor = (GumInterceptor *) gum_invocation_context_get_replacement_data(context);
//     gum_interceptor_revert(interceptor, context->function);
//     gum_interceptor_flush(interceptor);
//
//     memcpy(&g_cpu_context,context->cpu_context,sizeof(GumCpuContext));
//     g_function=context->function;
//
// #ifndef  QBDI_PLATFORM_WINDOWS
//     asm volatile (
//         "movq %%rbp, %0\n"     // 将RSP的值移动到rsp_value中
//          "andq $-16, %%rsp\n"   // 对齐RSP到16字节
//          "andq $-16, %%rbp\n"   // 对齐RSP到16字节
//         : "=r"(rspvalue)      // 输出操作数
//         :                      // 无输入操作数
//         : "rsp", "memory" // 告知编译器被修改的寄存器
//     );
//     // Print the register value
//     std::cout << "replace rbp: " << ToHex(rspvalue) << std::endl;
// #endif
//
//     LOGS("begin");
//     clock_t start,end;
//     start = clock();
//     auto qvm = init(g_function,isTraceAll,nullptr,g_print_mode);
//     auto state = qvm.getGPRState();
//     syn_reg_gum(&g_cpu_context, state, true);
//     LOGD("fun:%p",g_function);
//
//     qvm.run(reinterpret_cast<QBDI::rword>(g_function),FAKE_RET_ADDR);
//     syn_reg_gum(&g_cpu_context, state, false);
//     end = clock();
//     LOGS("time: %f",(double)(end-start)/CLOCKS_PER_SEC);
//     LOGS("end");
//     return 0;
// }
//
//

// balance for stack
// #ifndef  QBDI_PLATFORM_WINDOWS
// asm volatile (
//     "movq %%rbp, %0\n"     // 将RSP的值移动到rsp_value中
//     "movq %%rsp, %1\n"
//      "andq $-8, %%rsp\n"   // 对齐RSP到16字节
//      "andq $-8, %%rbp\n"   // 对齐RSP到16字节
//     : "=r"(rbpvalue) ,"=r"(rspvalue)     // 输出操作数
//     :                      // 无输入操作数
//     : "rsp", "memory" // 告知编译器被修改的寄存器
// );
//
//
// // Print the register value
// std::cout << "replace rsp: " << ToHex(rspvalue) << std::endl;
// std::cout << "replace rbp: " << ToHex(rbpvalue) << std::endl;
// #endif


static void on_enter(GumInvocationContext *context, gpointer user_data) {
    print_reg(context->cpu_context);
    LOGS("begin");
    memcpy(&g_cpu_context,context->cpu_context,sizeof(GumCpuContext));
    g_function=context->function;
    gum_interceptor_detach(g_interceptor,g_listener);
    // Use inline assembly to move the content of RAX into the variable

    clock_t start = clock();

    GumModule* module = gum_process_find_module_by_address((GumAddress)g_function);
    uint64_t base_addr = gum_module_get_range(module)->base_address;
    LOGE("Base:%llx",base_addr);
    auto *taint_trace = new TaintTrace(log_path, base_addr,g_print_mode);

    if (taintMemory)
        taint_trace->AddTaintMemory(*taintMemory);
    else {
        taint_trace->SetTaintStr(g_taint_str);
    }
    //
    // QBDI::setLogPriority(QBDI::DEBUG);
    // QBDI::setLogFile("log.asm",true);
    std::vector<MemoryRange> avoid_range={};

    // avoid_range.push_back(MemoryRange(base_addr+0x1710,base_addr+0x182d));
    QBDI::VM qvm = init(g_function,isTraceAll,taint_trace,avoid_range);
    qvm.setOptions(QBDI::OPT_ENABLE_FS_GS);




    auto state = qvm.getGPRState();
    syn_reg_gum(&g_cpu_context, state, true);
    // state->fs=get_fs_selector();
    // state->gs=get_gs_selector();
    // state->fs=get_fs_base();
    // state->gs=get_gs_base();
    LOGE("gs: %llx,fs:%llx",state->gs,state->fs);
    // LOGE("gs_base:%llx,fs_base:%llx",get_gs_base(),get_fs_base());

    qvm.run(reinterpret_cast<QBDI::rword>(g_function),FAKE_RET_ADDR);
    syn_reg_gum(&g_cpu_context, state, false);
    clock_t end = clock();
    LOGS("time: %f",(double)(end-start)/CLOCKS_PER_SEC);
    LOGS("end");
    printf("[*] Function entered! user_data=%s\n", (char *)user_data);
}


VISIBILITY_DEFAULT   void taint_trace(void *addr,bool trace_all,uint64_t taintAddr,int taintSize,int printMode) {
    isTraceAll = trace_all;
    LOGD("taint: %llx size:%d", taintAddr,taintSize);
    LOGD("hooking %p", addr);
    g_print_mode=static_cast<PrintMode>(printMode);
    taintMemory = new MemoryRange(taintAddr,taintAddr + taintSize);
    g_interceptor = gum_interceptor_obtain();
    g_listener = HookUtils::gum_attach(g_interceptor,addr, on_enter,nullptr, nullptr);
    LOGE("hooked");
}

VISIBILITY_DEFAULT   void taint_trace_str(void *addr,bool trace_all,char *taint_str,int printMode) {
    isTraceAll = trace_all;
    LOGD("taint string: %s", taint_str);
    LOGD("hooking %p", addr);
    g_print_mode=static_cast<PrintMode>(printMode);
    g_taint_str = new char[strlen(taint_str)+1];
    strcpy(g_taint_str,taint_str);
    g_interceptor = gum_interceptor_obtain();
    g_listener = HookUtils::gum_attach(g_interceptor,addr, on_enter,nullptr, nullptr);
    LOGE("hooked");
}


// VISIBILITY_DEFAULT   void attd_call(void *target_addr) {
//     LOGS("attd_call start %p", target_addr);
//     uint8_t *fakestack;
//     auto qvm = init(target_addr);
//     auto state = qvm.getGPRState();
//     QBDI::allocateVirtualStack(state, STACK_SIZE, &fakestack);
//     QBDI::rword ret;
//     qvm.call(&ret, (QBDI::rword) target_addr);
//     LOGS("attd_call end %p", target_addr);
// }

CONSTRUCTOR_ATTR void init_main() {
    gum_init_embedded();
    LOGE("load ok");
}

#ifdef  QBDI_PLATFORM_WINDOWS
#include <windows.h>
BOOL APIENTRY DllMain(HMODULE hModule,
                      DWORD  ul_reason_for_call,
                      LPVOID lpReserved)
{
  switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
      //  For optimization.
      DisableThreadLibraryCalls(hModule);
      break;
    case DLL_PROCESS_DETACH:
      break;
  }
    init_main();
    return TRUE;  // Successful DLL_PROCESS_ATTACH.
}

#endif