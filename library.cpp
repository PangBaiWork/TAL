
#include "library.h"

#include "QBDI.h"
#include "fs_gs.h"
#include "hook_utils.h"
#include "utils.h"
#include "vm.h"

GumInvocationListener *g_listener = nullptr;
GumInterceptor *g_interceptor = nullptr;
TaintTrace *tracer = nullptr;
char *g_taint_str = nullptr;

static void on_enter(GumInvocationContext *context, gpointer user_data) {
    print_frida_reg(context->cpu_context);
    LOGS("begin");
    // memcpy(&g_cpu_context,context->cpu_context,sizeof(GumCpuContext));
    void *address = context->function;
    gum_interceptor_detach(g_interceptor, g_listener);
    const clock_t start = clock();
    QBDI::setLogPriority(QBDI::DEBUG);
    QBDI::setLogFile("log.asm", true);
    QBDI::VM qvm = init(address, tracer);
    qvm.setOptions(QBDI::OPT_ENABLE_FS_GS);

    const auto state = qvm.getGPRState();
    syn_reg_gum(context->cpu_context, state, true);
    // state->fs=get_fs_selector();
    // state->gs=get_gs_selector();
    // state->fs=get_fs_base();
    // state->gs=get_gs_base();
    LOGE("gs: %llx,fs:%llx", state->gs, state->fs);
    qvm.run(reinterpret_cast<QBDI::rword>(address), tracer->trace_end);
    syn_reg_gum(context->cpu_context, state, false);
    const clock_t end = clock();
    LOGS("time: %d", (end - start) / CLOCKS_PER_SEC);
    LOGS("end");
}

C_EXPORT void trace(const uint64_t addr, const uint64_t end, const bool all,
                    int mode) {
    LOGD("hooking %llx", addr);
    GumModule *module = gum_process_find_module_by_address(addr);
    const uint64_t base_addr = gum_module_get_range(module)->base_address;
    LOGE("Base:%llx", base_addr);

    tracer = new TaintTrace(base_addr, static_cast<PrintMode>(mode));
    tracer->trace_all = all;
    tracer->trace_end = end;

    g_interceptor = gum_interceptor_obtain();
    g_listener =
        HookUtils::gum_attach(g_interceptor, reinterpret_cast<void *>(addr),
                              on_enter, nullptr, nullptr);
    LOGE("hooked");
}


C_EXPORT void taint_trace(uint64_t addr, const bool all,
                          const uint64_t taint_addr, const int taint_size,
                          int mode) {
    LOGD("hooking %llx", addr);
    LOGD("taint: %llx size:%d", taint_addr, taint_size);
    GumModule *module = gum_process_find_module_by_address(addr);
    const uint64_t base_addr = gum_module_get_range(module)->base_address;
    LOGE("Base:%llx", base_addr);
    const auto taint = new MemoryRange(taint_addr, taint_addr + taint_size);
    tracer = new TaintTrace(base_addr, static_cast<PrintMode>(mode));
    tracer->trace_all = all;
    tracer->trace_end = 0;
    tracer->AddTaintMemory(*taint);

    g_interceptor = gum_interceptor_obtain();
    g_listener =
        HookUtils::gum_attach(g_interceptor, reinterpret_cast<void *>(addr),
                              on_enter, nullptr, nullptr);
    LOGE("hooked");
}

C_EXPORT void taint_trace_str(uint64_t addr, bool all, char *taint_str,
                              int mode) {
    LOGD("hooking %llx", addr);
    g_taint_str = new char[strlen(taint_str) + 1];
    strcpy(g_taint_str, taint_str);
    GumModule *module = gum_process_find_module_by_address(addr);
    const uint64_t base_addr = gum_module_get_range(module)->base_address;
    LOGE("Base:%llx", base_addr);

    tracer = new TaintTrace(base_addr, static_cast<PrintMode>(mode));
    tracer->trace_all = all;
    tracer->trace_end = 0;
    tracer->SetTaintStr(g_taint_str);

    g_interceptor = gum_interceptor_obtain();
    g_listener =
        HookUtils::gum_attach(g_interceptor, reinterpret_cast<void *>(addr),
                              on_enter, nullptr, nullptr);
    LOGE("hooked");
}

C_EXPORT bool remove_range(uint64_t start, const uint64_t size) {
    if (tracer) {
        tracer->avoid_range.emplace_back(start, start + size);
        return true;
    }
    return false;
}
C_EXPORT bool add_taint_range(const uint64_t addr, const uint64_t size) {
    if (tracer) {
        tracer->AddTaintMemory(addr, size);
        return true;
    }
    return false;
}

C_INIT void init_main() {
    gum_init_embedded();
    LOGE("load ok");
}

#ifdef QBDI_PLATFORM_WINDOWS
#include <windows.h>
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call,
                      LPVOID lpReserved) {
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