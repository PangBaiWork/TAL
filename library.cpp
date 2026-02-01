
#include "library.h"

#include "QBDI.h"
#include "fs_gs.h"
#include "hook_utils.h"
#include "utils.h"
#include "vm.h"

template <class F>
void run_on_stack(BorrowedStackAllocator &alloc, F &&fn) {
    std::exception_ptr ep;

    // callcc 会：创建上下文 + 切到新栈 + 执行 lambda
    // lambda 返回 sink 后：立刻切回调用者（main）并从 callcc 返回
    (void)ctx::callcc(
        std::allocator_arg, alloc,
        [&](ctx::continuation &&sink) -> ctx::continuation {
            try {
                std::forward<F>(fn)();  // 你的函数在“新栈”上执行
            } catch (...) {
                ep = std::current_exception();  // 不让异常跨上下文边界乱跑
            }
            return std::move(sink);  // 执行完立即回到调用者
        });

    if (ep) std::rethrow_exception(ep);
}

void escape_on_enter(GumInvocationContext *context, gpointer user_data) {
    LOGI("escape attached");
    auto data = static_cast<CallbackData *>(user_data);
    TaintTrace *tracer = data->tracer;
    std::shared_ptr<QBDI::VM> qvm = tracer->qvm;
    gum_interceptor_detach(data->interceptor, data->listener);
    uint64_t address = reinterpret_cast<uint64_t>(context->function);

    run_on_stack(*tracer->alloc, [qvm, address, tracer] {
        LOGI("[vm] run once on custom stack\n");
        uint64_t start = address;
        qvm->run(start, tracer->trace_end);
    });
}

// GumInvocationListener *g_listener = nullptr;
// GumInterceptor *g_interceptor = nullptr;
TaintTrace *cur_tracer = nullptr;
char *g_taint_str = nullptr;

static void on_enter(GumInvocationContext *context, gpointer user_data) {
    // context->function
    print_frida_reg(context->cpu_context);
    LOGI("begin");
    auto data = static_cast<CallbackData *>(user_data);
    TaintTrace *tracer = data->tracer;
    // memcpy(&g_cpu_context,context->cpu_context,sizeof(GumCpuContext));
    void *address = context->function;
    gum_interceptor_detach(data->interceptor, data->listener);
    QBDI::setLogPriority(QBDI::DEBUG);
    QBDI::setLogFile("log.asm", true);

    std::shared_ptr<QBDI::VM> qvm = init(address, tracer);
    tracer->qvm = qvm;
    for (const auto &range : tracer->escape_execute) {
        LOGI("attach: %llx",range.max);
        HookUtils::gum_attach(data->interceptor,
                              reinterpret_cast<void *>(range.max),
                              escape_on_enter, tracer);
    }

#if defined(__x86_64__) || defined(_M_X64)
    // qvm->setOptions(QBDI::OPT_ENABLE_FS_GS);
#endif

    const auto state = qvm->getGPRState();
    syn_reg_gum(context->cpu_context, state, true);

    // state->fs=get_fs_selector();
    // state->gs=get_gs_selector();
    // state->fs=get_fs_base();
    // state->gs=get_gs_base();

    auto stack = std::make_unique<RawBufferStack>(1 << 24);  // 16 Mi
    const std::shared_ptr<BorrowedStackAllocator> alloc(
        new BorrowedStackAllocator{stack.get()});
    tracer->alloc = alloc;
    // 3. 在自定义栈上运行
    //    run_on_stack 接收引用，所以使用 *alloc 解引用智能指针
    run_on_stack(*alloc, [qvm, address, tracer] {
        LOGI("[vm] run once on custom stack\n");
        uint64_t start = reinterpret_cast<uint64_t>(address);
        qvm->run(start, tracer->trace_end);
    });

    // syn_reg_gum(context->cpu_context, state, false);
    // const clock_t end = clock();
    // LOGI("time: %d", (end - start) / CLOCKS_PER_SEC);
    LOGI("end");
}

C_EXPORT void trace(const uint64_t addr, const uint64_t end, const bool all,
                    int mode) {
    LOGI("hooking %llx", addr);
    GumModule *module = gum_process_find_module_by_address(addr);
    const uint64_t base_addr = gum_module_get_range(module)->base_address;
    LOGI("Base:%llx", base_addr);

    cur_tracer = new TaintTrace(base_addr, static_cast<PrintMode>(mode));
    cur_tracer->trace_all = all;
    cur_tracer->trace_end = end;

    auto interceptor = gum_interceptor_obtain();
    HookUtils::gum_attach(interceptor, reinterpret_cast<void *>(addr), on_enter,
                          cur_tracer);
    LOGI("hooked");
}
// 0x7fe668d670 0x7fe668d6a0
// 0x7fe668d670 0x7fe668d6a0
C_EXPORT void taint_trace(uint64_t addr, const bool all,
                          const uint64_t taint_addr, const int taint_size,
                          int mode) {
    LOGD("hooking %llx", addr);
    LOGD("taint: %llx size:%d", taint_addr, taint_size);
    GumModule *module = gum_process_find_module_by_address(addr);
    const uint64_t base_addr = gum_module_get_range(module)->base_address;
    LOGE("Base:%llx", base_addr);
    const auto taint = new MemoryRange(taint_addr, taint_addr + taint_size);
    cur_tracer = new TaintTrace(base_addr, static_cast<PrintMode>(mode));
    cur_tracer->trace_all = all;
    cur_tracer->trace_end = 0;
    cur_tracer->AddTaintMemory(*taint);

    auto interceptor = gum_interceptor_obtain();
    HookUtils::gum_attach(interceptor, reinterpret_cast<void *>(addr), on_enter,
                          cur_tracer);
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

    cur_tracer = new TaintTrace(base_addr, static_cast<PrintMode>(mode));
    cur_tracer->trace_all = all;
    cur_tracer->trace_end = 0;
    cur_tracer->SetTaintStr(g_taint_str);

    auto interceptor = gum_interceptor_obtain();

    HookUtils::gum_attach(interceptor, reinterpret_cast<void *>(addr), on_enter,
                          cur_tracer);
    LOGE("hooked");
}

C_EXPORT bool remove_range(uint64_t start, const uint64_t size) {
    if (cur_tracer) {
        cur_tracer->avoid_range.emplace_back(start, start + size);
        return true;
    }
    return false;
}

C_EXPORT void set_escape(uint64_t start, uint64_t end) {
    if (cur_tracer) {
        cur_tracer->escape_execute.emplace_back(start, end);
    }
}
C_EXPORT bool add_taint_range(const uint64_t addr, const uint64_t size) {
    if (cur_tracer) {
        cur_tracer->AddTaintMemory(addr, size);
        return true;
    }
    return false;
}

C_EXPORT bool set_log_path(const char *path) {
    const auto log_path = std::string(path);
    if (cur_tracer) {
        cur_tracer->SetOutputPath(&log_path);
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