
#pragma check_stack(off)
#include "library.h"

#include "QBDI.h"
#include "triton_taint.h"

#include "hook_utils.h"
#include "utils.h"
#include "vm.h"

extern "C" GumTlsKey gum_interceptor_get_key();

template <class F>
void run_on_stack(BorrowedStackAllocator &alloc, F &&fn) {
    std::exception_ptr ep;
    (void)ctx::callcc(
        std::allocator_arg, alloc,
        [&](ctx::continuation &&sink) -> ctx::continuation {
            try {
                std::forward<F>(fn)();  // 你的函数在“新栈”上执行
            } catch (...) {
                ep = std::current_exception();  // 不让异常跨上下文边界乱跑
            }
            return std::move(sink);
        });
    if (ep) std::rethrow_exception(ep);
}

void on_resume(GumInvocationContext *context, gpointer user_data) {

    const auto data = static_cast<CallbackData *>(user_data);
    Trace *tracer = data->tracer;
    std::shared_ptr<QBDI::VM> qvm = tracer->qvm;
    tracer->guest_stack.SaveStack();
    LOGI("vm resume on: %llx",context->function);
    gum_interceptor_detach(data->interceptor, data->listener);
    auto address = reinterpret_cast<uint64_t>(context->function);
    gum_tls_key_set_value(gum_interceptor_get_key(),nullptr);
    run_on_stack(*tracer->stack, [qvm, address,tracer] {
        LOGI("[vm] run again on custom stack\n");
        tracer->host_stack.SaveStack();
        tracer->SetPrivateRunning(false);
        const uint64_t start = address;
        qvm->run(start, 0);
        LOGE("VM end unexpectedly on resume hook");
    });
}

Trace *cur_tracer = nullptr;
char *g_taint_str = nullptr;

static void on_enter(GumInvocationContext* context,gpointer user_data) {
    LOGI("call on_enter");
    print_frida_reg(context->cpu_context);
    uint64_t tid = gum_process_get_current_thread_id();

    LOGI("thread id:%llu",tid);
    const auto data = static_cast<CallbackData *>(user_data);
    Trace *tracer = data->tracer;
    void *address = context->function;
    tracer->modules = gum_module_map_new();

    gum_interceptor_detach(data->interceptor, data->listener);
    gum_interceptor_unignore_current_thread(data->interceptor);
    if(tracer->IsDebugMode()){
        QBDI::setLogPriority(QBDI::DEBUG);
        QBDI::setLogFile( "log.asm", true);
    }

    std::shared_ptr<QBDI::VM> qvm = init(address, tracer);
    tracer->qvm = qvm;
    tracer->guest_stack.SaveStack();
    for (const auto &range : tracer->escape_execute) {
        if (range.max==0)continue;
        LOGI("set resume hook: %llu",range.max);
        HookUtils::gum_attach(reinterpret_cast<void *>(range.max),
                              on_resume, tracer);
    }


#if defined(__x86_64__) || defined(_M_X64)
    // qvm->setOptions(QBDI::OPT_ENABLE_FS_GS);
#elif defined(__aarch64__)
    int nice_value = -19;  // 最高优先级
    if (setpriority(PRIO_PROCESS, tid,nice_value ) != 0) {
       LOGE("setpriority failed: tid=%d nice=%d err=%d (%s)",
                            (int)tid, nice_value, errno, strerror(errno));
    }
#endif

    const auto state = qvm->getGPRState();
    syn_reg_gum(context->cpu_context, state, true);
    auto stack = std::make_unique<RawBufferStack>(1 << 24);  // 16 Mi
    const std::shared_ptr<BorrowedStackAllocator> alloc(new BorrowedStackAllocator{stack.get()});
    tracer->stack = alloc;
    gum_tls_key_set_value(gum_interceptor_get_key(),NULL);
    run_on_stack(*alloc, [qvm, address,tracer] {
        LOGI("[vm] run once on custom stack\n");
        tracer->host_stack.SaveStack();
        qvm->run(reinterpret_cast<uint64_t>(address), 0);
        LOGE("VM end unexpectedly on enter hook");
    });
    // broken stack ignore

}



C_EXPORT void trace(const uint64_t addr, const uint64_t end, const bool all,
                    int mode) {
    LOGI("hooking %lx", addr);
    GumModule *module = gum_process_find_module_by_address(addr);
    uint64_t base_addr = 0;

    if (module) {
        base_addr = gum_module_get_range(module)->base_address;
    }
    LOGI("Base:%lx", base_addr);
    if (!cur_tracer) {
        if (mode == TRITON_MODE) {
            cur_tracer = new TritonTaint(base_addr, static_cast<PrintMode>(mode));
        } else if (mode == TRACE_MODE || mode == DEBUG_MODE||mode == BIN_MODE||mode== TRACE_ARGS_MODE) {
            cur_tracer = new Trace(base_addr, static_cast<PrintMode>(mode));
        } else if (mode == ADDR_MODE) {
            cur_tracer = new TaintTrace(base_addr, static_cast<PrintMode>(mode));
        }
        cur_tracer->trace_all = all;
        cur_tracer->trace_end = end;
    }

    HookUtils::gum_attach(reinterpret_cast<void *>(addr), on_enter,
                          cur_tracer);
    LOGI("hooked");
}


C_EXPORT bool remove_range(uint64_t start, const uint64_t size) {
    if (cur_tracer) {
        cur_tracer->avoid_range.emplace_back(start, start + size);
        return true;
    }
    return false;
}

C_EXPORT void add_escape(uint64_t break_addr, uint64_t resume_addr) {
    if (cur_tracer) {
        cur_tracer->escape_execute.emplace_back(break_addr, resume_addr);
    }
}

C_EXPORT void add_resume(const uint64_t resume_addr) {
    if (cur_tracer) {
        HookUtils::gum_attach(reinterpret_cast<void *>(resume_addr),
                      on_resume, cur_tracer);
    }
}

C_EXPORT bool add_taint_range(const uint64_t addr, const uint64_t size) {
    if (cur_tracer) {
        LOGI("add taint mem : %lx size:%lx", addr, size);
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

C_EXPORT bool set_taint_str(const char *str) {
    g_taint_str = new char[strlen(str) + 1];
    strcpy(g_taint_str, str);
    if (cur_tracer){
        cur_tracer->SetTaintStr(g_taint_str);
        return true;
    }
    return false;
}


C_EXPORT bool set_printable_size(int size) {
    if (cur_tracer) {
        cur_tracer->printable_size = size;
        return true;
    }
    return false;
}

C_EXPORT bool set_triton(int mode) {
    if (cur_tracer&&typeid(*cur_tracer)==typeid(TritonTaint)) {
        const auto triton_tracer = dynamic_cast<TritonTaint*>(cur_tracer);
        triton_tracer->SetLiftMode(static_cast<TritonTaint::LiftMode>(mode));
        return true;
    }
    return false;
}

C_INIT void init_main() {
    gum_init_embedded();
    LOGE("load gum ok");
}

#ifdef QBDI_PLATFORM_WINDOWS
#include <windows.h>
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hModule);
            init_main();               // 只在进程附加时调用一次
            break;
        case DLL_PROCESS_DETACH:
            // 清理代码（如果需要）
            break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
            // 留空或处理线程相关逻辑
            break;
    }
    return TRUE;
}

#endif