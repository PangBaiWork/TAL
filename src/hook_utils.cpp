//
// Created by fang on 2024/1/3.
//

#include <cstdio>



#include "hook_utils.h"

#include "utils.h"
using namespace std;





void HookUtils::gum_replace(void* addr, void* replace, TaintTrace* tracer, void** backup){
    GumInterceptor *interceptor;
    interceptor = gum_interceptor_obtain();
    gum_interceptor_begin_transaction(interceptor);
    auto data = new CallbackData();
    data->tracer = tracer;
    data->interceptor = interceptor;
    auto ret = gum_interceptor_replace(interceptor,addr,replace, data,backup);
    gum_interceptor_end_transaction(interceptor);
    gum_interceptor_flush(interceptor);
    LOGI("HOOK REPLACE: %d",ret);
}


// GumInvocationListener *listener=nullptr;
GumInvocationListener *HookUtils::gum_attach(void* addr, GumInvocationCallback on_enter, TaintTrace* tracer){
    auto interceptor = gum_interceptor_obtain();
    gum_interceptor_begin_transaction(interceptor);
    if (on_enter == nullptr) on_enter = empty_on_enter;
    auto data = new CallbackData();
    data->tracer = tracer;
//    void* data = malloc(sizeof(void*));
    auto listener = gum_make_call_listener(on_enter,empty_on_leave, data, nullptr);
    data->listener = listener;
    data->interceptor = interceptor;

    gum_interceptor_attach(interceptor,addr,listener, nullptr,GUM_ATTACH_FLAGS_UNIGNORABLE);
    gum_interceptor_end_transaction(interceptor);
    return listener;
}

uint64_t latest_tls;
// void* ;
void (*orig_tls_set_value_fun)(uint64_t, uint64_t);
void tls_on_enter(GumInvocationContext * context, gpointer user_data) {
// #if defined(__x86_64__)
//     latest_tls = context->cpu_context->rdi;
// #elif  defined(_M_X64)
//     latest_tls = context->cpu_context->rcx;
// #elif defined(__aarch64__)
//     latest_tls = context->cpu_context->x0;
// #endif
    latest_tls =(uint64_t) gum_invocation_context_get_return_value(context);
}

void tls_on_replace() {
//     auto context = gum_interceptor_get_current_invocation();
//     uint64_t arg2;
// #if defined(__x86_64__)
//     latest_tls = context->cpu_context->rdi;
//     arg2 = context->cpu_context->rsi;
// #elif  defined(_M_X64)
//     latest_tls = context->cpu_context->rcx;
//     arg2 = context->cpu_context->rdx;
// #elif defined(__aarch64__)
//     latest_tls = context->cpu_context->x0;
//     arg2 = context->cpu_context->x1;
// #endif
//     orig_tls_set_value_fun(latest_tls,arg2);

}

uint64_t HookUtils::get_latest_tls() {
    return latest_tls;
}
void HookUtils::set_tls_hook(){
    auto interceptor = gum_interceptor_obtain();
    gum_interceptor_begin_transaction(interceptor);
    auto listener = gum_make_call_listener(empty_on_enter,tls_on_enter, interceptor, nullptr);

    // gum_interceptor_attach(interceptor,gum_tls_key_new,listener,nullptr,GUM_ATTACH_FLAGS_NONE);
    gum_interceptor_replace(interceptor,gum_tls_key_set_value,tls_on_replace, interceptor,(gpointer *) &orig_tls_set_value_fun);
    // gum_stac
    gum_interceptor_end_transaction(interceptor);
    gum_interceptor_flush(interceptor);
}



HOOK_DEF(void,call_array,const char* array_name,
         void* functions,
         size_t count,
         bool reverse,
         const char* realpath){

    // LOGD("call init function: %s %s ",array_name,realpath);
    orig_call_array(array_name,functions,count,reverse,realpath);

}
/*
void hookCallArray(){
    auto sym = gum_module_find_symbol_by_name("linker64","__dl__ZL10call_arrayIPFviPPcS1_EEvPKcPT_mbS5_");
    if (sym){
        LOGD("hooking call array %zx",sym);
        hookUtils::gum_replace((void*)sym, (void*)new_call_array, (void**)&orig_call_array);
    }


}
void hookUtils::hookLinker(GumInvocationCallback on_leave) {
    string dlopen_symbols[] = {
            "__dl__Z9do_dlopenPKciPK17android_dlextinfoPKv",
            "__dl__Z9do_dlopenPKciPK17android_dlextinfoPv",
            "__dl__ZL10dlopen_extPKciPK17android_dlextinfoPv",
            "__dl__Z20__android_dlopen_extPKciPK17android_dlextinfoPKv",
            "__dl___loader_android_dlopen_ext",
            "__dl__Z9do_dlopenPKciPK17android_dlextinfo",
            "__dl__Z8__dlopenPKciPKv",
            "__dl___loader_dlopen",
            "__dl_dlopen"
    };
    if (on_leave == nullptr){on_leave = listen_dlopen_onLeave;}
//    hookUtils::gum_attach((void*)dlopen,listen_dlopen_onEnter,on_leave);
    GumAddress addr ;
    for (const string& sym:dlopen_symbols) {
         addr = gum_module_find_symbol_by_name("linker64",sym.c_str());
        if (addr != 0) {
            LOGD("find dlopen  %s at %lx",sym.c_str(),addr);
            hookUtils::gum_attach((void*)addr, listen_dlopen_onEnter, on_leave);
        }
    }
    hookCallArray();

}
*/
void HookUtils::empty_on_enter(GumInvocationContext * context,
                              gpointer user_data) {

//    LOGD("call empty_onEnter");

}

void HookUtils::empty_on_leave(GumInvocationContext * context,
                              gpointer user_data) {
//    LOGD("call empty_onLeave");

}
