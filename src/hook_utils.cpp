//
// Created by fang on 2024/1/3.
//

#include <cstdio>



#include "hook_utils.h"

#include "utils.h"
using namespace std;





void hookUtils::gum_replace(void* addr, void* replace, void** backup){
    GumInterceptor *interceptor;
    interceptor = gum_interceptor_obtain();
    gum_interceptor_begin_transaction(interceptor);
    auto ret =gum_interceptor_replace(interceptor,addr,replace, interceptor,backup);
    gum_interceptor_end_transaction(interceptor);
    gum_interceptor_flush(interceptor);
    LOGI("HOOK REPLACE: %d",ret);
}


// GumInvocationListener *listener=nullptr;
GumInvocationListener *hookUtils::gum_attach(GumInterceptor *interceptor,void* addr, GumInvocationCallback on_enter, GumInvocationCallback on_leave, void* func_data ){

    gum_interceptor_begin_transaction(interceptor);
    if (on_enter == nullptr) on_enter = hookUtils::empty_onEnter;
    if (on_leave == nullptr) on_leave = hookUtils::empty_onLeave;
    void* data = malloc(sizeof(void*));
    auto listener = gum_make_call_listener(on_enter,on_leave, data, nullptr);

    gum_interceptor_attach(interceptor,addr,listener, func_data,GUM_ATTACH_FLAGS_NONE);
    gum_interceptor_end_transaction(interceptor);
    return listener;
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
void hookUtils::empty_onEnter(GumInvocationContext * context,
                              gpointer user_data) {

//    LOGD("call empty_onEnter");

}

void hookUtils::empty_onLeave(GumInvocationContext * context,
                              gpointer user_data) {
//    LOGD("call empty_onLeave");

}
