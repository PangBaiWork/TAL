//
// Created by fang on 2024/1/3.
//

#ifndef QBDI_HOOKUTILS_H
#define QBDI_HOOKUTILS_H
#include "frida-gum.h"
#include "taint_analyze.h"



#define HOOK_DEF(ret, func, ...) \
  ret   (*orig_##func)(__VA_ARGS__)=nullptr; \
  ret    new_##func(__VA_ARGS__)

class CallbackData{
public:
    Trace *tracer = nullptr;
    GumInterceptor *interceptor = nullptr;
    GumInvocationListener *listener = nullptr;
};

class HookUtils{
    public:
        static GumInvocationListener * gum_attach(void *addr,GumInvocationCallback on_enter, Trace* tracer);
        static void gum_replace(void* addr, void* replace,Trace*  tracer, void** backup);
private:
        static void empty_on_enter(GumInvocationContext * context,
                                  gpointer user_data);
        static void empty_on_leave(GumInvocationContext * context,
                                  gpointer user_data);

};


#endif //QBDI_HOOKUTILS_H
