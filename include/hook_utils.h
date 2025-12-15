//
// Created by fang on 2024/1/3.
//

#ifndef QBDI_HOOKUTILS_H
#define QBDI_HOOKUTILS_H
#include "frida-gum.h"




#define HOOK_DEF(ret, func, ...) \
  ret   (*orig_##func)(__VA_ARGS__)=nullptr; \
  ret    new_##func(__VA_ARGS__)
typedef size_t Size;
struct MapAddresInfo {
    /**
     * 函数的符号
     */
    char *sym = nullptr;
    /**
     * 函数在文件路径
     */
    char *fname = nullptr;

    /**
     * 所在函数的基地址
     */
    size_t sym_base = 0;
    /**
     * 文件基地址
     */
    size_t fbase = 0;

    /**
     * 传入地址,相对于so的偏移
     */
    size_t offset = 0;
};

struct MapItemInfo {
    /**
     * item开始位置
     */
    size_t start;

    /**
     * item结束位置
     */
    size_t end;
};




class HookUtils{
    public:
        static GumInvocationListener * gum_attach(GumInterceptor *interceptor,void *addr,GumInvocationCallback on_enter, GumInvocationCallback on_leave,void* func_data= nullptr);
        static void gum_replace(void* addr,void* replace,void** backup);


private:
        // static GumInvocationListener * obtainListener();
        static void empty_on_enter(GumInvocationContext * context,
                                  gpointer user_data);
        static void empty_on_leave(GumInvocationContext * context,
                                  gpointer user_data);

};

#endif //QBDI_HOOKUTILS_H
