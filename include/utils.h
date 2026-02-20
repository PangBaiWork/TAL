//
// Created by pangbai on 25-10-14.
//

#ifndef UTILS_H
#define UTILS_H

#include <chrono>
#include <iomanip>
#include <iostream>
#include <sstream>

#include "QBDI/State.h"
#include "frida-gum.h"
#include "library.h"
#if defined(__GNUC__) || defined(__clang__)
    #define C_EXPORT  extern "C" __attribute__((visibility("default")))
#elif defined(_MSC_VER)
    #define C_EXPORT extern "C"  __declspec(dllexport)
#else
    #define C_EXPORT
#endif

// 构造函数属性
#if defined(__GNUC__) || defined(__clang__)
    #define C_INIT __attribute__((constructor))
#elif defined(_MSC_VER)
    #define C_INIT
#else
    #define C_INIT
#endif


std::string ReadMemToHex(const void* ptr, size_t length);
std::string ToHex(uint64_t value);
void syn_reg_gum(GumCpuContext *cpu, QBDI::GPRState *state, bool F2Q);
int GetSameStrLen(const char *str1, const char *str2);
void print_frida_reg(GumCpuContext *cpu);
void print_qbdi_reg(QBDI::GPRState *state);


#include <boost/context/continuation.hpp>
#include <boost/context/stack_context.hpp>
#include <cstdint>
#include <cstddef>
#include <memory>
#include <exception>
#include <utility>

namespace ctx = boost::context;

struct RawBufferStack {
    std::unique_ptr<std::uint8_t[]> buf;
    std::size_t size;
    explicit RawBufferStack(std::size_t n) : buf(new std::uint8_t[n]), size(n) {}
};

struct BorrowedStackAllocator {
    RawBufferStack* backing;

    ctx::stack_context allocate() {
        ctx::stack_context sctx{};
        std::uintptr_t base = reinterpret_cast<std::uintptr_t>(backing->buf.get());
        std::uintptr_t top  = base + backing->size;
        top &= ~std::uintptr_t(0xF);          // 16-byte 对齐（很重要）
        LOGI("alloc stack: base=%p top=%p size=%zu", (void*)base, (void*)top, backing->size);
        sctx.size = backing->size;
        sctx.sp   = reinterpret_cast<void*>(top); // 栈顶（高地址）
        return sctx;
    }

    void deallocate(ctx::stack_context&) noexcept {}
};

class  StackInfo {
public:
    void* stack_base;           // GS:[0x08]
    void* stack_limit;          // GS:[0x10]
    void* deallocation_stack;   // GS:[0x1478]
    void SaveStack();
    void RestoreStack();
};

int IsPrintable(unsigned char *str,int max);
#endif //UTILS_H
