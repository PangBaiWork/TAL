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
#define READABLE_ADDR 0x3000
std::string PrintStr(uint64_t addr);
std::string ReadMemToHex(const void* ptr, size_t length);
std::string ToHex(uint64_t value);
std::string DataToHex(uint8_t* bytes,int size);
void syn_reg_gum(GumCpuContext *cpu, QBDI::GPRState *state, bool F2Q);
int GetSameStrLen(const char *str1, const char *str2);
void print_frida_reg(GumCpuContext *cpu);
void print_qbdi_reg(const QBDI::GPRState *state);


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

int IsPrintable(QBDI::rword addr,int max);


// for private var get
#include "Engine/Engine.h"
#include "ExecBroker/ExecBroker.h"
#include "ExecBlock/ExecBlock.h"
#include "QBDI/VM.h"
template<auto M>
struct Tunnel;

template<class T, class U, T U::*M>
struct Tunnel<M> {
    friend T& GetPrivate(U& u) {
        return u.*M;
    }
};

// Separate accessor name to avoid GetPrivate overload conflicts.
template<auto M>
struct TunnelRunning;
template<class T, class U, T U::*M>
struct TunnelRunning<M> {
    friend T& GetPrivateRunning(U& u) {
        return u.*M;
    }
};

template struct Tunnel<&QBDI::VM::engine>;           // T = std::unique_ptr<QBDI::Engine>
template struct Tunnel<&QBDI::Engine::execBroker>;    // T = QBDI::ExecBroker*
template struct Tunnel<&QBDI::ExecBroker::transferBlock>; // T = std::unique_ptr<QBDI::ExecBlock>
template struct TunnelRunning<&QBDI::Engine::running>;       // T = bool

std::unique_ptr<QBDI::Engine>& GetPrivate(QBDI::VM&);
QBDI::ExecBroker*& GetPrivate(QBDI::Engine&);  // 注意：返回的是指针的引用
std::unique_ptr<QBDI::ExecBlock>& GetPrivate(QBDI::ExecBroker&);

#if defined(QBDI_ARCH_AARCH64)
template<auto M>
struct TunnelArchData;
template<class T, class U, T U::*M>
struct TunnelArchData<M> {
    friend T& GetPrivateArchData(U& u) {
        return u.*M;
    }
};
template struct TunnelArchData<&QBDI::ExecBroker::archData>;
QBDI::ExecBrokerArchData& GetPrivateArchData(QBDI::ExecBroker&);
#endif

// Use a dedicated name to avoid overload collisions on GetPrivate.
bool& GetPrivateRunning(QBDI::Engine&);
void Hexdump(std::ostream& os, const void* data, size_t size, uintptr_t base = 0);
void PrintSymbolOffset (gpointer addr,std::ofstream& log);
#endif //UTILS_H
