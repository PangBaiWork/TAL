//
// Created by pangbai on 26-5-22.
//

#ifndef MEM_PROBE_H
#define MEM_PROBE_H

// mem_probe.hpp — 跨平台内存可读性查询 + 安全读取(自带降级纠正)
//
// 三层 + 方案B纠正网:
//   1) 快路径:页级位图,纯内存读。
//   2) 回填层:位图 miss 查内核状态(VirtualQuery / /proc/self/maps),不 hook API。
//      —— 解决"新映射"方向失效。
//   3) 纠正网(方案B):safeRead() 在位图命中后,于异常/信号保护下真正读取。
//      CPU 若因页降级(mprotect NONE / munmap)报错,清掉位图该页并返回失败。
//      —— 解决"权限降级"方向失效,稳态零开销,踩到才付一次代价。
//
// 接口:
//   bool readable(ptr)               仅查位图+回填,不保证降级实时(快,但可能骗你)
//   bool safeRead(ptr, out, len)     位图命中→保护性读取→降级自动纠正(trace 直接用这个)
//
// 编译:
//   Linux:   g++ -std=c++17 -O2 main.cpp -o demo
//   Windows: cl /std:c++17 /EHa /O2 main.cpp
#pragma once
#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <atomic>

#if defined(_WIN32)
  #include <windows.h>
#else
  #ifndef _GNU_SOURCE
  #define _GNU_SOURCE
  #endif
  #include <unistd.h>
  #include <fcntl.h>
  #include <sys/uio.h>
  #include <signal.h>
  #include <setjmp.h>
  #include <cstdio>
#endif

class MemProbe {
public:
    enum State : uint8_t { PG_NONE = 0, PG_R = 1, PG_RW = 2 };

    MemProbe() {
        l1_ = static_cast<std::atomic<uint8_t*>*>(
            std::calloc(L1_SLOTS, sizeof(std::atomic<uint8_t*>)));
#if !defined(_WIN32)
        self_pid_ = ::getpid();
        installSignalHandler();   // 安装 SIGSEGV/SIGBUS 纠正 handler(链式)
#endif
        importAll();
    }

    ~MemProbe() {
        if (l1_) {
            for (uint64_t i = 0; i < L1_SLOTS; ++i) {
                uint8_t* b = l1_[i].load(std::memory_order_relaxed);
                if (b) std::free(b);
            }
            std::free(l1_);
        }
    }

    MemProbe(const MemProbe&) = delete;
    MemProbe& operator=(const MemProbe&) = delete;

    // 仅查询(快,但对降级有滞后)。保留给只需粗判的场景。
    bool readable(const void* addr) {
        uintptr_t a = reinterpret_cast<uintptr_t>(addr);
        State s = bitmapQuery(a);
        if (s != PG_NONE) return true;
        LOGE("addr:%llx",addr);
        s = kernelQueryAndFill(a);
        return s != PG_NONE;
    }

    // 方案B核心:安全读取。这是 trace 应当直接调用的入口。
    // 返回成功读取的字节数(0 表示不可读)。降级页会在此被 CPU 发现并纠正。
    size_t safeRead(const void* addr, void* out, size_t len) {
        uintptr_t a = reinterpret_cast<uintptr_t>(addr);

        // 位图说完全没有 → 先回填(解决新映射)。回填后仍无则确属不可读。
        if (bitmapQuery(a) == PG_NONE) {
            if (kernelQueryAndFill(a) == PG_NONE) return 0;
        }
        // 位图命中:在保护下真正读。降级则由 CPU 触发,handler 清位图。
        return protectedCopy(out, (const void*)a, len);
    }

    // 便捷:读单字节
    bool tryReadU8(const void* addr, uint8_t* out) {
        return safeRead(addr, out, 1) == 1;
    }

    void refresh(const void* addr) {
        kernelQueryAndFill(reinterpret_cast<uintptr_t>(addr));
    }

private:
    static constexpr int      L1_BITS  = 18;
    static constexpr int      L2_BITS  = 18;
    static constexpr uint64_t L1_SLOTS = 1ull << L1_BITS;
    static constexpr uint64_t L2_PAGES = 1ull << L2_BITS;
    static constexpr size_t   L2_BYTES = (L2_PAGES * 2) / 8;

    std::atomic<uint8_t*>* l1_ = nullptr;

    static inline uint64_t pageNum(uintptr_t a) { return a >> 12; }

    uint8_t* l2Block(uint64_t pn, bool alloc) {
        uint64_t i = pn >> L2_BITS;
        if (i >= L1_SLOTS) return nullptr;
        uint8_t* blk = l1_[i].load(std::memory_order_acquire);
        if (!blk && alloc) {
            uint8_t* nb = static_cast<uint8_t*>(std::calloc(1, L2_BYTES));
            uint8_t* expected = nullptr;
            if (!l1_[i].compare_exchange_strong(expected, nb,
                    std::memory_order_acq_rel)) { std::free(nb); blk = expected; }
            else blk = nb;
        }
        return blk;
    }

    State bitmapQuery(uintptr_t addr) {
        uint64_t pn = pageNum(addr), i = pn >> L2_BITS;
        if (i >= L1_SLOTS) return PG_NONE;
        uint8_t* blk = l1_[i].load(std::memory_order_acquire);
        if (!blk) return PG_NONE;
        uint64_t lo = pn & (L2_PAGES - 1);
        return State((blk[lo >> 2] >> ((lo & 3) * 2)) & 0x3);
    }

    void setRange(uintptr_t start, uintptr_t end, State st) {
        if (end <= start) return;
        uint64_t p0 = pageNum(start), p1 = pageNum(end - 1);
        for (uint64_t pn = p0; pn <= p1; ++pn) {
            uint8_t* blk = l2Block(pn, st != PG_NONE);
            if (!blk) continue;
            uint64_t lo = pn & (L2_PAGES - 1);
            auto* cell = reinterpret_cast<std::atomic<uint8_t>*>(&blk[lo >> 2]);
            int shift = (lo & 3) * 2;
            uint8_t cur = cell->load(std::memory_order_relaxed), next;
            do { next = (cur & ~(0x3u << shift)) | (uint32_t(st) << shift); }
            while (!cell->compare_exchange_weak(cur, next,
                       std::memory_order_acq_rel, std::memory_order_relaxed));
        }
    }

    // 降级纠正:把某地址所在页在位图里清成 NONE
    void invalidatePage(uintptr_t a) {
        uintptr_t base = a & ~uintptr_t(0xFFF);
        // 块若存在则清零;不存在说明本就是 NONE。直接调 setRange 即可。
        uint64_t pn = pageNum(base), i = pn >> L2_BITS;
        if (i >= L1_SLOTS) return;
        if (l1_[i].load(std::memory_order_acquire))     // 仅当块已存在才需清
            setRange(base, base + 0x1000, PG_NONE);
    }

#if defined(_WIN32)
    static State protToState(DWORD p) {
        if (p & (PAGE_NOACCESS | PAGE_GUARD)) return PG_NONE;
        if (p & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE |
                 PAGE_WRITECOPY  | PAGE_EXECUTE_WRITECOPY)) return PG_RW;
        return PG_R;
    }
    void importAll() {
        uintptr_t addr = 0; MEMORY_BASIC_INFORMATION mbi;
        while (VirtualQuery((void*)addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            if (mbi.State == MEM_COMMIT)
                setRange((uintptr_t)mbi.BaseAddress,
                         (uintptr_t)mbi.BaseAddress + mbi.RegionSize,
                         protToState(mbi.Protect));
            uintptr_t next = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
            if (next <= addr) break;
            addr = next;
        }
    }
    State kernelQueryAndFill(uintptr_t a) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery((void*)a, &mbi, sizeof(mbi)) != sizeof(mbi)) return PG_NONE;
        State st = (mbi.State == MEM_COMMIT) ? protToState(mbi.Protect) : PG_NONE;
        setRange((uintptr_t)mbi.BaseAddress,
                 (uintptr_t)mbi.BaseAddress + mbi.RegionSize, st);
        return st;
    }
    // Windows 方案B:SEH 保护下 memcpy,AV 时纠正位图
    static int sehFilter(unsigned int code) {
        return (code == EXCEPTION_ACCESS_VIOLATION ||
                code == EXCEPTION_GUARD_PAGE)
                   ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH;
    }
    size_t protectedCopy(void* dst, const void* src, size_t len) {
        __try {
            memcpy(dst, src, len);
            return len;
        } __except (sehFilter(GetExceptionCode())) {
            invalidatePage((uintptr_t)src);     // 降级页纠正
            return 0;
        }
    }

#else  // ===== Linux =====
    pid_t self_pid_ = 0;

    static State permToState(const char* perm) {
        if (perm[0] != 'r') return PG_NONE;
        return (perm[1] == 'w') ? PG_RW : PG_R;
    }
    void importAll() {
        FILE* f = ::fopen("/proc/self/maps", "r"); if (!f) return;
        char line[512];
        while (::fgets(line, sizeof(line), f)) {
            uintptr_t s, e; char perm[8] = {0};
            if (::sscanf(line, "%lx-%lx %7s", &s, &e, perm) == 3) {
                State st = permToState(perm);
                if (st != PG_NONE) setRange(s, e, st);
            }
        }
        ::fclose(f);
    }
    State kernelQueryAndFill(uintptr_t a) {
        LOGE("enter query");
        FILE* f = ::fopen("/proc/self/maps", "r"); if (!f) return PG_NONE;
        char line[512]; State result = PG_NONE;
        while (::fgets(line, sizeof(line), f)) {
            uintptr_t s, e; char perm[8] = {0};
            LOGE("line:%s", line);
            if (::sscanf(line, "%lx-%lx %7s", &s, &e, perm) == 3 && a >= s && a < e) {
                result = permToState(perm);
                setRange(s, e, result);   // 无条件回填,降级也清
                break;
            }
        }
        ::fclose(f);
        return result;
    }

    // —— 方案B (Linux):信号保护下读取 ——
    // thread_local 隔离:只有本线程正在 protectedCopy 期间、且发生在我们读取的
    // 范围内,才接管;否则链式转发给目标程序原本的 handler,绝不吞掉它的 segv。
    struct ProbeCtx {
        sigjmp_buf jmp;
        volatile sig_atomic_t active = 0;
        volatile uintptr_t fault_page = 0;
    };
    static thread_local ProbeCtx tls_;
    static struct sigaction old_segv_, old_bus_;
    static MemProbe* g_self_;          // handler 回写位图用

    static void chainOrDie(int sig, siginfo_t* si, void* uc) {
        struct sigaction* old = (sig == SIGBUS) ? &old_bus_ : &old_segv_;
        if (old->sa_flags & SA_SIGINFO) {
            if (old->sa_sigaction) { old->sa_sigaction(sig, si, uc); return; }
        } else {
            if (old->sa_handler == SIG_IGN) return;
            if (old->sa_handler && old->sa_handler != SIG_DFL) {
                old->sa_handler(sig); return;
            }
        }
        // 没有原 handler:恢复默认并重抛,产生正常 coredump
        signal(sig, SIG_DFL);
        raise(sig);
    }

    static void segvHandler(int sig, siginfo_t* si, void* uc) {
        if (tls_.active) {
            tls_.fault_page = (uintptr_t)si->si_addr & ~uintptr_t(0xFFF);
            siglongjmp(tls_.jmp, 1);    // 跳回 protectedCopy,标记失败
        }
        chainOrDie(sig, si, uc);        // 非探测期间:这是目标真实的 segv,转发
    }

    void installSignalHandler() {
        g_self_ = this;
        struct sigaction sa; memset(&sa, 0, sizeof(sa));
        sa.sa_sigaction = segvHandler;
        sa.sa_flags = SA_SIGINFO | SA_NODEFER;   // NODEFER:longjmp 出 handler 后仍能再次接
        sigemptyset(&sa.sa_mask);
        sigaction(SIGSEGV, &sa, &old_segv_);
        sigaction(SIGBUS,  &sa, &old_bus_);
    }

    size_t protectedCopy(void* dst, const void* src, size_t len) {
        tls_.active = 1;
        size_t done = 0;
        // 第二参数 0:不保存/恢复信号掩码,省掉每次 rt_sigprocmask syscall。
        // 正确性依赖 handler 的 SA_NODEFER(SIGSEGV 不被自动屏蔽)。
        if (sigsetjmp(tls_.jmp, 0) == 0) {
            // 逐字节拷,出错时 done 即已成功的前缀长度
            const volatile uint8_t* s = (const volatile uint8_t*)src;
            uint8_t* d = (uint8_t*)dst;
            for (; done < len; ++done) d[done] = s[done];
        } else {
            // 从 siglongjmp 回来:src+done 处的页降级了,纠正位图
            if (g_self_ && tls_.fault_page)
                g_self_->invalidatePage(tls_.fault_page);
        }
        tls_.active = 0;
        return done;
    }
#endif
};

#if !defined(_WIN32)
thread_local MemProbe::ProbeCtx MemProbe::tls_;
struct sigaction MemProbe::old_segv_;
struct sigaction MemProbe::old_bus_;
MemProbe* MemProbe::g_self_ = nullptr;
#endif


#endif //MEM_PROBE_H
