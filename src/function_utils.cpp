//
// Created by pangb on 26-5-3.
//

#include "function_utils.h"
#include "utils.h"

#include <boost/core/demangle.hpp>
#include <frida-gum.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <ostream>
#include <string>
#include <string_view>
#include <vector>
#include "sparse_bitmap.h"

namespace {

int DEFAULT_C_ARGC = 3;
size_t ARG_HEXDUMP_SIZE = 0x40;
C_EXPORT void set_function_print(int argc,int hexdump_size) {
    DEFAULT_C_ARGC=argc;
    ARG_HEXDUMP_SIZE=hexdump_size;
}
struct ArgCountResult {
    int argc = DEFAULT_C_ARGC;
    bool used_default = true;
    std::string reason;
};

static std::string Trim(std::string s) {
    auto not_space = [](unsigned char c) {
        return !std::isspace(c);
    };

    s.erase(s.begin(), std::find_if(s.begin(), s.end(), not_space));
    s.erase(std::find_if(s.rbegin(), s.rend(), not_space).base(), s.end());

    return s;
}

static bool IsCppMangledSymbol(std::string_view name) {
    // Itanium ABI: Linux / Android / macOS
    if (name.size() >= 2 && name[0] == '_' && name[1] == 'Z') {
        return true;
    }

    // MSVC ABI
    if (!name.empty() && name[0] == '?') {
        return true;
    }

    return false;
}

static int CountParamsFromDemangled(const std::string& demangled) {
    struct Pair {
        size_t l;
        size_t r;
    };

    std::vector<Pair> pairs;
    std::vector<size_t> stack;

    int angle_depth = 0;

    for (size_t i = 0; i < demangled.size(); ++i) {
        char c = demangled[i];

        if (c == '<') {
            ++angle_depth;
            continue;
        }

        if (c == '>') {
            if (angle_depth > 0) {
                --angle_depth;
            }
            continue;
        }

        if (angle_depth != 0) {
            continue;
        }

        if (c == '(') {
            stack.push_back(i);
        } else if (c == ')') {
            if (!stack.empty()) {
                const size_t l = stack.back();
                stack.pop_back();

                if (stack.empty()) {
                    pairs.push_back({l, i});
                }
            }
        }
    }

    size_t param_l = std::string::npos;
    size_t param_r = std::string::npos;

    for (const auto& p : pairs) {
        const size_t l = p.l;
        const size_t r = p.r;

        size_t k = l;
        while (k > 0 && std::isspace(static_cast<unsigned char>(demangled[k - 1]))) {
            --k;
        }

        if (k == 0) {
            continue;
        }

        const char prev = demangled[k - 1];

        // 跳过 art::(anonymous namespace)
        if (prev == ':') {
            continue;
        }

        const std::string inside = demangled.substr(l + 1, r - l - 1);
        const std::string trimmed_inside = Trim(inside);

        // 跳过 LLVM 后缀，例如：
        // (.__uniq.9903397835.llvm.59705313)
        if (!trimmed_inside.empty() && trimmed_inside[0] == '.') {
            continue;
        }

        // 取最后一个最像函数参数列表的括号。
        param_l = l;
        param_r = r;
    }

    if (param_l == std::string::npos ||
        param_r == std::string::npos ||
        param_r <= param_l) {
        return -1;
    }

    std::string args = Trim(
        demangled.substr(param_l + 1, param_r - param_l - 1)
    );

    if (args.empty() || args == "void") {
        return 0;
    }

    int count = 1;
    angle_depth = 0;

    int paren_depth = 0;
    int square_depth = 0;

    for (char c : args) {
        switch (c) {
            case '<':
                ++angle_depth;
                break;

            case '>':
                if (angle_depth > 0) {
                    --angle_depth;
                }
                break;

            case '(':
                ++paren_depth;
                break;

            case ')':
                if (paren_depth > 0) {
                    --paren_depth;
                }
                break;

            case '[':
                ++square_depth;
                break;

            case ']':
                if (square_depth > 0) {
                    --square_depth;
                }
                break;

            case ',':
                if (angle_depth == 0 &&
                    paren_depth == 0 &&
                    square_depth == 0) {
                    ++count;
                }
                break;

            default:
                break;
        }
    }

    return count;
}

static ArgCountResult GuessArgCount(const std::string& raw_symbol,
                                    std::string& demangled) {
    ArgCountResult result;

    if (raw_symbol.empty()) {
        demangled.clear();
        result.argc = DEFAULT_C_ARGC;
        result.used_default = true;
        result.reason = "empty_symbol";
        return result;
    }

    if (!IsCppMangledSymbol(raw_symbol)) {
        demangled = raw_symbol;
        result.argc = DEFAULT_C_ARGC;
        result.used_default = true;
        result.reason = "c_symbol";
        return result;
    }

    demangled = boost::core::demangle(raw_symbol.c_str());

    const int parsed_argc = CountParamsFromDemangled(demangled);
    if (parsed_argc < 0) {
        result.argc = DEFAULT_C_ARGC;
        result.used_default = true;
        result.reason = "parse_failed";
        return result;
    }

    result.argc = parsed_argc+1; // add for this
    result.used_default = false;
    result.reason = "demangled";
    return result;
}

static std::vector<uint64_t> GetAbiArgs64(QBDI::GPRState* gpr,
                                          size_t wanted_argc) {
    std::vector<uint64_t> args;

    if (gpr == nullptr || wanted_argc == 0) {
        return args;
    }

    std::vector<uint64_t> regs;
    size_t stack_skip_slots = 0;

#if defined(__aarch64__) || defined(_M_ARM64)

    regs = {
        static_cast<uint64_t>(gpr->x0),
        static_cast<uint64_t>(gpr->x1),
        static_cast<uint64_t>(gpr->x2),
        static_cast<uint64_t>(gpr->x3),
        static_cast<uint64_t>(gpr->x4),
        static_cast<uint64_t>(gpr->x5),
        static_cast<uint64_t>(gpr->x6),
        static_cast<uint64_t>(gpr->x7),
    };

    stack_skip_slots = 0;

#elif defined(_M_X64) || defined(__x86_64__)

#if defined(_WIN64)

    regs = {
        static_cast<uint64_t>(gpr->rcx),
        static_cast<uint64_t>(gpr->rdx),
        static_cast<uint64_t>(gpr->r8),
        static_cast<uint64_t>(gpr->r9),
    };

    /*
     * Windows x64 函数入口处：
     *
     * [rsp + 0x00] return address
     * [rsp + 0x08] shadow space for rcx
     * [rsp + 0x10] shadow space for rdx
     * [rsp + 0x18] shadow space for r8
     * [rsp + 0x20] shadow space for r9
     * [rsp + 0x28] arg4
     */
    stack_skip_slots = 5;

#else

    regs = {
        static_cast<uint64_t>(gpr->rdi),
        static_cast<uint64_t>(gpr->rsi),
        static_cast<uint64_t>(gpr->rdx),
        static_cast<uint64_t>(gpr->rcx),
        static_cast<uint64_t>(gpr->r8),
        static_cast<uint64_t>(gpr->r9),
    };

    /*
     * SysV x86-64 函数入口处：
     *
     * [rsp + 0x00] return address
     * [rsp + 0x08] arg6
     */
    stack_skip_slots = 1;

#endif

#else

    return args;

#endif

    const size_t reg_count = regs.size();
    const size_t reg_n = std::min(wanted_argc, reg_count);

    for (size_t i = 0; i < reg_n; ++i) {
        args.push_back(regs[i]);
    }

    if (wanted_argc <= reg_count) {
        return args;
    }

    const uint64_t sp = QBDI_GPR_GET(gpr, QBDI::REG_SP);

    for (size_t i = reg_count; i < wanted_argc; ++i) {
        uint64_t value = 0;
        const uint64_t stack_addr =
            sp + (stack_skip_slots + (i - reg_count)) *
            sizeof(uint64_t);
        value =  *reinterpret_cast<const uint64_t*>(stack_addr);
        args.push_back(value);
    }

    return args;
}


#if !defined(_WIN64)
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
uint64_t fastVmPages() {
    static int fd = open("/proc/self/statm", O_RDONLY);

    char buf[32];

    lseek(fd, 0, SEEK_SET);

    ssize_t n = read(fd, buf, sizeof(buf));

    if (n <= 0)
        return 0;

    uint64_t v = 0;

    for (ssize_t i = 0; i < n; ++i) {
        char c = buf[i];

        if ((unsigned)(c - '0') > 9)
            break;

        v = v * 10 + (c - '0');
    }

    return v;
}
uint64_t vm_size=0;
#endif

//SparseBitmap blacklist;
bool IsMemoryReadable(const void* addr, GumMemoryMap* map) {

    GumMemoryRange range;

    range.base_address = reinterpret_cast<uint64_t>(addr);
    range.size=0;
    if (gum_memory_map_contains(map,&range)) {
        return true;
    }
#if defined(_WIN64)
    if (gum_memory_is_readable(addr,1)) {
        gum_memory_map_update(map);
        return true;
    }
#else
    uint64_t size = fastVmPages();
    if (size != vm_size) {
//        LOGE("update maps");
        vm_size = size;
        gum_memory_map_update(map);
        return gum_memory_map_contains(map,&range);
    }
#endif


    return false;
}

bool TryReadablePointer(uint64_t raw, size_t size, uint64_t& clean,GumMemoryMap* map) {
    clean = raw;

    if (raw == 0) {
        return false;
    }

    auto readable = [&](uint64_t value) -> bool {
        const auto* p = reinterpret_cast<gconstpointer>(
            static_cast<uintptr_t>(value)
        );


        if (IsMemoryReadable(p, map)) {
            clean = value;
            return true;
        }

        return false;
    };

    // 1. 原始值优先。
    if (readable(raw)) {
        return true;
    }

#if defined(__aarch64__) || defined(_M_ARM64)

    // 2. ARM64 上尝试 Frida-Gum 的 code address strip。
    // 对代码指针更合理；对数据指针只是 fallback。
    const uint64_t stripped_code =
        static_cast<uint64_t>(
            gum_strip_code_address(static_cast<GumAddress>(raw))
        );

    if (stripped_code != raw && readable(stripped_code)) {
        return true;
    }

    // 3. 常见 48-bit VA fallback。
    // 不要一开始就 mask，否则可能误伤 TBI/MTE/tagged pointer。
    const uint64_t stripped48 = raw & 0x0000FFFFFFFFFFFFULL;

    if (stripped48 != raw && readable(stripped48)) {
        return true;
    }

#endif

    return false;
}

void PrintOneArg(std::ostream& os, size_t index, uint64_t value,GumMemoryMap* map) {
    os << "arg[" << index << "] = 0x"
       << std::hex << value << std::dec;

    uint64_t clean = 0;

    if (TryReadablePointer(value, ARG_HEXDUMP_SIZE, clean,map)) {
        if (clean != value) {
            os << " -> 0x" << std::hex << clean << std::dec;
        }

        os << ":\n";

        Hexdump(
            os,
            reinterpret_cast<const void*>(static_cast<uintptr_t>(clean)),
            ARG_HEXDUMP_SIZE,
            static_cast<uintptr_t>(clean)
        );
    } else {
        os << "\n";
    }
}

} // namespace

void PrintFunctionArgs(std::ostream& os,
                       QBDI::GPRState* gpr,GumMemoryMap* map,
                       const std::string& raw_symbol_name) {
    std::string demangled;
    const ArgCountResult count = GuessArgCount(raw_symbol_name, demangled);

    const auto abi_args = GetAbiArgs64(gpr, static_cast<size_t>(count.argc));

    os << "demangled : " << demangled << "\n";
    os << "argc      : " << count.argc;

    if (count.used_default) {
        os << " default(" << DEFAULT_C_ARGC << ")"
           << " reason=" << count.reason;
    } else {
        os << " reason=" << count.reason;
    }

    os << "\n";

    for (size_t i = 0; i < abi_args.size(); ++i) {
        PrintOneArg(os, i, abi_args[i],map);
    }
}