//
// Created by pangb on 26-5-3.
//

#include "function_utils.h"
#include "utils.h"

#include <boost/core/demangle.hpp>
#include <frida-gum.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <iomanip>
#include <ostream>
#include <string>
#include <string_view>
#include <vector>

namespace {

    constexpr int DEFAULT_C_ARGC = 3;
    constexpr size_t ARG_HEXDUMP_SIZE = 0x40;

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

    static bool LooksLikeCppMemberFunction(const std::string& demangled) {
        const auto pos = demangled.find('(');
        if (pos == std::string::npos) {
            return false;
        }

        const std::string prefix = demangled.substr(0, pos);

        // 注意：Namespace::func() 也会命中，不过 trace 场景多打印一个 this 通常更有用。
        return prefix.find("::") != std::string::npos;
    }
    static int CountParamsFromDemangled(const std::string& demangled) {
        // 找“真正的函数参数括号”：
        // 要求 '(' 前一个非空白字符不是 ':'，这样可以跳过 art::(anonymous namespace)
        // 同时从左到右记录所有顶层括号对，再选最像函数参数列表的一对。
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
                if (angle_depth > 0) --angle_depth;
                continue;
            }

            if (angle_depth != 0) {
                continue;
            }

            if (c == '(') {
                stack.push_back(i);
            } else if (c == ')') {
                if (!stack.empty()) {
                    size_t l = stack.back();
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
            size_t l = p.l;
            size_t r = p.r;

            // 找 '(' 前面的非空白字符
            size_t k = l;
            while (k > 0 && std::isspace(static_cast<unsigned char>(demangled[k - 1]))) {
                --k;
            }

            if (k == 0) {
                continue;
            }

            char prev = demangled[k - 1];

            // 跳过 art::(anonymous namespace)
            if (prev == ':') {
                continue;
            }

            std::string inside = demangled.substr(l + 1, r - l - 1);

            // 跳过 LLVM 后缀这种： (.__uniq...)
            std::string trimmed_inside = inside;
            trimmed_inside.erase(
                    trimmed_inside.begin(),
                    std::find_if(
                            trimmed_inside.begin(),
                            trimmed_inside.end(),
                            [](unsigned char ch) { return !std::isspace(ch); }
                    )
            );

            if (!trimmed_inside.empty() && trimmed_inside[0] == '.') {
                continue;
            }

            // 这个就是最像函数参数列表的括号
            param_l = l;
            param_r = r;
        }

        if (param_l == std::string::npos || param_r == std::string::npos || param_r <= param_l) {
            return -1;
        }

        std::string args = demangled.substr(param_l + 1, param_r - param_l - 1);

        auto trim = [](std::string s) {
            auto not_space = [](unsigned char c) {
                return !std::isspace(c);
            };

            s.erase(s.begin(), std::find_if(s.begin(), s.end(), not_space));
            s.erase(std::find_if(s.rbegin(), s.rend(), not_space).base(), s.end());
            return s;
        };

        args = trim(args);

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
                    if (angle_depth > 0) --angle_depth;
                    break;

                case '(':
                    ++paren_depth;
                    break;

                case ')':
                    if (paren_depth > 0) --paren_depth;
                    break;

                case '[':
                    ++square_depth;
                    break;

                case ']':
                    if (square_depth > 0) --square_depth;
                    break;

                case ',':
                    if (angle_depth == 0 && paren_depth == 0 && square_depth == 0) {
                        ++count;
                    }
                    break;

                default:
                    break;
            }
        }

        return count;
    }

    static int GuessArgCount(const std::string& raw_symbol, std::string& demangled) {
        if (raw_symbol.empty()) {
            demangled.clear();
            return DEFAULT_C_ARGC;
        }

        if (!IsCppMangledSymbol(raw_symbol)) {
            demangled = raw_symbol;
            return DEFAULT_C_ARGC;
        }

        demangled = boost::core::demangle(raw_symbol.c_str());

        int argc = CountParamsFromDemangled(demangled);
        if (argc < 0) {
            argc = DEFAULT_C_ARGC;
        }

        if (LooksLikeCppMemberFunction(demangled)) {
            // C++ 成员函数 ABI 层会多一个 this。
            ++argc;
        }

        return argc;
    }

    static std::vector<uint64_t> GetAbiArgs(QBDI::GPRState* gpr) {
        std::vector<uint64_t> args;

        if (gpr == nullptr) {
            return args;
        }

#if defined(__aarch64__) || defined(_M_ARM64)

        args = {
                static_cast<uint64_t>(gpr->x0),
                static_cast<uint64_t>(gpr->x1),
                static_cast<uint64_t>(gpr->x2),
                static_cast<uint64_t>(gpr->x3),
                static_cast<uint64_t>(gpr->x4),
                static_cast<uint64_t>(gpr->x5),
                static_cast<uint64_t>(gpr->x6),
                static_cast<uint64_t>(gpr->x7),
        };

#elif defined(__arm__) || defined(_M_ARM)

        args = {
        static_cast<uint32_t>(gpr->r0),
        static_cast<uint32_t>(gpr->r1),
        static_cast<uint32_t>(gpr->r2),
        static_cast<uint32_t>(gpr->r3),
    };

#elif defined(_M_X64) || defined(__x86_64__)

#if defined(_WIN64)

    args = {
        static_cast<uint64_t>(gpr->rcx),
        static_cast<uint64_t>(gpr->rdx),
        static_cast<uint64_t>(gpr->r8),
        static_cast<uint64_t>(gpr->r9),
    };

#else

    args = {
        static_cast<uint64_t>(gpr->rdi),
        static_cast<uint64_t>(gpr->rsi),
        static_cast<uint64_t>(gpr->rdx),
        static_cast<uint64_t>(gpr->rcx),
        static_cast<uint64_t>(gpr->r8),
        static_cast<uint64_t>(gpr->r9),
    };

#endif

#elif defined(__i386__) || defined(_M_IX86)

    // 32-bit x86 普通 C 参数大多在栈上。
    // 这里保持接口简洁，只记录 thiscall 可能用到的 ecx。
    args = {
        static_cast<uint32_t>(gpr->ecx),
    };

#endif

        return args;
    }

    static bool TryReadablePointer(uint64_t raw, size_t size, uint64_t& clean) {
        clean = raw;

        if (raw == 0) {
            return false;
        }

        auto readable = [&](uint64_t value) -> bool {
            const auto* p = reinterpret_cast<gconstpointer>(static_cast<uintptr_t>(value));
            if (gum_memory_is_readable(p, size)) {
                clean = value;
                return true;
            }
            return false;
        };

        // 1. 原始指针先试，避免误伤正常数据指针。
        if (readable(raw)) {
            return true;
        }

#if defined(__aarch64__) || defined(_M_ARM64)

        // 2. ARM64 上尝试 Frida-Gum 的 code address strip。
        // 对代码指针更合理；对数据指针只是 fallback。
        const uint64_t stripped_code =
                static_cast<uint64_t>(gum_strip_code_address(static_cast<GumAddress>(raw)));

        if (stripped_code != raw && readable(stripped_code)) {
            return true;
        }

        // 3. 最后的 48-bit VA fallback。
        // 不要一开始就 mask，否则可能误伤 TBI/MTE/tagged pointer。
        const uint64_t stripped48 = raw & 0x0000FFFFFFFFFFFFULL;

        if (stripped48 != raw && readable(stripped48)) {
            return true;
        }

#endif

        return false;
    }

    static void PrintOneArg(std::ostream& os, size_t index, uint64_t value) {
        os << "arg[" << index << "] = 0x"
           << std::hex << value << std::dec;

        uint64_t clean = 0;

        if (TryReadablePointer(value, ARG_HEXDUMP_SIZE, clean)) {
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
                       QBDI::GPRState* gpr,
                       const std::string& raw_symbol_name) {
    std::string demangled;
    int argc = GuessArgCount(raw_symbol_name, demangled);

    const auto abi_args = GetAbiArgs(gpr);

    if (argc < 0) {
        argc = DEFAULT_C_ARGC;
    }

    argc = std::min<int>(argc, static_cast<int>(abi_args.size()));

    os << "\n";
    os << "demangled : " << demangled << "\n";
    os << "argc      : " << argc << "\n";

    for (int i = 0; i < argc; ++i) {
        PrintOneArg(os, static_cast<size_t>(i), abi_args[static_cast<size_t>(i)]);
    }
}