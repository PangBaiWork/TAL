#include <array>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <string_view>

#include "library.h"
#include "trace_utils.h"

namespace {

#if defined(_MSC_VER)
#define TAL_TEST_NOINLINE __declspec(noinline)
#define TAL_TEST_EXPORT __declspec(dllexport)
#else
#define TAL_TEST_NOINLINE __attribute__((noinline))
#define TAL_TEST_EXPORT __attribute__((visibility("default")))
#endif

constexpr std::uint64_t kSource = 0x1122334455667788ULL;
constexpr std::uint64_t kMask = 0x0102030405060708ULL;
constexpr std::size_t kInstructionWidth = 42;
volatile std::uint64_t g_end_calls = 0;

struct ModeCase {
    PrintMode mode;
    std::string_view name;
    std::string_view suffix;
};

constexpr std::array<ModeCase, 6> kModes = {{
    {ADDR_MODE, "addr", "_addr.asm"},
    {BIN_MODE, "bin", "_bin.asm"},
    {DEBUG_MODE, "debug", "_debug.asm"},
    {TRACE_MODE, "trace", "_trace.asm"},
    {TRITON_MODE, "triton", "_triton.asm"},
    {TRACE_ARGS_MODE, "trace_args", "_trace_args.asm"},
}};

extern "C" TAL_TEST_EXPORT TAL_TEST_NOINLINE std::uint64_t ModeRegressionCallee(
    std::uint64_t value) {
    volatile std::uint64_t result = value ^ kMask;
    return result;
}

extern "C" TAL_TEST_EXPORT TAL_TEST_NOINLINE std::uint64_t ModeRegressionMemory(
    std::uint64_t* source, std::uint64_t* target) {
    std::uint64_t result = 0;
#if defined(__x86_64__) && !defined(_MSC_VER)
    asm volatile(
        "mov (%[source]), %%r8\n\t"
        "mov %%r8, (%[target])\n\t"
        "movabs $0x0102030405060708, %%r9\n\t"
        "xor %%r9, %%r8\n\t"
        "mov %%r8, (%[target])\n\t"
        "mov %%r8, %%rax\n\t"
        : "=a"(result)
        : [source] "r"(source), [target] "r"(target)
        : "r8", "r9", "memory", "cc");
#elif defined(__aarch64__)
    asm volatile(
        "ldr x8, [%[source]]\n\t"
        "str x8, [%[target]]\n\t"
        "movz x9, #0x0708\n\t"
        "movk x9, #0x0506, lsl #16\n\t"
        "movk x9, #0x0304, lsl #32\n\t"
        "movk x9, #0x0102, lsl #48\n\t"
        "eor x8, x8, x9\n\t"
        "str x8, [%[target]]\n\t"
        "mov %0, x8\n\t"
        : "=r"(result)
        : [source] "r"(source), [target] "r"(target)
        : "x8", "x9", "memory", "cc");
#else
    result = *source;
    *target = result;
    *target ^= kMask;
    result = *target;
#endif
    return result;
}

extern "C" TAL_TEST_EXPORT TAL_TEST_NOINLINE std::uint64_t ModeRegressionArgs(
    std::uint64_t value) {
    volatile std::uint64_t result = ModeRegressionCallee(value);
    return result;
}

extern "C" TAL_TEST_EXPORT TAL_TEST_NOINLINE void ModeRegressionEnd() {
    ++g_end_calls;
}

const ModeCase* FindMode(std::string_view name) {
    for (const auto& mode : kModes) {
        if (mode.name == name) {
            return &mode;
        }
    }
    return nullptr;
}

bool StartsWith(std::string_view value, std::string_view prefix) {
    return value.size() >= prefix.size() &&
           value.compare(0, prefix.size(), prefix) == 0;
}

bool EndsWith(std::string_view value, std::string_view suffix) {
    return value.size() >= suffix.size() &&
           value.compare(value.size() - suffix.size(), suffix.size(), suffix) ==
               0;
}

std::filesystem::path FindLog(const std::filesystem::path& directory,
                              std::string_view prefix,
                              std::string_view suffix) {
    for (const auto& entry : std::filesystem::directory_iterator(directory)) {
        const std::string name = entry.path().filename().string();
        if (entry.is_regular_file() && StartsWith(name, prefix) &&
            EndsWith(name, suffix)) {
            return entry.path();
        }
    }
    return {};
}

void RemoveOldLogs(const std::filesystem::path& directory,
                   std::string_view prefix) {
    for (const auto& entry : std::filesystem::directory_iterator(directory)) {
        const std::string name = entry.path().filename().string();
        if (entry.is_regular_file() && StartsWith(name, prefix)) {
            std::filesystem::remove(entry.path());
        }
    }
}

std::string ReadFile(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(input),
            std::istreambuf_iterator<char>()};
}

bool HasMemoryAccess(std::string_view log) {
    return log.find(" R[") != std::string_view::npos ||
           log.find(" W[") != std::string_view::npos ||
           log.find(" RW[") != std::string_view::npos;
}

std::size_t Count(std::string_view value, char needle) {
    std::size_t count = 0;
    for (const char c : value) {
        if (c == needle) {
            ++count;
        }
    }
    return count;
}

bool IsInstructionBytes(std::string_view bytes) {
    if (bytes.empty() || bytes.size() % 2 != 0) {
        return false;
    }
    for (const unsigned char c : bytes) {
        if (!std::isxdigit(c)) {
            return false;
        }
    }
    return true;
}

bool CheckInstructionLayout(const ModeCase& mode, std::string_view log,
                            std::string& reason) {
    const bool ends_with_newline = log.back() == '\n';
    if ((mode.mode == BIN_MODE && ends_with_newline) ||
        (mode.mode != BIN_MODE && !ends_with_newline)) {
        reason = "mode-specific trailing newline layout changed";
        return false;
    }

    std::size_t instruction_count = 0;
    std::size_t begin = 0;
    while (begin < log.size()) {
        const std::size_t end = log.find('\n', begin);
        const std::string_view line = log.substr(begin, end - begin);
        begin = end == std::string_view::npos ? log.size() : end + 1;

        if (line.find(":\t") == std::string_view::npos) {
            continue;
        }
        ++instruction_count;

        std::size_t field = 0;
        if (mode.mode == ADDR_MODE || mode.mode == TRITON_MODE) {
            if (!StartsWith(line, "0x")) {
                reason = "instruction offset prefix changed";
                return false;
            }
        } else if (mode.mode == BIN_MODE) {
            const std::size_t bytes_begin = line.find(":(");
            const std::size_t bytes_end = line.find(')', bytes_begin);
            if (bytes_begin == std::string_view::npos ||
                bytes_end == std::string_view::npos ||
                line.substr(0, bytes_begin).find("tal_mode_regression") ==
                    std::string_view::npos ||
                !IsInstructionBytes(line.substr(bytes_begin + 2,
                                                bytes_end - bytes_begin - 2))) {
                reason = "BIN instruction byte field changed";
                return false;
            }
            field = bytes_end + 1;
        } else {
            field = line.find("0x");
            if (field == std::string_view::npos ||
                line.substr(0, field).find("tal_mode_regression") ==
                    std::string_view::npos) {
                reason = "module and offset prefix changed";
                return false;
            }
        }

        if (!StartsWith(line.substr(field), "0x") ||
            line.size() <= field + kInstructionWidth) {
            if (mode.mode == ADDR_MODE && StartsWith(line, "0x") &&
                line.find(":\tmov ") != std::string_view::npos &&
                line.find(", 0x") != std::string_view::npos &&
                line.find('|') == std::string_view::npos) {
                continue;
            }
            reason = "instruction field is incomplete";
            return false;
        }

        const char annotation = line[field + kInstructionWidth];
        if (annotation != ' ' && annotation != '|' && annotation != '*') {
            reason = "instruction annotation is not aligned to column 42";
            return false;
        }

        const std::size_t first_separator = line.find('|', field);
        const std::size_t required_separators = mode.mode == ADDR_MODE ? 1 : 2;
        if (first_separator < field + kInstructionWidth ||
            Count(line, '|') < required_separators) {
            reason = "instruction separators changed";
            return false;
        }
    }

    if (instruction_count < 3) {
        reason = "too few formatted instruction lines";
        return false;
    }
    return true;
}

bool CheckMemoryLayout(std::string_view log) {
    std::size_t access = log.find(" R[");
    if (access == std::string_view::npos) {
        access = log.find(" W[");
    }
    if (access == std::string_view::npos) {
        access = log.find(" RW[");
    }
    if (access == std::string_view::npos) {
        return false;
    }

    const std::size_t value = log.find("]=0x", access);
    const std::size_t size = log.find(" <0x", value);
    const std::size_t end = log.find("> ", size);
    return value != std::string_view::npos && size != std::string_view::npos &&
           end != std::string_view::npos;
}

bool CheckArchitectureLayout(std::string_view log, std::string& reason) {
#if defined(__x86_64__) && !defined(_MSC_VER)
    if (log.find("R8") == std::string_view::npos ||
        log.find("R9") == std::string_view::npos ||
        log.find("mov") == std::string_view::npos ||
        log.find("xor") == std::string_view::npos) {
        reason = "x64 assembly sequence changed";
        return false;
    }
#elif defined(__aarch64__)
    if (log.find("X8") == std::string_view::npos ||
        log.find("X9") == std::string_view::npos ||
        log.find("ldr") == std::string_view::npos ||
        log.find("str") == std::string_view::npos ||
        log.find("eor") == std::string_view::npos) {
        reason = "ARM64 assembly sequence changed";
        return false;
    }
#endif
    return true;
}

bool CheckLog(const ModeCase& mode, std::string_view log, std::string& reason) {
    if (log.empty()) {
        reason = "log is empty";
        return false;
    }
    if (!CheckInstructionLayout(mode, log, reason)) {
        return false;
    }

    switch (mode.mode) {
        case ADDR_MODE:
            if (log.find("0x1122334455667788") == std::string_view::npos) {
                reason = "ADDR log is missing tainted memory propagation";
                return false;
            }
            return CheckArchitectureLayout(log, reason);
        case BIN_MODE:
            if (log.find('(') == std::string_view::npos) {
                reason = "BIN log is missing instruction bytes";
                return false;
            }
            return true;
        case DEBUG_MODE:
        case TRACE_MODE:
            if (!HasMemoryAccess(log) || !CheckMemoryLayout(log)) {
                reason = "trace memory access layout changed";
                return false;
            }
            return true;
        case TRITON_MODE:
            if (log.find("0x1122334455667788") == std::string_view::npos ||
                log.find("] <0x8> |") == std::string_view::npos) {
                reason = "TRITON taint or memory layout changed";
                return false;
            }
            return true;
        case TRACE_ARGS_MODE:
            if (log.find("call  tal_mode_regression:ModeRegressionCallee "
                         "base:0x") == std::string_view::npos ||
                log.find("\ndemangled : ModeRegressionCallee\n"
                         "argc      : 1 default(1) reason=c_symbol\n"
                         "arg[0] = 0x1122334455667788\n") ==
                    std::string_view::npos) {
                reason = "TRACE_ARGS call block layout changed";
                return false;
            }
            return true;
    }

    reason = "unknown mode";
    return false;
}

int Run(const ModeCase& mode, const std::filesystem::path& directory) {
    std::filesystem::create_directories(directory);
    const std::string stem = "tal_mode_" + std::string(mode.name) + "_";
    RemoveOldLogs(directory, stem);
    const std::string prefix = (directory / stem).string();

    const bool args_mode = mode.mode == TRACE_ARGS_MODE;
    const std::uint64_t start =
        args_mode ? reinterpret_cast<std::uint64_t>(&ModeRegressionArgs)
                  : reinterpret_cast<std::uint64_t>(&ModeRegressionMemory);
    trace(start, reinterpret_cast<std::uint64_t>(&ModeRegressionEnd), true,
          mode.mode);

    if (!set_log_path(prefix.c_str()) || !set_printable_size(0)) {
        std::cerr << mode.name << ": failed to configure tracing" << std::endl;
        return 3;
    }

    std::uint64_t source = kSource;
    std::uint64_t target = 0;
    if (!add_taint_range(reinterpret_cast<std::uint64_t>(&source),
                         sizeof(source))) {
        std::cerr << mode.name << ": failed to add the taint range"
                  << std::endl;
        return 4;
    }

    set_function_print(1, 0);
    const std::uint64_t result = args_mode
                                     ? ModeRegressionArgs(source)
                                     : ModeRegressionMemory(&source, &target);
    ModeRegressionEnd();

    const std::uint64_t expected = source ^ kMask;
    if (result != expected || (!args_mode && target != expected)) {
        std::cerr << mode.name << ": traced function returned an invalid result"
                  << std::endl;
        return 5;
    }

    const std::filesystem::path log_path =
        FindLog(directory, stem, mode.suffix);
    if (log_path.empty()) {
        std::cerr << mode.name << ": expected log file was not created"
                  << std::endl;
        return 6;
    }

    const std::string log = ReadFile(log_path);
    std::string reason;
    if (!CheckLog(mode, log, reason)) {
        std::cerr << mode.name << ": " << reason << "\n"
                  << "log: " << log_path << std::endl;
        return 7;
    }

    std::cout << mode.name << " regression passed: " << log_path << std::endl;
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 3) {
        std::cerr << "usage: " << argv[0] << " MODE LOG_DIRECTORY" << std::endl;
        return 2;
    }

    const ModeCase* mode = FindMode(argv[1]);
    if (mode == nullptr) {
        std::cerr << "unknown mode: " << argv[1] << std::endl;
        return 2;
    }

    const int result = Run(*mode, argv[2]);
    std::_Exit(result);
}
