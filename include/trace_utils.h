//
// Created by pangbai on 2025/10/12.
//

#ifndef EZMYDROID_TAINTUTILS_H
#define EZMYDROID_TAINTUTILS_H

#include <cstring>
#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "QBDI/State.h"
#include "frida-gum.h"

#define  REGS_COUNT 272
#define TAINT_DEBUG 0
#define ASM_START_STR \
        ";nasm -f elf64 taint.asm -o taint.o\n"\
        "section .data\n" \
        "section .bss\n"\
        "section .text\n"\
        "    global _start\n"\
        "    _start:\n"

enum TaintState {
    NoTaint = 0,
    Taint
};

class Instruction {
    csh handle;
    cs_arch arch;
    cs_mode mode;
public:
    cs_insn *inst=nullptr;
    Instruction();
    ~Instruction() {
        cs_close(&handle);
    }
    std::vector<std::string> Disassemble(uintptr_t address, size_t size) const;
    std::string Disassemble(uintptr_t address) const;
    cs_insn* AnalyzeInst(uintptr_t address) ;
};

struct MemoryRange {
    uint64_t min;
    uint64_t max;
    MemoryRange(uint64_t min,uint64_t max){
        this->min = min;
        this->max = max;
    }
    MemoryRange(){}
};

class TaintMemory {
public:
    bool insert(uint64_t min, uint64_t max);
    bool InsertBySize(uint64_t base, uint64_t size);
    const MemoryRange* find(uint64_t target) const;
    bool erase(uint64_t addr);
    int size() const {
        return mmap.size();
    }
    void print() const;
private:
    std::map<uint64_t, MemoryRange> mmap;
};


struct RegStateInfo {
    TaintState state = NoTaint;
    uint64_t ref = 0;
};

class RegsState {
public:
    void SetTaintReg(int idx,uint64_t memRef);
    void ClearReg(int idx);
    bool IsTaintReg(int idx);
private:
    RegStateInfo regs[REGS_COUNT];
};


class RegArray {
public:
    RegArray() = default;
    void SetGPRArray(const char* const inNames[], RegsState& state) {
        this->state = &state;
        size_t totalLen = 0;
        for (int i = 0; i < QBDI::NUM_GPR; ++i) {
            if (inNames[i] != nullptr) {
                totalLen += std::strlen(inNames[i]) + 2;
            }
        }

        buffer.reset(new char[totalLen]);
        names.resize(QBDI::NUM_GPR, nullptr);
        char* p = buffer.get();
        for (int i = 0; i < QBDI::NUM_GPR; ++i) {
            const char* src = inNames[i];
            if (src == nullptr) {
                names[i] = nullptr;
                continue;
            }
            size_t len = std::strlen(src);
            names[i] = p;
            *p++ = '*';
            std::memcpy(p, src, len);
            p += len;
            *p++ = '\0';
        }
    }

    const char* operator[](int idx) const {
        if (idx < 0 || idx >= static_cast<int>(names.size())) {
            return "unk";
        }
        const char* base = names[idx];
        if (base == nullptr || state == nullptr) {
            return "unk";
        }

        if (state->IsTaintReg(idx)) {
            return base;
        }
        // skip '*'
        return base + 1;
    }

    const char* get(int idx) const {
        if (idx < 0) {
            return nullptr;
        }
        if (idx < QBDI::NUM_GPR) {
            const char* base = (idx < static_cast<int>(names.size())) ? names[idx] : nullptr;
            // skip '*'
            return (base != nullptr) ? (base + 1) : nullptr;
        }

        if (idx >= 160) {
            static thread_local char xmmName[16];
            int xmmIndex = (idx - 160) / 16;
            std::snprintf(xmmName, sizeof(xmmName), "XMM%d", xmmIndex);
            return xmmName;
        }

        return "unknown";
    }

private:
    std::unique_ptr<char[]> buffer;
    // * + reg_name
    std::vector<const char*> names;
    RegsState* state{nullptr};
};


enum PrintMode {
    ADDR_MODE = 0,
    BIN_MODE = 1,
    DEBUG_MODE = 2,
    TRACE_MODE = 3,
    TRITON_MODE = 4,
};
inline std::unordered_map<PrintMode, std::string> ModeName = {
    {ADDR_MODE, "addr"},   {BIN_MODE, "bin"},       {DEBUG_MODE, "debug"},
    {TRACE_MODE, "trace"}, {TRITON_MODE, "triton"},
};
enum RegAccess { WRITE, READ, READ_WRITE };
enum InstOprandType {
    NONE,
    CALL,
    RET,
    IF_JMP,  // for loop jmp
};



#endif //EZMYDROID_TAINTUTILS_H
