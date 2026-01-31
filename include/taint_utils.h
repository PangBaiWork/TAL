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
    Instruction(cs_arch arch = CS_ARCH_X86, cs_mode md = CS_MODE_64);

    ~Instruction();

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
    MemoryRange(){
    }
};

class TaintMemory {
public:
    // 插入新区间，返回是否成功（false = 与已有区间重叠）
    bool insert(uint64_t min, uint64_t max);

    bool InsertBySize(uint64_t base, uint64_t size);

    // 查找 targetaddr 所在区间
    const MemoryRange* find(uint64_t target) const;

    // 删除一个区间（通过 minAddr）
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


// class RegArray {
// public:
//     // 构造函数，接受数组指针
//     RegArray(){
//     }
//
//     void SetGPRArray(const char* const names[],RegsState &state) {
//         // 假设构造函数在调用时，保证 names 有效且长度不超过 maxRegisters
//         this->names=names;
//         this->state=&state;
//     }
//
//     std::string operator[](int idx) const {
//         if (idx >=std::extent_v<decltype(QBDI::GPR_NAMES)> || names[idx] == nullptr) {
//            return  "";
//         }
//         if (state->IsTaintReg(idx)) {
//             return "*"+std::string(names[idx]) ;
//         }
//         return names[idx];
//     }
//     std::string get(int idx) const {
//
//         if (idx < QBDI::NUM_GPR) {
//             return names[idx];
//         }
//         if (idx >= 160) { // x86_64 xmm0
//             std::string reg = std::to_string((idx - 160) / 16);
//             return "XMM" + reg;
//         }
//         return "unkown";
//     }
//
// private:
//     const char* const* names{};   // 指向字符指针数组，不复制数据
//     RegsState *state{};
// };

class RegArray {
public:
    RegArray() = default;

    // 初始化：传入原始寄存器名数组（不带'*'），长度为 QBDI::NUM_GPR
    void SetGPRArray(const char* const inNames[], RegsState& state) {
        this->state = &state;

        // 先计算总长度：每个名需要 len + 2（1 个 '*' + 1 个 '\0'）
        size_t totalLen = 0;
        for (int i = 0; i < QBDI::NUM_GPR; ++i) {
            if (inNames[i] != nullptr) {
                totalLen += std::strlen(inNames[i]) + 2;
            }
        }

        // 分配连续缓冲区
        buffer.reset(new char[totalLen]);
        names.resize(QBDI::NUM_GPR, nullptr);

        // 依次拷贝为 "*name\0"
        char* p = buffer.get();
        for (int i = 0; i < QBDI::NUM_GPR; ++i) {
            const char* src = inNames[i];
            if (src == nullptr) {
                names[i] = nullptr;
                continue;
            }

            size_t len = std::strlen(src);
            names[i] = p;        // 指向以 '*' 开头的位置
            *p++ = '*';          // 前缀
            std::memcpy(p, src, len);
            p += len;
            *p++ = '\0';
        }
    }

    // 污点寄存器：返回从 0 开始的 char\*（带 '*'）
    // 非污点寄存器：返回从 1 开始的 char\*（跳过 '*'）
    const char* operator[](int idx) const {
        if (idx < 0 || idx >= static_cast<int>(names.size())) {
            return "unk";
        }
        const char* base = names[idx];
        if (base == nullptr || state == nullptr) {
            return "unk";
        }

        if (state->IsTaintReg(idx)) {
            // 污点：从索引 0 开始（'*' 位置）
            return base;
        } else {
            // 非污点：从索引 1 开始（跳过 '*'）
            return base + 1;
        }
    }

    // 保留原来的 get 逻辑（不区分污点，仅返回寄存器名）
    const char* get(int idx) const {
        if (idx < 0) {
            return nullptr;
        }

        if (idx < QBDI::NUM_GPR) {
            const char* base = (idx < static_cast<int>(names.size())) ? names[idx] : nullptr;
            // 跳过 '*'，只返回纯寄存器名
            return (base != nullptr) ? (base + 1) : nullptr;
        }

        // 其他寄存器（如 XMM），直接用静态缓冲生成
        if (idx >= 160) { // x86_64 xmm0
            static thread_local char xmmName[16];
            int xmmIndex = (idx - 160) / 16;
            std::snprintf(xmmName, sizeof(xmmName), "XMM%d", xmmIndex);
            return xmmName;
        }

        return "unkown";
    }

private:
    // 连续内存缓冲区，存 "*name\0"
    std::unique_ptr<char[]> buffer;
    // 每个寄存器对应的指针，指向缓冲区中以 '*' 开头的位置
    std::vector<const char*> names;
    RegsState* state{nullptr};
};



#endif //EZMYDROID_TAINTUTILS_H
