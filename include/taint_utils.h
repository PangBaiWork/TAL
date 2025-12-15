//
// Created by pangbai on 2025/10/12.
//

#ifndef EZMYDROID_TAINTUTILS_H
#define EZMYDROID_TAINTUTILS_H
#include "QBDI/State.h"

#include "frida-gum.h"
#include <string>
#include <vector>
#include <iostream>
#include <map>

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

    bool InsertBySize(uint64_t base, int size);

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


class RegArray {
public:
    // 构造函数，接受数组指针
    RegArray(){
    }

    void SetGPRArray(const char* const names[],RegsState &state) {
        // 假设构造函数在调用时，保证 names 有效且长度不超过 maxRegisters
        this->names=names;
        this->state=&state;
    }

    std::string operator[](int idx) const {
        if (idx >=std::extent_v<decltype(QBDI::GPR_NAMES)> || names[idx] == nullptr) {
           return  "";
        }
        if (state->IsTaintReg(idx)) {
            return "*"+std::string(names[idx]) ;
        }
        return names[idx];
    }
    std::string get(int idx) const {

        if (idx < QBDI::NUM_GPR) {
            return names[idx];
        }
        if (idx >= 160) { // x86_64 xmm0
            std::string reg = std::to_string((idx - 160) / 16);
            return "XMM" + reg;
        }
        return "unkown";
    }

private:
    const char* const* names{};   // 指向字符指针数组，不复制数据
    RegsState *state{};
};




#endif //EZMYDROID_TAINTUTILS_H
