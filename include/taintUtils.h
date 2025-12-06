//
// Created by pangbai on 2025/10/12.
//

#ifndef EZMYDROID_TAINTUTILS_H
#define EZMYDROID_TAINTUTILS_H
#include "QBDI/State.h"
#define  REGS_COUNT 272

#include "frida-gum.h"
#include <string>
#include <vector>
#define TAINT_DEBUG 0
enum TaintState {
    NoTaint = 0,
    Taint

};

class Instruction {
private:
    csh handle;
    cs_arch arch;
    cs_mode mode;


public:
    cs_insn *inst=nullptr;
    Instruction(cs_arch arch = CS_ARCH_X86, cs_mode md = CS_MODE_64);

    ~Instruction();

    std::vector<std::string> disassemble(uintptr_t address, size_t size) const;

    std::string disassemble(uintptr_t address) const;
    cs_insn* analyzeInst(uintptr_t address) ;
};


#include <iostream>
#include <map>


struct MemoryRange {
    uint64_t minAddr;
    uint64_t maxAddr;
    MemoryRange(uint64_t min,uint64_t max){
        minAddr = min;
        maxAddr = max;
    }
    MemoryRange(){
    }
};

class TaintMemory {
public:
    // 插入新区间，返回是否成功（false = 与已有区间重叠）
    bool insert(uint64_t minAddr, uint64_t maxAddr);

    bool insertBySize(uint64_t baseAddr, int size);

    // 查找 targetaddr 所在区间
    const MemoryRange* find(uint64_t targetaddr) const;

    // 删除一个区间（通过 minAddr）
    bool erase(uint64_t minAddr);
    int size() const {
        return memoryMap.size();
    }

    void print() const;

private:
    std::map<uint64_t, MemoryRange> memoryMap;
};


struct RegStateInfo {
    enum TaintState taintState = NoTaint;
    uint64_t memRef = 0;
};

class RegsState {
public:
    void setTaintReg(int idx,uint64_t memRef);
    void clearReg(int idx);

    bool isTaintReg(int idx);

private:
    RegStateInfo regs[REGS_COUNT];
};


class RegArray {
public:
    // 构造函数，接受数组指针
    RegArray(){
    }

    void setGPRArray(const char* const names[],RegsState &regs_state) {
        // 假设构造函数在调用时，保证 names 有效且长度不超过 maxRegisters
        this->gprNames=names;
        this->regsState=&regs_state;
    }

    std::string operator[](int index) const {
        if (index >=std::extent_v<decltype(QBDI::GPR_NAMES)> || gprNames[index] == nullptr) {
           return  "";
        }
        if (regsState->isTaintReg(index)) {
            return "*"+std::string(gprNames[index]) ;
        }
        return gprNames[index];
    }
    std::string get(int idx) const {

        if (idx < QBDI::NUM_GPR) {
            return gprNames[idx];
        }
        if (idx >= 160) { // x86_64 xmm0
            std::string reg = std::to_string((idx - 160) / 16);
            return "XMM" + reg;
        }
        return "unkown";
    }

private:
    const char* const* gprNames{};   // 指向字符指针数组，不复制数据
    RegsState *regsState{};
    static const size_t maxRegisters = REGS_COUNT; // 设置最大的寄存器数量
};


#define ASM_START_STR \
";nasm -f elf64 taint.asm -o taint.o\n"\
"section .data\n" \
"section .bss\n"\
"section .text\n"\
"    global _start\n"\
"    _start:\n"

#endif //EZMYDROID_TAINTUTILS_H
