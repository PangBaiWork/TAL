//
// Created by pangbai on 2025/10/12.
//

#include "taintUtils.h"


Instruction::Instruction(cs_arch arch, cs_mode md)
        : arch(arch), mode(md) {
    if (cs_open(arch, md, &handle) != CS_ERR_OK) {
        return;
        // throw std::runtime_error("Failed to initialize Capstone");
    }
}

Instruction::~Instruction() {
    cs_close(&handle);
}

std::vector<std::string> Instruction::disassemble(uintptr_t address, size_t size) const {
    std::vector<std::string> result;
    const uint8_t *code = reinterpret_cast<const uint8_t *>(address);

    cs_insn *insn;
    size_t count = cs_disasm(handle, code, size, address, 0, &insn);

    if (count > 0) {
        for (size_t i = 0; i < count; i++) {
            std::string instruction =
                    std::string(insn[i].mnemonic) + " " + std::string(insn[i].op_str);
            result.push_back(instruction);
        }
        cs_free(insn, count);
    }

    return result;
}

std::string Instruction::disassemble(uintptr_t address) const {
    const uint8_t *code = reinterpret_cast<const uint8_t *>(address);

    cs_insn *insn;
    size_t count = cs_disasm(handle, code, 16, address, 1, &insn);

    std::string result;
    if (count > 0) {
        result = std::string(insn[0].mnemonic) + " " + std::string(insn[0].op_str);
        cs_free(insn, count);
    }

    return result;
}

 cs_insn * Instruction::analyzeInst(uintptr_t address)  {
    const uint8_t *code = reinterpret_cast<const uint8_t *>(address);
    if (inst != nullptr) {
        cs_free(inst, 1);
        inst = nullptr;
    }
    size_t count = cs_disasm(handle, code, 16, address, 1, &inst);

    std::string result;
    if (count > 0) {
        return  inst;
        // cs_free(insn, count);
    }

    return nullptr;
}





bool TaintMemory::insert(uint64_t minAddr, uint64_t maxAddr) {
    // 0-8 not 8
    maxAddr-=1;
    if (minAddr > maxAddr) return false;

    // 找到第一个起始地址 >= minAddr 的区间
    auto it = memoryMap.lower_bound(minAddr);

    // 检查与前一个区间是否重叠
    if (it != memoryMap.begin()) {
        auto prev = std::prev(it);
        if (prev->second.maxAddr >= minAddr)
            return false; // 重叠
    }

    // 检查与当前 it 是否重叠
    if (it != memoryMap.end() && it->first <= maxAddr)
        return false;

    // 不重叠，可以插入
    memoryMap[minAddr] = {minAddr, maxAddr};
    return true;
}

bool TaintMemory::insertBySize(uint64_t baseAddr, int size){
    return insert(baseAddr,baseAddr+size);
}

// 查找 targetaddr 所在区间
const MemoryRange* TaintMemory::find(uint64_t targetaddr) const {
    auto it = memoryMap.upper_bound(targetaddr);
    if (it == memoryMap.begin())
        return nullptr; // target 小于所有区间

    it = std::prev(it);
    if (targetaddr >= it->second.minAddr && targetaddr <= it->second.maxAddr)
        return &it->second;
    return nullptr;
}

// 删除一个区间（通过 minAddr）
bool TaintMemory::erase(uint64_t minAddr) {
    // auto it = find(minAddr);
    // // if (it == memoryMap.end()) return false;
    // if (it != nullptr)
    // memoryMap.erase(it);
    auto it = memoryMap.upper_bound(minAddr);
    if (it == memoryMap.begin())
        return false; // target 小于所有区间

    it = std::prev(it);
    if (minAddr >= it->second.minAddr && minAddr <= it->second.maxAddr)
    {
        memoryMap.erase(it);
        return true;
    }

    return false;
}

void TaintMemory::print() const {
    for (auto &kv : memoryMap) {
        std::cout << "[" << kv.second.minAddr << ", " << kv.second.maxAddr << "]\n";
    }
}



void RegsState::setTaintReg(int idx,uint64_t memRef){
    regs[idx].taintState = Taint;
    regs[idx].memRef = memRef;
}
void RegsState::clearReg(int idx){
    regs[idx].taintState = NoTaint;
    regs[idx].memRef = 0;
}

bool RegsState::isTaintReg(int idx){
    return regs[idx].taintState == Taint;
}

