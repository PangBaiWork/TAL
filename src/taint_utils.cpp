//
// Created by pangbai on 2025/10/12.
//

#include "taint_utils.h"


Instruction::Instruction(){

#if defined(__x86_64__) || defined(_M_X64)
    cs_arch_register_x86();
    cs_arch arch = CS_ARCH_X86; cs_mode md = CS_MODE_64;
#elif defined(__aarch64__)
    cs_arch_register_arm64();
    cs_arch arch = CS_ARCH_ARM64; cs_mode md = CS_MODE_ARM;
#endif

    if (cs_open(arch, md, &handle) != CS_ERR_OK) {
        // return;
        throw std::runtime_error("Failed to initialize Capstone");
    }
}

Instruction::~Instruction() {
    cs_close(&handle);
}

std::vector<std::string> Instruction::Disassemble(uintptr_t address, size_t size) const {
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

std::string Instruction::Disassemble(uintptr_t address) const {
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

 cs_insn * Instruction::AnalyzeInst(uintptr_t address)  {
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





bool TaintMemory::insert(uint64_t min, uint64_t max) {
    // 0-8 not 8
    max-=1;
    if (min > max) return false;

    // 找到第一个起始地址 >= minAddr 的区间
    auto it = mmap.lower_bound(min);

    // 检查与前一个区间是否重叠
    if (it != mmap.begin()) {
        auto prev = std::prev(it);
        if (prev->second.max >= min)
            return false; // 重叠
    }

    // 检查与当前 it 是否重叠
    if (it != mmap.end() && it->first <= max)
        return false;

    // 不重叠，可以插入
    mmap[min] = {min, max};
    return true;
}

bool TaintMemory::InsertBySize(uint64_t base, uint64_t size){
    return insert(base,base+size);
}

// 查找 targetaddr 所在区间
const MemoryRange* TaintMemory::find(uint64_t target) const {
    auto it = mmap.upper_bound(target);
    if (it == mmap.begin())
        return nullptr; // target 小于所有区间

    it = std::prev(it);
    if (target >= it->second.min && target <= it->second.max)
        return &it->second;
    return nullptr;
}

// 删除一个区间（通过 minAddr）
bool TaintMemory::erase(uint64_t addr) {
    // auto it = find(minAddr);
    // // if (it == memoryMap.end()) return false;
    // if (it != nullptr)
    // memoryMap.erase(it);
    auto it = mmap.upper_bound(addr);
    if (it == mmap.begin())
        return false; // target 小于所有区间

    it = std::prev(it);
    if (addr >= it->second.min && addr <= it->second.max)
    {
        mmap.erase(it);
        return true;
    }

    return false;
}

void TaintMemory::print() const {
    for (auto &kv : mmap) {
        std::cout << "[" << kv.second.min << ", " << kv.second.max << "]\n";
    }
}



void RegsState::SetTaintReg(int idx,uint64_t memRef){
    regs[idx].state = Taint;
    regs[idx].ref = memRef;
}
void RegsState::ClearReg(int idx){
    regs[idx].state = NoTaint;
    regs[idx].ref = 0;
}

bool RegsState::IsTaintReg(int idx){
    return regs[idx].state == Taint;
}


