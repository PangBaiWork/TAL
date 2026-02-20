//
// Created by pangbai on 25-10-14.
//

#include "utils.h"

#include "QBDI/State.h"
#include "frida-gum.h"
std::string ToHex(uint64_t value) {
    char buff[32];
    sprintf(buff, "0x%llx", value);
    return buff;
}

inline std::string ByteToHex(unsigned char byte) {
    std::stringstream ss;
    ss << std::hex << std::setw(2) << std::setfill('0')
       << static_cast<uint8_t>(byte);
    return ss.str();
}

std::string ReadMemToHex(const void *ptr, size_t length) {
    std::string hexString;
    const auto *bytePtr = static_cast<const unsigned char *>(ptr);
    for (size_t i = 0; i < length; ++i) {
        hexString += ByteToHex(bytePtr[i]);
    }
    return hexString;
}

int GetSameStrLen(const char *str1, const char *str2) {
    int count = 0;
    while (*str1 && *str2 && *str1 == *str2) {
        count++;
        str1++;
        str2++;
    }
    return count;
}

int IsPrintable(unsigned char *str,int max) {
    // if (str == NULL||str <=(unsigned char*) 0x3000) return 0;
    int i = 0;
    for (i = 0; str[i] != '\0'&& i < max; i++) {
        unsigned char c = str[i];
        // ASCII 可打印字符范围：32-126（空格到波浪线）
        if (c < 32 || c > 126) {
            return 0;
        }
    }
    return i == max;
}

#if defined(_M_X64)
#define NOMINMAX
#include <windows.h>
#include <cstdint>
void StackInfo::SaveStack(){
    NT_TIB* tib = (NT_TIB*)NtCurrentTeb();
    stack_base = tib->StackBase;
    stack_limit = tib->StackLimit;

    // DeallocationStack 在 TEB 偏移 0x1478 (x64)
    auto teb = (uint8_t*)NtCurrentTeb();
    deallocation_stack = *(void**)(teb + 0x1478);
}

void StackInfo::RestoreStack(){
    NT_TIB* tib = (NT_TIB*)NtCurrentTeb();
    tib->StackBase = stack_base;
    tib->StackLimit = stack_limit;

    auto teb = (uint8_t*)NtCurrentTeb();
    *(void**)(teb + 0x1478) = deallocation_stack;
}
#else
void StackInfo::SaveStack(){};
void StackInfo::RestoreStack(){};
#endif



#define PRINT_REG(reg) LOGI(#reg "_F:%llx,", cpu->reg)
#define PRINT_QBDI_REG(reg) LOGI(#reg "_Q:%llx,", state->reg)
#if defined(__x86_64__) || defined(_M_X64)
// X86_64

void syn_reg_gum(GumCpuContext *cpu, QBDI::GPRState *state, bool F2Q) {
#define SET_QBDI(reg)        \
    (state->reg = cpu->reg);
    // LOGE(#reg "_syn:%llx,", cpu->reg)
#define SET_FRIDA(reg) (cpu->reg = state->reg)
    if (F2Q) {
        SET_QBDI(r8);
        SET_QBDI(r9);
        SET_QBDI(r10);
        SET_QBDI(r11);
        SET_QBDI(r12);
        SET_QBDI(r13);
        SET_QBDI(r14);
        SET_QBDI(r15);

        SET_QBDI(rax);
        SET_QBDI(rcx);
        SET_QBDI(rdx);
        SET_QBDI(rbx);
        SET_QBDI(rsp);
        SET_QBDI(rbp);
        SET_QBDI(rsi);
        SET_QBDI(rdi);
    } else {
        SET_FRIDA(r8);
        SET_FRIDA(r9);
        SET_FRIDA(r10);
        SET_FRIDA(r11);
        SET_FRIDA(r12);
        SET_FRIDA(r13);
        SET_FRIDA(r14);
        SET_FRIDA(r15);

        SET_FRIDA(rax);
        SET_FRIDA(rcx);
        SET_FRIDA(rdx);
        SET_FRIDA(rbx);
        SET_FRIDA(rsp);
        SET_FRIDA(rbp);
        SET_FRIDA(rsi);
        SET_FRIDA(rdi);
    }
}



void print_frida_reg(GumCpuContext *cpu) {
    PRINT_REG(r8);
    PRINT_REG(r9);
    PRINT_REG(r10);
    PRINT_REG(r11);
    PRINT_REG(r12);
    PRINT_REG(r13);
    PRINT_REG(r14);
    PRINT_REG(r15);

    PRINT_REG(rax);
    PRINT_REG(rcx);
    PRINT_REG(rdx);
    PRINT_REG(rbx);
    PRINT_REG(rsp);
    // LOGE("frida str rsp:%p %s", cpu->rsp, cpu->rsp);
    PRINT_REG(rbp);
    PRINT_REG(rsi);
    PRINT_REG(rdi);
}
void print_qbdi_reg(QBDI::GPRState *state) {
    PRINT_QBDI_REG(r8);
    PRINT_QBDI_REG(r9);
    PRINT_QBDI_REG(r10);
    PRINT_QBDI_REG(r11);
    PRINT_QBDI_REG(r12);
    PRINT_QBDI_REG(r13);
    PRINT_QBDI_REG(r14);
    PRINT_QBDI_REG(r15);

    PRINT_QBDI_REG(rax);
    PRINT_QBDI_REG(rcx);
    PRINT_QBDI_REG(rdx);
    PRINT_QBDI_REG(rbx);
    PRINT_QBDI_REG(rsp);

    PRINT_QBDI_REG(rbp);
    PRINT_QBDI_REG(rsi);
    PRINT_QBDI_REG(rdi);
}
#elif defined(__arm__)
// ARM 32-bit
#elif defined(__aarch64__)
// ARM64

void syn_reg_gum(GumCpuContext *cpu, QBDI::GPRState *state, bool F2Q) {

    if (F2Q) {
        for (int i = 0; i < 29; i++) {
            QBDI_GPR_SET(state, i, cpu->x[i]);
        }
        state->lr = cpu->lr;
        state->sp = cpu->sp;
        state->x29 = cpu->fp;
        state->nzcv = cpu->nzcv;

    } else {
        for (int i = 0; i < 29; i++) {
            cpu->x[i] = QBDI_GPR_GET(state, i);
        }
        cpu->fp = state->x29;
        cpu->lr = state->lr;
        cpu->sp = state->sp;
        cpu->nzcv = state->nzcv;
    }

}


void print_frida_reg(GumCpuContext *cpu) {
    for (int i = 0; i < 18; i++) {
        PRINT_REG(x[i]);
    }
    PRINT_REG(sp);
}
void print_qbdi_reg(QBDI::GPRState *state) {
    for (int i = 0; i < 18; i++) {
        LOGI("x%d_Q:%llx,",i,QBDI_GPR_GET(state, i));
    }
    LOGI("sp_Q:%llx,", state->sp);
}

#elif defined(__i386__)
  // x86 32-bit
#endif

