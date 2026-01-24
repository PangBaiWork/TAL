//
// Created by pangbai on 25-10-14.
//

#ifndef UTILS_H
#define UTILS_H

#include <chrono>
#include <iomanip>
#include <iostream>
#include <sstream>

#include "QBDI/State.h"
#include "frida-gum.h"
#include "library.h"
#if defined(__GNUC__) || defined(__clang__)
    #define C_EXPORT  extern "C" __attribute__((visibility("default")))
#elif defined(_MSC_VER)
    #define C_EXPORT extern "C"  __declspec(dllexport)
#else
    #define C_EXPORT
#endif

// 构造函数属性
#if defined(__GNUC__) || defined(__clang__)
    #define C_INIT __attribute__((constructor))
#elif defined(_MSC_VER)
    #define C_INIT
#else
    #define C_INIT
#endif


std::string ReadMemToHex(const void* ptr, size_t length);
std::string ToHex(uint64_t value);
void syn_reg_gum(GumCpuContext *cpu, QBDI::GPRState *state, bool F2Q);
int GetSameStrLen(const char *str1, const char *str2);
void print_frida_reg(GumCpuContext *cpu);
void print_qbdi_reg(QBDI::GPRState *state);
#endif //UTILS_H
