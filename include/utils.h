//
// Created by pangbai on 25-10-14.
//

#ifndef UTILS_H
#define UTILS_H

#include <sstream>

#include <iomanip>
#include <iostream>

#include <chrono>
#if defined(__GNUC__) || defined(__clang__)
    #define VISIBILITY_DEFAULT  extern "C" __attribute__((visibility("default")))
#elif defined(_MSC_VER)
    #define VISIBILITY_DEFAULT extern "C"  __declspec(dllexport)
#else
    #define VISIBILITY_DEFAULT
#endif

// 构造函数属性
#if defined(__GNUC__) || defined(__clang__)
    #define CONSTRUCTOR_ATTR __attribute__((constructor))
#elif defined(_MSC_VER)
    #define CONSTRUCTOR_ATTR
#else
    #define CONSTRUCTOR_ATTR
#endif

// 格式化字符串的 LOGD 宏
#define LOGD(fmt, ...) fprintf(stdout, fmt "\n", ##__VA_ARGS__)
#define LOGI(fmt, ...) fprintf(stdout, "[TTD INFO] " fmt "\n", ##__VA_ARGS__)
#define LOGW(fmt, ...) fprintf(stdout, "[TTD WARN] " fmt "\n", ##__VA_ARGS__)
#define LOGE(fmt, ...) fprintf(stderr, "[TTD ERROR] " fmt "\n", ##__VA_ARGS__)
#define LOGS(fmt, ...) fprintf(stdout, "[TTD] " fmt "\n", ##__VA_ARGS__)

std::string ReadMemToHex(const void* ptr, size_t length);
std::string ToHex(uint64_t value);

int GetSameStrLen(const char *str1, const char *str2);

#endif //UTILS_H
