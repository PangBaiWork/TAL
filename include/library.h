//
// Created by pangbai on 25-10-14.
//

#ifndef LIBRARY_H
#define LIBRARY_H

#include <stdint.h>

#if defined(__GNUC__) || defined(__clang__)
#define C_EXPORT  extern "C" __attribute__((visibility("default")))
#elif defined(_MSC_VER)
#define C_EXPORT extern "C"  __declspec(dllexport)
#else
    #define C_EXPORT
#endif


#ifdef __ANDROID__
#include <android/log.h>
#include <sys/resource.h>
#include <unistd.h>
#define LOG_TAG "TAL"
#define LOGD(fmt, ...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, \
        "[%s:%d] " fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define LOGI(fmt, ...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, \
        "[%s:%d] " fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define LOGW(fmt, ...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, \
        "[%s:%d] " fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define LOGE(fmt, ...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, \
        "[%s:%d] " fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#else
#define LOGD(fmt, ...) fprintf(stdout, fmt "\n", ##__VA_ARGS__)
#define LOGI(fmt, ...) fprintf(stdout, "[TAL INFO] " fmt "\n", ##__VA_ARGS__)
#define LOGW(fmt, ...) fprintf(stdout, "[TAL WARN] " fmt "\n", ##__VA_ARGS__)
#define LOGE(fmt, ...) fprintf(stderr, "[TAL ERROR] " fmt "\n", ##__VA_ARGS__)
#endif



C_EXPORT void trace(uint64_t addr, uint64_t end, bool all,
                    int mode) ;
C_EXPORT bool remove_range(uint64_t start, uint64_t size);
C_EXPORT bool add_taint_range(uint64_t addr, uint64_t size);
C_EXPORT bool set_log_path(const char* path);
C_EXPORT void add_escape(uint64_t break_addr, uint64_t resume_addr);
C_EXPORT void add_resume(const uint64_t resume_addr);
C_EXPORT bool set_printable_size(int size);
C_EXPORT bool set_taint_str(const char *str);
C_EXPORT bool set_triton(int mode);
C_EXPORT void set_function_print(int argc,int hexdump_size);
 void init_main();

#endif // LIBRARY_H
