//
// Created by pangbai on 25-10-14.
//

#include "test.h"
#include "library.h"
#include <iostream>
#include <stdint.h>
#include <signal.h>
#include "frida-gum.h"

// 容易魔改
#include <iostream>
#include <cstdint>
#include <cstring>

#if defined(__x86_64__)
#include <emmintrin.h>  // SSE2

// 模拟 movups xmm0, xmmword ptr [rax+0DA0h] 操作
void simulate_movups_instruction() {
    // std::cout << "=== 模拟 movups xmm0, [rax+0DA0h] ===" << std::endl;

    // 创建模拟的内存区域（RAX指向的基地址）
    constexpr int BASE_SIZE = 0xDA0 + 64;  // 确保有足够空间
    alignas(16) uint8_t memory_region[BASE_SIZE];

    // 初始化内存数据
    // std::cout << "初始化内存数据..." << std::endl;
    for (int i = 0; i < BASE_SIZE; ++i) {
        memory_region[i] = static_cast<uint8_t>(i % 256);
    }

    // 在目标地址 [rax+0DA0h] 处设置特定的测试数据
    float* target_data = reinterpret_cast<float*>(memory_region + 0xDA0);
    target_data[0] = 1.5f;
    target_data[1] = 2.5f;
    target_data[2] = 3.5f;
    target_data[3] = 4.5f;

    // std::cout << "目标地址数据: "
    //           << target_data[0] << ", "
    //           << target_data[1] << ", "
    //           << target_data[2] << ", "
    //           << target_data[3] << std::endl;

    // 模拟汇编指令：movups xmm0, [rax+0DA0h]
    // std::cout << "执行 movups 操作..." << std::endl;

    // RAX 寄存器指向内存区域的基地址
    void* rax = static_cast<void*>(memory_region);

    // 计算目标地址: rax + 0xDA0
    void* target_address = static_cast<char*>(rax) + 0xDA0;

    // 执行非对齐加载到 XMM0
    __m128 xmm0 = _mm_loadu_ps(static_cast<float*>(target_address));

    // 显示结果
    float* result = reinterpret_cast<float*>(&xmm0);
    // // std::cout << "XMM0 寄存器内容: ";
    // for (int i = 0; i < 4; ++i) {
    //     std::cout << result[i] << " ";
    // }
    // std::cout << std::endl;

    // 显示十六进制表示
    // std::cout << "十六进制表示: ";
    uint32_t* hex_result = reinterpret_cast<uint32_t*>(&xmm0);
    // for (int i = 0; i < 4; ++i) {
    //     std::cout << std::hex << "0x" << hex_result[i] << " ";
    // }
    // std::cout << std::dec << std::endl;
}
#endif
void reg_jmp_test() {
    // int i=0;
    // int sum=0;
    // for (;i<0x114;i++) {
    //     sum+=i;
    // }
}
#include <stdlib.h>
#include <string.h>
void free_test() {
    int i =0;
  for (int i=0;i<100;i++) {
    unsigned char* ptr = (unsigned char*)malloc(200+i);
    if (ptr) {
      free(ptr);
    }
  }
}
void memcpy_test() {
  unsigned char source[0x200]="1";
  unsigned char destination[0x200];
  memcpy(destination, source, 0x200);
}
#include <time.h>
uint64_t time_test() {
  time_t  now = time(NULL);
    now+=0xdeadbeef;
  return now;
}

#define DELTA 0x9e3779b9
#define MX (((z>>5^y<<2) + (y>>3^z<<4)) ^ ((sum^y) + (key[(p&3)^e] ^ z)))
void btea(uint32_t * v, int n, uint32_t const key[4]) {
    std::string ss("0x114500");
    // LOGD("testing");
    // memcpy_test();
    //v 为数据，n 为数据长度 (负时为解密)，key 为密钥
    uint32_t y,  z, sum;  unsigned p, rounds, e;
    if (n > 1)
    /* Coding Part */
    {
      rounds = 6 + 52 / n;
      sum = 0;
      z = v[n - 1];
      do {
        sum += DELTA;
        e = (sum >> 2) & 3;
        for (p = 0; p < n - 1; p++) {
          y = v[p + 1];
          z = v[p] += MX;
        } // // std::cout << "XMM0 寄存器内容: ";
        // for (int i = 0; i < 4; ++i) {
        //     std::cout << result[i] << " ";
        // }
        // std::cout << std::endl;
        y = v[0];
        z = v[n - 1] += MX;
      } while (--rounds);
    } else if (n < -1)
    /* Decoding Part */
    {
      n = -n;
      rounds = 6 + 52 / n;
      sum = rounds * DELTA;
      y = v[0];
      do {
        e = (sum >> 2) & 3;
        for (p = n - 1; p > 0; p--) {
          z = v[p - 1];
          y = v[p] -= MX;
        }
        z = v[n - 1];
        y = v[0] -= MX;
        sum -= DELTA;
      } while (--rounds);
    }



  free_test();

  // time_test();
  void (*funcPtr)();
  funcPtr=reg_jmp_test;

  funcPtr();
  reg_jmp_test();
}
int end() {
    return  0xdeadbeef;
}
#include <stdio.h>



#include "taint_analyze.h"
int main()
{
#ifdef _MSC_VER
    init_main();
#endif


    std::cout << "Hello World!\n";
    unsigned char flag[17]="1145144444441111";
    unsigned char key[16]="11111111";

    if (gum_memory_is_readable ((gconstpointer) 0x28, 1)) {
        LOGE("can read");
    };

    //printf("%p",btea);
    // taint_trace((void*)&btea,1,(uint64_t)flag,16,2);
    // setbuf(stdout, NULL);
    // taint_trace_str((uint64_t)&btea,1,(char*)flag,TRACE_MODE);
    trace((uint64_t)&btea,(uint64_t)time_test,1,TRACE_MODE);

    // add_taint_range((uint64_t)flag,16);
    set_taint_str((char*)flag);
    // set_triton(1);
    // remove_range((uint64_t)memcpy_test,4);
    // remove_range((uint64_t)fprintf,4);
    // add_escape((uint64_t)memcpy_test,(uint64_t)time_test);
    // add_escape((uint64_t)end,(uint64_t)0);
    LOGD("test begin");
    btea((uint32_t*)flag,4,(uint32_t*)key);
    free_test();
    memcpy_test();
    time_test();
    LOGD("test finish");
    end();
    exit(0);
    return  114514;
}

