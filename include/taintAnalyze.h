//
// Created by pangbai on 2025/10/12.
//

#ifndef EZMYDROID_TAINTANALYZE_H
#define EZMYDROID_TAINTANALYZE_H

#include "QBDI.h"
#include <fstream>
#include "taintUtils.h"
#include <string>
#include <sstream>

#include <iomanip>
#include "utils.h"
#include <exception>
#include "QBDI/State.h"
#define STR_ALIGN 40
#define READABLE_ADDR 0x10000
enum PRINT_MODE
{
    ADDR_MODE = 0,
    ASM_MODE = 1,
    DEBUG_MODE = 2,
};
using  namespace  std;
class TaintTrace{
public:
    TaintMemory taintMemory;
    RegsState regsState;
    uint64_t base;
    PRINT_MODE printMode=ADDR_MODE;
    std::ofstream log;
    std::ofstream allLog;
    Instruction disasmer;
    int16_t rRegIdx = -1, wRegIdx = -1, rwRegIdx[2] = {-1, -1}; //for post reg
    bool postInstFlag=false;
    RegArray regNames;
    char *taintStr=nullptr;
    void setPostInstFlag()
    {
        postInstFlag=true;
    }
    void cleanPostInstFlag()
    {
        postInstFlag=false;
    }
    bool checkTaintedStr(uint64_t addr) {
        // LOGE("READ:%llx",addr);
        if (!taintMemory.size()&&taintStr&&READABLE_ADDR<addr) {
            auto ptr =
               reinterpret_cast<char *>(addr);
                if (ptr[0]==taintStr[0]&&
                    ptr[1]==taintStr[1]&&
                    ptr[2]==taintStr[2]&&
                    ptr[3]==taintStr[3]) {
                    int len = getSameStrLen(ptr,taintStr);
                    LOGE("Insert Taint Memory: %s %d",ptr,len);


                    taintMemory.insertBySize(reinterpret_cast<uint64_t>(ptr),len);
                    return true;
                    }

        }
        return false;
    }
    void printReg(QBDI::GPRState *state);
    bool isAddrMode() const;
    bool isAsmMode() const;
    bool isDebugMode() const;
    QBDI::VMAction instTrace(QBDI::VM *vm, QBDI::GPRState *gprState, QBDI::FPRState *fprState);
    void postInstTrace(QBDI::VM *vm, QBDI::GPRState *gprState, QBDI::FPRState *fprState);
    void memoryTrace(QBDI::VM *vm, QBDI::GPRState *gprState, QBDI::FPRState *fprState);
    bool isTaintReg(int regIdx);
    bool isValid(int64_t input);
    void printMemoryOp(QBDI::GPRState* gpr,uint64_t offset,QBDI::MemoryAccess *memoryAccess,int wRegIdx=-1,int rRegIdx=-1);
    void addTaintMemory(uint64_t addr,int size);
    void addTaintMemory(MemoryRange& memoryRange);
    void setTaintStr(char* str);
    TaintTrace(std::string* path, uint64_t base, PRINT_MODE printMode);
    ~TaintTrace();
};
#endif //EZMYDROID_TAINTANALYZE_H
