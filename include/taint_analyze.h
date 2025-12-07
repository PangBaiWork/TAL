//
// Created by pangbai on 2025/10/12.
//

#ifndef EZMYDROID_TAINTANALYZE_H
#define EZMYDROID_TAINTANALYZE_H

#include <exception>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>

#include "QBDI.h"
#include "QBDI/State.h"
#include "taint_utils.h"
#include "utils.h"
#define STR_ALIGN 40
#define READABLE_ADDR 0x10000
enum PrintMode {
  ADDR_MODE = 0,
  ASM_MODE = 1,
  DEBUG_MODE = 2,
  TRACE_MODE = 3,
};
using namespace std;
class TaintTrace {
 public:
  TaintMemory taintMemory;
  RegsState regsState;
  uint64_t base;
  PrintMode printMode = ADDR_MODE;
  std::ofstream log;
  std::ofstream allLog;
  Instruction disasmer;
  int16_t rRegIdx = -1, wRegIdx = -1, rwRegIdx[2] = {-1, -1};  // for post reg
  bool postInstFlag = false;
  RegArray regNames;
  char *taintStr = nullptr;
  PrintMode getPrintMode() const { return printMode; }
  void setPostInstFlag() { postInstFlag = true; }
  void cleanPostInstFlag() { postInstFlag = false; }
  bool isAddrMode() const { return printMode == ADDR_MODE; }
  bool isAsmMode() const { return printMode == ASM_MODE; }
  bool isDebugMode() const { return printMode == DEBUG_MODE; }
  bool isTraceMode() const { return printMode == TRACE_MODE; }

  bool checkTaintedStr(uint64_t addr) {
    // LOGE("READ:%llx",addr);
    if (!taintMemory.size() && taintStr && READABLE_ADDR < addr) {
      auto ptr = reinterpret_cast<char *>(addr);
      if (ptr[0] == taintStr[0] && ptr[1] == taintStr[1] &&
          ptr[2] == taintStr[2] && ptr[3] == taintStr[3]) {
        int len = getSameStrLen(ptr, taintStr);
        LOGE("Insert Taint Memory: %s %d", ptr, len);

        taintMemory.insertBySize(reinterpret_cast<uint64_t>(ptr), len);
        return true;
      }
    }
    return false;
  }
  void printReg(QBDI::GPRState *state);
  QBDI::VMAction instTrace(QBDI::VM *vm, QBDI::GPRState *gprState,
                           QBDI::FPRState *fprState);
  void postInstTrace(QBDI::VM *vm, QBDI::GPRState *gprState,
                     QBDI::FPRState *fprState);
  void memoryTrace(QBDI::VM *vm, QBDI::GPRState *gprState,
                   QBDI::FPRState *fprState);
  void printMemoryOp(QBDI::GPRState *gpr, uint64_t offset,
                     QBDI::MemoryAccess *memoryAccess, int wRegIdx = -1,
                     int rRegIdx = -1);
  TaintTrace(std::string *path, uint64_t base, PrintMode printMode);

  ~TaintTrace() {
    log.close();
  }
  bool isValid(int64_t input) {
    return input>=0;
  }
  bool isTaintReg(int regIdx) {
    if (!isValid(regIdx))return false;
    return regsState.isTaintReg(regIdx);
  }

  void addTaintMemory(uint64_t addr,int size){
    taintMemory.insertBySize(addr,size);
  }

  void addTaintMemory(const MemoryRange & memoryRange){
    taintMemory.insert(memoryRange.minAddr,memoryRange.maxAddr);
  }
  void setTaintStr(char *str) {
    if (str) {
      taintStr=new char[strlen(str)+1];
      strcpy(taintStr,str);
      LOGE("TaintStr set: %s %s",taintStr,str);
    }
  }

};
#endif  // EZMYDROID_TAINTANALYZE_H
