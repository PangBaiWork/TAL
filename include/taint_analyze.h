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
inline  std::unordered_map<PrintMode, std::string> ModeName = {
  {ADDR_MODE,   "addr"},
  {ASM_MODE,    "asm"},
  {DEBUG_MODE,  "debug"},
  {TRACE_MODE,  "trace"},
};

// using namespace std;
class TaintTrace {
 public:
  TaintMemory memory;
  RegsState state;
  uint64_t base;
  PrintMode mode = ADDR_MODE;
  std::ofstream log;
  std::ofstream all_log;
  Instruction disassembler;
  int16_t reg_r = -1, reg_w = -1, reg_rw[2] = {-1, -1};  // for post reg
  bool enable_post_inst = false;
  RegArray reg_name;
  char *taint_str = nullptr;

  void PrintReg(const QBDI::GPRState *state);
  QBDI::VMAction InstTrace(const QBDI::VM *vm, const QBDI::GPRState *gpr,QBDI::FPRState *fpr);
  void PostInstTrace(QBDI::VM *vm, QBDI::GPRState *gpr,QBDI::FPRState *fpr);
  void MemoryTrace(QBDI::VM *vm, QBDI::GPRState *gpr,QBDI::FPRState *fpr);
  void PrintMemoryOp(QBDI::GPRState *gpr, uint64_t offset,
                     QBDI::MemoryAccess *access, int reg_w = -1,int reg_r= -1);
  TaintTrace(const std::string *path, uint64_t base, PrintMode mode);

  PrintMode GetPrintMode() const { return mode; }
  void SetPostInstFlag() { enable_post_inst = true; }
  void CleanPostInstFlag() { enable_post_inst = false; }
  bool IsAddrMode() const { return mode == ADDR_MODE; }
  bool IsAsmMode() const { return mode == ASM_MODE; }
  bool IsDebugMode() const { return mode == DEBUG_MODE; }
  bool IsTraceMode() const { return mode == TRACE_MODE; }
  bool  NeedFlush() const { return IsDebugMode();}
  ~TaintTrace() {
    log.close();
  }
  static bool IsValid(const int64_t input) {return input>=0;}
  bool SetTaintReg(const int reg, const uint64_t ref) {
    state.SetTaintReg(reg,ref);
    return true;
  }
  bool IsTaint(const int reg) {
    if (!IsValid(reg))return false;
    return state.IsTaintReg(reg);
  }
  void AddTaintMemory(const uint64_t addr, const int size){
    memory.InsertBySize(addr,size);
  }
  void AddTaintMemory(const MemoryRange & range){
    memory.insert(range.min,range.max);
  }
  void SetTaintStr(char *str) {
    if (str) {
      taint_str=new char[strlen(str)+1];
      strcpy(taint_str,str);
      LOGE("TaintStr set: %s %s",taint_str,str);
    }
  }

  bool CheckTaintedStr(const uint64_t addr) {
    if (!memory.size() && taint_str && READABLE_ADDR < addr) {
      if (auto ptr = reinterpret_cast<char *>(addr);
          ptr[0] == taint_str[0] && ptr[1] == taint_str[1] &&
          ptr[2] == taint_str[2] && ptr[3] == taint_str[3]) {
            const int len = GetSameStrLen(ptr, taint_str);
            LOGE("Insert Taint Memory: %s %d", ptr, len);
            memory.InsertBySize(reinterpret_cast<uint64_t>(ptr), len);
            return true;
          }
    }
    return false;
  }

};
#endif  // EZMYDROID_TAINTANALYZE_H
