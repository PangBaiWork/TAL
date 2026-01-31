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

#define UNKNOWN_CONST 0xdeadbeef
#define TAB "\t"
#define SPLIT " | "
#define ENTER "\n"
#define SPACE " "
#define EQ "="
#define MOV (TAB "mov ")
#define BLANK ""
// std::endl

#define ASM_NOTE (IsAsmMode() ? ";" : BLANK)
#define PRINT_OFFSET(OFFSET) (ToHex(OFFSET) + ":")
#define PRINT_ADDR(VALUE) ("[" + ToHex(VALUE) + "]")
#define PRINT_SIZE(SIZE) (" <" + ToHex(SIZE) + "> ")
#define PRINT_GPR(REG)  ToHex(QBDI_GPR_GET(gpr,REG))
#define PRINT_QBDI_REG(reg) (all_log << #reg << ":" << ToHex(state->reg) << ENTER)

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
enum RegAccess{
    WRITE,
    READ,
    READ_WRITE
};

enum InstOprandType{
    NONE,
    CALL,
    RET,
    IF_JMP, // for loop jmp
};

// using namespace std;
class TaintTrace {
 public:
  bool trace_all = false;
  uint64_t trace_end = 0;
  TaintMemory memory;
    std::vector<MemoryRange> escape_execute;
    std::vector<MemoryRange> avoid_range;
  std::map<std::string,uint64_t> base_map;
  RegsState state;
  uint64_t base;
  PrintMode mode = ADDR_MODE;
  std::ofstream log;
  std::ofstream all_log;
  Instruction disassembler;
  bool is_enter = false;
  InstOprandType inst_type = NONE;

//  int16_t taint_r[4] ={-1,-1,-1}, taint_w[4] = {}, rwreg[2] = {-1, -1};  // for post reg

  bool enable_post_inst = false;
  RegArray reg_name;
  char *taint_str = nullptr;

  QBDI::VMAction InstTrace(const QBDI::VM *vm, const QBDI::GPRState *gpr,QBDI::FPRState *fpr);
  void PostInstTrace(QBDI::VM *vm, const QBDI::GPRState *gpr,QBDI::FPRState *fpr);
  void MemoryTrace(const QBDI::VM *vm, QBDI::GPRState *gpr,
                   QBDI::FPRState *fpr);
  TaintTrace(uint64_t base,PrintMode mode=ADDR_MODE,const std::string* path=nullptr);
  void PrintMemoryOp(QBDI::GPRState *gpr, uint64_t offset,
                     QBDI::MemoryAccess *access, int reg_w = -1,int reg_r= -1);
  bool SetOutputPath(const std::string *path);
  // Taint reg name
  const char *TName(const int reg) const {return reg_name[reg];}
  const char *RegName(const int idx) const {return reg_name.get(idx);}
  PrintMode GetPrintMode() const { return mode; }
  void SetPostInstFlag() { enable_post_inst = true; }
  void CleanPostInstFlag() { enable_post_inst = false; }
  bool IsAddrMode() const { return mode == ADDR_MODE; }
  bool IsAsmMode() const { return mode == ASM_MODE; }
  bool IsDebugMode() const { return mode == DEBUG_MODE; }
  bool IsTraceMode() const { return mode == TRACE_MODE; }
  bool  NeedFlush() const { return true;}
  ~TaintTrace() {
    log.close();
  }
  void  AnalysisInstType(const QBDI::InstAnalysis *inst) {
      if (inst->isCall){
          inst_type = CALL;
      } else if (inst->isReturn){
          inst_type = RET;
      } else if (inst->isPredicable && inst->isBranch){
          inst_type = IF_JMP;
      } else {
          inst_type = NONE;
      }
  }


  uint64_t GetAndSaveBase(const char* module_name) {
    uint64_t bais = 0;
    const auto iter = base_map.find(module_name);
    if (iter == base_map.end()) {
      GumModule * mod = gum_process_find_module_by_name(module_name);
      if (mod) {
        bais = gum_module_get_range(mod)->base_address;
        all_log << "base:"<< module_name << "=" << ToHex(bais) << std::endl;
        base_map[module_name] = bais;
      }
    }else {
      bais = iter->second;
    }
    return bais;
  }

  static bool IsValid(const int input) {return input>=0;}

  bool SetTaintReg(const int reg, const uint64_t ref) {
      if (reg < 0) return false;
#if defined(__aarch64__)
      // for wzr(idx 32) : subs xzr, x0, x1
      // when keep flag but lost result
      if(reg == 32) return false;
#endif

    state.SetTaintReg(reg,ref);
    return true;
  }
  bool IsTaint(const int reg) {
    if (!IsValid(reg))return false;
    return state.IsTaintReg(reg);
  }
  void AddTaintMemory(const uint64_t addr, const uint64_t size){
    memory.InsertBySize(addr, size);
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
  void PrintRangeOp() {

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

  class RegAnalysis{
    public:
        RegAnalysis(TaintTrace* tracer){
            this->tracer = tracer;
        }
        TaintTrace* tracer;
        int Tr[4]={},Tw[4]={},Trw[2]={},Cr[4]={},Cw[4]={},Crw[2]={};
        int Tr_idx = -1,Tw_idx = -1,Trw_idx = -1,Cr_idx = -1,Cw_idx = -1,Crw_idx = -1;
        void reset(){
            Tr_idx = -1;
            Tw_idx = -1;
            Trw_idx = -1;
            Cr_idx = -1;
            Cw_idx = -1;
            Crw_idx = -1;
        }
        static bool IsValid(const int input) {return input>=0;}
        void SetReg(int reg,enum RegAccess access){
            if (!IsValid(reg)||reg >= (sizeof(QBDI::GPR_NAMES)/sizeof(QBDI::GPR_NAMES[0])))return;
          switch (access) {
              case READ:
                  if (tracer->IsTaint(reg)){
                      Tr[++Tr_idx] = reg;
                  } else {
                      Cr[++Cr_idx] = reg;
                  }
                  break;
              case WRITE:
                  if (tracer->IsTaint(reg)){
                      Tw[++Tw_idx] = reg;
                  } else {
                      Cw[++Cw_idx] = reg;
                  }
                  break;
              case READ_WRITE:
                  if (tracer->IsTaint(reg)){
                      Trw[++Trw_idx] = reg;
                  } else {
                      Crw[++Crw_idx] = reg;
                  }
                  break;
          }
        }
        void PrintReg(std::ofstream& log,const QBDI::GPRState *gpr,bool before){
            int Tr_idx=this->Tr_idx,Tw_idx=this->Tw_idx,Trw_idx=this->Trw_idx;
            int Cr_idx=this->Cr_idx,Cw_idx=this->Cw_idx,Crw_idx=this->Crw_idx;

            if (before) {
                while (IsValid(Tr_idx))
                    log << SPACE << tracer->TName(Tr[Tr_idx]) << EQ<< PRINT_GPR(Tr[Tr_idx--]) + SPACE;
                while (IsValid(Cr_idx))
                    log << SPACE << tracer->TName(Cr[Cr_idx]) << EQ<< PRINT_GPR(Cr[Cr_idx--]) + SPACE;
            }
            while (IsValid(Tw_idx))
                log << SPACE << tracer->TName(Tw[Tw_idx]) << EQ << PRINT_GPR(Tw[Tw_idx--]) + SPACE;
            while (IsValid(Cw_idx))
                log << SPACE << tracer->TName(Cw[Cw_idx]) << EQ << PRINT_GPR(Cw[Cw_idx--]) + SPACE;
            while (IsValid(Trw_idx))
                log << SPACE << tracer->TName(Trw[Trw_idx]) << EQ << PRINT_GPR(Trw[Trw_idx--]) + SPACE;
            while (IsValid(Crw_idx))
                log << SPACE << tracer->TName(Crw[Crw_idx]) << EQ << PRINT_GPR(Crw[Crw_idx--]) + SPACE;
        }

    };
    RegAnalysis anal = RegAnalysis(this);

};
#endif  // EZMYDROID_TAINTANALYZE_H
