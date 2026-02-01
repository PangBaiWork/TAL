//
// Created by pangbai on 25-10-14.
//

#include "vm.h"



#include <cassert>
#include <iostream>
#include <sstream>

#include "QBDI.h"
#include "frida-gum.h"
#include "library.h"
#include "taint_analyze.h"
#include "taint_utils.h"
#include "utils.h"

using namespace std;
using namespace QBDI;



void removeConflictModule(VM& vm);

VMAction postInstruction(VM *vm, GPRState *gprState, FPRState *fprState, void *data) {
    auto extend_data = static_cast<extends *>(data);
    if (extend_data->enableTaint()) {
      auto taint_trace=extend_data->taintTrace;
      taint_trace->PostInstTrace(vm, gprState, fprState);
    }


    return CONTINUE;
}

inline void memReadAnalyze(const vector<MemoryAccess> &memAccVector,extends* extends) {

}

inline void memWriteAnalyze(const vector<MemoryAccess> &memAccVector,extends* extends) {


}

VMAction memReadAccess(VM *vm, GPRState *gprState, FPRState *fprState, void *data) {
    auto extend_data = (extends *) data;
    vector<MemoryAccess> memAccVector = vm->getInstMemoryAccess();
    // memReadAnalyze(memAccVector,extend_data);
    return CONTINUE;

}

VMAction memWriteAccess(VM *vm, GPRState *gprState, FPRState *fprState, void *data) {
    auto extend_data = (extends *) data;
    vector<MemoryAccess> memAccVector = vm->getInstMemoryAccess();
    memWriteAnalyze(memAccVector,extend_data);
    return CONTINUE;
}



VMAction preInstruction(VM *vm, GPRState *gprState, FPRState *fprState, void *data) {
    auto extend_data = (extends *) data;

    if (extend_data->enableTaint())
        return  extend_data->taintTrace->InstTrace(vm,gprState,fprState);
    return CONTINUE;
}

VMAction memWRAccess(VM *vm, GPRState *gprState, FPRState *fprState, void *data) {
    auto extend_data = (extends *) data;
    if (extend_data->enableTaint())
        extend_data->taintTrace->MemoryTrace(vm,gprState,fprState);
    return CONTINUE;
}


std::shared_ptr<VM> init(void *address,TaintTrace *tracer) {
    auto qvm = std::make_unique<VM>();
    auto *data = new extends(tracer);
    if (!tracer->IsTraceMode())
    {
        qvm->addMemAccessCB(MEMORY_READ_WRITE,memWRAccess,data);
    }

    qvm->addCodeCB(POSTINST, postInstruction, data);
    qvm->addCodeCB(PREINST, preInstruction, data);


    if (tracer->trace_all){
        qvm->instrumentAllExecutableMaps();
        for (const MemoryRange & range : tracer->avoid_range) {
            qvm->removeInstrumentedRange(range.min,range.max);
        }
    }else {
        qvm->addInstrumentedModuleFromAddr(reinterpret_cast<rword>(address));
    }
    for (const MemoryRange & range : tracer->escape_execute) {
        // todo asm size 4 is not always correct
        qvm->removeInstrumentedRange(range.min,range.min+4);
    }

     removeConflictModule(*qvm);


    return qvm;
}

#ifdef  QBDI_PLATFORM_WINDOWS

#include <shlwapi.h>
#include <tlhelp32.h>
#include "QBDI/Memory.h"
void removeConflictModule(VM& vm) {
  size_t size;
  qbdi_MemoryMap *modules=qbdi_getCurrentProcessMaps(false, &size);
  for (size_t i = 0; i < size; i++) {
    if ((modules[i].permission & QBDI_PF_EXEC) &&
        (StrStrIA(modules[i].name, "advapi") ||
         StrStrIA(modules[i].name, "combase") ||
         StrStrIA(modules[i].name, "comctl32") ||
         StrStrIA(modules[i].name, "comdlg") ||
         StrStrIA(modules[i].name, "gdi32") ||
         StrStrIA(modules[i].name, "gdiplus") ||
         StrStrIA(modules[i].name, "imm32") ||
         StrStrIA(modules[i].name, "kernel") ||
         StrStrIA(modules[i].name, "msvcp") ||
         StrStrIA(modules[i].name, "msvcrt") ||
         StrStrIA(modules[i].name, "ntdll") ||
         StrStrIA(modules[i].name, "ole32") ||
         StrStrIA(modules[i].name, "oleaut") ||
         StrStrIA(modules[i].name, "rpcrt") ||
         StrStrIA(modules[i].name, "sechost") ||
         StrStrIA(modules[i].name, "shcore") ||
         StrStrIA(modules[i].name, "shell32") ||
         StrStrIA(modules[i].name, "shlwapi") ||
         StrStrIA(modules[i].name, "ucrtbase") ||
         StrStrIA(modules[i].name, "user32") ||
         StrStrIA(modules[i].name, "uxtheme") ||
         StrStrIA(modules[i].name, "vcruntime") ||
         StrStrIA(modules[i].name, "win32u") || modules[i].name[0] == 0)) {
         vm.removeInstrumentedRange(modules[i].start, modules[i].end);
         }
  }
}

#endif

#ifdef QBDI_PLATFORM_LINUX
#include "QBDI/Memory.h"
int tmp=0;
void removeConflictModule(VM& vm) {
  size_t size;
  qbdi_MemoryMap *modules=qbdi_getCurrentProcessMaps(false, &size);
  for (size_t i = 0; i < size; i++) {
    LOGD("module:%s",modules[i].name);
    if (
      // (modules[i].permission & QBDI_PF_EXEC) &&
        (strstr(modules[i].name, "libc-2.")     ||
         strstr(modules[i].name, "libc.so")    ||
         strstr(modules[i].name, "libstdc++")   ||
         strstr(modules[i].name, "ld-2.")       ||
         strstr(modules[i].name, "ld-linux-")   ||
         strstr(modules[i].name, "libpthread-") ||
         strstr(modules[i].name, "libcofi") || modules[i].name[0] == 0)) {

            LOGD("removeConflictModule: %s %llx %llx",modules[i].name,modules[i].start,modules[i].end);
            vm.removeInstrumentedRange(modules[i].start, modules[i].end);
         }
  }
}


#endif

#ifdef QBDI_PLATFORM_ANDROID
#include "QBDI/Memory.h"
void removeConflictModule(VM& vm) {
  size_t size;
  qbdi_MemoryMap *modules=qbdi_getCurrentProcessMaps(false, &size);
  for (size_t i = 0; i < size; i++) {

//    LOGD("module:%s",modules[i].name);
    if ((modules[i].permission & QBDI_PF_EXEC) &&
        (strstr(modules[i].name, "libart.so")       ||
         strstr(modules[i].name, "libEGL.so")       ||
         strstr(modules[i].name, "libc++.so")        ||
         strstr(modules[i].name, "libc.so")        ||
         strstr(modules[i].name, "liblog.so")        ||
         strstr(modules[i].name, "libGLESv1_CM.so") ||modules[i].name[0] == 0)) {
            LOGD("removeConflictModule: %s",modules[i].name);
            vm.removeInstrumentedRange(modules[i].start, modules[i].end);
         }
  }
}
#endif





