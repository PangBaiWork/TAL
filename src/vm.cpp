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


VM init(void *address, uint64_t trace_all,TaintTrace *taint_trace,vector<MemoryRange> avoid_range) {
    VM qvm{};
    extends *data;

    if (taint_trace) {
        data = new extends(taint_trace);
        if (!taint_trace->IsTraceMode())
        {
          qvm.addMemAccessCB(MEMORY_READ_WRITE,memWRAccess,data);
        }
    } else {
        data = new extends();
    }


    qvm.addCodeCB(POSTINST, postInstruction, data);
    qvm.addCodeCB(PREINST,preInstruction,data);


    if (trace_all){
        qvm.instrumentAllExecutableMaps();
        for (MemoryRange range : avoid_range) {
          qvm.removeInstrumentedRange(range.min,range.max);
        }
        // qvm.setInstrumentationMode(InstrumentationMode::Blacklist);
        // qvm.addInstrumentedRange((rword) free, (rword) free + 8);
        // qvm.addInstrumentedRange((rword) malloc, (rword) malloc + 8);
        // qvm.addInstrumentedRange((rword) realloc, (rword) realloc + 8);
        // qvm.addInstrumentedRange((rword) calloc, (rword) calloc + 8);
        // qvm.addInstrumentedRange((rword) memset, (rword) memset + 8);
        // return qvm;

        // qvm.enableBlackListMode();
    }else {
        qvm.addInstrumentedModuleFromAddr(reinterpret_cast<rword>(address));
    }
    std::string module_name[] ={
        "libc.so.6",
        "libstdc++.so.6.0.34",
        "libdl.so.2",
        "libgcc_s.so.1",
        "libpthread.so.0",
        "libdl.so.2",
        "ld-linux-x86-64.so.2",
        "ntdll.dll",
        "libartbase.so",
        "libc++.so",
        "libart.so",
        "libEGL.so",
        "libGLESv1_CM.so",
           "USER32.dll",
      "user32.dll",
      "KERNEL32.dll",
      "kernel32.dll",
    };
    for (const auto& name : module_name) {
        bool result = qvm.removeInstrumentedModule(name);
        LOGD("remove %s result %d",name.c_str(),result);
    }

#ifndef  QBDI_PLATFORM_WINDOWS
    // This is not MSVC compiler
    qvm.removeInstrumentedRange((rword) pthread_mutex_init, (rword) pthread_mutex_init + 8);

    qvm.removeInstrumentedRange((rword) pthread_mutex_lock, (rword) pthread_mutex_lock + 8);
    qvm.removeInstrumentedRange((rword) pthread_mutex_unlock, (rword) pthread_mutex_unlock + 8);
    qvm.removeInstrumentedRange((rword) pthread_getspecific, (rword) pthread_getspecific + 8);
    qvm.removeInstrumentedRange((rword) pthread_atfork, (rword) pthread_atfork + 8);
    qvm.removeInstrumentedRange((rword) pthread_create, (rword) pthread_create + 8);
#endif
    qvm.removeInstrumentedRange((rword) free, (rword) free + 8);
    qvm.removeInstrumentedRange((rword) malloc, (rword) malloc + 8);
    qvm.removeInstrumentedRange((rword) realloc, (rword) realloc + 8);
    qvm.removeInstrumentedRange((rword) calloc, (rword) calloc + 8);
    qvm.removeInstrumentedRange((rword) memset, (rword) memset + 8);



    return qvm;
}








