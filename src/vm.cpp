//
// Created by pangbai on 25-10-14.
//



#include <iostream>
#include "frida-gum.h"
#include <cassert>
#include <sstream>
#include "QBDI.h"
#include "vm.h"
#include "utils.h"

#include "taintAnalyze.h"
#include "taintUtils.h"


using namespace std;
using namespace QBDI;




QBDI::VMAction postInstruction(QBDI::VM *vm, QBDI::GPRState *gprState, QBDI::FPRState *fprState, void *data) {
    auto extend_data = (extends *) data;
    extend_data->taintTrace->postInstTrace(vm, gprState, fprState);

    return QBDI::VMAction::CONTINUE;
}

inline void memReadAnalyze(const vector<QBDI::MemoryAccess> &memAccVector,extends* extends) {

}

inline void memWriteAnalyze(const vector<QBDI::MemoryAccess> &memAccVector,extends* extends) {


}

QBDI::VMAction memReadAccess(QBDI::VM *vm, QBDI::GPRState *gprState, QBDI::FPRState *fprState, void *data) {
    auto extend_data = (extends *) data;
    vector<QBDI::MemoryAccess> memAccVector = vm->getInstMemoryAccess();
    // memReadAnalyze(memAccVector,extend_data);
    return QBDI::VMAction::CONTINUE;

}

QBDI::VMAction memWriteAccess(QBDI::VM *vm, QBDI::GPRState *gprState, QBDI::FPRState *fprState, void *data) {
    auto extend_data = (extends *) data;
    vector<QBDI::MemoryAccess> memAccVector = vm->getInstMemoryAccess();
    memWriteAnalyze(memAccVector,extend_data);
    return QBDI::VMAction::CONTINUE;
}


// void settingRecordName(void *address) {
//
//     char *private_path = "";
//     std::string path = private_path;
//     path.append("attd/");
//
//     // 如果文件夹存在，删除它
//     char *record_path = const_cast<char *>(path.c_str());
//     if (access(record_path, F_OK) != -1) {
//         system((std::string("rm -rf ") + path).c_str());
//     }
//     g_mkdir_with_parents(path.c_str(), 00777);
//
//     path.append("record");
// //    path.append(std::to_string(tid));
//     Dl_info info;
//     stringstream ss;
//     if (dladdr(address, &info)) {
//         ss << "_";
//         ss << std::hex << (uint64_t) info.dli_fbase; // base
//         ss << "_";
//         ss << std::hex << (uint64_t) address - (uint64_t) info.dli_fbase; // offset
//     }
// //    path.append(ss.str());
//     path.append(".txt");
//     LOGD("trace path:%s",path.c_str());
//
//     RecorderManager::getInstance().initialize(RecorderType::TEXT,path.c_str());
// }




QBDI::VMAction preInstruction(QBDI::VM *vm, QBDI::GPRState *gprState, QBDI::FPRState *fprState, void *data) {
    auto extend_data = (extends *) data;

    if (extend_data->enableTaint())
        return  extend_data->taintTrace->instTrace(vm,gprState,fprState);
    return QBDI::VMAction::CONTINUE;
}

QBDI::VMAction memWRAccess(QBDI::VM *vm, QBDI::GPRState *gprState, QBDI::FPRState *fprState, void *data) {
    auto extend_data = (extends *) data;
    if (extend_data->enableTaint())
        extend_data->taintTrace->memoryTrace(vm,gprState,fprState);
    return QBDI::VMAction::CONTINUE;
}


QBDI::VM init(void *address, uint64_t trace_all,TaintTrace *taint_trace,PRINT_MODE* printMode) {
    QBDI::VM qvm{};
    extends *data;

    if (taint_trace) {
        data = new extends(taint_trace);
    } else {
        data = new extends();
    }
    LOGD("init %p %p", data, data->gprState);

    qvm.recordMemoryAccess(QBDI::MEMORY_READ_WRITE);
    // qvm.addMemAccessCB(MemoryAccessType::MEMORY_READ, memReadAccess, data);
    // qvm.addMemAccessCB(MemoryAccessType::MEMORY_WRITE, memWriteAccess, data);
    qvm.addCodeCB(QBDI::POSTINST, postInstruction, data);
    //add
    qvm.addCodeCB(QBDI::PREINST,preInstruction,data);
    qvm.addMemAccessCB(QBDI::MEMORY_READ_WRITE,memWRAccess,data);


    if (trace_all){
        qvm.instrumentAllExecutableMaps();
        // qvm.enableBlackListMode();
    }else {
        qvm.addInstrumentedModuleFromAddr(reinterpret_cast<QBDI::rword>(address));
    }

    bool result = qvm.removeInstrumentedModule("libc.so.6");
    LOGD("result1 %d",result);
    result = qvm.removeInstrumentedModule("libstdc++.so.6.0.34");
    LOGD("result2 %d",result);
    result = qvm.removeInstrumentedModule("libdl.so.2");
    LOGD("result3 %d",result);
    result = qvm.removeInstrumentedModule("libgcc_s.so.1");
    LOGD("result4 %d",result);
    result = qvm.removeInstrumentedModule("libpthread.so.0");
    LOGD("result5 %d",result);
    result = qvm.removeInstrumentedModule("libdl.so.2");
    LOGD("result6 %d",result);
    result = qvm.removeInstrumentedModule("ld-linux-x86-64.so.2");
    LOGD("result7 %d",result);
    result = qvm.removeInstrumentedModule("ntdll.dll");
    LOGD("result7 %d",result);


    qvm.removeInstrumentedModule("libartbase.so");

    qvm.removeInstrumentedModule("libc++.so");

    qvm.removeInstrumentedModule("libart.so");



    qvm.removeInstrumentedModule("libEGL.so");
    qvm.removeInstrumentedModule("libGLESv1_CM.so");

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








