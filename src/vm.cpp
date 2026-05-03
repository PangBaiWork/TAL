//
// Created by pangbai on 25-10-14.
//
#include "vm.h"

#include "taint_analyze.h"
#include "trace_utils.h"
#include "utils.h"

using namespace std;
using namespace QBDI;

VMAction memReadAccess(VM *vm, GPRState *gprState, FPRState *fprState,
                       void *data) {
    return CONTINUE;
}

VMAction memWriteAccess(VM *vm, GPRState *gprState, FPRState *fprState,
                        void *data) {
    return CONTINUE;
}

VMAction preInstruction(VM *vm, GPRState *gprState, FPRState *fprState,
                        void *data) {
    auto tracer = static_cast<Trace *>(data);
    tracer->InstTrace(vm, gprState, fprState);
    return CONTINUE;
}
VMAction postInstruction(VM *vm, GPRState *gprState, FPRState *fprState,
                         void *data) {
    auto tracer = static_cast<Trace *>(data);
    tracer->PostInstTrace(vm, gprState, fprState);
    return CONTINUE;
}
VMAction memWRAccess(VM *vm, GPRState *gprState, FPRState *fprState,
                     void *data) {
    auto tracer = static_cast<Trace *>(data);
    tracer->MemoryTrace(vm, gprState, fprState);
    return CONTINUE;
}
VMAction transferCall(VMInstanceRef vm, const VMState *state,
                      GPRState *gprState, FPRState *fprState, void *data) {
    auto tracer = static_cast<Trace *>(data);
    tracer->guest_stack.RestoreStack();
    return CONTINUE;
}

VMAction transferRet(VMInstanceRef vm, const VMState *state, GPRState *gprState,
                     FPRState *fprState, void *data) {
    auto tracer = static_cast<Trace *>(data);
    tracer->host_stack.RestoreStack();

    return CONTINUE;
}

std::shared_ptr<VM> init(void *address, Trace *tracer) {
    auto qvm = std::make_unique<VM>();
    qvm->addCodeCB(PREINST, preInstruction, tracer);
    qvm->addCodeCB(POSTINST, postInstruction, tracer, 10);
    qvm->addVMEventCB(EXEC_TRANSFER_CALL, transferCall, tracer);
    qvm->addVMEventCB(EXEC_TRANSFER_RETURN, transferRet, tracer);
    if (tracer->mode != TRITON_MODE) {
        qvm->addMemAccessCB(MEMORY_READ_WRITE, memWRAccess, tracer, -10);
    }

    if (tracer->trace_all) {
        qvm->instrumentAllExecutableMaps();
        for (const MemoryRange &range : tracer->avoid_range) {
            qvm->removeInstrumentedRange(range.min, range.max);
        }
    } else {
        qvm->addInstrumentedModuleFromAddr(reinterpret_cast<rword>(address));
    }

    removeConflictModule(*qvm);
    return qvm;
}

#ifdef QBDI_PLATFORM_WINDOWS

#include <shlwapi.h>

#include "QBDI/Memory.h"
void removeConflictModule(VM &vm) {
    size_t size;
    qbdi_MemoryMap *modules = qbdi_getCurrentProcessMaps(false, &size);
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
int tmp = 0;
void removeConflictModule(VM &vm) {
    size_t size;
    qbdi_MemoryMap *modules = qbdi_getCurrentProcessMaps(false, &size);
    for (size_t i = 0; i < size; i++) {
        LOGD("module:%s", modules[i].name);
        if (
            // (modules[i].permission & QBDI_PF_EXEC) &&
            (strstr(modules[i].name, "libc-2.") ||
             strstr(modules[i].name, "libc.so") ||
             strstr(modules[i].name, "libstdc++") ||
             strstr(modules[i].name, "ld-2.") ||
             strstr(modules[i].name, "ld-linux-") ||
             strstr(modules[i].name, "libpthread-") ||
             strstr(modules[i].name, "libcofi") || modules[i].name[0] == 0)) {
            LOGD("removeConflictModule: %s %llx %llx", modules[i].name,
                 modules[i].start, modules[i].end);
            vm.removeInstrumentedRange(modules[i].start, modules[i].end);
        }
    }


}

#endif

#ifdef QBDI_PLATFORM_ANDROID
#include "QBDI/Memory.h"
void removeConflictModule(VM &vm) {
    size_t size;
    qbdi_MemoryMap *modules = qbdi_getCurrentProcessMaps(false, &size);
    for (size_t i = 0; i < size; i++) {
        //    LOGD("module:%s",modules[i].name);
        if ((modules[i].permission & QBDI_PF_EXEC) &&
            (strstr(modules[i].name, "libart.so") ||
             strstr(modules[i].name, "libEGL.so") ||
             strstr(modules[i].name, "linker") ||
             strstr(modules[i].name, "libart-compiler.so") ||
             strstr(modules[i].name, "libnativehelper.so") ||
             strstr(modules[i].name, "libandroid_runtime.so") ||
             strstr(modules[i].name, "libbinder.so") ||
             strstr(modules[i].name, "libc++.so") ||
             strstr(modules[i].name, "libc.so") ||
             strstr(modules[i].name, "liblog.so") ||
             strstr(modules[i].name, "libGLESv1_CM.so") ||
             modules[i].name[0] == 0)) {
            LOGD("removeConflictModule: %s", modules[i].name);
            vm.removeInstrumentedRange(modules[i].start, modules[i].end);
        }
    }
}
#endif
