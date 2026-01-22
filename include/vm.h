//
// Created by fang on 23-12-19.
//

#ifndef QBDIRECORDER_VM_H
#define QBDIRECORDER_VM_H

#include "QBDI.h"
#include "taint_analyze.h"

#define STACK_SIZE  0x100000

struct extends {
    int depth;
    bool isFirstRecord;
    QBDI::GPRState *gprState;
    std::string memRecord;
    std::string callTarget;
    int memAccessCount;
    TaintTrace *taintTrace;

    bool enableTaint(){
        return taintTrace != nullptr;
    }
    extends(TaintTrace *taintTrace) {
        depth = 0;
        isFirstRecord = true;
        gprState = new QBDI::GPRState();
        memAccessCount = 0;
        this->taintTrace = taintTrace;;
    }
    extends() {
        depth = 0;
        isFirstRecord = true;
        gprState = new QBDI::GPRState();
        memAccessCount = 0;
        taintTrace = nullptr;;
    }
    
    // 析构函数
    ~extends() {
        delete gprState;
    }
};



 QBDI::VM init(void *address,TaintTrace *tracer);


#endif //QBDIRECORDER_VM_H

