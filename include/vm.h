//
// Created by fang on 23-12-19.
//

#ifndef QBDIRECORDER_VM_H
#define QBDIRECORDER_VM_H

#include "QBDI.h"
#include "taint_analyze.h"


#define STACK_SIZE  0x100000

std::shared_ptr<QBDI::VM>init(void *address,Trace *tracer);
void removeConflictModule(QBDI::VM& vm);



#endif //QBDIRECORDER_VM_H

