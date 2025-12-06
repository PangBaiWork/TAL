//
// Created by pangbai on 25-10-14.
//

#ifndef LIBRARY_H
#define LIBRARY_H
#include "utils.h"

#include "stdint.h"

VISIBILITY_DEFAULT void attd(void *target_addr);
VISIBILITY_DEFAULT void attd_trace(void *addr, bool trace_all);
VISIBILITY_DEFAULT void taint_trace(void *addr, bool trace_all,
                                    uint64_t taintAddr, int taintSize,
                                    int traceMode);

VISIBILITY_DEFAULT void attd_call(void *target_addr);
VISIBILITY_DEFAULT void taint_trace_str(void *addr, bool trace_all,
                                        char *taint_str, int printMode);

#endif // LIBRARY_H
