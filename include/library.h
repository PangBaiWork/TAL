//
// Created by pangbai on 25-10-14.
//

#ifndef LIBRARY_H
#define LIBRARY_H
#include "utils.h"

#include <cstdint>


C_EXPORT void taint_trace(uint64_t addr, bool all,
                                    uint64_t taint_addr, int taint_size,
                                    int mode);
C_EXPORT void taint_trace_str(uint64_t addr,bool all,char *taint_str,int mode);

C_EXPORT void trace(uint64_t addr, uint64_t end, bool all,
                    int mode) ;
C_EXPORT bool remove_range(uint64_t start, uint64_t size);
C_EXPORT bool add_taint_range(uint64_t addr, uint64_t size);
#endif // LIBRARY_H
