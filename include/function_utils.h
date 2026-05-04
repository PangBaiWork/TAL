//
// Created by pangb on 26-5-3.
//

#ifndef FUNCTION_UTILS_H
#define FUNCTION_UTILS_H
#include "trace.h"
void PrintFunctionArgs(std::ostream& os,
                              QBDI::GPRState* gpr,
                              const std::string& raw_symbol_name);
#endif //FUNCTION_UTILS_H
