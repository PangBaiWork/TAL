//
// Created by pangb on 26-2-23.
//

#ifndef STR_FORMAT_H
#define STR_FORMAT_H

#define STR_ALIGN 42
#define UNKNOWN_CONST 0xdeadbeef
#define TAB "\t"
#define SPLIT "|"
#define ENTER "\n"
#define SPACE " "
#define EQ "="
#define MOV (TAB "mov ")
#define BLANK ""
// std::endl


#define PRINT_OFFSET(OFFSET) ToHex(OFFSET) << ":"
#define PRINT_ADDR(VALUE)  "[" << ToHex(VALUE) << "]"
#define PRINT_SIZE(SIZE)  " <" << ToHex(SIZE) << "> "
#define PRINT_DATA(VALUE,SIZE) "(" << DataToHex(VALUE,SIZE) << ")"


#endif //STR_FORMAT_H
