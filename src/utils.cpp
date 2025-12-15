//
// Created by pangbai on 25-10-14.
//

#include "utils.h"
std::string ToHex(uint64_t value) {
    char buff[32];
    sprintf(buff, "0x%llx", value);
    return buff;
}

inline std::string ByteToHex(unsigned char byte) {
    std::stringstream ss;
    ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<uint8_t>(byte);
    return ss.str();
}

std::string ReadMemToHex(const void *ptr, size_t length) {
    std::string hexString;
    const auto *bytePtr = static_cast<const unsigned char *>(ptr);
    for (size_t i = 0; i < length; ++i) {
        hexString += ByteToHex(bytePtr[i]);
    }
    return hexString;
}




int GetSameStrLen(const char *str1, const char *str2) {
    int count = 0;
    while (*str1 && *str2 && *str1 == *str2) {
        count++;
        str1++;
        str2++;
    }
    return count;
}