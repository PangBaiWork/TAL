


cmake_minimum_required(VERSION 3.22.1)

# Setting Android Build
#set(CMAKE_SYSTEM_NAME ANDROID)

if(CMAKE_HOST_SYSTEM_NAME MATCHES "Linux")
    set(QBDI_PLATFORM "linux")
    message("current platform: Linux ")

elseif(CMAKE_HOST_SYSTEM_NAME MATCHES "Windows")
    set(QBDI_PLATFORM "windows")
    message("current platform: Windows ")
else()
    message("current platform: unkonw ")
endif()



set(QBDI_LOG_DEBUG ON)
set(QBDI_ARCH "X86_64")
set(CMAKE_BUILD_PARALLEL_LEVEL 8)
set(CMAKE_BUILD_TYPE Debug)
set(TARGET_NAME "attd")

if(QBDI_PLATFORM STREQUAL "windows")
    message(STATUS "Windows")
    add_compile_options("$<$<C_COMPILER_ID:MSVC>:/utf-8>")
    add_compile_options("$<$<CXX_COMPILER_ID:MSVC>:/utf-8>")

    set(FRIDA_LIB "frida-gum.lib")
    set(QBDI_LIB "QBDI_static.lib")
    set(CMAKE_CROSSCOMPILING "FALSE")


    # set(CMAKE_CXX_FLAGS_RELEASE " -DNDEBUG")
    # windows 并行编译选项

    cmake_host_system_information(RESULT CPU_NUMBER_OF_LOGICAL_CORES QUERY NUMBER_OF_LOGICAL_CORES)
    add_compile_options($<$<CXX_COMPILER_ID:MSVC>:/MP${CPU_NUMBER_OF_LOGICAL_CORES}>)
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /Z7")
    set(CMAKE_SHARED_LINKER_FLAGS_DEBUG "${CMAKE_SHARED_LINKER_FLAGS_DEBUG} /DEBUG:FULL")

else(QBDI_PLATFORM STREQUAL "linux" OR QBDI_PLATFORM STREQUAL "android")
    message(STATUS "Linux or Android")
    set(FRIDA_LIB "libfrida-gum.a")
    set(QBDI_LIB "libQBDI.a")
    set(CMAKE_CROSSCOMPILING "FALSE")

    set(CMAKE_CXX_FLAGS_RELEASE " -DNDEBUG -ffast-math -flto -fomit-frame-pointer -funroll-loops -fno-stack-protector")

endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 优化编译选项
#set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG -ffast-math -flto -fomit-frame-pointer -funroll-loops -fno-stack-protector")

add_compile_definitions(ULTRA_FAST_MODE=1)
#add_library(QBDI_static STATIC IMPORTED)
#set_target_properties(QBDI_static PROPERTIES IMPORTED_LOCATION
#        ${CMAKE_CURRENT_SOURCE_DIR}/cmake-build-visualstudio/qbdi-src/QBDI/${QBDI_LIB})


add_subdirectory(qbdi-src)


project(TARGET_NAME)
set(HOME ${PROJECT_SOURCE_DIR})
include_directories(
        ${CMAKE_CURRENT_SOURCE_DIR}/include/
        ${CMAKE_CURRENT_SOURCE_DIR}/third_party/${QBDI_PLATFORM}/frida
#        ${CMAKE_CURRENT_SOURCE_DIR}/third_party/${QBDI_PLATFORM}
)

FILE(GLOB_RECURSE FILE_SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/src/*.c*
)

message("Variable value: ${FILE_SOURCES}")

add_library(${TARGET_NAME} SHARED
        ${FILE_SOURCES}
        library.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/fs_gs_x64_msvc.asm
)
#target_compile_options(${TARGET_NAME} PRIVATE -mstackrealign)
add_library(${TARGET_NAME}_static STATIC
        ${FILE_SOURCES}
        library.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/fs_gs_x64_msvc.asm
)



if(QBDI_PLATFORM STREQUAL "windows")
    add_compile_definitions(_HAS_STD_BYTE=0)
    enable_language(ASM_MASM)
endif ()

add_library(frida-gum STATIC IMPORTED)
set_target_properties(frida-gum PROPERTIES IMPORTED_LOCATION
        ${CMAKE_CURRENT_SOURCE_DIR}/libs/frida-gum/${QBDI_PLATFORM}/${FRIDA_LIB})



if(NOT QBDI_PLATFORM STREQUAL "windows")
    set(CMAKE_BUILD_TYPE Debug)
endif ()
set(CMAKE_BUILD_TYPE Debug)
#set(CMAKE_BUILD_TYPE "RELEASE")

#set(CMAKE_CXX_VISIBILITY_PRESET hidden)
#set(CMAKE_C_VISIBILITY_PRESET hidden)

## 关闭C++特性
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-inline")
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-exceptions")
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti")
#
#set(CMAKE_C_FLAGS_RELEASE     "${CMAKE_C_FLAGS_RELEASE}   -fvisibility=hidden")
#set(CMAKE_CXX_FLAGS_RELEASE   "${CMAKE_CXX_FLAGS_RELEASE} -fvisibility=hidden")
## 删除调试符号
#set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -s")
#set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -s")
## 开启空间优化
#set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -Os")
#set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -Os")

target_link_options(${TARGET_NAME} PRIVATE -Wl,--exclude-libs=ALL -Wall -Wextra)

target_link_libraries(${TARGET_NAME}_static

        frida-gum
        QBDI_static
)

target_link_libraries(${TARGET_NAME}

        frida-gum
        QBDI_static
)

add_executable(${TARGET_NAME}_test
        ${FILE_SOURCES}
        test/test.cpp
)
if(QBDI_PLATFORM STREQUAL "windows")
    target_link_libraries(${TARGET_NAME}_test
            ntdll.lib
    )
    target_link_libraries(${TARGET_NAME}
            ntdll.lib
    )
endif ()


target_link_libraries(${TARGET_NAME}_test
        ${TARGET_NAME}_static
)
