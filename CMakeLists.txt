


cmake_minimum_required(VERSION 3.22.1)


set(QBDI_ARCH "X86_64")
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

#set(QBDI_LOG_DEBUG ON)
set(CMAKE_BUILD_PARALLEL_LEVEL 8)
set(CMAKE_BUILD_TYPE Release)
set(TARGET_NAME "tal")
project(${TARGET_NAME})

if(CMAKE_HOST_SYSTEM_NAME MATCHES "Linux")
    set(QBDI_PLATFORM "linux")
    message("current platform: Linux ")
    # 在项目最顶层，所有 add_subdirectory / FetchContent 之前设置
    set(CMAKE_POSITION_INDEPENDENT_CODE ON CACHE BOOL "" FORCE)

    # 强制全局 fPIC（兜底）

    set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS} -fPIC")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")

    if (CMAKE_BUILD_TYPE MATCHES "Release")
        

    set(CMAKE_C_FLAGS_RELEASE "-Os")
    set(CMAKE_CXX_FLAGS_RELEASE "-Os")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ffunction-sections -fdata-sections -fvisibility=hidden -fno-asynchronous-unwind-tables -fno-unwind-tables")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -ffunction-sections -fdata-sections -fvisibility=hidden -fno-asynchronous-unwind-tables -fno-unwind-tables")

    add_link_options(
            -Wl,--gc-sections
            -Wl,--strip-all
            -flto=auto
    )
    endif ()

elseif(CMAKE_HOST_SYSTEM_NAME MATCHES "Windows")
    set(QBDI_PLATFORM "windows")
    message("current platform: Windows ")
    enable_language(ASM)
    enable_language(ASM_MASM)
else()
    message("current platform: unkonw ")
endif()

if(ANDROID OR CMAKE_SYSTEM_NAME STREQUAL "Android")
    if(NOT ANDROID_NDK)
        message(FATAL_ERROR "ANDROID_NDK is not set")
    endif()
    set(QBDI_PLATFORM "android")
    message("current platform: android ")
    set(CMAKE_CROSSCOMPILING TRUE)
    set(QBDI_ARCH "AARCH64")

    message(STATUS "NDK version: ${ANDROID_NDK_VERSION}")
    message(STATUS "Android API level: ${ANDROID_PLATFORM}")
endif()



if(CMAKE_BUILD_TYPE STREQUAL "Release")
    set(CMAKE_C_VISIBILITY_PRESET hidden)
    set(CMAKE_CXX_VISIBILITY_PRESET hidden)
    set(CMAKE_VISIBILITY_INLINES_HIDDEN ON)
endif()


include_directories(
        ${CMAKE_CURRENT_SOURCE_DIR}/include/
        ${CMAKE_CURRENT_SOURCE_DIR}/third_party/${QBDI_PLATFORM}/frida
        ${CMAKE_CURRENT_SOURCE_DIR}/boost-1.90.0/libs/context/include
        ${CMAKE_CURRENT_SOURCE_DIR}/qbdi-src/src
        #        ${CMAKE_CURRENT_SOURCE_DIR}/third_party/${QBDI_PLATFORM}
)
set(Boost_USE_STATIC_LIBS ON) # 使用静态库
set(BOOST_INCLUDE_LIBRARIES context multiprecision)
add_subdirectory(boost-1.90.0)


set(Z3_INTERFACE OFF)
set(BOOST_INTERFACE OFF)

add_subdirectory(Triton)


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
    set(CMAKE_CXX_FLAGS_RELEASE "-flto -fomit-frame-pointer -funroll-loops -fno-stack-protector")
endif()


add_compile_definitions(ULTRA_FAST_MODE=1)

add_subdirectory(qbdi-src)




set(HOME ${PROJECT_SOURCE_DIR})
include_directories(
        ${CMAKE_CURRENT_SOURCE_DIR}/Triton/src/libtriton/includes
)

FILE(GLOB_RECURSE FILE_SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/src/*.c*
)

message("Variable value: ${FILE_SOURCES}")

add_library(${TARGET_NAME} SHARED
        ${FILE_SOURCES}
        library.cpp
)
#target_compile_options(${TARGET_NAME} PRIVATE -mstackrealign)
add_library(${TARGET_NAME}_static STATIC
        ${FILE_SOURCES}
        library.cpp
)



if(QBDI_PLATFORM STREQUAL "windows")
    add_compile_definitions(_HAS_STD_BYTE=0)
endif ()

add_library(frida-gum STATIC IMPORTED)
set_target_properties(frida-gum PROPERTIES IMPORTED_LOCATION
        ${CMAKE_CURRENT_SOURCE_DIR}/libs/frida-gum/${QBDI_PLATFORM}/${FRIDA_LIB})





target_link_options(${TARGET_NAME} PRIVATE -Wl,--exclude-libs=ALL -Wall -Wextra)

target_link_libraries(${TARGET_NAME}_static

        frida-gum
        qbdi-llvm
        QBDI_static
        Boost::context
        triton
)

target_link_libraries(${TARGET_NAME}
        frida-gum
        qbdi-llvm
        QBDI_static
        Boost::context
        triton
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
add_custom_command(TARGET ${TARGET_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_CURRENT_SOURCE_DIR}/${CMAKE_BUILD_TYPE}/${QBDI_PLATFORM}"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "$<TARGET_FILE:${TARGET_NAME}>"
        "${CMAKE_CURRENT_SOURCE_DIR}/${CMAKE_BUILD_TYPE}/${QBDI_PLATFORM}/$<TARGET_FILE_NAME:${TARGET_NAME}>"
        VERBATIM
)