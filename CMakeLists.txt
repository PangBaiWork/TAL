cmake_minimum_required(VERSION 3.22.1)

project(tal LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

option(TAL_BUILD_TESTS "Build tal test executable on desktop platforms" ON)
option(TAL_ENABLE_LTO "Enable link-time optimization for tal release builds" OFF)
option(TAL_STRIP_RELEASE "Strip tal release binaries after linking on ELF/Mach-O targets" ON)

set(BUILD_TESTING OFF CACHE BOOL "Disable dependency tests" FORCE)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build vendored dependencies as static libraries" FORCE)

if(CMAKE_SYSTEM_NAME STREQUAL "Android" OR ANDROID)
    set(TAL_PLATFORM "android")
    set(TAL_PLATFORM_DEFINITION "TAL_PLATFORM_ANDROID=1")
    set(QBDI_PLATFORM "android")
    set(QBDI_ARCH "AARCH64")
elseif(WIN32)
    set(TAL_PLATFORM "windows")
    set(TAL_PLATFORM_DEFINITION "TAL_PLATFORM_WINDOWS=1")
    set(QBDI_PLATFORM "windows")
    set(QBDI_ARCH "X86_64")
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(TAL_PLATFORM "linux")
    set(TAL_PLATFORM_DEFINITION "TAL_PLATFORM_LINUX=1")
    set(QBDI_PLATFORM "linux")
    set(QBDI_ARCH "X86_64")
else()
    message(FATAL_ERROR "Unsupported target platform: ${CMAKE_SYSTEM_NAME}")
endif()

message(STATUS "tal target platform: ${TAL_PLATFORM}")
message(STATUS "QBDI target: ${QBDI_PLATFORM}/${QBDI_ARCH}")

if(MSVC)
    cmake_host_system_information(RESULT TAL_CPU_COUNT QUERY NUMBER_OF_LOGICAL_CORES)
endif()

enable_language(ASM)
if(WIN32)
    enable_language(ASM_MASM)
endif()

if(TAL_PLATFORM STREQUAL "windows")
    set(FRIDA_LIB_NAME "frida-gum.lib")
else()
    set(FRIDA_LIB_NAME "libfrida-gum.a")
endif()

set(TAL_FRIDA_GUM_LIBRARY
        "${CMAKE_CURRENT_SOURCE_DIR}/libs/frida-gum/${TAL_PLATFORM}/${FRIDA_LIB_NAME}"
        CACHE FILEPATH "Path to platform frida-gum static library")

if(NOT EXISTS "${TAL_FRIDA_GUM_LIBRARY}")
    message(FATAL_ERROR "frida-gum library not found: ${TAL_FRIDA_GUM_LIBRARY}")
endif()

add_library(frida-gum STATIC IMPORTED GLOBAL)
set_target_properties(frida-gum PROPERTIES
        IMPORTED_LOCATION "${TAL_FRIDA_GUM_LIBRARY}")

set(TAL_BOOST_ROOT
        "${CMAKE_CURRENT_SOURCE_DIR}/third_party/boost-lite"
        CACHE PATH "Path to the Boost source tree used by tal")
add_subdirectory("${TAL_BOOST_ROOT}" "${CMAKE_CURRENT_BINARY_DIR}/boost-lite")

set(BUILD_EXAMPLES OFF CACHE BOOL "Disable Triton examples" FORCE)
set(ENABLE_TEST OFF CACHE BOOL "Disable Triton tests" FORCE)
set(PYTHON_BINDINGS OFF CACHE BOOL "Disable Triton Python bindings" FORCE)
set(PYTHON_BINDINGS_AUTOCOMPLETE OFF CACHE BOOL "Disable Triton autocomplete generation" FORCE)
set(Z3_INTERFACE OFF CACHE BOOL "Disable Triton Z3 interface" FORCE)
set(BOOST_INTERFACE OFF CACHE BOOL "Disable Triton Boost interface" FORCE)

set(CAPSTONE_INCLUDE_DIRS
        "${CMAKE_CURRENT_SOURCE_DIR}/third_party/frida-capstone"
        CACHE PATH "Frida-bundled Capstone compatibility include directory for Triton" FORCE)
set(CAPSTONE_LIBRARIES frida-gum CACHE STRING "Frida-gum provides Capstone symbols for Triton" FORCE)
set(CAPSTONE_VERSION_HEADER
        "${CMAKE_CURRENT_SOURCE_DIR}/third_party/${TAL_PLATFORM}/frida/frida-gum.h"
        CACHE FILEPATH "Frida-bundled Capstone version header for Triton" FORCE)

add_subdirectory(Triton)
target_include_directories(triton
        PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/third_party/${TAL_PLATFORM}/frida")
target_compile_definitions(triton PRIVATE "${TAL_PLATFORM_DEFINITION}")

set(QBDI_SHARED_LIBRARY OFF CACHE BOOL "Skip unused QBDI shared library target" FORCE)
set(QBDI_TEST OFF CACHE BOOL "Skip unused QBDI tests" FORCE)
set(QBDI_BENCHMARK OFF CACHE BOOL "Skip unused QBDI benchmarks" FORCE)
set(QBDI_EXAMPLES OFF CACHE BOOL "Skip unused QBDI examples" FORCE)
set(QBDI_TOOLS_QBDIPRELOAD OFF CACHE BOOL "Skip unused QBDIPreload tool" FORCE)
set(QBDI_TOOLS_VALIDATOR OFF CACHE BOOL "Skip unused QBDI validator tool" FORCE)
set(QBDI_TOOLS_PYQBDI OFF CACHE BOOL "Skip unused PyQBDI bindings" FORCE)
set(QBDI_TOOLS_FRIDAQBDI OFF CACHE BOOL "Skip unused frida-qbdi install target" FORCE)
set(QBDI_INCLUDE_DOCS OFF CACHE BOOL "Skip unused QBDI docs" FORCE)
set(QBDI_INCLUDE_PACKAGE OFF CACHE BOOL "Skip unused QBDI package target" FORCE)
set(QBDI_INSTALL OFF CACHE BOOL "Skip unused QBDI install metadata" FORCE)
add_subdirectory(qbdi-src)

file(GLOB_RECURSE FILE_SOURCES CONFIGURE_DEPENDS
        "${CMAKE_CURRENT_SOURCE_DIR}/src/*.c"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cc"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cxx")

add_library(tal_common INTERFACE)
target_include_directories(tal_common
        INTERFACE
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
        "${CMAKE_CURRENT_SOURCE_DIR}/third_party/${TAL_PLATFORM}/frida"
        "${CMAKE_CURRENT_SOURCE_DIR}/qbdi-src/include"
        "${CMAKE_CURRENT_BINARY_DIR}/qbdi-src/include"
        "${CMAKE_CURRENT_BINARY_DIR}/qbdi-src/include-static"
        "${CMAKE_CURRENT_SOURCE_DIR}/qbdi-src/src"
        "${CMAKE_CURRENT_BINARY_DIR}/qbdi-src/src"
        "${CMAKE_CURRENT_SOURCE_DIR}/Triton/src/libtriton/includes")

target_compile_definitions(tal_common INTERFACE ULTRA_FAST_MODE=1 "${TAL_PLATFORM_DEFINITION}")

target_link_libraries(tal_common
        INTERFACE
        frida-gum
        qbdi-llvm
        QBDI_static
        Boost::context
        triton)

if(MSVC)
    target_compile_options(tal_common INTERFACE /utf-8)
else()
    target_compile_options(tal_common
            INTERFACE
            -Wall
            -Wextra
            $<$<CONFIG:Release>:-Os>
            $<$<CONFIG:Release>:-fomit-frame-pointer>
            $<$<CONFIG:Release>:-fno-stack-protector>
            $<$<CONFIG:Release>:-ffunction-sections>
            $<$<CONFIG:Release>:-fdata-sections>
            $<$<CONFIG:Release>:-fvisibility=hidden>
            $<$<CONFIG:Release>:-fno-asynchronous-unwind-tables>
            $<$<CONFIG:Release>:-fno-unwind-tables>)

    target_link_options(tal_common
            INTERFACE
            -Wl,--exclude-libs=ALL
            $<$<CONFIG:Release>:-Wl,--gc-sections>
            $<$<AND:$<CONFIG:Release>,$<BOOL:${TAL_STRIP_RELEASE}>>:-Wl,--strip-all>)

    if(TAL_ENABLE_LTO)
        target_compile_options(tal_common INTERFACE $<$<CONFIG:Release>:-flto>)
        target_link_options(tal_common INTERFACE $<$<CONFIG:Release>:-flto=auto>)
    endif()
endif()

if(TAL_PLATFORM STREQUAL "windows")
    target_compile_definitions(tal_common INTERFACE _HAS_STD_BYTE=0)
    target_link_libraries(tal_common INTERFACE ntdll.lib)
endif()

function(tal_configure_library target)
    target_link_libraries(${target} PRIVATE tal_common)
    if(MSVC AND TAL_CPU_COUNT)
        target_compile_options(${target} PRIVATE /MP${TAL_CPU_COUNT})
    endif()
endfunction()

add_library(tal SHARED
        ${FILE_SOURCES}
        library.cpp)

tal_configure_library(tal)

if(TAL_BUILD_TESTS)
    add_library(tal_static STATIC
            ${FILE_SOURCES}
            library.cpp)

    tal_configure_library(tal_static)

    if(NOT TAL_PLATFORM STREQUAL "android")
        enable_testing()

        add_executable(tal_test test/test.cpp)
        target_link_libraries(tal_test PRIVATE tal_static tal_common)
    endif()

    add_subdirectory(test/part)
endif()
