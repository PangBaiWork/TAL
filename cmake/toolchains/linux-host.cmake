set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

get_filename_component(_tal_toolchain_dir "${CMAKE_CURRENT_LIST_FILE}" DIRECTORY)
get_filename_component(_tal_cmake_dir "${_tal_toolchain_dir}" DIRECTORY)

if(DEFINED ENV{TAL_HOST_CC} AND NOT "$ENV{TAL_HOST_CC}" STREQUAL "")
    set(_tal_host_cc "$ENV{TAL_HOST_CC}")
elseif(DEFINED ENV{CC} AND NOT "$ENV{CC}" STREQUAL "")
    set(_tal_host_cc "$ENV{CC}")
else()
    find_program(_tal_host_cc NAMES cc gcc clang)
endif()

if(DEFINED ENV{TAL_HOST_CXX} AND NOT "$ENV{TAL_HOST_CXX}" STREQUAL "")
    set(_tal_host_cxx "$ENV{TAL_HOST_CXX}")
elseif(DEFINED ENV{CXX} AND NOT "$ENV{CXX}" STREQUAL "")
    set(_tal_host_cxx "$ENV{CXX}")
else()
    find_program(_tal_host_cxx NAMES c++ g++ clang++)
endif()

if(DEFINED ENV{TAL_HOST_AR} AND NOT "$ENV{TAL_HOST_AR}" STREQUAL "")
    set(_tal_host_ar "$ENV{TAL_HOST_AR}")
else()
    find_program(_tal_host_ar NAMES ar llvm-ar)
endif()

if(DEFINED ENV{TAL_HOST_RANLIB} AND NOT "$ENV{TAL_HOST_RANLIB}" STREQUAL "")
    set(_tal_host_ranlib "$ENV{TAL_HOST_RANLIB}")
else()
    find_program(_tal_host_ranlib NAMES ranlib llvm-ranlib)
endif()

if(NOT _tal_host_cc OR NOT _tal_host_cxx)
    find_program(_tal_host_zig NAMES python-zig zig)
    if(_tal_host_zig)
        set(_tal_host_cc "${_tal_cmake_dir}/host-tools/zig-cc")
        set(_tal_host_cxx "${_tal_cmake_dir}/host-tools/zig-cxx")
        set(_tal_host_ar "${_tal_cmake_dir}/host-tools/zig-ar")
        set(_tal_host_ranlib "${_tal_cmake_dir}/host-tools/zig-ranlib")
    else()
        message(FATAL_ERROR
            "No Linux host C/C++ compiler found for QBDI native tools. "
            "Install gcc/clang, set TAL_HOST_CC and TAL_HOST_CXX, or install zig/python-zig.")
    endif()
endif()

if(NOT _tal_host_ar)
    set(_tal_host_ar ar)
endif()

if(NOT _tal_host_ranlib)
    set(_tal_host_ranlib ranlib)
endif()

set(CMAKE_C_COMPILER "${_tal_host_cc}" CACHE FILEPATH "Host C compiler for QBDI native tools" FORCE)
set(CMAKE_CXX_COMPILER "${_tal_host_cxx}" CACHE FILEPATH "Host CXX compiler for QBDI native tools" FORCE)
set(CMAKE_ASM_COMPILER "${_tal_host_cc}" CACHE FILEPATH "Host ASM compiler for QBDI native tools" FORCE)
set(CMAKE_AR "${_tal_host_ar}" CACHE FILEPATH "Host archiver for QBDI native tools" FORCE)
set(CMAKE_RANLIB "${_tal_host_ranlib}" CACHE FILEPATH "Host ranlib for QBDI native tools" FORCE)

set(_tal_native_toolchain_flags
    "-DCMAKE_C_COMPILER=${_tal_host_cc}"
    "-DCMAKE_CXX_COMPILER=${_tal_host_cxx}"
    "-DCMAKE_ASM_COMPILER=${_tal_host_cc}"
    "-DCMAKE_AR=${_tal_host_ar}"
    "-DCMAKE_RANLIB=${_tal_host_ranlib}")

set(CROSS_TOOLCHAIN_FLAGS_NATIVE "${_tal_native_toolchain_flags}"
    CACHE STRING "Compiler flags for LLVM recursive native builds" FORCE)
set(CROSS_TOOLCHAIN_FLAGS_LLVM_NATIVE "${_tal_native_toolchain_flags}"
    CACHE STRING "Compiler flags for LLVM recursive native builds" FORCE)
