cmake_minimum_required(VERSION 3.22.1)

if(NOT DEFINED BOOST_LITE_DIR)
    set(BOOST_LITE_DIR "${CMAKE_CURRENT_LIST_DIR}/../third_party/boost-lite")
endif()

get_filename_component(BOOST_LITE_DIR "${BOOST_LITE_DIR}" ABSOLUTE)

if(NOT DEFINED BOOST_SOURCE_DIR)
    message(FATAL_ERROR
        "BOOST_SOURCE_DIR is required when regenerating boost-lite.\n"
        "Example:\n"
        "  cmake -DBOOST_SOURCE_DIR=/path/to/boost-1.90.0 -DBCP_EXECUTABLE=/path/to/bcp -P cmake/UpdateBoostLite.cmake")
endif()

get_filename_component(BOOST_SOURCE_DIR "${BOOST_SOURCE_DIR}" ABSOLUTE)

if(NOT EXISTS "${BOOST_SOURCE_DIR}/boost/version.hpp")
    message(FATAL_ERROR "BOOST_SOURCE_DIR is not a Boost source tree: ${BOOST_SOURCE_DIR}")
endif()

if(NOT DEFINED BCP_EXECUTABLE)
    set(_bcp_candidates
        "${BOOST_SOURCE_DIR}/dist/bin/bcp"
        "${BOOST_SOURCE_DIR}/dist/bin/bcp.exe"
        "${BOOST_SOURCE_DIR}/build/tools/bcp"
        "${BOOST_SOURCE_DIR}/build/tools/bcp.exe")

    foreach(_candidate IN LISTS _bcp_candidates)
        if(EXISTS "${_candidate}")
            set(BCP_EXECUTABLE "${_candidate}")
            break()
        endif()
    endforeach()
endif()

if(NOT BCP_EXECUTABLE OR NOT EXISTS "${BCP_EXECUTABLE}")
    message(FATAL_ERROR
        "BCP_EXECUTABLE was not found. Build Boost.BCP once, then rerun:\n"
        "  cmake -DBOOST_SOURCE_DIR=${BOOST_SOURCE_DIR} -DBCP_EXECUTABLE=/path/to/bcp -P cmake/UpdateBoostLite.cmake")
endif()

set(_boost_lite_cmakelists "${BOOST_LITE_DIR}/CMakeLists.txt")
if(EXISTS "${_boost_lite_cmakelists}")
    file(READ "${_boost_lite_cmakelists}" _boost_lite_cmake)
endif()

file(REMOVE_RECURSE "${BOOST_LITE_DIR}")
file(MAKE_DIRECTORY "${BOOST_LITE_DIR}")

set(_bcp_common_args "--boost=${BOOST_SOURCE_DIR}" "--unix-lines")

execute_process(
    COMMAND "${BCP_EXECUTABLE}" ${_bcp_common_args}
        context
        multiprecision
        numeric/conversion
        core
        include
        src
        library.cpp
        "${BOOST_LITE_DIR}"
    WORKING_DIRECTORY "${CMAKE_CURRENT_LIST_DIR}/.."
    COMMAND_ECHO STDOUT
    COMMAND_ERROR_IS_FATAL ANY)

execute_process(
    COMMAND "${BCP_EXECUTABLE}" ${_bcp_common_args}
        libs/config/include/boost/cstdint.hpp
        libs/smart_ptr/include/boost/intrusive_ptr.hpp
        "${BOOST_LITE_DIR}"
    WORKING_DIRECTORY "${CMAKE_CURRENT_LIST_DIR}/.."
    COMMAND_ECHO STDOUT
    COMMAND_ERROR_IS_FATAL ANY)

if(DEFINED _boost_lite_cmake)
    file(WRITE "${_boost_lite_cmakelists}" "${_boost_lite_cmake}")
else()
    file(WRITE "${_boost_lite_cmakelists}" [=[
cmake_minimum_required(VERSION 3.22.1)

project(boost_lite LANGUAGES CXX)

set(BOOST_SUPERPROJECT_VERSION 1.90.0)

file(GLOB _boost_lite_include_dirs
    LIST_DIRECTORIES true
    CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/libs/*/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/libs/numeric/*/include")

list(PREPEND _boost_lite_include_dirs "${CMAKE_CURRENT_SOURCE_DIR}")

add_library(Boost_headers INTERFACE)
target_include_directories(Boost_headers INTERFACE ${_boost_lite_include_dirs})

add_library(Boost::headers ALIAS Boost_headers)

foreach(_boost_lite_header_lib
        assert
        config
        core
        mp11
        pool
        predef
        smart_ptr
        multiprecision
        numeric_conversion)
    add_library(Boost_${_boost_lite_header_lib} INTERFACE)
    target_link_libraries(Boost_${_boost_lite_header_lib} INTERFACE Boost::headers)
    add_library(Boost::${_boost_lite_header_lib} ALIAS Boost_${_boost_lite_header_lib})
endforeach()

add_subdirectory(libs/context)
target_link_libraries(boost_context PUBLIC Boost::headers)

if(NOT TARGET Boost::context)
    add_library(Boost::context ALIAS boost_context)
endif()
]=])
endif()

set(_boost_lite_prune_dirs
    doc
    libs/context/doc
    libs/context/example
    libs/context/performance
    libs/context/test
    libs/core/doc
    libs/core/test
    libs/math/test
    libs/multiprecision/doc
    libs/multiprecision/example
    libs/multiprecision/performance
    libs/multiprecision/plots
    libs/multiprecision/test
    libs/multiprecision/tools
    libs/numeric/conversion/doc
    libs/numeric/conversion/test
    libs/predef/tools)

foreach(_prune_dir IN LISTS _boost_lite_prune_dirs)
    file(REMOVE_RECURSE "${BOOST_LITE_DIR}/${_prune_dir}")
endforeach()

message(STATUS "Updated Boost lite tree: ${BOOST_LITE_DIR}")
