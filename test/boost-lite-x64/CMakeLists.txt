cmake_minimum_required(VERSION 3.22.1)

project(boost_lite_x64_test LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "boost-lite x64 test requires a 64-bit target")
endif()

set(BOOST_CONTEXT_ARCHITECTURE x86_64 CACHE STRING "Boost.Context architecture" FORCE)

add_subdirectory(
    "${CMAKE_CURRENT_LIST_DIR}/../../third_party/boost-lite"
    "${CMAKE_CURRENT_BINARY_DIR}/boost-lite")

add_executable(boost_lite_x64_test main.cpp)
target_link_libraries(boost_lite_x64_test PRIVATE Boost::context)

enable_testing()
add_test(NAME boost_lite_x64_test COMMAND boost_lite_x64_test)
