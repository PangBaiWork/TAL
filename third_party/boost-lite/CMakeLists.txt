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
