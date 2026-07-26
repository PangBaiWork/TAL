add_executable(tal_mode_regression mode_regression.cpp)
target_link_libraries(tal_mode_regression PRIVATE tal_static tal_common)
set_target_properties(tal_mode_regression PROPERTIES ENABLE_EXPORTS ON)

if(MSVC)
    set_source_files_properties(mode_regression.cpp PROPERTIES COMPILE_OPTIONS /Od)
else()
    set_source_files_properties(mode_regression.cpp PROPERTIES COMPILE_OPTIONS -O0)
endif()

if(NOT TAL_PLATFORM STREQUAL "android")
    set(TAL_MODE_LOG_DIR "${CMAKE_CURRENT_BINARY_DIR}/logs")

    foreach(mode IN ITEMS addr bin debug trace triton trace_args)
        add_test(
                NAME "tal.mode.${mode}"
                COMMAND tal_mode_regression "${mode}" "${TAL_MODE_LOG_DIR}")
        set_tests_properties(
                "tal.mode.${mode}"
                PROPERTIES
                TIMEOUT 20
                WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")
    endforeach()
endif()
