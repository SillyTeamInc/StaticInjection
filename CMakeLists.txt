cmake_minimum_required(VERSION 3.30)
include(cmake/CPM.cmake)
project(StaticInjection)

set(CMAKE_CXX_STANDARD 26)
set(CMAKE_SUPPRESS_DEVELOPER_WARNINGS TRUE)
set(CMAKE_UNITY_BUILD TRUE)

CPMAddPackage(
        NAME magic_enum
        GITHUB_REPOSITORY Neargye/magic_enum
        VERSION 0.9.5
)

set(LIEF_EXAMPLES FALSE CACHE BOOL "Build examples" FORCE)

CPMAddPackage(
        NAME LIEF
        GITHUB_REPOSITORY lief-project/LIEF
        GIT_TAG main
)

set(IS_DEBUG_BUILD CMAKE_BUILD_TYPE STREQUAL "Debug")

add_link_options(
        $<$<CONFIG:Debug>:/INCREMENTAL>
        $<$<CONFIG:Debug>:/DEBUG>
        $<$<CONFIG:Release>:/Zi>
        $<$<CONFIG:Release>:/INCREMENTAL:NO>
        $<$<CONFIG:Release>:/LTCG>
        $<$<CONFIG:Release>:/DEBUG>
)

add_compile_options(
        $<$<CONFIG:Debug>:/Zi>
        $<$<CONFIG:Release>:/Zi>
        $<$<CONFIG:Release>:/GL>
)

set_target_properties(LIB_LIEF PROPERTIES UNITY_BUILD FALSE)

include_directories(src)
include_directories(.)

#i fucking hate this library so much
include_directories(${lief_BINARY_DIR}/lief_spdlog_project-prefix/src/lief_spdlog_project)

add_executable(StaticInjection src/main.cpp
        src/util.cpp
        src/util.hpp
        src/arg_parser.cpp
        src/arg_parser.hpp)

target_link_libraries(StaticInjection PUBLIC lief_spdlog magic_enum LIEF::LIEF Wintrust.lib)

target_precompile_headers(StaticInjection PRIVATE
        "$<$<COMPILE_LANGUAGE:CXX>:<src/pch.hpp$<ANGLE-R>>"
)


