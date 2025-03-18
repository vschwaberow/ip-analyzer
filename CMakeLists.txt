cmake_minimum_required(VERSION 3.22)
project(ip-analyzer VERSION 0.1.4 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/cmake/CPM.cmake")
    message(STATUS "Downloading CPM.cmake")
    file(DOWNLOAD
        "https://github.com/cpm-cmake/CPM.cmake/releases/download/v0.40.8/CPM.cmake"
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake/CPM.cmake"
        EXPECTED_HASH SHA256=78ba32abdf798bc616bab7c73aac32a17bbd7b06ad9e26a6add69de8f3ae4791
        TLS_VERIFY ON)
endif()

include(cmake/CPM.cmake)
CPMAddPackage("gh:catchorg/Catch2@3.8.0")

CPMAddPackage(
    NAME fmt
    GITHUB_REPOSITORY fmtlib/fmt
    GIT_TAG 11.1.4
)

add_executable(ip-analyzer src/main.cc src/ip_analyzer.cc src/cli_app.cc)
target_include_directories(ip-analyzer PRIVATE src)
target_link_libraries(ip-analyzer PRIVATE fmt::fmt)

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    target_compile_options(ip-analyzer PRIVATE -O3 -march=native -mtune=native)
endif()

enable_testing()

file(GLOB TEST_SOURCES "tests/*.cc")

add_executable(ip_analyzer_tests ${TEST_SOURCES} src/ip_analyzer.cc src/cli_app.cc)
target_link_libraries(ip_analyzer_tests PRIVATE Catch2::Catch2WithMain fmt::fmt)
target_include_directories(ip_analyzer_tests PRIVATE src)

include(CTest)

list(APPEND CMAKE_MODULE_PATH ${Catch2_SOURCE_DIR}/extras)
include(Catch)
catch_discover_tests(ip_analyzer_tests
    EXTRA_ARGS "-d;yes;-s"
)
