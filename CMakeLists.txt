cmake_minimum_required(VERSION 3.22)
project(ip-analyzer VERSION 0.1.6 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(ip-analyzer
    src/main.cc
    src/ip_analyzer.cc
    src/cli_app.cc
)
target_include_directories(ip-analyzer PRIVATE src)

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    target_compile_options(ip-analyzer PRIVATE -O3 -march=native -mtune=native)
endif()

enable_testing()

include(FetchContent)
FetchContent_Declare(
    Catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG v3.15.3
)
FetchContent_MakeAvailable(Catch2)

file(GLOB TEST_SOURCES "tests/*.cc")

add_executable(ip_analyzer_tests ${TEST_SOURCES} src/ip_analyzer.cc src/cli_app.cc)
target_link_libraries(ip_analyzer_tests PRIVATE Catch2::Catch2WithMain)
target_include_directories(ip_analyzer_tests PRIVATE src)

include(CTest)

list(APPEND CMAKE_MODULE_PATH ${catch2_SOURCE_DIR}/extras)
include(Catch)
catch_discover_tests(ip_analyzer_tests
    EXTRA_ARGS "-d;yes;-s"
)
