cmake_minimum_required(VERSION 3.8)
project(realpath_fuzz)

set(WRAP_FLAGS "-Wl,--wrap=malloc -Wl,--wrap=getcwd -Wl,--wrap=readlink -Wl,--wrap=lstat")
set(FUZZER_FLAGS "-fsanitize=fuzzer,address")

set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}   ${FUZZER_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${FUZZER_FLAGS}")

set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${WRAP_FLAGS}")

add_library(realpath realpath.c)
target_compile_definitions(realpath PRIVATE realpath=fuzz_realpath)

add_executable(realpath_fuzzer realpath_fuzzer.cpp)
target_link_libraries(realpath_fuzzer realpath)
