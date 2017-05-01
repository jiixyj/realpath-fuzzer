cmake_minimum_required(VERSION 3.8)
project(realpath_fuzz)

set(WRAP_FLAGS "-Wl,--wrap=malloc -Wl,--wrap=getcwd -Wl,--wrap=readlink -Wl,--wrap=lstat")
set(FUZZER_FLAGS "-fsanitize=fuzzer,address")

set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}   ${FUZZER_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${FUZZER_FLAGS}")

set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${WRAP_FLAGS}")

add_library(realpath realpath.c)
target_compile_definitions(realpath PRIVATE realpath=fuzz_realpath)

add_library(realpath_obsd realpath_obsd.c)
target_compile_definitions(realpath_obsd PRIVATE
  realpath=fuzz_realpath
  SYMLOOP_MAX=32
)

add_library(realpath_nbsd realpath_nbsd.c)
target_compile_definitions(realpath_nbsd PRIVATE
  realpath=fuzz_realpath
)

add_executable(realpath_fuzzer realpath_fuzzer.cpp)
target_link_libraries(realpath_fuzzer realpath)

add_executable(realpath_fuzzer_obsd realpath_fuzzer.cpp)
target_link_libraries(realpath_fuzzer_obsd realpath_obsd)

add_executable(realpath_fuzzer_nbsd realpath_fuzzer.cpp)
target_link_libraries(realpath_fuzzer_nbsd realpath_nbsd)
