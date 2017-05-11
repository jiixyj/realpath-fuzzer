cmake_minimum_required(VERSION 3.8)
project(realpath_fuzz)

find_package(PkgConfig REQUIRED)
pkg_check_modules(ATFC REQUIRED IMPORTED_TARGET atf-c)

set(WRAP_FLAGS "-Wl,--wrap=malloc -Wl,--wrap=getcwd -Wl,--wrap=readlink -Wl,--wrap=lstat")
set(FUZZER_FLAGS "-fsanitize=fuzzer,address")
set(ASAN_FLAGS "-fsanitize=address")


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
  __getcwd=getcwd
)

add_executable(realpath_fuzzer realpath_fuzzer.cpp)
target_link_libraries(realpath_fuzzer realpath ${WRAP_FLAGS} ${FUZZER_FLAGS})

add_executable(realpath_fuzzer_obsd realpath_fuzzer.cpp)
target_link_libraries(realpath_fuzzer_obsd realpath_obsd ${WRAP_FLAGS} ${FUZZER_FLAGS})

add_executable(realpath_fuzzer_nbsd realpath_fuzzer.cpp)
target_link_libraries(realpath_fuzzer_nbsd realpath_nbsd ${WRAP_FLAGS} ${FUZZER_FLAGS})

target_compile_options(realpath             PUBLIC ${FUZZER_FLAGS})
target_compile_options(realpath_obsd        PUBLIC ${FUZZER_FLAGS})
target_compile_options(realpath_nbsd        PUBLIC ${FUZZER_FLAGS})
target_compile_options(realpath_fuzzer      PUBLIC ${FUZZER_FLAGS})
target_compile_options(realpath_fuzzer_obsd PUBLIC ${FUZZER_FLAGS})
target_compile_options(realpath_fuzzer_nbsd PUBLIC ${FUZZER_FLAGS})


add_executable(realpath_test t_realpath.c realpath.c)
target_link_libraries(realpath_test PkgConfig::ATFC ${ASAN_FLAGS})
target_compile_options(realpath_test PUBLIC ${ASAN_FLAGS})
target_compile_definitions(realpath_test PRIVATE
  realpath=fuzz_realpath
  __arraycount=nitems
)

configure_file(Kyuafile ${CMAKE_BINARY_DIR}/Kyuafile COPYONLY)
