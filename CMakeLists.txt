project(realpath_fuzz)

set(WRAP_FLAGS "-Wl,--wrap=realpath")
set(FUZZER_FLAGS "-fsanitize=fuzzer,address")

set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}   ${FUZZER_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${FUZZER_FLAGS}")

set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${WRAP_FLAGS}")

add_executable(realpath_fuzzer realpath_fuzzer.cpp realpath.c)
