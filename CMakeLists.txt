cmake_minimum_required(VERSION 3.22)
project(ebpf-rs C)

set(CMAKE_C_STANDARD 11)

include_directories(include protocol/src/bpf/include)
file(GLOB_RECURSE INCLUDE_DIRS "include/*")
include_directories(${INCLUDE_DIRS})


include_directories()

file(GLOB_RECURSE SOURCES "include/**/*.c")

add_executable(ebpf-rs
        ${SOURCES}
        hashmap/src/hashmap.bpf.c
        offcputime/src/offcputime.bpf.c
        java-usdt/src/javausdt.bpf.c
        drop/src/drop.bpf.c
        bio/src/bio.bpf.c
        protocol/src/bpf/pre/protocol.bpf.c)

