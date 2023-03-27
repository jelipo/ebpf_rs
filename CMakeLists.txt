cmake_minimum_required(VERSION 3.22)
project(ebpf-rs C)

set(CMAKE_C_STANDARD 11)

include_directories(include)

add_executable(ebpf-rs
        hashmap/src/hashmap.bpf.c
        tracepoint/src/tracepoint.bpf.c)
