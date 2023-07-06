cmake_minimum_required(VERSION 3.22)
project(ebpf-rs C)

set(CMAKE_C_STANDARD 11)

include_directories(include)

add_executable(ebpf-rs
        hashmap/src/hashmap.bpf.c
        offcputime/src/offcputime.bpf.c
        java-usdt/src/javausdt.bpf.c
        drop/src/drop.bpf.c
        bio/src/bio.bpf.c
        protocol/src/protocol.bpf.c)
