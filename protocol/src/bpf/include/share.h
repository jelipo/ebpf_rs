#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

const u8 ZERO_U8 = 0;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, u32);
    __type(value, u8);
} listen_tgid SEC(".maps");


