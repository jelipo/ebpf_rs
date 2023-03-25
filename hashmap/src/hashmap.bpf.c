#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, int32);
} my_map SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int bpf_prog(void *ctx) {
    char key[64] = "key";
    int *value = NULL;
    value = bpf_map_lookup_elem(&my_map, &key);
    if (value != NULL) {
        *value += 1;
    }
    return 0;
}
