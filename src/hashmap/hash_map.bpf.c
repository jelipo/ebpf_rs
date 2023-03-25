#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "vmlinux.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def SEC("maps") my_map = {
        .type = BPF_MAP_TYPE_HASH,
        .max_entries = 128,
        .key_size = 64,
        .value_size = sizeof(u64),
        .map_flags = BPF_F_NO_PREALLOC,
};

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
