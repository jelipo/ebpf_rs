#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char __license[] SEC("license") = "Dual MIT/GPL";



SEC("tracepoint/syscalls/sys_enter_connect")
int sys_enter_connect() {

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int sys_exit_connect() {
    return 0;
}
