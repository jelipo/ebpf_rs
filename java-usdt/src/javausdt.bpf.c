#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/usdt.bpf.h>

char __license[] SEC("license") = "Dual MIT/GPL";


SEC("usdt")
int BPF_USDT(gc_begin, void *arg1) {
    bpf_printk("USDT gc_begin arg1 = %lx", arg1);
    return 0;
}
