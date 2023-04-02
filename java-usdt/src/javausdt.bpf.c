#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/usdt.bpf.h>

char __license[] SEC("license") = "Dual MIT/GPL";


SEC("usdt")
int BPF_USDT(gc_begin, void *arg1) {
    bpf_printk("USDT gc_begin arg1 = %lx", arg1);
    bpf_usdt_arg(ctx,0,)
    return 0;
}
