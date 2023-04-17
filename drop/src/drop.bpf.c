#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char __license[] SEC("license") = "Dual MIT/GPL";;

SEC("prog")
int ping_drop(struct xdp_buff *ctx) {

    return XDP_PASS;
}