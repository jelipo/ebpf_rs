#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char __license[] SEC("license") = "Dual MIT/GPL";;

SEC("prog")
int ping_drop(struct xdp_buff *ctx) {
    void *data = (void *) (long) ctx->data;         //报文数据开始处
    void *end = (void *) (long) ctx->data_end;      //报文数据结束点

    struct ethhdr *eh;                           // 以太头
    eh = data;
    //这个检测有点多余，一个合格驱动会保证data一定是小于end的
    if (data > end) {
        return XDP_PASS;
    }
    //这个检测非常重要，否则在下面读取 eh->h_proto 的时候，无法通过bpf verifier的验证，程序就无法加载
    if ((void *) (eh + 1) > end) {
        return XDP_PASS;
    }
    //不是IP报文，放过
    if (eh->h_proto != __constant_htons(ETH_P_IP)) {
        return XDP_PASS;
    }
    struct iphdr *iph;
    iph = (void *) (eh + 1);
    //这里的检测也非常重要，原因同上
    if ((void *) (iph + 1) > end) {
        return XDP_PASS;
    }
    //判断如果是ping报文，丢弃 返回 XDP_DROP，会导致无法ping通主机，其他如ssh等不受影响
    if (iph->protocol == IPPROTO_ICMP) {
        return XDP_DROP;
    }
    return XDP_PASS;
}