#include <vmlinux.h>
#include <pkt_cls_def.h>
#include <if_ether_def.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include <linux/pkt_cls.h>

char __license[] SEC("license") = "Dual MIT/GPL";;

static bool is_TCP(void *data_begin, void *data_end) {
    struct ethhdr *eth = data_begin;
    // Check packet's size
    // the pointer arithmetic is based on the size of data type, current_address plus int(1) means:
    // new_address= current_address + size_of(data type)
    if ((void *) (eth + 1) > data_end) //
        return false;
    // Check if Ethernet frame has IP packet
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *iph = (struct iphdr *) (eth + 1); // or (struct iphdr *)( ((void*)eth) + ETH_HLEN );
        if ((void *) (iph + 1) > data_end)
            return false;
        // Check if IP packet contains a TCP segment
        if (iph->protocol == IPPROTO_TCP)
            return true;
    }
    return false;
}

SEC("tc")
int BPF_PROG(tc_ingress, struct __sk_buff *skb) {
    void *data_end = (void *) (__u64) skb->data_end;
    void *data = (void *) (__u64) skb->data;

    if (is_TCP(data, data_end)) {

    }

    struct ethhdr *l2;
    struct iphdr *l3;

    if (skb->protocol != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    l2 = data;
    if ((void *) (l2 + 1) > data_end)
        return TC_ACT_OK;

    l3 = (struct iphdr *) (l2 + 1);
    if ((void *) (l3 + 1) > data_end)
        return TC_ACT_OK;

    bpf_printk("Got IP packet: tot_len: %d, ttl: %d", bpf_ntohs(l3->tot_len), l3->ttl);
    return TC_ACT_OK;
}
