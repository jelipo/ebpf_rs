#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "def.h"
#include "socket_def.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct addr_info_t {
    struct sockaddr *addr;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, long int);
    __type(value, struct addr_info_t);
} syscall_addr_id_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} ip_info_map SEC(".maps");

static inline void save_ip(struct sockaddr *address) {
    sa_family_t sa_family = BPF_CORE_READ_USER(address, sa_family);
    if (sa_family == PF_INET) {
        struct sockaddr_in *ipv4_addr = (void *) address;
        __be16 be_port = BPF_CORE_READ_USER(ipv4_addr, sin_port);
        u16 port = bpf_ntohs(be_port);
        struct in_addr be_addr = BPF_CORE_READ_USER(ipv4_addr, sin_addr);
        u32 ip = bpf_ntohl(be_addr.s_addr);
        bpf_printk("%d.%d.%d.%d:%d", ip >> 24 & 0xFF, ip >> 16 & 0xFF, ip >> 8 & 0xFF, ip & 0xFF, port);
    } else if (sa_family == PF_INET6) {
        struct sockaddr_in6 *ipv6_addr = (void *) address;
        __be16 be_port = BPF_CORE_READ_USER(ipv6_addr, sin6_port);
        u16 port = bpf_ntohs(be_port);
        struct in6_addr be_addr;
        bpf_core_read_user(&be_addr, sizeof(struct in6_addr), &ipv6_addr->sin6_addr);
        bpf_printk("IPv6 address: [%x:%x:%x:%x:%x:%x:%x:%x]:%d",
                   bpf_ntohs(be_addr.in6_u.u6_addr16[0]), bpf_ntohs(be_addr.in6_u.u6_addr16[1]),
                   bpf_ntohs(be_addr.in6_u.u6_addr16[2]), bpf_ntohs(be_addr.in6_u.u6_addr16[3]),
                   bpf_ntohs(be_addr.in6_u.u6_addr16[4]), bpf_ntohs(be_addr.in6_u.u6_addr16[5]),
                   bpf_ntohs(be_addr.in6_u.u6_addr16[6]), bpf_ntohs(be_addr.in6_u.u6_addr16[7]), port);
    } else {
        bpf_printk("sa_family:%d", sa_family);
    }
}

SEC("tracepoint/syscalls/sys_enter_accept4")
int sys_enter_accept4(struct trace_event_raw_sys_enter *ctx) {
    struct sockaddr *address = BPF_PTR_ARG(ctx, 1);
    long int id = ctx->id;
    struct addr_info_t addr_info = {};
    addr_info.addr = address;
    bpf_map_update_elem(&syscall_addr_id_map, &id, &addr_info, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_accept4")
int sys_exit_accept4(struct trace_event_raw_sys_exit *ctx) {
    long int id = ctx->id;
    struct addr_info_t *addr_info = bpf_map_lookup_elem(&syscall_addr_id_map, &id);
    if (addr_info != NULL) {
        struct sockaddr *address = BPF_PROBE_READ(addr_info, addr);
        save_ip(address);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_accept")
int sys_enter_accept(struct trace_event_raw_sys_enter *ctx) {
    struct sockaddr *address = BPF_PTR_ARG(ctx, 1);
    long int id = ctx->id;
    struct addr_info_t addr_info = {};
    addr_info.addr = address;
    bpf_map_update_elem(&syscall_addr_id_map, &id, &addr_info, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_accept")
int sys_exit_accept(struct trace_event_raw_sys_exit *ctx) {
    long int id = ctx->id;
    struct addr_info_t *addr_info = bpf_map_lookup_elem(&syscall_addr_id_map, &id);
    if (addr_info != NULL) {
        struct sockaddr *address = BPF_PROBE_READ(addr_info, addr);
        save_ip(address);
    }
    return 0;
}
