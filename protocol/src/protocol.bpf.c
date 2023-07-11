#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "def.h"
#include "socket_def.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct addr_temp_t {
    struct sockaddr *addr;
    int sockfd;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, u64);
    __type(value, struct addr_temp_t);
} syscall_addr_id_map SEC(".maps");

static inline void accept_enter(struct trace_event_raw_sys_enter *ctx, void *address_map) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sockaddr *address = ((void *) ctx->args[1]);
    struct addr_temp_t addr_temp = {};
    addr_temp.addr = address;
    addr_temp.sockfd=ctx->args[0];
    bpf_map_update_elem(address_map, &pid_tgid, &addr_temp, BPF_ANY);
}

SEC("tracepoint/syscalls/sys_enter_accept4")
int sys_enter_accept4(struct trace_event_raw_sys_enter *ctx) {
    accept_enter(ctx, &syscall_addr_id_map);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_accept")
int sys_enter_accept(struct trace_event_raw_sys_enter *ctx) {
    accept_enter(ctx, &syscall_addr_id_map);
    return 0;
}


struct addr_info_t {
    short unsigned int family;
    u16 port_le;
    union {
        unsigned char ipv6_addr_be[16];
        u32 ipv4_be;
    } ip;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} address_ringbuf SEC(".maps");

const struct addr_info_t *unused __attribute__((unused));

static inline void accept_exit(void *address_map) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct addr_temp_t *addr_temp = bpf_map_lookup_elem(address_map, &pid_tgid);
    if (addr_temp == NULL) {
        return;
    }
    struct sockaddr *address = BPF_PROBE_READ(addr_temp, addr);
    sa_family_t sa_family = BPF_CORE_READ_USER(address, sa_family);
    if (sa_family != PF_INET && sa_family != PF_INET6) {
        bpf_map_delete_elem(address_map, &pid_tgid);
        return;
    }
    struct addr_info_t addr_info = {};
    if (sa_family == PF_INET) {
        struct sockaddr_in *ipv4_addr = (void *) address;
        __be16 be_port = BPF_CORE_READ_USER(ipv4_addr, sin_port);
        u16 port = bpf_ntohs(be_port);
        struct in_addr be_addr = BPF_CORE_READ_USER(ipv4_addr, sin_addr);
        addr_info.port_le = port;
        addr_info.family = sa_family;
        addr_info.ip.ipv4_be = be_addr.s_addr;
    } else if (sa_family == PF_INET6) {
        struct sockaddr_in6 *ipv6_addr = (void *) address;
        __be16 be_port = BPF_CORE_READ_USER(ipv6_addr, sin6_port);
        u16 port = bpf_ntohs(be_port);
        struct in6_addr be_addr = BPF_CORE_READ_USER(ipv6_addr, sin6_addr);
        addr_info.port_le = port;
        addr_info.family = sa_family;
        memcpy(&addr_info.ip.ipv6_addr_be, &be_addr.in6_u.u6_addr8, sizeof(addr_info.ip.ipv6_addr_be));
    }
    bpf_ringbuf_output(&address_ringbuf, &addr_info, sizeof(struct addr_info_t), 0);
    bpf_map_delete_elem(address_map, &pid_tgid);
}

SEC("tracepoint/syscalls/sys_exit_accept4")
int sys_exit_accept4(struct trace_event_raw_sys_exit *ctx) {
    accept_exit(&syscall_addr_id_map);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_accept")
int sys_exit_accept(struct trace_event_raw_sys_exit *ctx) {
    accept_exit(&syscall_addr_id_map);
    return 0;
}
