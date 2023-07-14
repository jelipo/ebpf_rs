#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "def.h"
#include "socket_def.h"
#include "net/ip.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define PERF_MAX_STACK_DEPTH      127

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, u32);
    __type(value, u8);
} listen_tgid SEC(".maps");

struct addr_temp_value_t {
    struct sockaddr *addr;
    int sockfd;
};

struct addr_temp_key_t {
    u64 pid_tgid;
    long int syscall_id;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct addr_temp_key_t);
    __type(value, struct addr_temp_value_t);
} syscall_addr_id_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} address_ringbuf SEC(".maps");

static inline void record_addr_temp(struct trace_event_raw_sys_enter *ctx, void *address_map) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    // filter tgid
    u32 tgid = pid_tgid >> 32;
    if (bpf_map_lookup_elem(&listen_tgid, &tgid) == NULL) {
        return;
    }
    struct sockaddr *address = ((void *) ctx->args[1]);

    struct addr_temp_value_t addr_temp = {};
    addr_temp.addr = address;
    addr_temp.sockfd = ctx->args[0];

    struct addr_temp_key_t key = {};
    key.pid_tgid = pid_tgid;
    key.syscall_id = ctx->id;
    // save to cache
    bpf_map_update_elem(address_map, &key, &addr_temp, BPF_ANY);
}

static inline int select_ip(sa_family_t sa_family, struct sockaddr *address, struct ip_info_t *ip_info) {
    switch (sa_family) {
        case PF_INET: {
            struct sockaddr_in *ipv4_addr = (void *) address;
            __be16 be_port = BPF_CORE_READ_USER(ipv4_addr, sin_port);
            u16 port = bpf_ntohs(be_port);
            struct in_addr be_addr = BPF_CORE_READ_USER(ipv4_addr, sin_addr);
            ip_info->port_le = port;
            ip_info->ip.ipv4_be = be_addr.s_addr;
            return PF_INET;
        }
        case PF_INET6: {
            struct sockaddr_in6 *ipv6_addr = (void *) address;
            __be16 be_port = BPF_CORE_READ_USER(ipv6_addr, sin6_port);
            u16 port = bpf_ntohs(be_port);
            struct in6_addr be_addr = BPF_CORE_READ_USER(ipv6_addr, sin6_addr);
            ip_info->port_le = port;
            __be32 ipv6[4];
            memcpy(&ipv6, &be_addr.in6_u.u6_addr32, sizeof(ipv6));
            if (ipv6[0] == 0 && ipv6[1] == 0 && ipv6[2] == 0xFFFF0000) {
                // ipv4
                ip_info->ip.ipv4_be = ipv6[3];
                return PF_INET;
            } else {
                memcpy(&ip_info->ip.ipv6_be, &be_addr.in6_u.u6_addr8, sizeof(ip_info->ip.ipv6_be));
                return PF_INET6;
            }
        }
        default: {
            return -1;
        }
    }
}

SEC("tracepoint/syscalls/sys_enter_accept4")
int sys_enter_accept4(struct trace_event_raw_sys_enter *ctx) {
    record_addr_temp(ctx, &syscall_addr_id_map);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_accept")
int sys_enter_accept(struct trace_event_raw_sys_enter *ctx) {
    record_addr_temp(ctx, &syscall_addr_id_map);
    return 0;
}


static inline void accept_exit(void *address_map, struct trace_event_raw_sys_exit *exit, short addr_type) {
    long int syscall_id = exit->id;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct addr_temp_key_t key = {};
    key.pid_tgid = pid_tgid;
    key.syscall_id = syscall_id;

    struct addr_temp_value_t *addr_temp = bpf_map_lookup_elem(address_map, &key);
    if (addr_temp == NULL) {
        return;
    }
    // Check return value is 0
    if (exit->ret == -1) {
        bpf_map_delete_elem(address_map, &key);
        return;
    }
    struct sockaddr *address = BPF_PROBE_READ(addr_temp, addr);
    sa_family_t sa_family = BPF_CORE_READ_USER(address, sa_family);
    struct ip_info_t ip_info = {};
    // parse ip and port
    int ip_type = select_ip(sa_family, address, &ip_info);
    if (ip_type < 0) {
        bpf_map_delete_elem(address_map, &key);
        return;
    }
    struct addr_info_t addr_info = {};
    addr_info.pid_tgid = pid_tgid;
    addr_info.addr_type = addr_type;
    addr_info.ip_info = ip_info;
    addr_info.family = ip_type;
    bpf_ringbuf_output(&address_ringbuf, &addr_info, sizeof(struct addr_info_t), 0);
    bpf_map_delete_elem(address_map, &key);
}

SEC("tracepoint/syscalls/sys_exit_accept4")
int sys_exit_accept4(struct trace_event_raw_sys_exit *ctx) {
    accept_exit(&syscall_addr_id_map, ctx, ADDR_TYPE_ACCEPT);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_accept")
int sys_exit_accept(struct trace_event_raw_sys_exit *ctx) {
    accept_exit(&syscall_addr_id_map, ctx, ADDR_TYPE_ACCEPT);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int sys_enter_connect(struct trace_event_raw_sys_enter *ctx) {
    record_addr_temp(ctx, &syscall_addr_id_map);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int sys_exit_connect(struct trace_event_raw_sys_exit *ctx) {
    accept_exit(&syscall_addr_id_map, ctx, ADDR_TYPE_CONNECT);
    return 0;
}
