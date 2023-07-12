#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "def.h"
#include "socket_def.h"
#include "net/ip.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define PERF_MAX_STACK_DEPTH 127

#define PERF_MAX_STACK_DEPTH        127

struct addr_temp_t {
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
    __type(value, struct addr_temp_t);
} syscall_addr_id_map SEC(".maps");

static inline void accept_enter(struct trace_event_raw_sys_enter *ctx, void *address_map, long int syscall_id) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sockaddr *address = ((void *) ctx->args[1]);
    struct addr_temp_t addr_temp = {};
    addr_temp.addr = address;
    addr_temp.sockfd = ctx->args[0];
    struct addr_temp_key_t key = {};
    key.pid_tgid = pid_tgid;
    key.syscall_id = syscall_id;
    bpf_map_update_elem(address_map, &key, &addr_temp, BPF_ANY);
}

SEC("tracepoint/syscalls/sys_enter_accept4")
int sys_enter_accept4(struct trace_event_raw_sys_enter *ctx) {
    accept_enter(ctx, &syscall_addr_id_map, ctx->id);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_accept")
int sys_enter_accept(struct trace_event_raw_sys_enter *ctx) {
    accept_enter(ctx, &syscall_addr_id_map, ctx->id);
    return 0;
}


struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} address_ringbuf SEC(".maps");


static inline void accept_exit(void *address_map, long int syscall_id) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct addr_temp_key_t key = {};
    key.pid_tgid = pid_tgid;
    key.syscall_id = syscall_id;
    // filter tgid
    struct addr_temp_t *addr_temp = bpf_map_lookup_elem(address_map, &key);
    if (addr_temp == NULL) {
        return;
    }
    struct sockaddr *address = BPF_PROBE_READ(addr_temp, addr);
    sa_family_t sa_family = BPF_CORE_READ_USER(address, sa_family);
    struct ip_info_t ip_info = {};
    // parse ip and port
    if (select_ip(sa_family, address, &ip_info) != 0) {
        bpf_map_delete_elem(address_map, &key);
        return;
    }
    struct addr_info_t addr_info = {};
    addr_info.ip_info = ip_info;
    addr_info.family = sa_family;
    bpf_ringbuf_output(&address_ringbuf, &addr_info, sizeof(struct addr_info_t), 0);
    bpf_map_delete_elem(address_map, &key);
}

SEC("tracepoint/syscalls/sys_exit_accept4")
int sys_exit_accept4(struct trace_event_raw_sys_exit *ctx) {
    long int syscall_id = ctx->id;
    accept_exit(&syscall_addr_id_map, syscall_id);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_accept")
int sys_exit_accept(struct trace_event_raw_sys_exit *ctx) {
    accept_exit(&syscall_addr_id_map, ctx->id);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int sys_enter_connect(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sockaddr *address = ((void *) ctx->args[1]);
    struct addr_temp_t addr_temp = {};
    addr_temp.addr = address;
    addr_temp.sockfd = ctx->args[0];
    return 0;
}
