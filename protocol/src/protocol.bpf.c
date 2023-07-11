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
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, u64);
    __type(value, struct addr_info_t);
} syscall_addr_id_map SEC(".maps");

// 记录accept时的address参数
static inline void accept_enter(struct trace_event_raw_sys_enter *ctx, void *address_map) {
    struct sockaddr *address = ((void *) ctx->args[1]);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct addr_temp_t addr_temp = {};
    addr_temp.addr = address;
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
    char addr_data[14];
    short unsigned int family;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} address_ringbuf SEC(".maps");

static inline void exit_accept(void *address_map) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct addr_temp_t *addr_temp = bpf_map_lookup_elem(address_map, &pid_tgid);
    if (addr_temp == NULL) {
        return;
    }
    struct sockaddr *address = BPF_PROBE_READ(addr_temp, addr);
    sa_family_t sa_family = BPF_CORE_READ_USER(address, sa_family);
    char sa_data[14];
    bpf_core_read_user(&sa_data, sizeof(sa_data), address->sa_data);
    struct addr_info_t addr_info = {};
    memcpy(&addr_info.addr_data, &sa_data, sizeof(sa_data));
    addr_info.family = sa_family;
    bpf_ringbuf_output(&address_ringbuf, &addr_info, sizeof(struct addr_info_t), 0);
}

SEC("tracepoint/syscalls/sys_exit_accept4")
int sys_exit_accept4(struct trace_event_raw_sys_exit *ctx) {
    exit_accept(&syscall_addr_id_map);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_accept")
int sys_exit_accept(struct trace_event_raw_sys_exit *ctx) {
    exit_accept(&syscall_addr_id_map);
    return 0;
}
