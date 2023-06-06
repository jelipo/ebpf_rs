#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char __license[] SEC("license") = "Dual MIT/GPL";

const volatile u32 listen_tgid;

struct key_t {
    u32 tgid;
    u32 pid;
    u64 user_stack_id;
    u64 kernel_stack_id;
    u8 comm[16];
};

// 用于暂存到map的struck
struct temp_key_t {
    u32 tgid;
    u32 pid;
};

struct temp_value_t {
    u64 start_time;
    u64 user_stack_id;
    u64 kernel_stack_id;
    u8 comm[16];
};

const struct key_t *unused __attribute__((unused));

const struct temp_key_t *unused1 __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct temp_key_t);
    __type(value, struct temp_value_t);
} temp_pid_status SEC(".maps");

#define PERF_MAX_STACK_DEPTH        127

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __type(key, u32);
    __uint(value_size, PERF_MAX_STACK_DEPTH * sizeof(u64));
    __uint(max_entries, 4096);
} stack_traces SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct key_t);
    __type(value, u64);
} pid_stack_counter SEC(".maps");


SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next) {
    pid_t prev_pid = prev->pid;
    pid_t prev_tgid = prev->tgid;

    pid_t next_pid = next->pid;
    pid_t next_tgid = next->tgid;

    try_record_start(ctx, prev_pid, prev_tgid);
    try_record_end(next_pid, next_tgid);
    return 0;
}
