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

void increment_ns(u32 pid, u32 tgid, u64 usage_us, struct temp_value_t *temp_value) {
    struct key_t key = {};
    key.tgid = tgid;
    key.pid = pid;
    key.user_stack_id = temp_value->user_stack_id;
    key.kernel_stack_id = temp_value->kernel_stack_id;
    __builtin_memcpy(&key.comm, &temp_value->comm, sizeof(key.comm));

    u64 *total_usage_us = bpf_map_lookup_elem(&pid_stack_counter, &key);
    u64 result = 0;
    if (total_usage_us == NULL) {
        result = usage_us;
    } else {
        result = usage_us + *total_usage_us;
    }
    bpf_map_update_elem(&pid_stack_counter, &key, &result, BPF_ANY);
}

// 尝试记录offcputime开始时间
inline void try_record_start(void *ctx, u32 prev_pid, u32 prev_tgid) {
    if (prev_tgid == 0) {
        return;
    }
    if (prev_pid == prev_tgid) {
        bpf_printk("record start %d   listen:%d", prev_tgid, listen_tgid);
    }
    if (prev_tgid != listen_tgid) {
        return;
    }

    struct temp_value_t value = {};
    value.start_time = bpf_ktime_get_ns();
    value.user_stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
    value.kernel_stack_id = bpf_get_stackid(ctx, &stack_traces, 0);
    bpf_get_current_comm(&value.comm, sizeof(value.comm));
    struct temp_key_t key = {
            .pid = prev_pid,
            .tgid = prev_tgid
    };
    bpf_map_update_elem(&temp_pid_status, &key, &value, BPF_ANY);
}

// 尝试记录offcputime结束并计算时间
inline void try_record_end(u32 next_pid, u32 next_tgid) {
    if (next_tgid == 0 || next_pid == 0) {
        return;
    }
    if (next_tgid != listen_tgid) {
        return;
    }

    struct temp_key_t key = {
            .pid = next_pid,
            .tgid = next_tgid
    };
    struct temp_value_t *temp_value = NULL;
    temp_value = bpf_map_lookup_elem(&temp_pid_status, &key);
    if (temp_value == NULL) {
        // 找不到直接return
        return;
    }
    u64 end_time = bpf_ktime_get_ns();
    // 计算出使用的时间，微秒
    u64 usage_us = (end_time - temp_value->start_time) / 1000;
    increment_ns(next_pid, next_tgid, usage_us, temp_value);
}

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
