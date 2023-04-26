#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char __license[] SEC("license") = "Dual MIT/GPL";

const volatile u32 listen_tgid;

struct key_t {
    u32 tgid;
    u32 pid;
    u32 user_stack_id;
};

#define DISTRIBUTION_COUNT_LEN    24

struct value_t {
    u32 distribution_count[DISTRIBUTION_COUNT_LEN];
    u32 max_len;
    u32 min_len;
};


// 用于暂存到map的struck
struct temp_key_t {
    u32 tgid;
    u32 pid;
};

struct temp_value_t {
    u64 start_time;
    u32 user_stack_id;
    u32 len;
};

struct piddata {
    u32 tgid;
    u32 pid;
    u32 user_stack_id;
};

const struct key_t *unused __attribute__((unused));

const struct temp_key_t *unused1 __attribute__((unused));

const struct value_t *unused2 __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct request *);
    __type(value, struct piddata);
} reqmap SEC(".maps");

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
    __uint(max_entries, 64);
} stack_traces SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct key_t);
    __type(value, struct value_t);
} pid_stack_counter SEC(".maps");

inline int trace_pid(void *ctx, struct request *rq, u32 tgid, u32 pid) {
    struct piddata piddata = {};
    piddata.tgid = tgid;
    piddata.pid = pid;
    piddata.user_stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
    bpf_map_update_elem(&reqmap, &rq, &piddata, BPF_ANY);
    return 0;
}

SEC("fentry/__blk_account_io_start")
int BPF_PROG(blk_account_io_start, struct request *rq) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32;
    if (tgid != listen_tgid) {
        return 0;
    }
    return trace_pid(ctx, rq, tgid, pid_tgid);
}

SEC("tp_btf/block_rq_issue")
int BPF_PROG(bio_start, struct request *rq) {
    struct piddata *pid_data = bpf_map_lookup_elem(&reqmap, &rq);
    if (pid_data == NULL) {
        return 0;
    }
    u32 pid = pid_data->pid;
    // 记录
    struct temp_key_t key = {
            .pid = pid,
            .tgid = pid_data->tgid
    };

    u32 len = BPF_CORE_READ(rq, __data_len);
    struct temp_value_t value = {};
    value.start_time = bpf_ktime_get_ns();
    value.user_stack_id = pid_data->user_stack_id;
    value.len = len;
    bpf_map_update_elem(&temp_pid_status, &key, &value, BPF_ANY);
    return 0;
}

SEC("tp_btf/block_rq_complete")
int BPF_PROG(bio_complete, struct request *rq, blk_status_t error, unsigned int nr_bytes) {
    struct piddata *pid_data = bpf_map_lookup_elem(&reqmap, &rq);
    if (pid_data == NULL) {
        return 0;
    }
    u32 pid = pid_data->pid;
    struct temp_key_t key = {
            .pid = pid,
            .tgid = pid_data->tgid
    };
    struct temp_value_t *temp_value = bpf_map_lookup_elem(&temp_pid_status, &key);
    if (temp_value == NULL) {
        return 0;
    }
    // 计算用时(微秒)
    u32 us = (bpf_ktime_get_ns() - temp_value->start_time) / 1000;
    int i = 0;
    for (; i < DISTRIBUTION_COUNT_LEN; ++i) {
        u64 max = 1 << i;
        if (us < max) {
            break;
        }
    }
    // 查找缓存
    struct key_t key_t = {
            .tgid=pid_data->tgid,
            .pid=pid_data->pid,
            .user_stack_id=temp_value->user_stack_id,
    };
    struct value_t *value_t = bpf_map_lookup_elem(&pid_stack_counter, &key_t);
    struct value_t new_value;
    if (value_t != NULL) {
        new_value = *value_t;
    } else {
        // 为了防止验证器不过，需要给new_value设置0
        __builtin_memset(&new_value, 0, sizeof(new_value));
    }
    if (temp_value->len > new_value.max_len) {
        new_value.max_len = temp_value->len;
    }
    if (new_value.min_len == 0 || temp_value->len < new_value.min_len) {
        new_value.min_len = temp_value->len;
    }
    new_value.distribution_count[i] += 1;
    bpf_map_update_elem(&pid_stack_counter, &key_t, &new_value, BPF_ANY);
    return 0;
}
