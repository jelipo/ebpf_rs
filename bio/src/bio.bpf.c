#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

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
    __uint(max_entries, 64);
} stack_traces SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct key_t);
    __type(value, struct value_t);
} pid_stack_counter SEC(".maps");

SEC("tp_btf/block_rq_issue")
int BPF_PROG(bio_start, struct request *rq) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32;
    if (tgid != listen_tgid) {
        return 0;
    }
    bpf_printk("start: %d", tgid);
    u32 pid = pid_tgid;
    // 记录
    struct temp_key_t key = {
            .pid = pid,
            .tgid = tgid
    };
    u32 len = rq->__data_len;
    struct temp_value_t value = {};
    value.start_time = bpf_ktime_get_ns();
    value.user_stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
    value.len = len;
    bpf_map_update_elem(&temp_pid_status, &key, &value, BPF_ANY);
    return 0;
}

SEC("tp_btf/block_bio_complete")
int BPF_PROG(bio_complete, struct request_queue *q, struct bio *bio) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32;
    bpf_printk("end: %d", tgid);
    if (tgid != listen_tgid) {
        return 0;
    }
    u32 pid = pid_tgid;
    struct temp_key_t key = {
            .pid = pid,
            .tgid = tgid
    };
    struct temp_value_t *temp_value = bpf_map_lookup_elem(&temp_pid_status, &key);
    if (temp_value == NULL) {
        return 0;
    }
    // 计算用时
    u32 ms = (bpf_ktime_get_ns() - temp_value->start_time) / 1000;
    int i = 0;
    for (; i < DISTRIBUTION_COUNT_LEN; ++i) {
        u64 max = 2 << (i + 1);
        if (ms < max) {
            break;
        }
    }
    // 查找缓存
    struct key_t key_t = {
            .tgid=tgid,
            .pid=pid_tgid,
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
