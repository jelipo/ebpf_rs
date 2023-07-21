#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "share.h"
#include "def.h"

char __license[] SEC("license") = "Dual MIT/GPL";

//// 当监控的进程
//SEC("tp_btf/sched_process_fork")
//int BPF_PROG(sched_process_fork, struct task_struct *parent, struct task_struct *child) {
//    pid_t parent_tgid = parent->tgid;
//    pid_t child_tgid = child->tgid;
//    // 新线程退出
//    if (parent_tgid == child_tgid) {
//        return 0;
//    }
//    // 父进程没有找到，退出
//    if (bpf_map_lookup_elem(&listen_tgid, &parent_tgid) == NULL) {
//        return 0;
//    }
//    bpf_map_update_elem(&listen_tgid, &parent_tgid, &ZERO_U8, BPF_ANY);
//    return 0;
//}
//
SEC("tp_btf/sched_process_exit")
int BPF_PROG(sched_process_exit, struct task_struct *task) {
    pid_t tgid = task->tgid;
    pid_t pid = task->pid;
    if (tgid != pid) {
        return 0;
    }
    bpf_map_delete_elem(&deny_tgid, &tgid);
    return 0;
}