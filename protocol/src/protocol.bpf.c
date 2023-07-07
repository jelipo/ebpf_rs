#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "def.h"
#include "socket_def.h"

char __license[] SEC("license") = "Dual MIT/GPL";

//SEC("tracepoint/syscalls/sys_enter_connect")
//int sys_enter_connect(struct trace_event_raw_sys_enter *ctx) {
//    struct sockaddr *address;
//    address = (struct sockaddr *) ctx->args[1];
//    sa_family_t fam;
//    bpf_core_read_user(&fam, sizeof(fam), &address->sa_family);
//
//    sa_family_t fam2 = BPF_CORE_READ_USER(address, sa_family);
//    bpf_printk("%d %d ", fam, fam2);
//
//    return 0;
//}



//SEC("tracepoint/syscalls/sys_enter_accept")
//int BPF_PROG(sys_enter_accept, int sockfd, struct sockaddr *_Nullable restrict addr,
//             unsigned int *_Nullable restrict addrlen) {
//    sa_family_t sa_family = BPF_CORE_READ(addr, sa_family);
//    if (sa_family == AF_INET) {
//        char sa_data[14];
//        bpf_core_read(&sa_data, sizeof(sa_data), &addr->sa_data);
//        bpf_printk("%d.%d.%d.%d", sa_data[0], sa_data[1], sa_data[2], sa_data[3]);
//    } else {
//        bpf_printk(":sys_enter_acceptfamily:%d", sa_family);
//    }
//    return 0;
//}


//SEC("tracepoint/syscalls/sys_enter_connect")
//int sys_enter_connect() {
//    return 0;
//}
//
//SEC("tracepoint/syscalls/sys_exit_connect")
//int sys_exit_connect() {
//    return 0;
//}
//
//SEC("tracepoint/syscalls/sys_enter_accept")
//int sys_enter_accept() {
//    return 0;
//}
//
//SEC("tracepoint/syscalls/sys_exit_accept")
//int sys_exit_accept() {
//    return 0;
//}
//
//SEC("tracepoint/syscalls/sys_enter_accept4")
//int sys_enter_accept4() {
//    return 0;
//}
//
//SEC("tracepoint/syscalls/sys_exit_accept4")
//int sys_exit_accept4() {
//    return 0;
//}
