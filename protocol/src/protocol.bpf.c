#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "def.h"
#include "socket_def.h"

char __license[] SEC("license") = "Dual MIT/GPL";

inline void print_addr(struct sockaddr *address) {
    sa_family_t sa_family = BPF_CORE_READ_USER(address, sa_family);
    if (sa_family != PF_INET) {
        return;
    }
    struct sockaddr_in *ipv4_addr = (void *) address;
    __be16 be_port = BPF_CORE_READ_USER(ipv4_addr, sin_port);
    u16 port = bpf_ntohs(be_port);
    struct in_addr be_addr = BPF_CORE_READ_USER(ipv4_addr, sin_addr);
    u32 ip = bpf_ntohl(be_addr.s_addr);
    bpf_printk("%d.%d.%d.%d:%d", ip >> 24 & 0xFF, ip >> 16 & 0xFF, ip >> 8 & 0xFF, ip & 0xFF, port);
}

//SEC("tracepoint/syscalls/sys_enter_connect")
//int sys_enter_connect(struct trace_event_raw_sys_enter *ctx) {
//    struct sockaddr *address = BPF_PTR_ARG(ctx, 1);
//    print_addr(address);
//    return 0;
//}



SEC("tracepoint/syscalls/sys_enter_accept")
int sys_enter_accept(struct trace_event_raw_sys_enter *ctx) {
    bpf_printk("hello");
//    struct sockaddr *address = BPF_PTR_ARG(ctx, 1);
//    print_addr(address);
    return 0;
}


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
