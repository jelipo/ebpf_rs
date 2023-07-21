#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "def.h"
#include "socket_def.h"

#define ADDR_TYPE_CONNECT    1
#define ADDR_TYPE_ACCEPT     2

struct ip_info_t {
    u16 port_le;
    union {
        __u8 ipv6_be[16];
        u32 ipv4_be;
    } ip;
};

struct addr_info_t {
    u8 addr_type;
    u8 family;
    u64 pid_tgid;
    struct ip_info_t ip_info;
};

const struct addr_info_t *unused __attribute__((unused));

