#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "def.h"
#include "socket_def.h"

struct ip_info_t {
    u16 port_le;
    union {
        __u8 ipv6_be[16];
        u32 ipv4_be;
    } ip;
};

struct addr_info_t {
    short unsigned int family;
    struct ip_info_t ip_info;
};

const struct addr_info_t *unused __attribute__((unused));

static inline int select_ip(sa_family_t sa_family, struct sockaddr *address, struct ip_info_t *ip_info) {
    switch (sa_family) {
        case PF_INET: {
            struct sockaddr_in *ipv4_addr = (void *) address;
            __be16 be_port = BPF_CORE_READ_USER(ipv4_addr, sin_port);
            u16 port = bpf_ntohs(be_port);
            struct in_addr be_addr = BPF_CORE_READ_USER(ipv4_addr, sin_addr);
            ip_info->port_le = port;
            ip_info->ip.ipv4_be = be_addr.s_addr;
            return 0;
        }
        case PF_INET6: {
            struct sockaddr_in6 *ipv6_addr = (void *) address;
            __be16 be_port = BPF_CORE_READ_USER(ipv6_addr, sin6_port);
            u16 port = bpf_ntohs(be_port);
            struct in6_addr be_addr = BPF_CORE_READ_USER(ipv6_addr, sin6_addr);
            ip_info->port_le = port;
            __be32 ipv6[4];
            memcpy(&ipv6, &be_addr.in6_u.u6_addr32, sizeof(ipv6));
            if (ipv6[0] == 0 && ipv6[1] == 0 && ipv6[2] == 0xFFFF) {
                // ipv4
                ip_info->ip.ipv4_be = ipv6[3];
            } else {
                memcpy(&ip_info->ip.ipv6_be, &be_addr.in6_u.u6_addr8, sizeof(ip_info->ip.ipv6_be));
            }
            return 0;
        }
        default: {
            return -1;
        }
    }
}
