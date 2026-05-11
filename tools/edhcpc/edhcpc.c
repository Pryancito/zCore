#define _GNU_SOURCE

#include <arpa/inet.h>
#include <stddef.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

// Eclipse DHCP Client (edhcpc)
// Minimal DHCPv4 client intended for Eclipse OS userland.
//
// - Negotiates DISCOVER/OFFER/REQUEST/ACK
// - Applies IPv4 + netmask using rtnetlink RTM_NEWADDR
// - Applies default gateway using rtnetlink RTM_NEWROUTE (RTA_GATEWAY + RTA_OIF)
// - Writes /etc/resolv.conf with DNS servers (best-effort)

static void die(const char *msg) {
    perror(msg);
    exit(1);
}

static void warnx(const char *msg) {
    fprintf(stderr, "edhcpc: %s\n", msg);
}

static uint32_t now_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint32_t)(tv.tv_sec * 1000u + (uint32_t)(tv.tv_usec / 1000u));
}

static uint32_t weak_xid(void) {
    // DHCP does not require cryptographic randomness; a changing xid is enough.
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint32_t)(tv.tv_sec ^ tv.tv_usec ^ (uint32_t)getpid() ^ 0x9e3779b9u);
}

static int prefix_len_from_netmask(uint32_t netmask_be) {
    // netmask in network order; convert to host for bit operations.
    uint32_t mask = ntohl(netmask_be);
    int prefix = 0;
    bool seen_zero = false;
    for (int i = 31; i >= 0; i--) {
        bool bit = (mask >> i) & 1u;
        if (bit) {
            if (seen_zero) return -1; // non-canonical mask
            prefix++;
        } else {
            seen_zero = true;
        }
    }
    return prefix;
}

// ---------------- Checksums ----------------

static uint16_t csum16(const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    uint32_t sum = 0;
    while (len > 1) {
        sum += (uint32_t)((p[0] << 8) | p[1]);
        p += 2;
        len -= 2;
    }
    if (len) sum += (uint32_t)(p[0] << 8);
    while (sum >> 16) sum = (sum & 0xffffu) + (sum >> 16);
    return (uint16_t)(~sum);
}

static uint16_t udp_checksum_ipv4(uint32_t src_be, uint32_t dst_be, const void *udp_hdr,
                                  const void *payload, size_t payload_len) {
    // Pseudo-header + UDP header + payload, RFC 768.
    struct {
        uint32_t src;
        uint32_t dst;
        uint8_t zero;
        uint8_t proto;
        uint16_t udp_len;
    } __attribute__((packed)) ph;

    const uint16_t udp_len = (uint16_t)(8 + payload_len);
    ph.src = src_be;
    ph.dst = dst_be;
    ph.zero = 0;
    ph.proto = 17;
    ph.udp_len = htons(udp_len);

    uint32_t sum = 0;
    // pseudo header
    sum += (uint32_t)~csum16(&ph, sizeof(ph)) & 0xffffu;
    // udp header
    sum += (uint32_t)~csum16(udp_hdr, 8) & 0xffffu;
    // payload
    sum += (uint32_t)~csum16(payload, payload_len) & 0xffffu;
    while (sum >> 16) sum = (sum & 0xffffu) + (sum >> 16);
    uint16_t out = (uint16_t)(~sum);
    // checksum value 0 means "no checksum" for UDP/IPv4; avoid generating 0.
    if (out == 0) out = 0xffff;
    return out;
}

// ---------------- DHCP ----------------

enum {
    DHCP_CLIENT_PORT = 68,
    DHCP_SERVER_PORT = 67,
};

enum {
    BOOTREQUEST = 1,
    BOOTREPLY = 2,
};

enum {
    DHCPDISCOVER = 1,
    DHCPOFFER = 2,
    DHCPREQUEST = 3,
    DHCPDECLINE = 4,
    DHCPACK = 5,
    DHCPNAK = 6,
    DHCPRELEASE = 7,
    DHCPINFORM = 8,
};

enum {
    DHCP_OPTION_PAD = 0,
    DHCP_OPTION_END = 255,
    DHCP_OPTION_SUBNET_MASK = 1,
    DHCP_OPTION_ROUTER = 3,
    DHCP_OPTION_DNS = 6,
    DHCP_OPTION_REQ_IP = 50,
    DHCP_OPTION_LEASE_TIME = 51,
    DHCP_OPTION_MSG_TYPE = 53,
    DHCP_OPTION_SERVER_ID = 54,
    DHCP_OPTION_PARAM_REQ_LIST = 55,
    DHCP_OPTION_RENEWAL_T1 = 58,
    DHCP_OPTION_REBINDING_T2 = 59,
    DHCP_OPTION_CLIENT_ID = 61,
};

struct dhcp_msg {
    uint8_t op;
    uint8_t htype;
    uint8_t hlen;
    uint8_t hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    uint32_t ciaddr;
    uint32_t yiaddr;
    uint32_t siaddr;
    uint32_t giaddr;
    uint8_t chaddr[16];
    uint8_t sname[64];
    uint8_t file[128];
    uint32_t cookie; // 0x63825363
    uint8_t options[312]; // enough for basic options
} __attribute__((packed));

struct dhcp_offer {
    uint32_t yiaddr;
    uint32_t subnet_mask;
    uint32_t router;
    uint32_t dns[2];
    int dns_count;
    uint32_t server_id;
    uint32_t lease_time;
};

// Minimal headers for Ethernet+IPv4+UDP.
struct ipv4_hdr {
    uint8_t ver_ihl;
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t proto;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
} __attribute__((packed));

struct udp_hdr {
    uint16_t sport;
    uint16_t dport;
    uint16_t len;
    uint16_t check;
} __attribute__((packed));

static void opt_put(uint8_t *opts, size_t *off, uint8_t code, const void *data, uint8_t len) {
    opts[(*off)++] = code;
    opts[(*off)++] = len;
    memcpy(&opts[*off], data, len);
    *off += len;
}

static void opt_put_u8(uint8_t *opts, size_t *off, uint8_t code, uint8_t v) {
    opt_put(opts, off, code, &v, 1);
}

static void opt_put_u32(uint8_t *opts, size_t *off, uint8_t code, uint32_t v_be) {
    opt_put(opts, off, code, &v_be, 4);
}

static int parse_options(const uint8_t *opts, size_t len, int *msg_type, struct dhcp_offer *out) {
    memset(out, 0, sizeof(*out));
    *msg_type = 0;

    size_t i = 0;
    while (i < len) {
        uint8_t code = opts[i++];
        if (code == DHCP_OPTION_PAD) continue;
        if (code == DHCP_OPTION_END) break;
        if (i >= len) break;
        uint8_t olen = opts[i++];
        if (i + olen > len) break;

        const uint8_t *val = &opts[i];
        switch (code) {
        case DHCP_OPTION_MSG_TYPE:
            if (olen == 1) *msg_type = val[0];
            break;
        case DHCP_OPTION_SUBNET_MASK:
            if (olen == 4) memcpy(&out->subnet_mask, val, 4);
            break;
        case DHCP_OPTION_ROUTER:
            if (olen >= 4) memcpy(&out->router, val, 4);
            break;
        case DHCP_OPTION_DNS: {
            out->dns_count = 0;
            for (int j = 0; j < 2 && (j * 4 + 4) <= olen; j++) {
                memcpy(&out->dns[j], &val[j * 4], 4);
                out->dns_count++;
            }
            break;
        }
        case DHCP_OPTION_SERVER_ID:
            if (olen == 4) memcpy(&out->server_id, val, 4);
            break;
        case DHCP_OPTION_LEASE_TIME:
            if (olen == 4) memcpy(&out->lease_time, val, 4);
            break;
        default:
            break;
        }
        i += olen;
    }
    return 0;
}

static void build_common(struct dhcp_msg *m, uint32_t xid_be, const uint8_t mac[6]) {
    memset(m, 0, sizeof(*m));
    m->op = BOOTREQUEST;
    m->htype = 1; // Ethernet
    m->hlen = 6;
    m->xid = xid_be;
    m->flags = htons(0x8000); // broadcast
    memcpy(m->chaddr, mac, 6);
    m->cookie = htonl(0x63825363);
}

static size_t build_dhcp_discover(uint8_t *out, size_t cap, const uint8_t mac[6], uint32_t xid_be) {
    struct dhcp_msg m;
    build_common(&m, xid_be, mac);

    size_t off = 0;
    uint8_t mt = DHCPDISCOVER;
    opt_put_u8(m.options, &off, DHCP_OPTION_MSG_TYPE, mt);

    uint8_t cid[7] = {1, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]};
    opt_put(m.options, &off, DHCP_OPTION_CLIENT_ID, cid, sizeof(cid));

    uint8_t prl[] = {DHCP_OPTION_SUBNET_MASK, DHCP_OPTION_ROUTER, DHCP_OPTION_DNS, DHCP_OPTION_LEASE_TIME};
    opt_put(m.options, &off, DHCP_OPTION_PARAM_REQ_LIST, prl, sizeof(prl));
    m.options[off++] = DHCP_OPTION_END;

    const size_t msg_len = offsetof(struct dhcp_msg, options) + off;
    if (msg_len > cap) return 0;
    memcpy(out, &m, msg_len);
    return msg_len;
}

static size_t build_dhcp_request(uint8_t *out, size_t cap, const uint8_t mac[6], uint32_t xid_be,
                                 uint32_t req_ip_be, uint32_t server_id_be) {
    struct dhcp_msg m;
    build_common(&m, xid_be, mac);

    size_t off = 0;
    uint8_t mt = DHCPREQUEST;
    opt_put_u8(m.options, &off, DHCP_OPTION_MSG_TYPE, mt);
    opt_put_u32(m.options, &off, DHCP_OPTION_REQ_IP, req_ip_be);
    opt_put_u32(m.options, &off, DHCP_OPTION_SERVER_ID, server_id_be);

    uint8_t cid[7] = {1, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]};
    opt_put(m.options, &off, DHCP_OPTION_CLIENT_ID, cid, sizeof(cid));

    uint8_t prl[] = {DHCP_OPTION_SUBNET_MASK, DHCP_OPTION_ROUTER, DHCP_OPTION_DNS, DHCP_OPTION_LEASE_TIME};
    opt_put(m.options, &off, DHCP_OPTION_PARAM_REQ_LIST, prl, sizeof(prl));
    m.options[off++] = DHCP_OPTION_END;

    const size_t msg_len = offsetof(struct dhcp_msg, options) + off;
    if (msg_len > cap) return 0;
    memcpy(out, &m, msg_len);
    return msg_len;
}

static int send_dhcp_packet(int pfd, const uint8_t mac[6], const uint8_t *dhcp, size_t dhcp_len) {
    uint8_t frame[1514];
    if (dhcp_len == 0) return -1;

    const uint32_t src_ip = htonl(INADDR_ANY);        // 0.0.0.0
    const uint32_t dst_ip = htonl(INADDR_BROADCAST);  // 255.255.255.255

    struct ether_header *eth = (struct ether_header *)frame;
    memset(eth->ether_dhost, 0xff, 6);
    memcpy(eth->ether_shost, mac, 6);
    eth->ether_type = htons(ETHERTYPE_IP);

    struct ipv4_hdr *ip = (struct ipv4_hdr *)(frame + sizeof(*eth));
    struct udp_hdr *udp = (struct udp_hdr *)((uint8_t *)ip + sizeof(*ip));
    uint8_t *payload = (uint8_t *)udp + sizeof(*udp);

    memcpy(payload, dhcp, dhcp_len);

    const uint16_t udp_len = (uint16_t)(sizeof(*udp) + dhcp_len);
    const uint16_t ip_len = (uint16_t)(sizeof(*ip) + udp_len);

    memset(ip, 0, sizeof(*ip));
    ip->ver_ihl = (4u << 4) | (uint8_t)(sizeof(*ip) / 4);
    ip->tot_len = htons(ip_len);
    ip->id = htons((uint16_t)(weak_xid() & 0xffffu));
    ip->frag_off = htons(0);
    ip->ttl = 64;
    ip->proto = 17;
    ip->saddr = src_ip;
    ip->daddr = dst_ip;
    ip->check = 0;
    ip->check = csum16(ip, sizeof(*ip));

    udp->sport = htons(DHCP_CLIENT_PORT);
    udp->dport = htons(DHCP_SERVER_PORT);
    udp->len = htons(udp_len);
    udp->check = 0;
    udp->check = udp_checksum_ipv4(src_ip, dst_ip, udp, payload, dhcp_len);

    const size_t frame_len = sizeof(*eth) + ip_len;
    ssize_t n = send(pfd, frame, frame_len, 0);
    return (n < 0) ? -1 : 0;
}

static int parse_dhcp_payload(const uint8_t *payload, size_t payload_len, uint32_t xid_be,
                              struct dhcp_offer *offer_out, int *msg_type_out) {
    if (payload_len < offsetof(struct dhcp_msg, options)) return -1;
    const struct dhcp_msg *m = (const struct dhcp_msg *)payload;
    if (m->op != BOOTREPLY) return -1;
    if (m->xid != xid_be) return -1;
    if (ntohl(m->cookie) != 0x63825363) return -1;

    struct dhcp_offer o;
    int mt = 0;
    size_t opt_off = offsetof(struct dhcp_msg, options);
    if (payload_len <= opt_off) return -1;
    parse_options((const uint8_t *)m->options, payload_len - opt_off, &mt, &o);
    if (mt == 0) return -1;
    o.yiaddr = m->yiaddr;
    *offer_out = o;
    *msg_type_out = mt;
    return 0;
}

static int try_recv_dhcp_packet_once(int pfd, uint32_t xid_be, struct dhcp_offer *offer_out,
                                     int *msg_type_out) {
    uint8_t buf[2048];
    ssize_t n = recv(pfd, buf, sizeof(buf), 0);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 1;
        return -1;
    }
    if ((size_t)n < sizeof(struct ether_header) + sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr)) return 1;

    const struct ether_header *eth = (const struct ether_header *)buf;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) return 1;

    const struct ipv4_hdr *ip = (const struct ipv4_hdr *)(buf + sizeof(*eth));
    const uint8_t ihl = (uint8_t)((ip->ver_ihl & 0x0f) * 4);
    if ((ip->ver_ihl >> 4) != 4) return 1;
    if (ihl < sizeof(struct ipv4_hdr)) return 1;
    if (ip->proto != 17) return 1;

    if ((size_t)n < sizeof(*eth) + ihl + sizeof(struct udp_hdr)) return 1;
    const struct udp_hdr *udp = (const struct udp_hdr *)(buf + sizeof(*eth) + ihl);
    if (ntohs(udp->dport) != DHCP_CLIENT_PORT) return 1;
    if (ntohs(udp->sport) != DHCP_SERVER_PORT) return 1;

    const uint16_t ulen = ntohs(udp->len);
    if (ulen < sizeof(struct udp_hdr)) return 1;
    const size_t payload_len = (size_t)ulen - sizeof(struct udp_hdr);
    const uint8_t *payload = (const uint8_t *)udp + sizeof(struct udp_hdr);
    if ((const uint8_t *)payload + payload_len > buf + n) return 1;

    if (parse_dhcp_payload(payload, payload_len, xid_be, offer_out, msg_type_out) == 0) return 0;
    return 1;
}

static int try_recv_dhcp_udp_once(int fd, uint32_t xid_be, struct dhcp_offer *offer_out, int *msg_type_out) {
    uint8_t buf[2048];
    ssize_t n = recv(fd, buf, sizeof(buf), 0);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 1;
        return -1;
    }
    if (n <= 0) return 1;
    if (parse_dhcp_payload(buf, (size_t)n, xid_be, offer_out, msg_type_out) == 0) return 0;
    return 1;
}

static int recv_dhcp_message_any(int pfd, int fd, uint32_t xid_be, struct dhcp_offer *offer_out,
                                 int *msg_type_out, uint32_t deadline_ms) {
    for (;;) {
        uint32_t t = now_ms();
        if (t >= deadline_ms) return -1;

        int pr = try_recv_dhcp_packet_once(pfd, xid_be, offer_out, msg_type_out);
        if (pr == 0) return 0;
        if (pr < 0) return -1;

        int ur = try_recv_dhcp_udp_once(fd, xid_be, offer_out, msg_type_out);
        if (ur == 0) return 0;
        if (ur < 0) return -1;

        usleep(50 * 1000);
    }
}

// ---------------- Netlink apply ----------------

static int nl_send(int fd, const void *buf, size_t len) {
    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    ssize_t n = sendto(fd, buf, len, 0, (struct sockaddr *)&sa, sizeof(sa));
    return (n < 0) ? -1 : 0;
}

static int nl_recv_ack(int fd, uint32_t seq) {
    char buf[8192];
    for (;;) {
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n < 0) return -1;
        struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
        for (; NLMSG_OK(nlh, (unsigned int)n); nlh = NLMSG_NEXT(nlh, n)) {
            if (nlh->nlmsg_seq != seq) continue;
            if (nlh->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *e = (struct nlmsgerr *)NLMSG_DATA(nlh);
                if (e->error == 0) return 0;
                errno = -e->error;
                return -1;
            }
            if (nlh->nlmsg_type == NLMSG_DONE) return 0;
        }
    }
}

static void rta_put(struct rtattr *rta, uint16_t type, const void *data, size_t len) {
    rta->rta_type = type;
    rta->rta_len = (uint16_t)RTA_LENGTH(len);
    memcpy(RTA_DATA(rta), data, len);
}

static int apply_ipv4_addr(int ifindex, const char *ifname, uint32_t ip_be, int prefix_len) {
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd < 0) return -1;

    struct sockaddr_nl local;
    memset(&local, 0, sizeof(local));
    local.nl_family = AF_NETLINK;
    local.nl_pid = (uint32_t)getpid();
    if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
        close(fd);
        return -1;
    }

    uint8_t req_buf[512];
    memset(req_buf, 0, sizeof(req_buf));

    struct nlmsghdr *nlh = (struct nlmsghdr *)req_buf;
    struct ifaddrmsg *ifa = (struct ifaddrmsg *)NLMSG_DATA(nlh);

    uint32_t seq = 100;
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(*ifa));
    nlh->nlmsg_type = RTM_NEWADDR;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;
    nlh->nlmsg_seq = seq;
    nlh->nlmsg_pid = (uint32_t)getpid();

    ifa->ifa_family = AF_INET;
    ifa->ifa_prefixlen = (uint8_t)prefix_len;
    ifa->ifa_scope = 0;
    ifa->ifa_index = (uint32_t)ifindex;

    size_t off = NLMSG_ALIGN(nlh->nlmsg_len);
    struct rtattr *rta = (struct rtattr *)(req_buf + off);
    rta_put(rta, IFA_LOCAL, &ip_be, 4);
    off += RTA_ALIGN(rta->rta_len);

    rta = (struct rtattr *)(req_buf + off);
    rta_put(rta, IFA_ADDRESS, &ip_be, 4);
    off += RTA_ALIGN(rta->rta_len);

    // Label: NUL-terminated interface name, as expected by some userlands
    char label[IFNAMSIZ];
    memset(label, 0, sizeof(label));
    strncpy(label, ifname, IFNAMSIZ - 1);
    rta = (struct rtattr *)(req_buf + off);
    rta_put(rta, IFA_LABEL, label, strnlen(label, IFNAMSIZ - 1) + 1);
    off += RTA_ALIGN(rta->rta_len);

    nlh->nlmsg_len = (uint32_t)off;

    int rc = 0;
    if (nl_send(fd, req_buf, nlh->nlmsg_len) < 0) rc = -1;
    if (rc == 0 && nl_recv_ack(fd, seq) < 0) rc = -1;
    close(fd);
    return rc;
}

static int apply_default_route(int ifindex, uint32_t gw_be) {
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd < 0) return -1;

    struct sockaddr_nl local;
    memset(&local, 0, sizeof(local));
    local.nl_family = AF_NETLINK;
    local.nl_pid = (uint32_t)getpid();
    if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
        close(fd);
        return -1;
    }

    uint8_t req_buf[512];
    memset(req_buf, 0, sizeof(req_buf));

    struct nlmsghdr *nlh = (struct nlmsghdr *)req_buf;
    uint8_t *p = (uint8_t *)NLMSG_DATA(nlh);

    uint32_t seq = 101;
    nlh->nlmsg_len = NLMSG_LENGTH(12); // kernel parser in Eclipse OS expects 12 bytes rtmsg
    nlh->nlmsg_type = RTM_NEWROUTE;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;
    nlh->nlmsg_seq = seq;
    nlh->nlmsg_pid = (uint32_t)getpid();

    // 12-byte Linux rtmsg layout: family, dst_len, src_len, tos, table, protocol, scope, type, flags(u32)
    // We only need a default route: dst_len=0 and RTA_GATEWAY + RTA_OIF attributes.
    p[0] = AF_INET; // family
    p[1] = 0;       // dst_len
    p[2] = 0;       // src_len
    p[3] = 0;       // tos
    p[4] = 0;       // table (unspecified)
    p[5] = 0;       // protocol
    p[6] = 0;       // scope
    p[7] = 0;       // type
    // flags (u32) already zero

    size_t off = NLMSG_ALIGN(nlh->nlmsg_len);
    struct rtattr *rta = (struct rtattr *)(req_buf + off);
    rta_put(rta, 5 /* RTA_GATEWAY */, &gw_be, 4);
    off += RTA_ALIGN(rta->rta_len);

    uint32_t oif = (uint32_t)ifindex;
    rta = (struct rtattr *)(req_buf + off);
    rta_put(rta, 4 /* RTA_OIF */, &oif, 4);
    off += RTA_ALIGN(rta->rta_len);

    nlh->nlmsg_len = (uint32_t)off;

    int rc = 0;
    if (nl_send(fd, req_buf, nlh->nlmsg_len) < 0) rc = -1;
    if (rc == 0 && nl_recv_ack(fd, seq) < 0) rc = -1;
    close(fd);
    return rc;
}

static void write_resolv_conf(const uint32_t *dns, int dns_count) {
    FILE *f = fopen("/etc/resolv.conf", "w");
    if (!f) return;
    for (int i = 0; i < dns_count; i++) {
        struct in_addr a;
        a.s_addr = dns[i];
        fprintf(f, "nameserver %s\n", inet_ntoa(a));
    }
    fclose(f);
}

static void print_ipv4(const char *label, uint32_t be) {
    struct in_addr a;
    a.s_addr = be;
    fprintf(stderr, "%s%s", label, inet_ntoa(a));
}

// ---------------- Main ----------------

static void usage(const char *argv0) {
    fprintf(stderr, "usage: %s -i <ifname> [--timeout <sec>]\n", argv0);
    exit(2);
}

int main(int argc, char **argv) {
    const char *ifname = NULL;
    int timeout_sec = 10;

    for (int i = 1; i < argc; i++) {
        if ((strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--iface") == 0) && i + 1 < argc) {
            ifname = argv[++i];
        } else if (strcmp(argv[i], "--timeout") == 0 && i + 1 < argc) {
            timeout_sec = atoi(argv[++i]);
            if (timeout_sec <= 0) timeout_sec = 10;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
        } else {
            usage(argv[0]);
        }
    }

    if (!ifname) usage(argv[0]);

    // Get interface MAC + ifindex
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) die("socket(AF_INET)");

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0) die("ioctl(SIOCGIFHWADDR)");
    uint8_t mac[6];
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);

    if (ioctl(s, SIOCGIFINDEX, &ifr) < 0) die("ioctl(SIOCGIFINDEX)");
    int ifindex = ifr.ifr_ifindex;
    close(s);

    // DHCP UDP socket
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) die("socket(udp)");

    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &yes, sizeof(yes));

    struct sockaddr_in local;
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_port = htons(DHCP_CLIENT_PORT);
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0) die("bind(udp:68)");

    // Eclipse OS currently does not apply SO_RCVTIMEO for UDP sockets.
    // Use non-blocking IO and a userland timeout loop instead.
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0) die("fcntl(F_GETFL)");
    if (fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0) die("fcntl(F_SETFL,O_NONBLOCK)");

    uint32_t xid = weak_xid();
    uint32_t xid_be = htonl(xid);

    uint32_t deadline = now_ms() + (uint32_t)timeout_sec * 1000u;

    // Prefer AF_PACKET because smoltcp may not emit IPv4 broadcast before the
    // interface has an address. The packet path crafts Ethernet/IP/UDP manually.
    int pfd = socket(AF_PACKET, SOCK_RAW, 0);
    if (pfd < 0) die("socket(AF_PACKET)");

    // Bind packet socket to interface index (1-based in Eclipse OS).
    struct sockaddr_ll sall;
    memset(&sall, 0, sizeof(sall));
    sall.sll_family = AF_PACKET;
    sall.sll_ifindex = ifindex;
    sall.sll_halen = 6;
    if (bind(pfd, (struct sockaddr *)&sall, sizeof(sall)) < 0) die("bind(AF_PACKET)");

    int pfl = fcntl(pfd, F_GETFL, 0);
    if (pfl < 0) die("fcntl(F_GETFL,packet)");
    if (fcntl(pfd, F_SETFL, pfl | O_NONBLOCK) < 0) die("fcntl(F_SETFL,packet)");

    uint8_t dhcp_buf[600];
    size_t dhcp_len = build_dhcp_discover(dhcp_buf, sizeof(dhcp_buf), mac, xid_be);
    if (dhcp_len == 0) die("build_dhcp_discover");
    if (send_dhcp_packet(pfd, mac, dhcp_buf, dhcp_len) < 0) die("send(packet:discover)");

    struct dhcp_offer offer;
    int mt = 0;
    if (recv_dhcp_message_any(pfd, fd, xid_be, &offer, &mt, deadline) < 0 || mt != DHCPOFFER) {
        warnx("timeout waiting for DHCPOFFER");
        return 1;
    }

    if (offer.server_id == 0) {
        warnx("offer missing server identifier (option 54)");
        return 1;
    }

    dhcp_len = build_dhcp_request(dhcp_buf, sizeof(dhcp_buf), mac, xid_be, offer.yiaddr, offer.server_id);
    if (dhcp_len == 0) die("build_dhcp_request");
    if (send_dhcp_packet(pfd, mac, dhcp_buf, dhcp_len) < 0) die("send(packet:request)");

    struct dhcp_offer ack;
    int mt2 = 0;
    if (recv_dhcp_message_any(pfd, fd, xid_be, &ack, &mt2, deadline) < 0) {
        warnx("timeout waiting for DHCPACK");
        return 1;
    }
    if (mt2 == DHCPNAK) {
        warnx("received DHCPNAK");
        return 1;
    }
    if (mt2 != DHCPACK) {
        warnx("unexpected DHCP message (expected ACK)");
        return 1;
    }

    // Prefer options from ACK; fall back to OFFER if missing.
    uint32_t ip_be = ack.yiaddr ? ack.yiaddr : offer.yiaddr;
    uint32_t mask_be = ack.subnet_mask ? ack.subnet_mask : offer.subnet_mask;
    uint32_t gw_be = ack.router ? ack.router : offer.router;
    uint32_t dns0 = (ack.dns_count > 0) ? ack.dns[0] : (offer.dns_count > 0 ? offer.dns[0] : 0);
    uint32_t dns1 = (ack.dns_count > 1) ? ack.dns[1] : (offer.dns_count > 1 ? offer.dns[1] : 0);
    uint32_t dns[2] = {dns0, dns1};
    int dns_count = 0;
    if (dns0) dns_count++;
    if (dns1) dns_count++;

    if (!ip_be) {
        warnx("no yiaddr in ACK");
        return 1;
    }

    int prefix_len = 24;
    if (mask_be) {
        int pfx = prefix_len_from_netmask(mask_be);
        if (pfx >= 0) prefix_len = pfx;
    }

    fprintf(stderr, "edhcpc: bound ");
    print_ipv4("", ip_be);
    fprintf(stderr, "/%d", prefix_len);
    if (gw_be) {
        fprintf(stderr, " gw=");
        print_ipv4("", gw_be);
    }
    fprintf(stderr, "\n");

    if (apply_ipv4_addr(ifindex, ifname, ip_be, prefix_len) < 0) die("netlink(RTM_NEWADDR)");
    if (gw_be) {
        if (apply_default_route(ifindex, gw_be) < 0) die("netlink(RTM_NEWROUTE)");
    }
    if (dns_count) write_resolv_conf(dns, dns_count);

    close(pfd);
    close(fd);
    return 0;
}
