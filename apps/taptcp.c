/* taptcp - run the stack on a Linux TAP device.
 *
 * This brings the whole stack to life: it answers ARP, replies to ping, and
 * accepts a single TCP connection on port 7 (echo), bouncing back whatever you
 * send. It is the "integration demo" that ties together every module the unit
 * tests exercise in isolation.
 *
 * TAP devices are a Linux feature (/dev/net/tun), so this file only builds on
 * Linux. The library itself (src/) is portable and its tests run anywhere.
 *
 * Usage (see the README for the full walkthrough):
 *
 *   make taptcp
 *   sudo ./build/taptcp                 # creates and uses tap0
 *   # in another terminal, as root:
 *   sudo ip addr add 10.0.0.1/24 dev tap0
 *   sudo ip link set tap0 up
 *   ping 10.0.0.2
 *   nc 10.0.0.2 7
 */
#if !defined(__linux__)
#error "taptcp uses Linux TAP devices and only builds on Linux. \
The library and its unit tests (make test) are portable."
#endif

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "netstack/arp.h"
#include "netstack/ethernet.h"
#include "netstack/icmp.h"
#include "netstack/ipv4.h"
#include "netstack/tcp.h"

/* The address this stack answers to. The host side (tap0) is 10.0.0.1. */
static const uint8_t OUR_IP[4]  = {10, 0, 0, 2};
static const uint8_t OUR_MAC[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};
#define ECHO_PORT 7

/* Open a TAP device and return its file descriptor. */
static int tap_alloc(const char *name) {
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        perror("open /dev/net/tun");
        return -1;
    }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;   /* raw Ethernet frames, no prefix */
    strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        perror("ioctl TUNSETIFF (are you root?)");
        close(fd);
        return -1;
    }
    return fd;
}

/* Wrap an L3 payload (already including its own header, e.g. ICMP or TCP) in
 * IPv4 + Ethernet and write it to the TAP device. */
static void send_ip(int fd, const eth_hdr_t *req_eth, uint8_t proto,
                    const uint8_t dst_ip[4], const uint8_t *l3, size_t l3_len) {
    uint8_t frame[1600];
    eth_hdr_t eth;
    memcpy(eth.dst, req_eth->src, ETH_ALEN);   /* back to the sender */
    memcpy(eth.src, OUR_MAC, ETH_ALEN);
    eth.ethertype = ETH_TYPE_IPV4;
    size_t off = eth_build(frame, &eth);

    ipv4_hdr_t ip = {0};
    ip.ttl = 64;
    ip.protocol = proto;
    ip.total_length = (uint16_t)(IPV4_HDR_LEN + l3_len);
    ip.id = 0;
    memcpy(ip.src, OUR_IP, 4);
    memcpy(ip.dst, dst_ip, 4);
    off += ipv4_build(frame + off, &ip);

    memcpy(frame + off, l3, l3_len);
    off += l3_len;

    if (write(fd, frame, off) < 0)
        perror("write");
}

static void handle_arp(int fd, const eth_hdr_t *eth, const uint8_t *payload,
                       size_t len) {
    arp_packet_t req;
    if (arp_parse(payload, len, &req) != 0)
        return;
    arp_packet_t reply;
    if (arp_make_reply(&req, OUR_IP, OUR_MAC, &reply) != 0)
        return;

    uint8_t frame[64];
    eth_hdr_t reth;
    memcpy(reth.dst, eth->src, ETH_ALEN);
    memcpy(reth.src, OUR_MAC, ETH_ALEN);
    reth.ethertype = ETH_TYPE_ARP;
    size_t off = eth_build(frame, &reth);
    off += arp_build(frame + off, &reply);
    if (write(fd, frame, off) < 0)
        perror("write");
    printf("ARP: told %u.%u.%u.%u that we are at 10.0.0.2\n",
           req.sender_ip[0], req.sender_ip[1], req.sender_ip[2], req.sender_ip[3]);
}

static void send_tcp(int fd, const eth_hdr_t *eth, const uint8_t remote_ip[4],
                     const tcp_output_t *out) {
    uint8_t seg[1500];
    size_t n = tcp_build(seg, OUR_IP, remote_ip, out);
    send_ip(fd, eth, IP_PROTO_TCP, remote_ip, seg, n);
}

static void handle_tcp(int fd, const eth_hdr_t *eth, const ipv4_hdr_t *ip,
                       const uint8_t *payload, size_t len, tcp_conn_t *conn) {
    tcp_segment_t seg;
    if (tcp_parse(payload, len, ip->src, ip->dst, &seg) != 0)
        return;
    if (seg.dst_port != ECHO_PORT)
        return;

    memcpy(conn->remote_ip, ip->src, 4);
    tcp_state_t before = conn->state;

    tcp_output_t out;
    tcp_input(conn, &seg, &out);
    if (out.send)
        send_tcp(fd, eth, ip->src, &out);

    /* Echo any freshly received bytes straight back. */
    if (conn->rxlen > 0 && conn->state == TCP_ESTABLISHED) {
        tcp_output_t data;
        if (tcp_send(conn, conn->rxbuf, conn->rxlen, &data) == 0) {
            send_tcp(fd, eth, ip->src, &data);
            printf("TCP: echoed %zu byte(s)\n", conn->rxlen);
            conn->rxlen = 0;
        }
    }

    if (before != conn->state)
        printf("TCP: %s -> %s\n", tcp_state_name(before),
               tcp_state_name(conn->state));

    /* Once a connection fully closes, re-arm the listener for the next one. */
    if (conn->state == TCP_CLOSED)
        tcp_listen(conn, OUR_IP, ECHO_PORT, 1000);
}

int main(void) {
    int fd = tap_alloc("tap0");
    if (fd < 0)
        return 1;

    tcp_conn_t conn;
    tcp_listen(&conn, OUR_IP, ECHO_PORT, /*iss=*/1000);

    printf("mini-tcp-stack listening as 10.0.0.2 on tap0\n");
    printf("  ping 10.0.0.2   and   nc 10.0.0.2 %d\n\n", ECHO_PORT);

    uint8_t frame[2048];
    for (;;) {
        ssize_t n = read(fd, frame, sizeof(frame));
        if (n <= 0)
            continue;

        eth_hdr_t eth;
        if (eth_parse(frame, (size_t)n, &eth) != 0)
            continue;
        const uint8_t *payload = frame + ETH_HDR_LEN;
        size_t plen = (size_t)n - ETH_HDR_LEN;

        if (eth.ethertype == ETH_TYPE_ARP) {
            handle_arp(fd, &eth, payload, plen);
        } else if (eth.ethertype == ETH_TYPE_IPV4) {
            ipv4_hdr_t ip;
            if (ipv4_parse(payload, plen, &ip) != 0)
                continue;
            if (memcmp(ip.dst, OUR_IP, 4) != 0)
                continue;
            const uint8_t *l4 = payload + IPV4_HDR_LEN;
            size_t l4len = ip.total_length - IPV4_HDR_LEN;

            if (ip.protocol == IP_PROTO_ICMP) {
                uint8_t reply[1500];
                int r = icmp_make_echo_reply(l4, l4len, reply);
                if (r > 0) {
                    send_ip(fd, &eth, IP_PROTO_ICMP, ip.src, reply, (size_t)r);
                    printf("ICMP: echo reply to %u.%u.%u.%u\n",
                           ip.src[0], ip.src[1], ip.src[2], ip.src[3]);
                }
            } else if (ip.protocol == IP_PROTO_TCP) {
                handle_tcp(fd, &eth, &ip, l4, l4len, &conn);
            }
        }
    }
    return 0;
}
