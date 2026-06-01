/* Round-trip tests for Ethernet, ARP, IPv4 and ICMP. */
#include "netstack/ethernet.h"
#include "netstack/arp.h"
#include "netstack/ipv4.h"
#include "netstack/icmp.h"
#include "netstack/byteorder.h"
#include "netstack/checksum.h"
#include "test_util.h"

#include <string.h>

static void test_ethernet_roundtrip(void) {
    eth_hdr_t in = {
        .dst = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
        .src = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
        .ethertype = ETH_TYPE_IPV4,
    };
    uint8_t frame[ETH_HDR_LEN];
    CHECK_EQ(eth_build(frame, &in), ETH_HDR_LEN);

    eth_hdr_t out;
    CHECK_EQ(eth_parse(frame, sizeof(frame), &out), 0);
    CHECK(memcmp(in.dst, out.dst, ETH_ALEN) == 0);
    CHECK(memcmp(in.src, out.src, ETH_ALEN) == 0);
    CHECK_EQ(out.ethertype, ETH_TYPE_IPV4);
}

static void test_ethernet_short_frame_rejected(void) {
    uint8_t tiny[4] = {0};
    eth_hdr_t out;
    CHECK_EQ(eth_parse(tiny, sizeof(tiny), &out), -1);
}

static void test_arp_reply_to_request(void) {
    uint8_t our_ip[4] = {10, 0, 0, 2};
    uint8_t our_mac[6] = {0x02, 0, 0, 0, 0, 0x02};

    arp_packet_t req = {
        .opcode = ARP_OP_REQUEST,
        .sender_mac = {0x02, 0, 0, 0, 0, 0x01},
        .sender_ip = {10, 0, 0, 1},
        .target_mac = {0, 0, 0, 0, 0, 0},
        .target_ip = {10, 0, 0, 2},
    };
    uint8_t wire[ARP_HDR_LEN];
    CHECK_EQ(arp_build(wire, &req), ARP_HDR_LEN);

    arp_packet_t parsed;
    CHECK_EQ(arp_parse(wire, sizeof(wire), &parsed), 0);
    CHECK_EQ(parsed.opcode, ARP_OP_REQUEST);

    arp_packet_t reply;
    CHECK_EQ(arp_make_reply(&parsed, our_ip, our_mac, &reply), 0);
    CHECK_EQ(reply.opcode, ARP_OP_REPLY);
    CHECK(memcmp(reply.sender_mac, our_mac, 6) == 0);
    CHECK(memcmp(reply.sender_ip, our_ip, 4) == 0);
    CHECK(memcmp(reply.target_ip, req.sender_ip, 4) == 0);
}

static void test_arp_request_for_someone_else_ignored(void) {
    uint8_t our_ip[4] = {10, 0, 0, 2};
    uint8_t our_mac[6] = {0x02, 0, 0, 0, 0, 0x02};
    arp_packet_t req = {.opcode = ARP_OP_REQUEST, .target_ip = {10, 0, 0, 99}};
    arp_packet_t reply;
    CHECK_EQ(arp_make_reply(&req, our_ip, our_mac, &reply), -1);
}

static void test_arp_cache(void) {
    arp_cache_t cache;
    arp_cache_init(&cache);
    uint8_t ip[4] = {192, 168, 1, 5};
    uint8_t mac[6] = {1, 2, 3, 4, 5, 6};
    uint8_t got[6];
    CHECK_EQ(arp_cache_lookup(&cache, ip, got), 0);    /* miss */
    arp_cache_put(&cache, ip, mac);
    CHECK_EQ(arp_cache_lookup(&cache, ip, got), 1);    /* hit */
    CHECK(memcmp(got, mac, 6) == 0);
    /* Update existing entry. */
    uint8_t mac2[6] = {9, 9, 9, 9, 9, 9};
    arp_cache_put(&cache, ip, mac2);
    CHECK_EQ(arp_cache_lookup(&cache, ip, got), 1);
    CHECK(memcmp(got, mac2, 6) == 0);
}

static void test_ipv4_build_then_parse(void) {
    ipv4_hdr_t in = {
        .ttl = 64,
        .protocol = IP_PROTO_TCP,
        .total_length = 40,
        .id = 0x1234,
        .src = {10, 0, 0, 2},
        .dst = {10, 0, 0, 1},
    };
    uint8_t buf[IPV4_HDR_LEN];
    CHECK_EQ(ipv4_build(buf, &in), IPV4_HDR_LEN);
    /* A freshly-built header must validate (checksum folds to zero). */
    CHECK_EQ(ns_checksum(buf, IPV4_HDR_LEN), 0);

    ipv4_hdr_t out;
    CHECK_EQ(ipv4_parse(buf, sizeof(buf), &out), 0);
    CHECK_EQ(out.ttl, 64);
    CHECK_EQ(out.protocol, IP_PROTO_TCP);
    CHECK_EQ(out.total_length, 40);
    CHECK(memcmp(out.src, in.src, 4) == 0);
    CHECK(memcmp(out.dst, in.dst, 4) == 0);
}

static void test_ipv4_corrupt_checksum_rejected(void) {
    ipv4_hdr_t in = {.ttl = 64, .protocol = IP_PROTO_TCP, .total_length = 20,
                     .src = {1, 1, 1, 1}, .dst = {2, 2, 2, 2}};
    uint8_t buf[IPV4_HDR_LEN];
    ipv4_build(buf, &in);
    buf[12] ^= 0xff;                 /* corrupt the source address */
    ipv4_hdr_t out;
    CHECK_EQ(ipv4_parse(buf, sizeof(buf), &out), -1);
}

static void test_icmp_echo_reply(void) {
    /* An 8-byte ICMP header + 4 bytes of payload. */
    uint8_t req[12] = {
        ICMP_TYPE_ECHO_REQUEST, 0, 0, 0,     /* type, code, csum (filled) */
        0x12, 0x34, 0x00, 0x01,              /* id, seq */
        'p', 'i', 'n', 'g',                  /* payload */
    };
    uint16_t c = ns_checksum(req, sizeof(req));
    ns_put_be16(req + 2, c);

    uint8_t reply[12];
    int n = icmp_make_echo_reply(req, sizeof(req), reply);
    CHECK_EQ(n, 12);
    CHECK_EQ(reply[0], ICMP_TYPE_ECHO_REPLY);
    /* Identifier, sequence and payload are echoed unchanged. */
    CHECK(memcmp(reply + 4, req + 4, 8) == 0);
    /* The reply carries a valid checksum. */
    CHECK_EQ(ns_checksum(reply, sizeof(reply)), 0);
}

int main(void) {
    RUN(test_ethernet_roundtrip);
    RUN(test_ethernet_short_frame_rejected);
    RUN(test_arp_reply_to_request);
    RUN(test_arp_request_for_someone_else_ignored);
    RUN(test_arp_cache);
    RUN(test_ipv4_build_then_parse);
    RUN(test_ipv4_corrupt_checksum_rejected);
    RUN(test_icmp_echo_reply);
    TEST_SUMMARY();
}
