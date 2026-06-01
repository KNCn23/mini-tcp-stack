/* ARP - Address Resolution Protocol (RFC 826) for IPv4 over Ethernet.
 *
 * ARP maps a 32-bit IPv4 address to a 48-bit MAC address. A host that wants to
 * send to an IP it has not seen broadcasts a "who-has" request; the owner
 * replies with its MAC. We implement request/reply parsing, reply building,
 * and a small fixed-size cache.
 */
#ifndef NETSTACK_ARP_H
#define NETSTACK_ARP_H

#include <stddef.h>
#include <stdint.h>

#include "netstack/ethernet.h"

#define ARP_HDR_LEN     28           /* for IPv4-over-Ethernet */
#define ARP_OP_REQUEST  1
#define ARP_OP_REPLY    2
#define ARP_CACHE_SIZE  16

/* A parsed ARP packet (the fixed IPv4/Ethernet shape). */
typedef struct {
    uint16_t opcode;                 /* ARP_OP_REQUEST or ARP_OP_REPLY */
    uint8_t  sender_mac[ETH_ALEN];
    uint8_t  sender_ip[4];
    uint8_t  target_mac[ETH_ALEN];
    uint8_t  target_ip[4];
} arp_packet_t;

/* Parse an ARP payload (the bytes after the Ethernet header). Returns 0 and
 * fills `out` on success, -1 if the buffer is too small or not IPv4/Ethernet
 * ARP. */
int arp_parse(const uint8_t *buf, size_t len, arp_packet_t *out);

/* Serialise `pkt` into `buf` (must hold ARP_HDR_LEN bytes). Returns the number
 * of bytes written (ARP_HDR_LEN). */
size_t arp_build(uint8_t *buf, const arp_packet_t *pkt);

/* Build the ARP reply that answers `request`, announcing that `our_ip` is at
 * `our_mac`. Returns 0 on success, -1 if the request does not target us. */
int arp_make_reply(const arp_packet_t *request, const uint8_t our_ip[4],
                   const uint8_t our_mac[ETH_ALEN], arp_packet_t *reply);

/* --- a tiny ARP cache ------------------------------------------------- */

typedef struct {
    struct {
        uint8_t ip[4];
        uint8_t mac[ETH_ALEN];
        int     valid;
    } entries[ARP_CACHE_SIZE];
} arp_cache_t;

void arp_cache_init(arp_cache_t *c);

/* Insert or update the mapping ip -> mac (least-recently-added eviction). */
void arp_cache_put(arp_cache_t *c, const uint8_t ip[4], const uint8_t mac[ETH_ALEN]);

/* Look up `ip`. On hit, copies the MAC into `mac_out` and returns 1; returns 0
 * on miss. */
int arp_cache_lookup(const arp_cache_t *c, const uint8_t ip[4], uint8_t mac_out[ETH_ALEN]);

#endif /* NETSTACK_ARP_H */
