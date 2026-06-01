#include "netstack/arp.h"
#include "netstack/byteorder.h"

#include <string.h>

/* Fixed header fields for IPv4-over-Ethernet ARP. */
#define ARP_HTYPE_ETHERNET 1
#define ARP_PTYPE_IPV4     ETH_TYPE_IPV4
#define ARP_HLEN_ETHERNET  6
#define ARP_PLEN_IPV4      4

int arp_parse(const uint8_t *buf, size_t len, arp_packet_t *out) {
    if (len < ARP_HDR_LEN)
        return -1;
    if (ns_get_be16(buf) != ARP_HTYPE_ETHERNET)
        return -1;
    if (ns_get_be16(buf + 2) != ARP_PTYPE_IPV4)
        return -1;
    if (buf[4] != ARP_HLEN_ETHERNET || buf[5] != ARP_PLEN_IPV4)
        return -1;

    out->opcode = ns_get_be16(buf + 6);
    memcpy(out->sender_mac, buf + 8, ETH_ALEN);
    memcpy(out->sender_ip, buf + 14, 4);
    memcpy(out->target_mac, buf + 18, ETH_ALEN);
    memcpy(out->target_ip, buf + 24, 4);
    return 0;
}

size_t arp_build(uint8_t *buf, const arp_packet_t *pkt) {
    ns_put_be16(buf, ARP_HTYPE_ETHERNET);
    ns_put_be16(buf + 2, ARP_PTYPE_IPV4);
    buf[4] = ARP_HLEN_ETHERNET;
    buf[5] = ARP_PLEN_IPV4;
    ns_put_be16(buf + 6, pkt->opcode);
    memcpy(buf + 8, pkt->sender_mac, ETH_ALEN);
    memcpy(buf + 14, pkt->sender_ip, 4);
    memcpy(buf + 18, pkt->target_mac, ETH_ALEN);
    memcpy(buf + 24, pkt->target_ip, 4);
    return ARP_HDR_LEN;
}

int arp_make_reply(const arp_packet_t *request, const uint8_t our_ip[4],
                   const uint8_t our_mac[ETH_ALEN], arp_packet_t *reply) {
    if (request->opcode != ARP_OP_REQUEST)
        return -1;
    if (memcmp(request->target_ip, our_ip, 4) != 0)
        return -1; /* not asking about us */

    reply->opcode = ARP_OP_REPLY;
    memcpy(reply->sender_mac, our_mac, ETH_ALEN);
    memcpy(reply->sender_ip, our_ip, 4);
    /* The reply is unicast back to whoever asked. */
    memcpy(reply->target_mac, request->sender_mac, ETH_ALEN);
    memcpy(reply->target_ip, request->sender_ip, 4);
    return 0;
}

/* --- cache -------------------------------------------------------------- */

void arp_cache_init(arp_cache_t *c) {
    memset(c, 0, sizeof(*c));
}

void arp_cache_put(arp_cache_t *c, const uint8_t ip[4],
                   const uint8_t mac[ETH_ALEN]) {
    /* Update in place if the IP is already known. */
    for (int i = 0; i < ARP_CACHE_SIZE; i++) {
        if (c->entries[i].valid && memcmp(c->entries[i].ip, ip, 4) == 0) {
            memcpy(c->entries[i].mac, mac, ETH_ALEN);
            return;
        }
    }
    /* Otherwise take the first free slot. */
    for (int i = 0; i < ARP_CACHE_SIZE; i++) {
        if (!c->entries[i].valid) {
            memcpy(c->entries[i].ip, ip, 4);
            memcpy(c->entries[i].mac, mac, ETH_ALEN);
            c->entries[i].valid = 1;
            return;
        }
    }
    /* Cache full: evict slot 0 (simple round-robin-ish replacement). */
    memcpy(c->entries[0].ip, ip, 4);
    memcpy(c->entries[0].mac, mac, ETH_ALEN);
}

int arp_cache_lookup(const arp_cache_t *c, const uint8_t ip[4],
                     uint8_t mac_out[ETH_ALEN]) {
    for (int i = 0; i < ARP_CACHE_SIZE; i++) {
        if (c->entries[i].valid && memcmp(c->entries[i].ip, ip, 4) == 0) {
            memcpy(mac_out, c->entries[i].mac, ETH_ALEN);
            return 1;
        }
    }
    return 0;
}
