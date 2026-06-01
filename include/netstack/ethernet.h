/* Ethernet II framing (the L2 layer).
 *
 * An Ethernet frame is a 14-byte header followed by the payload:
 *
 *   +-------------------+-------------------+-----------+
 *   | dst MAC (6 bytes) | src MAC (6 bytes) | type (2)  |  payload ...
 *   +-------------------+-------------------+-----------+
 */
#ifndef NETSTACK_ETHERNET_H
#define NETSTACK_ETHERNET_H

#include <stddef.h>
#include <stdint.h>

#define ETH_ALEN       6      /* bytes in a MAC address */
#define ETH_HDR_LEN    14     /* dst + src + ethertype  */

/* EtherType values we understand. */
#define ETH_TYPE_IPV4  0x0800
#define ETH_TYPE_ARP   0x0806

/* A parsed Ethernet header (host byte order for `ethertype`). */
typedef struct {
    uint8_t  dst[ETH_ALEN];
    uint8_t  src[ETH_ALEN];
    uint16_t ethertype;
} eth_hdr_t;

/* Parse the 14-byte header at `frame`. Returns 0 on success and fills `out`,
 * or -1 if `len` is too small. The payload starts at frame + ETH_HDR_LEN. */
int eth_parse(const uint8_t *frame, size_t len, eth_hdr_t *out);

/* Serialise `hdr` into the first ETH_HDR_LEN bytes of `frame`. The caller must
 * ensure the buffer is at least ETH_HDR_LEN bytes. Returns ETH_HDR_LEN. */
size_t eth_build(uint8_t *frame, const eth_hdr_t *hdr);

#endif /* NETSTACK_ETHERNET_H */
