/* IPv4 (RFC 791) - the network layer.
 *
 * We handle the common 20-byte header (no options). The header carries the
 * source/destination addresses, the upper-layer protocol number, and a
 * checksum that covers the header only.
 */
#ifndef NETSTACK_IPV4_H
#define NETSTACK_IPV4_H

#include <stddef.h>
#include <stdint.h>

#define IPV4_HDR_LEN     20
#define IPV4_VERSION     4

/* Protocol numbers we care about (IANA assigned). */
#define IP_PROTO_ICMP    1
#define IP_PROTO_TCP     6
#define IP_PROTO_UDP     17

/* A parsed IPv4 header. Addresses are kept as raw 4-byte arrays so byte order
 * is never ambiguous. */
typedef struct {
    uint8_t  version;       /* always 4 here */
    uint8_t  ihl;           /* header length in 32-bit words (5 = no options) */
    uint8_t  ttl;
    uint8_t  protocol;      /* IP_PROTO_* */
    uint16_t total_length;  /* header + payload, host order */
    uint16_t id;
    uint8_t  src[4];
    uint8_t  dst[4];
} ipv4_hdr_t;

/* Parse a 20-byte IPv4 header. Returns 0 on success, -1 if too short, the
 * version is not 4, options are present (ihl > 5), or the header checksum is
 * wrong. On success the payload starts at buf + IPV4_HDR_LEN. */
int ipv4_parse(const uint8_t *buf, size_t len, ipv4_hdr_t *out);

/* Build a 20-byte header into `buf`, computing the checksum. `total_length`,
 * `protocol`, `src`, `dst` and `ttl` must be set in `hdr`; `version`/`ihl`
 * are forced to a standard IPv4 header. Returns IPV4_HDR_LEN. */
size_t ipv4_build(uint8_t *buf, const ipv4_hdr_t *hdr);

#endif /* NETSTACK_IPV4_H */
