#include "netstack/ipv4.h"
#include "netstack/byteorder.h"
#include "netstack/checksum.h"

#include <string.h>

int ipv4_parse(const uint8_t *buf, size_t len, ipv4_hdr_t *out) {
    if (len < IPV4_HDR_LEN)
        return -1;

    uint8_t version = buf[0] >> 4;
    uint8_t ihl = buf[0] & 0x0f;
    if (version != IPV4_VERSION)
        return -1;
    if (ihl < 5)            /* malformed: header shorter than 20 bytes */
        return -1;
    if (ihl > 5)            /* options present: not supported by this stack */
        return -1;

    /* The header checksum covers exactly the 20 header bytes and must fold to
     * zero when the stored checksum is included. */
    if (ns_checksum(buf, IPV4_HDR_LEN) != 0)
        return -1;

    out->version = version;
    out->ihl = ihl;
    out->total_length = ns_get_be16(buf + 2);
    out->id = ns_get_be16(buf + 4);
    out->ttl = buf[8];
    out->protocol = buf[9];
    memcpy(out->src, buf + 12, 4);
    memcpy(out->dst, buf + 16, 4);
    return 0;
}

size_t ipv4_build(uint8_t *buf, const ipv4_hdr_t *hdr) {
    memset(buf, 0, IPV4_HDR_LEN);
    buf[0] = (IPV4_VERSION << 4) | 5;       /* version 4, ihl 5 (no options) */
    buf[1] = 0;                              /* DSCP / ECN */
    ns_put_be16(buf + 2, hdr->total_length);
    ns_put_be16(buf + 4, hdr->id);
    ns_put_be16(buf + 6, 0);                 /* flags + fragment offset */
    buf[8] = hdr->ttl;
    buf[9] = hdr->protocol;
    ns_put_be16(buf + 10, 0);                /* checksum placeholder */
    memcpy(buf + 12, hdr->src, 4);
    memcpy(buf + 16, hdr->dst, 4);

    uint16_t csum = ns_checksum(buf, IPV4_HDR_LEN);
    ns_put_be16(buf + 10, csum);
    return IPV4_HDR_LEN;
}
