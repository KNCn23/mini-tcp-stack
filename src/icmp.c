#include "netstack/icmp.h"
#include "netstack/byteorder.h"
#include "netstack/checksum.h"

#include <string.h>

int icmp_make_echo_reply(const uint8_t *in, size_t len, uint8_t *out) {
    if (len < ICMP_HDR_LEN)
        return -1;
    if (in[0] != ICMP_TYPE_ECHO_REQUEST)
        return -1;
    /* Validate the request checksum (covers the whole ICMP message). */
    if (ns_checksum(in, len) != 0)
        return -1;

    /* Copy everything, then patch the type and recompute the checksum. The
     * identifier, sequence number and payload are echoed verbatim. */
    memcpy(out, in, len);
    out[0] = ICMP_TYPE_ECHO_REPLY;
    out[1] = 0;                      /* code */
    ns_put_be16(out + 2, 0);         /* clear checksum before recomputing */
    uint16_t csum = ns_checksum(out, len);
    ns_put_be16(out + 2, csum);
    return (int)len;
}
