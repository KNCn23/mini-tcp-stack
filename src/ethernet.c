#include "netstack/ethernet.h"
#include "netstack/byteorder.h"

#include <string.h>

int eth_parse(const uint8_t *frame, size_t len, eth_hdr_t *out) {
    if (len < ETH_HDR_LEN)
        return -1;
    memcpy(out->dst, frame, ETH_ALEN);
    memcpy(out->src, frame + ETH_ALEN, ETH_ALEN);
    out->ethertype = ns_get_be16(frame + 12);
    return 0;
}

size_t eth_build(uint8_t *frame, const eth_hdr_t *hdr) {
    memcpy(frame, hdr->dst, ETH_ALEN);
    memcpy(frame + ETH_ALEN, hdr->src, ETH_ALEN);
    ns_put_be16(frame + 12, hdr->ethertype);
    return ETH_HDR_LEN;
}
