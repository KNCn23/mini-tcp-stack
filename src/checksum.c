#include "netstack/checksum.h"

void ns_csum_init(ns_csum_t *c) {
    c->sum = 0;
    c->odd = 0;
    c->carry = 0;
}

void ns_csum_update(ns_csum_t *c, const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;

    /* If a previous chunk ended on an odd byte, pair it with the first byte
     * of this chunk so 16-bit alignment is preserved across calls. */
    if (c->odd && len > 0) {
        c->sum += (uint32_t)((c->carry << 8) | *p);
        p++;
        len--;
        c->odd = 0;
    }

    /* Sum full 16-bit big-endian words. */
    while (len > 1) {
        c->sum += (uint32_t)((p[0] << 8) | p[1]);
        p += 2;
        len -= 2;
    }

    /* Stash a trailing odd byte for the next call (or for finalisation). */
    if (len == 1) {
        c->carry = *p;
        c->odd = 1;
    }
}

uint16_t ns_csum_final(const ns_csum_t *c) {
    uint32_t sum = c->sum;

    /* A leftover odd byte is treated as the high byte of a word padded with a
     * zero low byte, exactly as RFC 1071 specifies. */
    if (c->odd)
        sum += (uint32_t)(c->carry << 8);

    /* Fold the carries back in until the sum fits in 16 bits. */
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    /* One's complement. The accumulator read words big-endian, so the result
     * is the host value of the checksum; callers store it with ns_put_be16().
     * A correctly-checksummed packet (including its checksum field) folds to
     * 0xffff, so re-running ns_checksum over it yields 0. */
    return (uint16_t)~sum;
}

uint16_t ns_checksum(const void *data, size_t len) {
    ns_csum_t c;
    ns_csum_init(&c);
    ns_csum_update(&c, data, len);
    return ns_csum_final(&c);
}
