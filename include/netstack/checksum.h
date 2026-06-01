/* The Internet checksum (RFC 1071).
 *
 * IPv4, ICMP, TCP and UDP all use the same one's-complement sum of 16-bit
 * words. TCP and UDP additionally fold in a "pseudo-header" built from the IP
 * addresses, so we expose an incremental API: start a sum, feed it buffers,
 * then finalise.
 */
#ifndef NETSTACK_CHECKSUM_H
#define NETSTACK_CHECKSUM_H

#include <stddef.h>
#include <stdint.h>

/* Accumulator for an incremental checksum. Zero-initialise before use, or use
 * ns_checksum() for the common single-buffer case. */
typedef struct {
    uint32_t sum;   /* running 32-bit sum of 16-bit words */
    int odd;        /* 1 if a leftover low byte is pending */
    uint8_t carry;  /* the pending high byte when odd == 1 */
} ns_csum_t;

/* Reset an accumulator to its initial state. */
void ns_csum_init(ns_csum_t *c);

/* Add `len` bytes from `data` to the running sum. May be called repeatedly. */
void ns_csum_update(ns_csum_t *c, const void *data, size_t len);

/* Fold the running sum to 16 bits and return the one's-complement result,
 * in network byte order, ready to drop into a header field. */
uint16_t ns_csum_final(const ns_csum_t *c);

/* Convenience: checksum a single contiguous buffer. */
uint16_t ns_checksum(const void *data, size_t len);

#endif /* NETSTACK_CHECKSUM_H */
