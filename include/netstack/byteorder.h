/* Host <-> network byte-order helpers.
 *
 * Network protocols are big-endian. Rather than depend on the platform's
 * <arpa/inet.h> (which is not available everywhere and drags in extra
 * headers), we provide tiny portable conversions. They are correct on both
 * little- and big-endian hosts because they work on bytes, not on the host's
 * native integer layout.
 */
#ifndef NETSTACK_BYTEORDER_H
#define NETSTACK_BYTEORDER_H

#include <stdint.h>

/* Read a 16-bit big-endian value from a byte buffer. */
static inline uint16_t ns_get_be16(const uint8_t *p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}

/* Read a 32-bit big-endian value from a byte buffer. */
static inline uint32_t ns_get_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/* Write a 16-bit value to a byte buffer in big-endian order. */
static inline void ns_put_be16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xff);
}

/* Write a 32-bit value to a byte buffer in big-endian order. */
static inline void ns_put_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v & 0xff);
}

#endif /* NETSTACK_BYTEORDER_H */
