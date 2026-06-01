/* ICMP (RFC 792) - just enough to answer a ping.
 *
 * An echo request (type 8) is turned into an echo reply (type 0) by changing
 * the type byte and recomputing the checksum; the identifier, sequence number
 * and payload are echoed back unchanged.
 */
#ifndef NETSTACK_ICMP_H
#define NETSTACK_ICMP_H

#include <stddef.h>
#include <stdint.h>

#define ICMP_TYPE_ECHO_REPLY   0
#define ICMP_TYPE_ECHO_REQUEST 8
#define ICMP_HDR_LEN           8   /* type, code, csum, id, seq */

/* Turn an ICMP echo *request* in `in` (length `len`, including the 8-byte
 * header and any payload) into an echo *reply* written to `out`. `out` must be
 * at least `len` bytes. Returns the reply length on success, or -1 if the
 * input is not a valid echo request. */
int icmp_make_echo_reply(const uint8_t *in, size_t len, uint8_t *out);

#endif /* NETSTACK_ICMP_H */
