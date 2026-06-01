/* TCP (RFC 793) - a deliberately small, readable subset.
 *
 * What this implements:
 *   - header parse/build with the pseudo-header checksum
 *   - the passive-open three-way handshake (LISTEN -> SYN_RECEIVED ->
 *     ESTABLISHED)
 *   - in-order data receive with cumulative ACKs
 *   - sending application data
 *   - graceful teardown (FIN handshake) from either side
 *
 * What it intentionally leaves out (documented in the README): retransmission
 * timers, congestion control, sliding-window flow control beyond a static
 * advertised window, out-of-order reassembly, and TCP options. The goal is to
 * make the state machine and on-the-wire format easy to read and test, not to
 * be production-ready.
 */
#ifndef NETSTACK_TCP_H
#define NETSTACK_TCP_H

#include <stddef.h>
#include <stdint.h>

#define TCP_MIN_HDR_LEN 20
#define TCP_RXBUF       2048
#define TCP_DEFAULT_WND 1024

/* Control-bit flags. */
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20

/* Connection states (RFC 793 figure 6). */
typedef enum {
    TCP_CLOSED = 0,
    TCP_LISTEN,
    TCP_SYN_SENT,
    TCP_SYN_RECEIVED,
    TCP_ESTABLISHED,
    TCP_FIN_WAIT_1,
    TCP_FIN_WAIT_2,
    TCP_CLOSE_WAIT,
    TCP_CLOSING,
    TCP_LAST_ACK,
    TCP_TIME_WAIT
} tcp_state_t;

/* A parsed TCP segment. `payload` points into the caller's buffer. */
typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t  data_offset;   /* header length in 32-bit words */
    uint8_t  flags;         /* TCP_FIN .. TCP_URG */
    uint16_t window;
    const uint8_t *payload;
    size_t   payload_len;
} tcp_segment_t;

/* A segment the stack wants to transmit, produced by the functions below. */
typedef struct {
    int      send;          /* 0 = nothing to send */
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t  flags;
    uint16_t window;
    const uint8_t *data;
    size_t   data_len;
} tcp_output_t;

/* The per-connection control block. */
typedef struct {
    tcp_state_t state;
    uint8_t  local_ip[4];
    uint8_t  remote_ip[4];
    uint16_t local_port;
    uint16_t remote_port;

    uint32_t iss;        /* our initial send sequence number */
    uint32_t snd_una;    /* oldest unacknowledged sequence number */
    uint32_t snd_nxt;    /* next sequence number to send */
    uint32_t rcv_nxt;    /* next sequence number we expect to receive */
    uint16_t rcv_wnd;    /* advertised receive window */

    uint8_t  rxbuf[TCP_RXBUF];  /* delivered, in-order application data */
    size_t   rxlen;
} tcp_conn_t;

/* --- wire format ------------------------------------------------------- */

/* Parse a TCP segment from `buf`/`len`. The 12-byte pseudo-header checksum is
 * verified using `src_ip`/`dst_ip`. Returns 0 on success, -1 on a short buffer
 * or checksum failure. */
int tcp_parse(const uint8_t *buf, size_t len,
              const uint8_t src_ip[4], const uint8_t dst_ip[4],
              tcp_segment_t *out);

/* Serialise `out` (header + optional data) into `buf`, computing the checksum
 * from `src_ip`/`dst_ip`. Returns the total number of bytes written. */
size_t tcp_build(uint8_t *buf, const uint8_t src_ip[4], const uint8_t dst_ip[4],
                 const tcp_output_t *out);

/* --- connection state machine ----------------------------------------- */

/* Put a fresh connection block into the LISTEN state. `iss` is the initial
 * send sequence number (caller-chosen so tests are deterministic; a real stack
 * would randomise it). */
void tcp_listen(tcp_conn_t *c, const uint8_t local_ip[4], uint16_t local_port,
                uint32_t iss);

/* Feed one received segment into the connection. Updates the state machine and
 * the receive buffer, and fills `out` with the segment (if any) that must be
 * sent in response. Returns 0 always; check `out->send`. */
int tcp_input(tcp_conn_t *c, const tcp_segment_t *seg, tcp_output_t *out);

/* Prepare a segment carrying `len` bytes of application data. Advances
 * snd_nxt. Only valid in ESTABLISHED / CLOSE_WAIT. Returns 0 on success and
 * fills `out`, -1 if the connection is not writable. */
int tcp_send(tcp_conn_t *c, const uint8_t *data, size_t len, tcp_output_t *out);

/* Begin a graceful close: produce a FIN segment and advance the state. Returns
 * 0 and fills `out`, or -1 if closing is not valid from the current state. */
int tcp_close(tcp_conn_t *c, tcp_output_t *out);

/* Human-readable state name, for logging. */
const char *tcp_state_name(tcp_state_t s);

#endif /* NETSTACK_TCP_H */
