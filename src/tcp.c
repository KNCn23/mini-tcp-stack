#include "netstack/tcp.h"
#include "netstack/byteorder.h"
#include "netstack/checksum.h"
#include "netstack/ipv4.h"

#include <string.h>

/* Serial-number comparison (RFC 1323 style): true when a is "after" b on the
 * 32-bit sequence wheel. */
static inline int seq_gt(uint32_t a, uint32_t b) {
    return (int32_t)(a - b) > 0;
}

/* Compute the TCP checksum over the pseudo-header followed by `seg`/`seg_len`.
 * The pseudo-header is src_ip | dst_ip | 0 | proto(6) | tcp_length. */
static uint16_t tcp_checksum(const uint8_t src_ip[4], const uint8_t dst_ip[4],
                             const uint8_t *seg, size_t seg_len) {
    uint8_t pseudo[12];
    memcpy(pseudo, src_ip, 4);
    memcpy(pseudo + 4, dst_ip, 4);
    pseudo[8] = 0;
    pseudo[9] = IP_PROTO_TCP;
    ns_put_be16(pseudo + 10, (uint16_t)seg_len);

    ns_csum_t c;
    ns_csum_init(&c);
    ns_csum_update(&c, pseudo, sizeof(pseudo));
    ns_csum_update(&c, seg, seg_len);
    return ns_csum_final(&c);
}

int tcp_parse(const uint8_t *buf, size_t len,
              const uint8_t src_ip[4], const uint8_t dst_ip[4],
              tcp_segment_t *out) {
    if (len < TCP_MIN_HDR_LEN)
        return -1;

    uint8_t data_offset = buf[12] >> 4;
    size_t hdr_len = (size_t)data_offset * 4;
    if (hdr_len < TCP_MIN_HDR_LEN || hdr_len > len)
        return -1;

    /* The checksum covers the pseudo-header plus the entire segment. */
    if (tcp_checksum(src_ip, dst_ip, buf, len) != 0)
        return -1;

    out->src_port = ns_get_be16(buf);
    out->dst_port = ns_get_be16(buf + 2);
    out->seq = ns_get_be32(buf + 4);
    out->ack = ns_get_be32(buf + 8);
    out->data_offset = data_offset;
    out->flags = buf[13] & 0x3f;
    out->window = ns_get_be16(buf + 14);
    out->payload = buf + hdr_len;
    out->payload_len = len - hdr_len;
    return 0;
}

size_t tcp_build(uint8_t *buf, const uint8_t src_ip[4], const uint8_t dst_ip[4],
                 const tcp_output_t *out) {
    memset(buf, 0, TCP_MIN_HDR_LEN);
    ns_put_be16(buf, out->src_port);
    ns_put_be16(buf + 2, out->dst_port);
    ns_put_be32(buf + 4, out->seq);
    ns_put_be32(buf + 8, out->ack);
    buf[12] = (5 << 4);              /* data offset = 5 words, no options */
    buf[13] = out->flags;
    ns_put_be16(buf + 14, out->window);
    ns_put_be16(buf + 16, 0);        /* checksum placeholder */
    ns_put_be16(buf + 18, 0);        /* urgent pointer */

    if (out->data_len && out->data)
        memcpy(buf + TCP_MIN_HDR_LEN, out->data, out->data_len);

    size_t total = TCP_MIN_HDR_LEN + out->data_len;
    uint16_t csum = tcp_checksum(src_ip, dst_ip, buf, total);
    ns_put_be16(buf + 16, csum);
    return total;
}

/* --- state machine ----------------------------------------------------- */

void tcp_listen(tcp_conn_t *c, const uint8_t local_ip[4], uint16_t local_port,
                uint32_t iss) {
    memset(c, 0, sizeof(*c));
    c->state = TCP_LISTEN;
    memcpy(c->local_ip, local_ip, 4);
    c->local_port = local_port;
    c->iss = iss;
    c->snd_una = iss;
    c->snd_nxt = iss;
    c->rcv_wnd = TCP_DEFAULT_WND;
}

/* Fill the fixed fields shared by every outgoing segment of this connection. */
static void prep_out(const tcp_conn_t *c, tcp_output_t *out) {
    memset(out, 0, sizeof(*out));
    out->src_port = c->local_port;
    out->dst_port = c->remote_port;
    out->window = c->rcv_wnd;
}

/* Emit a pure ACK acknowledging everything received so far. */
static void emit_ack(tcp_conn_t *c, tcp_output_t *out) {
    prep_out(c, out);
    out->flags = TCP_ACK;
    out->seq = c->snd_nxt;
    out->ack = c->rcv_nxt;
    out->send = 1;
}

int tcp_input(tcp_conn_t *c, const tcp_segment_t *seg, tcp_output_t *out) {
    prep_out(c, out);

    /* A reset tears the connection down immediately. */
    if (seg->flags & TCP_RST) {
        c->state = TCP_CLOSED;
        return 0;
    }

    switch (c->state) {
    case TCP_LISTEN:
        if ((seg->flags & TCP_SYN) && !(seg->flags & TCP_ACK)) {
            c->remote_port = seg->src_port;
            c->rcv_nxt = seg->seq + 1;          /* SYN consumes one number */
            c->snd_una = c->iss;
            c->snd_nxt = c->iss;
            /* Reply SYN+ACK; our SYN also consumes a sequence number. */
            prep_out(c, out);
            out->flags = TCP_SYN | TCP_ACK;
            out->seq = c->snd_nxt;
            out->ack = c->rcv_nxt;
            out->send = 1;
            c->snd_nxt += 1;
            c->state = TCP_SYN_RECEIVED;
        }
        break;

    case TCP_SYN_RECEIVED:
        if ((seg->flags & TCP_ACK) && seg->ack == c->snd_nxt) {
            c->snd_una = seg->ack;
            c->state = TCP_ESTABLISHED;
        }
        break;

    case TCP_ESTABLISHED: {
        int need_ack = 0;
        if ((seg->flags & TCP_ACK) && seq_gt(seg->ack, c->snd_una))
            c->snd_una = seg->ack;

        if (seg->seq == c->rcv_nxt) {
            /* In-order segment: accept any data, then any FIN. */
            if (seg->payload_len > 0 &&
                c->rxlen + seg->payload_len <= TCP_RXBUF) {
                memcpy(c->rxbuf + c->rxlen, seg->payload, seg->payload_len);
                c->rxlen += seg->payload_len;
                c->rcv_nxt += (uint32_t)seg->payload_len;
                need_ack = 1;
            }
            if (seg->flags & TCP_FIN) {
                c->rcv_nxt += 1;            /* FIN consumes one number */
                c->state = TCP_CLOSE_WAIT;
                need_ack = 1;
            }
        } else if (seg->payload_len > 0 || (seg->flags & TCP_FIN)) {
            /* Out-of-order or duplicate: re-ACK what we have. */
            need_ack = 1;
        }

        if (need_ack)
            emit_ack(c, out);
        break;
    }

    case TCP_CLOSE_WAIT:
        if ((seg->flags & TCP_ACK) && seq_gt(seg->ack, c->snd_una))
            c->snd_una = seg->ack;
        break;

    case TCP_FIN_WAIT_1:
        if ((seg->flags & TCP_ACK) && seg->ack == c->snd_nxt) {
            c->snd_una = seg->ack;
            c->state = TCP_FIN_WAIT_2;
        }
        if ((seg->flags & TCP_FIN) && seg->seq == c->rcv_nxt) {
            c->rcv_nxt += 1;
            emit_ack(c, out);
            /* If our FIN was already acked we go to TIME_WAIT, otherwise we
             * are in simultaneous close (CLOSING). */
            c->state = (c->state == TCP_FIN_WAIT_2) ? TCP_TIME_WAIT
                                                    : TCP_CLOSING;
        }
        break;

    case TCP_FIN_WAIT_2:
        if ((seg->flags & TCP_FIN) && seg->seq == c->rcv_nxt) {
            c->rcv_nxt += 1;
            emit_ack(c, out);
            c->state = TCP_TIME_WAIT;
        }
        break;

    case TCP_CLOSING:
        if ((seg->flags & TCP_ACK) && seg->ack == c->snd_nxt)
            c->state = TCP_TIME_WAIT;
        break;

    case TCP_LAST_ACK:
        if ((seg->flags & TCP_ACK) && seg->ack == c->snd_nxt)
            c->state = TCP_CLOSED;
        break;

    default:
        break;
    }

    return 0;
}

int tcp_send(tcp_conn_t *c, const uint8_t *data, size_t len, tcp_output_t *out) {
    if (c->state != TCP_ESTABLISHED && c->state != TCP_CLOSE_WAIT)
        return -1;
    prep_out(c, out);
    out->flags = TCP_ACK | TCP_PSH;
    out->seq = c->snd_nxt;
    out->ack = c->rcv_nxt;
    out->data = data;
    out->data_len = len;
    out->send = 1;
    c->snd_nxt += (uint32_t)len;
    return 0;
}

int tcp_close(tcp_conn_t *c, tcp_output_t *out) {
    prep_out(c, out);
    out->flags = TCP_FIN | TCP_ACK;
    out->seq = c->snd_nxt;
    out->ack = c->rcv_nxt;

    if (c->state == TCP_ESTABLISHED) {
        c->state = TCP_FIN_WAIT_1;
    } else if (c->state == TCP_CLOSE_WAIT) {
        c->state = TCP_LAST_ACK;
    } else {
        return -1;
    }
    c->snd_nxt += 1;            /* FIN consumes one sequence number */
    out->send = 1;
    return 0;
}

const char *tcp_state_name(tcp_state_t s) {
    switch (s) {
    case TCP_CLOSED:       return "CLOSED";
    case TCP_LISTEN:       return "LISTEN";
    case TCP_SYN_SENT:     return "SYN_SENT";
    case TCP_SYN_RECEIVED: return "SYN_RECEIVED";
    case TCP_ESTABLISHED:  return "ESTABLISHED";
    case TCP_FIN_WAIT_1:   return "FIN_WAIT_1";
    case TCP_FIN_WAIT_2:   return "FIN_WAIT_2";
    case TCP_CLOSE_WAIT:   return "CLOSE_WAIT";
    case TCP_CLOSING:      return "CLOSING";
    case TCP_LAST_ACK:     return "LAST_ACK";
    case TCP_TIME_WAIT:    return "TIME_WAIT";
    default:               return "?";
    }
}
