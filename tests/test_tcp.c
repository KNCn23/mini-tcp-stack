/* TCP wire-format and state-machine tests.
 *
 * The state-machine test drives a server connection through a full lifecycle
 * by hand-crafting the segments a client would send.
 */
#include "netstack/tcp.h"
#include "test_util.h"

#include <string.h>

static const uint8_t SRV_IP[4] = {10, 0, 0, 2};
static const uint8_t CLI_IP[4] = {10, 0, 0, 1};
#define SRV_PORT 80
#define CLI_PORT 40000

static void test_tcp_header_roundtrip(void) {
    tcp_output_t out = {
        .src_port = CLI_PORT,
        .dst_port = SRV_PORT,
        .seq = 0xdeadbeef,
        .ack = 0x01020304,
        .flags = TCP_SYN | TCP_ACK,
        .window = 4096,
        .data = (const uint8_t *)"hi",
        .data_len = 2,
    };
    uint8_t buf[64];
    size_t n = tcp_build(buf, CLI_IP, SRV_IP, &out);
    CHECK_EQ(n, TCP_MIN_HDR_LEN + 2);

    tcp_segment_t seg;
    CHECK_EQ(tcp_parse(buf, n, CLI_IP, SRV_IP, &seg), 0);
    CHECK_EQ(seg.src_port, CLI_PORT);
    CHECK_EQ(seg.dst_port, SRV_PORT);
    CHECK_EQ(seg.seq, 0xdeadbeef);
    CHECK_EQ(seg.ack, 0x01020304);
    CHECK_EQ(seg.flags, TCP_SYN | TCP_ACK);
    CHECK_EQ(seg.window, 4096);
    CHECK_EQ(seg.payload_len, 2);
    CHECK(memcmp(seg.payload, "hi", 2) == 0);
}

static void test_tcp_bad_checksum_rejected(void) {
    tcp_output_t out = {.src_port = 1, .dst_port = 2, .flags = TCP_SYN};
    uint8_t buf[64];
    size_t n = tcp_build(buf, CLI_IP, SRV_IP, &out);
    buf[4] ^= 0xff;                 /* corrupt the sequence number */
    tcp_segment_t seg;
    CHECK_EQ(tcp_parse(buf, n, CLI_IP, SRV_IP, &seg), -1);
}

/* Build a segment as if it came from the client. */
static tcp_segment_t client_seg(uint8_t flags, uint32_t seq, uint32_t ack,
                                const char *data) {
    tcp_segment_t s;
    memset(&s, 0, sizeof(s));
    s.src_port = CLI_PORT;
    s.dst_port = SRV_PORT;
    s.flags = flags;
    s.seq = seq;
    s.ack = ack;
    s.window = 4096;
    if (data) {
        s.payload = (const uint8_t *)data;
        s.payload_len = strlen(data);
    }
    return s;
}

static void test_tcp_full_lifecycle(void) {
    tcp_conn_t srv;
    tcp_listen(&srv, SRV_IP, SRV_PORT, /*iss=*/1000);
    CHECK_EQ(srv.state, TCP_LISTEN);

    tcp_output_t out;

    /* 1. Client SYN (seq=500) -> server replies SYN+ACK. */
    tcp_segment_t syn = client_seg(TCP_SYN, 500, 0, NULL);
    tcp_input(&srv, &syn, &out);
    CHECK_EQ(out.send, 1);
    CHECK_EQ(out.flags, TCP_SYN | TCP_ACK);
    CHECK_EQ(out.seq, 1000);
    CHECK_EQ(out.ack, 501);
    CHECK_EQ(srv.state, TCP_SYN_RECEIVED);

    /* 2. Client ACK completes the handshake. */
    tcp_segment_t ack = client_seg(TCP_ACK, 501, 1001, NULL);
    tcp_input(&srv, &ack, &out);
    CHECK_EQ(out.send, 0);
    CHECK_EQ(srv.state, TCP_ESTABLISHED);

    /* 3. Client sends 5 bytes -> server buffers them and ACKs. */
    tcp_segment_t data = client_seg(TCP_ACK | TCP_PSH, 501, 1001, "hello");
    tcp_input(&srv, &data, &out);
    CHECK_EQ(srv.rxlen, 5);
    CHECK(memcmp(srv.rxbuf, "hello", 5) == 0);
    CHECK_EQ(out.send, 1);
    CHECK_EQ(out.flags, TCP_ACK);
    CHECK_EQ(out.ack, 506);          /* acknowledges all 5 bytes */

    /* 4. Server sends a reply of its own. */
    CHECK_EQ(tcp_send(&srv, (const uint8_t *)"world", 5, &out), 0);
    CHECK_EQ(out.flags, TCP_ACK | TCP_PSH);
    CHECK_EQ(out.seq, 1001);
    CHECK_EQ(srv.snd_nxt, 1006);

    /* 5. Client closes: FIN -> server ACKs and enters CLOSE_WAIT. */
    tcp_segment_t fin = client_seg(TCP_ACK | TCP_FIN, 506, 1006, NULL);
    tcp_input(&srv, &fin, &out);
    CHECK_EQ(out.send, 1);
    CHECK_EQ(out.ack, 507);          /* FIN consumed one sequence number */
    CHECK_EQ(srv.state, TCP_CLOSE_WAIT);

    /* 6. Server closes its side: FIN -> LAST_ACK. */
    CHECK_EQ(tcp_close(&srv, &out), 0);
    CHECK_EQ(out.flags, TCP_FIN | TCP_ACK);
    CHECK_EQ(srv.state, TCP_LAST_ACK);

    /* 7. Client ACKs the server FIN -> connection fully closed. */
    tcp_segment_t last = client_seg(TCP_ACK, 507, 1007, NULL);
    tcp_input(&srv, &last, &out);
    CHECK_EQ(srv.state, TCP_CLOSED);
}

static void test_tcp_reset_closes(void) {
    tcp_conn_t srv;
    tcp_listen(&srv, SRV_IP, SRV_PORT, 1000);
    srv.state = TCP_ESTABLISHED;
    tcp_output_t out;
    tcp_segment_t rst = client_seg(TCP_RST, 100, 0, NULL);
    tcp_input(&srv, &rst, &out);
    CHECK_EQ(srv.state, TCP_CLOSED);
    CHECK_EQ(out.send, 0);
}

int main(void) {
    RUN(test_tcp_header_roundtrip);
    RUN(test_tcp_bad_checksum_rejected);
    RUN(test_tcp_full_lifecycle);
    RUN(test_tcp_reset_closes);
    TEST_SUMMARY();
}
