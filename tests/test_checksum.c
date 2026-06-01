/* Checksum tests, including a worked example from the literature. */
#include "netstack/checksum.h"
#include "netstack/byteorder.h"
#include "test_util.h"

#include <string.h>

/* Classic RFC 1071 example: the 16-bit words 0x0001 0xf203 0xf4f5 0xf6f7 sum
 * (with end-around carry) to 0xddf2, whose one's complement is 0x220d. */
static void test_rfc1071_example(void) {
    uint8_t data[] = {0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7};
    uint16_t c = ns_checksum(data, sizeof(data));
    CHECK_EQ(c, 0x220d);
}

static void test_odd_length_matches_padded(void) {
    /* An odd trailing byte must be treated as a high byte padded with zero. */
    uint8_t odd[] = {0x11, 0x22, 0x33};
    uint8_t padded[] = {0x11, 0x22, 0x33, 0x00};
    CHECK_EQ(ns_checksum(odd, sizeof(odd)), ns_checksum(padded, sizeof(padded)));
}

static void test_incremental_equals_oneshot(void) {
    uint8_t data[] = {0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03};
    ns_csum_t c;
    ns_csum_init(&c);
    /* Split across an odd boundary to exercise the carry-byte path. */
    ns_csum_update(&c, data, 3);
    ns_csum_update(&c, data + 3, 4);
    CHECK_EQ(ns_csum_final(&c), ns_checksum(data, sizeof(data)));
}

static void test_valid_block_folds_to_zero(void) {
    /* Append the checksum to a buffer; re-checksumming the whole thing must
     * yield 0. This is the property receivers rely on. */
    uint8_t buf[6] = {0x45, 0x00, 0x00, 0x28, 0x00, 0x00};
    uint16_t c = ns_checksum(buf, 4);
    ns_put_be16(buf + 4, c);
    CHECK_EQ(ns_checksum(buf, 6), 0);
}

int main(void) {
    RUN(test_rfc1071_example);
    RUN(test_odd_length_matches_padded);
    RUN(test_incremental_equals_oneshot);
    RUN(test_valid_block_folds_to_zero);
    TEST_SUMMARY();
}
