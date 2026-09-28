/*
 * proto.c - byte-level helpers and packet builders for the stack.
 *
 * Everything on the wire is big-endian; these helpers read and write it on
 * unaligned pointers so we never cast a buffer to a packed struct.
 */
#include "proto.h"
#include <string.h>

uint16_t rd16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
uint32_t rd32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}
void wr16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
void wr32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}

/* Internet checksum (RFC 1071): sum big-endian 16-bit words into a wide
 * accumulator; csum_fin folds the carries and complements. Splitting add/fin
 * lets us checksum a pseudo-header and a segment in one running sum. */
uint32_t csum_add(const uint8_t *data, size_t len, uint32_t acc) {
    size_t i = 0;
    for (; i + 1 < len; i += 2) acc += (uint32_t)((data[i] << 8) | data[i + 1]);
    if (i < len) acc += (uint32_t)(data[i] << 8);   /* odd trailing byte */
    return acc;
}
uint16_t csum_fin(uint32_t acc) {
    while (acc >> 16) acc = (acc & 0xffff) + (acc >> 16);
    return (uint16_t)~acc;
}
uint16_t ip_checksum(const uint8_t *iphdr, size_t ihl) {
    return csum_fin(csum_add(iphdr, ihl, 0));
}
uint16_t l4_checksum(uint32_t src_ip, uint32_t dst_ip, uint8_t proto,
                     const uint8_t *seg, size_t len) {
    uint8_t ph[12];
    wr32(ph, src_ip); wr32(ph + 4, dst_ip);
    ph[8] = 0; ph[9] = proto; wr16(ph + 10, (uint16_t)len);
    uint32_t acc = csum_add(ph, 12, 0);
    acc = csum_add(seg, len, acc);
    return csum_fin(acc);
}

size_t eth_build(uint8_t *out, const uint8_t dst[6], const uint8_t src[6], uint16_t etype) {
    memcpy(out, dst, 6);
    memcpy(out + 6, src, 6);
    wr16(out + 12, etype);
    return ETH_HLEN;
}

size_t ip_build(uint8_t *out, uint32_t src, uint32_t dst, uint8_t proto,
                const uint8_t *payload, size_t plen) {
    size_t total = 20 + plen;
    out[0] = 0x45;                 /* version 4, IHL 5 */
    out[1] = 0;                    /* DSCP/ECN */
    wr16(out + 2, (uint16_t)total);
    wr16(out + 4, 0);              /* id */
    wr16(out + 6, 0x4000);         /* flags: don't fragment */
    out[8] = 64;                   /* TTL */
    out[9] = proto;
    wr16(out + 10, 0);             /* checksum placeholder */
    wr32(out + 12, src);
    wr32(out + 16, dst);
    wr16(out + 10, ip_checksum(out, 20));
    if (plen) memcpy(out + 20, payload, plen);
    return total;
}

size_t tcp_build(uint8_t *out, uint32_t src_ip, uint32_t dst_ip,
                 uint16_t sport, uint16_t dport, uint32_t seq, uint32_t ack,
                 uint8_t flags, uint16_t win, const uint8_t *payload, size_t plen) {
    wr16(out, sport);
    wr16(out + 2, dport);
    wr32(out + 4, seq);
    wr32(out + 8, ack);
    out[12] = 5 << 4;              /* data offset = 5 words, no options */
    out[13] = flags;
    wr16(out + 14, win);
    wr16(out + 16, 0);             /* checksum placeholder */
    wr16(out + 18, 0);             /* urgent pointer */
    if (plen) memcpy(out + 20, payload, plen);
    size_t seglen = 20 + plen;
    wr16(out + 16, l4_checksum(src_ip, dst_ip, IP_PROTO_TCP, out, seglen));
    return seglen;
}
