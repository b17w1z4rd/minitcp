#ifndef PROTO_H
#define PROTO_H
#include <stdint.h>
#include <stddef.h>

/* Ethernet */
#define ETH_HLEN        14
#define ETH_ALEN        6
#define ETHERTYPE_IP    0x0800
#define ETHERTYPE_ARP   0x0806

/* IPv4 */
#define IP_PROTO_ICMP   1
#define IP_PROTO_TCP    6

/* TCP flags */
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10

/* big-endian (network order) load/store on unaligned byte pointers */
uint16_t rd16(const uint8_t *p);
uint32_t rd32(const uint8_t *p);
void     wr16(uint8_t *p, uint16_t v);
void     wr32(uint8_t *p, uint32_t v);

/* Internet checksum: accumulate 16-bit words, fold, ones-complement. */
uint32_t csum_add(const uint8_t *data, size_t len, uint32_t acc);
uint16_t csum_fin(uint32_t acc);
uint16_t ip_checksum(const uint8_t *iphdr, size_t ihl);
uint16_t l4_checksum(uint32_t src_ip, uint32_t dst_ip, uint8_t proto,
                     const uint8_t *seg, size_t len);

/* Builders. IPs are host-order uint32_t; each returns bytes written. */
size_t eth_build(uint8_t *out, const uint8_t dst[6], const uint8_t src[6], uint16_t etype);
size_t ip_build(uint8_t *out, uint32_t src, uint32_t dst, uint8_t proto,
                const uint8_t *payload, size_t plen);
size_t tcp_build(uint8_t *out, uint32_t src_ip, uint32_t dst_ip,
                 uint16_t sport, uint16_t dport, uint32_t seq, uint32_t ack,
                 uint8_t flags, uint16_t win, const uint8_t *payload, size_t plen);

#endif
