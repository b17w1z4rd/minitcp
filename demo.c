/*
 * demo.c - drive the stack through a full conversation and check every reply.
 *
 * This is the offline test harness: it plays the PEER, hand-builds inbound
 * frames (ARP, ICMP, TCP), feeds them to netif_rx(), and captures whatever the
 * stack transmits so it can assert on the flags, sequence/ack numbers, payload,
 * and - importantly - that the checksums the stack produced are actually valid.
 * No TAP device, no root, fully deterministic.
 */
#include "minitcp.h"
#include "proto.h"
#include <stdio.h>
#include <string.h>

static const uint8_t OUR_MAC[6]  = { 0x52,0x54,0x00,0x11,0x22,0x33 };
static const uint8_t PEER_MAC[6] = { 0x52,0x54,0x00,0xaa,0xbb,0xcc };
static const uint8_t BCAST[6]    = { 0xff,0xff,0xff,0xff,0xff,0xff };
static uint32_t ip4(int a,int b,int c,int d){ return ((uint32_t)a<<24)|(b<<16)|(c<<8)|d; }
#define OUR_IP    ip4(10,0,0,2)
#define PEER_IP   ip4(10,0,0,1)
#define OUR_PORT  7
#define PEER_PORT 40000
#define CLIENT_ISN 5000u

/* ---- capture whatever the stack sends ---------------------------------- */
static uint8_t cap[8][2048];
static size_t  caplen[8];
static int     capn;
static void cap_tx(NetIf *nif, const uint8_t *f, size_t n) { (void)nif;
    if (capn < 8) { memcpy(cap[capn], f, n); caplen[capn] = n; capn++; } }
static void cap_reset(void){ capn = 0; }

/* ---- assertions -------------------------------------------------------- */
static int fails = 0;
#define CHECK(cond, ...) do { \
    if (cond) printf("  [PASS] " __VA_ARGS__); \
    else    { printf("  [FAIL] " __VA_ARGS__); fails++; } \
    printf("\n"); } while (0)

/* Locate the L4 payload of a captured IP frame and report checksum validity. */
static const uint8_t *ipl4(const uint8_t *f, size_t flen, size_t *l4len,
                           uint32_t *src, uint32_t *dst, uint8_t *proto, int *ip_ok) {
    const uint8_t *ip = f + 14;
    size_t ihl = (size_t)(ip[0] & 0x0f) * 4;
    *ip_ok = (ip_checksum(ip, ihl) == 0);
    *src = rd32(ip + 12); *dst = rd32(ip + 16); *proto = ip[9];
    *l4len = rd16(ip + 2) - ihl;
    (void)flen;
    return ip + ihl;
}

/* ---- frame builders (we are the peer) ---------------------------------- */
static size_t build_arp_request(uint8_t *out) {
    size_t n = eth_build(out, BCAST, PEER_MAC, ETHERTYPE_ARP);
    uint8_t *a = out + n;
    wr16(a,1); wr16(a+2,ETHERTYPE_IP); a[4]=6; a[5]=4; wr16(a+6,1);   /* request */
    memcpy(a+8, PEER_MAC, 6); wr32(a+14, PEER_IP);
    memset(a+18, 0, 6);       wr32(a+24, OUR_IP);
    return n + 28;
}
static size_t build_icmp_echo(uint8_t *out, uint16_t id, uint16_t seq, const char *data) {
    uint8_t msg[64]; size_t dl = strlen(data);
    msg[0]=8; msg[1]=0; wr16(msg+2,0); wr16(msg+4,id); wr16(msg+6,seq);
    memcpy(msg+8, data, dl);
    size_t ml = 8 + dl;
    wr16(msg+2, csum_fin(csum_add(msg, ml, 0)));
    size_t n = eth_build(out, OUR_MAC, PEER_MAC, ETHERTYPE_IP);
    n += ip_build(out+n, PEER_IP, OUR_IP, IP_PROTO_ICMP, msg, ml);
    return n;
}
static size_t build_tcp(uint8_t *out, uint32_t seq, uint32_t ack, uint8_t flags,
                        const char *data) {
    uint8_t seg[128]; size_t dl = data ? strlen(data) : 0;
    size_t sl = tcp_build(seg, PEER_IP, OUR_IP, PEER_PORT, OUR_PORT,
                          seq, ack, flags, 64240, (const uint8_t*)data, dl);
    size_t n = eth_build(out, OUR_MAC, PEER_MAC, ETHERTYPE_IP);
    n += ip_build(out+n, PEER_IP, OUR_IP, IP_PROTO_TCP, seg, sl);
    return n;
}

/* Parse the single captured TCP reply into fields; verify both checksums. */
static int take_tcp(uint8_t *flags, uint32_t *seq, uint32_t *ack,
                    char *payload, size_t *plen) {
    if (capn != 1) return 0;
    size_t l4len; uint32_t s,d; uint8_t proto; int ip_ok;
    const uint8_t *t = ipl4(cap[0], caplen[0], &l4len, &s, &d, &proto, &ip_ok);
    if (!ip_ok || proto != IP_PROTO_TCP) return 0;
    if (l4_checksum(s, d, IP_PROTO_TCP, t, l4len) != 0) return 0;   /* bad TCP cksum */
    *flags = t[13];
    *seq = rd32(t + 4); *ack = rd32(t + 8);
    size_t off = (size_t)(t[12] >> 4) * 4;
    *plen = l4len - off;
    if (*plen) memcpy(payload, t + off, *plen);
    payload[*plen] = 0;
    return 1;
}

int main(void) {
    NetIf nif;
    netif_init(&nif, OUR_MAC, OUR_IP, OUR_PORT);
    nif.tx = cap_tx;

    uint8_t f[2048];
    uint8_t flags; uint32_t seq, ack; char pl[128]; size_t plen;

    puts("== ARP ==");
    cap_reset(); netif_rx(&nif, f, build_arp_request(f));
    {
        int ok = (capn == 1) && rd16(cap[0]+12) == ETHERTYPE_ARP;
        const uint8_t *a = cap[0] + 14;
        ok = ok && rd16(a+6) == 2 && memcmp(a+8, OUR_MAC, 6) == 0 &&
             rd32(a+14) == OUR_IP && rd32(a+24) == PEER_IP;
        CHECK(ok, "ARP reply: 10.0.0.2 is-at 52:54:00:11:22:33");
    }

    puts("== ICMP ==");
    cap_reset(); netif_rx(&nif, f, build_icmp_echo(f, 0xABCD, 1, "ping!"));
    {
        size_t l4len; uint32_t s,d; uint8_t proto; int ip_ok;
        const uint8_t *ic = ipl4(cap[0], caplen[0], &l4len, &s, &d, &proto, &ip_ok);
        int icmp_ok = csum_fin(csum_add(ic, l4len, 0)) == 0;
        int ok = capn==1 && ip_ok && proto==IP_PROTO_ICMP && ic[0]==0 /*reply*/ &&
                 s==OUR_IP && d==PEER_IP && icmp_ok &&
                 rd16(ic+4)==0xABCD && memcmp(ic+8,"ping!",5)==0;
        CHECK(ok, "ICMP echo reply: id=0xABCD payload=\"ping!\" (ip+icmp cksum ok)");
    }

    puts("== TCP handshake ==");
    cap_reset(); netif_rx(&nif, f, build_tcp(f, CLIENT_ISN, 0, TCP_SYN, NULL));
    CHECK(take_tcp(&flags,&seq,&ack,pl,&plen) &&
          flags==(TCP_SYN|TCP_ACK) && seq==1000 && ack==CLIENT_ISN+1,
          "SYN,ACK  seq=1000 ack=5001 (cksum ok)");

    cap_reset(); netif_rx(&nif, f, build_tcp(f, CLIENT_ISN+1, 1001, TCP_ACK, NULL));
    CHECK(capn==0 && nif.conn.state==TCP_ESTABLISHED,
          "bare ACK completes handshake -> ESTABLISHED (no reply)");

    puts("== TCP data (echo) ==");
    cap_reset(); netif_rx(&nif, f, build_tcp(f, CLIENT_ISN+1, 1001, TCP_PSH|TCP_ACK, "hello"));
    CHECK(take_tcp(&flags,&seq,&ack,pl,&plen) &&
          flags==(TCP_PSH|TCP_ACK) && seq==1001 && ack==CLIENT_ISN+6 &&
          plen==5 && strcmp(pl,"hello")==0,
          "PSH,ACK  seq=1001 ack=5006 payload=\"hello\" echoed (cksum ok)");

    puts("== TCP teardown ==");
    cap_reset(); netif_rx(&nif, f, build_tcp(f, CLIENT_ISN+6, 1006, TCP_FIN|TCP_ACK, NULL));
    CHECK(take_tcp(&flags,&seq,&ack,pl,&plen) &&
          flags==(TCP_FIN|TCP_ACK) && seq==1006 && ack==CLIENT_ISN+7,
          "FIN,ACK  seq=1006 ack=5007 (cksum ok)");

    cap_reset(); netif_rx(&nif, f, build_tcp(f, CLIENT_ISN+7, 1007, TCP_ACK, NULL));
    CHECK(capn==0 && nif.conn.state==TCP_CLOSED,
          "final ACK -> CLOSED");

    printf("\n%s\n", fails ? "SOME CHECKS FAILED" : "all checks passed: full ARP/ICMP/TCP conversation verified");
    return fails ? 1 : 0;
}
