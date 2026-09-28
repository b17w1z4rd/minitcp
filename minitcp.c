/*
 * minitcp.c - a small userspace TCP/IP stack.
 *
 * Handles inbound Ethernet frames and answers them: ARP requests, ICMP echo
 * (ping), and a TCP passive-open connection running an echo application. The
 * stack never touches a socket or the kernel network stack; it speaks the wire
 * format directly. The only thing it needs from the outside world is a `tx`
 * callback that puts a frame on some link (a TAP device, or a test harness).
 *
 * Simplifications (called out honestly): one TCP connection at a time, no
 * retransmission timers, no congestion/flow control beyond a fixed window, and
 * in-order segments only. The goal is a correct handshake / data / teardown
 * state machine, verified against a peer, not a production stack.
 */
#include "minitcp.h"
#include "proto.h"
#include <string.h>

void netif_init(NetIf *nif, const uint8_t mac[6], uint32_t ip, uint16_t listen_port) {
    memset(nif, 0, sizeof *nif);
    memcpy(nif->mac, mac, 6);
    nif->ip = ip;
    nif->listen_port = listen_port;
    nif->conn.state = TCP_CLOSED;
}

/* ---- ARP -------------------------------------------------------------- */
static void handle_arp(NetIf *nif, const uint8_t *p, size_t len) {
    if (len < 28) return;
    if (rd16(p + 6) != 1) return;                 /* opcode: request */
    if (rd32(p + 24) != nif->ip) return;          /* target protocol addr = us */

    uint8_t  sha[6]; memcpy(sha, p + 8, 6);       /* sender hw addr  */
    uint32_t spa = rd32(p + 14);                  /* sender proto addr */

    uint8_t out[64];
    size_t n = eth_build(out, sha, nif->mac, ETHERTYPE_ARP);
    uint8_t *a = out + n;
    wr16(a, 1); wr16(a + 2, ETHERTYPE_IP); a[4] = 6; a[5] = 4; wr16(a + 6, 2); /* reply */
    memcpy(a + 8, nif->mac, 6); wr32(a + 14, nif->ip);        /* sender = us   */
    memcpy(a + 18, sha, 6);     wr32(a + 24, spa);            /* target = them */
    nif->tx(nif, out, n + 28);
}

/* ---- ICMP ------------------------------------------------------------- */
static void handle_icmp(NetIf *nif, const uint8_t *dstmac, uint32_t peer,
                        const uint8_t *p, size_t len) {
    if (len < 8 || p[0] != 8) return;             /* echo request only */
    uint8_t msg[1500];
    if (len > sizeof msg) return;
    memcpy(msg, p, len);
    msg[0] = 0;                                   /* echo reply */
    wr16(msg + 2, 0);                             /* clear then recompute cksum */
    wr16(msg + 2, csum_fin(csum_add(msg, len, 0)));

    uint8_t out[1600];
    size_t n = eth_build(out, dstmac, nif->mac, ETHERTYPE_IP);
    n += ip_build(out + n, nif->ip, peer, IP_PROTO_ICMP, msg, len);
    nif->tx(nif, out, n);
}

/* ---- TCP -------------------------------------------------------------- */
static void tcp_send(NetIf *nif, uint8_t flags, const uint8_t *data, size_t dlen) {
    TcpConn *c = &nif->conn;
    uint8_t seg[2048];
    if (dlen > sizeof seg - 20) dlen = sizeof seg - 20;
    size_t seglen = tcp_build(seg, nif->ip, c->peer_ip, c->local_port, c->peer_port,
                              c->snd_nxt, c->rcv_nxt, flags, 64240, data, dlen);
    uint8_t out[2100];
    size_t n = eth_build(out, c->peer_mac, nif->mac, ETHERTYPE_IP);
    n += ip_build(out + n, nif->ip, c->peer_ip, IP_PROTO_TCP, seg, seglen);
    nif->tx(nif, out, n);
}

static void handle_tcp(NetIf *nif, const uint8_t *peermac, uint32_t peer,
                       const uint8_t *seg, size_t len) {
    if (len < 20) return;
    uint16_t sport = rd16(seg), dport = rd16(seg + 2);
    uint32_t seq = rd32(seg + 4), ack = rd32(seg + 8);
    uint8_t  off = (uint8_t)((seg[12] >> 4) * 4), flags = seg[13];
    const uint8_t *data = seg + off;
    size_t dlen = (off <= len) ? len - off : 0;
    TcpConn *c = &nif->conn;

    if (dport != nif->listen_port) return;

    /* SYN with no ACK: open (or re-open) the connection. */
    if ((flags & TCP_SYN) && !(flags & TCP_ACK)) {
        memcpy(c->peer_mac, peermac, 6);
        c->peer_ip = peer; c->peer_port = sport; c->local_port = dport;
        c->rcv_nxt = seq + 1;             /* SYN occupies one sequence number */
        c->snd_nxt = 1000;                /* our ISN (fixed => deterministic)  */
        c->snd_una = 1000;
        c->state   = TCP_SYN_RCVD;
        tcp_send(nif, TCP_SYN | TCP_ACK, NULL, 0);
        c->snd_nxt += 1;                  /* our SYN occupies one too          */
        return;
    }

    if (c->state == TCP_CLOSED) return;
    if (peer != c->peer_ip || sport != c->peer_port) return;

    if (flags & TCP_ACK) c->snd_una = ack;

    /* Their ACK of our SYN/ACK completes the handshake. */
    if (c->state == TCP_SYN_RCVD && (flags & TCP_ACK) && ack == c->snd_nxt)
        c->state = TCP_ESTABLISHED;

    /* In-order data: echo it back with the ACK piggybacked. */
    if (c->state == TCP_ESTABLISHED && dlen > 0 && seq == c->rcv_nxt) {
        c->rcv_nxt += (uint32_t)dlen;
        tcp_send(nif, TCP_PSH | TCP_ACK, data, dlen);
        c->snd_nxt += (uint32_t)dlen;
    } else if (c->state == TCP_ESTABLISHED && dlen > 0) {
        tcp_send(nif, TCP_ACK, NULL, 0);          /* out of order: re-ack */
    }

    /* Their FIN (in order): ack it and send our own, one segment. */
    if ((flags & TCP_FIN) && c->state == TCP_ESTABLISHED && seq + dlen == c->rcv_nxt) {
        c->rcv_nxt += 1;
        tcp_send(nif, TCP_FIN | TCP_ACK, NULL, 0);
        c->snd_nxt += 1;
        c->state = TCP_LAST_ACK;
    }

    /* Their ACK of our FIN: fully closed. */
    if (c->state == TCP_LAST_ACK && (flags & TCP_ACK) && ack == c->snd_nxt)
        c->state = TCP_CLOSED;
}

/* ---- IPv4 + dispatch -------------------------------------------------- */
static void handle_ip(NetIf *nif, const uint8_t *srcmac, const uint8_t *p, size_t len) {
    if (len < 20) return;
    size_t ihl = (size_t)(p[0] & 0x0f) * 4;
    if (ihl < 20 || ihl > len) return;
    if (ip_checksum(p, ihl) != 0) return;         /* drop bad header checksum */
    if (rd32(p + 16) != nif->ip) return;          /* not addressed to us */

    uint32_t src = rd32(p + 12);
    uint16_t total = rd16(p + 2);
    const uint8_t *l4 = p + ihl;
    size_t l4len = (total >= ihl && total <= len) ? total - ihl : len - ihl;

    switch (p[9]) {
    case IP_PROTO_ICMP: handle_icmp(nif, srcmac, src, l4, l4len); break;
    case IP_PROTO_TCP:  handle_tcp(nif, srcmac, src, l4, l4len);  break;
    }
}

void netif_rx(NetIf *nif, const uint8_t *frame, size_t len) {
    if (len < ETH_HLEN) return;
    const uint8_t *srcmac = frame + 6;
    uint16_t etype = rd16(frame + 12);
    const uint8_t *payload = frame + ETH_HLEN;
    size_t plen = len - ETH_HLEN;

    if (etype == ETHERTYPE_ARP)     handle_arp(nif, payload, plen);
    else if (etype == ETHERTYPE_IP) handle_ip(nif, srcmac, payload, plen);
}
