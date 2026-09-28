#ifndef MINITCP_H
#define MINITCP_H
#include <stdint.h>
#include <stddef.h>

typedef struct NetIf NetIf;

typedef enum {
    TCP_CLOSED, TCP_SYN_RCVD, TCP_ESTABLISHED, TCP_LAST_ACK
} TcpState;

/* A single passive-open connection (this is a teaching stack, not a server
 * farm). Sequence-number bookkeeping is the heart of TCP: what we've sent, what
 * we expect next. */
typedef struct {
    TcpState state;
    uint8_t  peer_mac[6];
    uint32_t peer_ip;
    uint16_t peer_port;
    uint16_t local_port;
    uint32_t snd_nxt;      /* next sequence number we will send */
    uint32_t snd_una;      /* earliest sequence we sent but is unacked */
    uint32_t rcv_nxt;      /* next sequence number we expect from the peer */
} TcpConn;

struct NetIf {
    uint8_t  mac[6];
    uint32_t ip;                 /* host byte order */
    uint16_t listen_port;
    void   (*tx)(NetIf *, const uint8_t *frame, size_t len);   /* send a frame */
    void    *user;
    TcpConn  conn;
};

void netif_init(NetIf *nif, const uint8_t mac[6], uint32_t ip, uint16_t listen_port);
void netif_rx(NetIf *nif, const uint8_t *frame, size_t len);   /* feed one inbound frame */

#endif
