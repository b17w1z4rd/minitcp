/*
 * tap.c - run the stack on a real Linux TAP device, so you can ping it and
 * connect to it with ordinary tools.
 *
 * Setup (needs root):
 *   sudo ip tuntap add dev tap0 mode tap
 *   sudo ip addr add 10.0.0.1/24 dev tap0
 *   sudo ip link set tap0 up
 *   sudo ./tap tap0 10.0.0.2
 *
 * Then, from another terminal:
 *   ping 10.0.0.2                 # ICMP echo, answered by the stack
 *   printf 'hi\n' | nc 10.0.0.2 7 # TCP to the echo server on port 7
 *
 * A TAP device hands us whole Ethernet frames, which is exactly what the stack
 * consumes - so the driver is just: read a frame -> netif_rx, and a tx callback
 * that writes frames back to the device.
 */
#define _GNU_SOURCE
#include "minitcp.h"
#include "proto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>

static int tap_open(const char *name) {
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) { perror("open /dev/net/tun"); return -1; }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;          /* raw Ethernet frames */
    strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
    if (ioctl(fd, TUNSETIFF, &ifr) < 0) { perror("TUNSETIFF (need root?)"); close(fd); return -1; }
    return fd;
}

static int g_fd;
static void tap_tx(NetIf *nif, const uint8_t *frame, size_t len) {
    (void)nif;
    if (write(g_fd, frame, len) < 0) perror("write");
}

static uint32_t parse_ip(const char *s) {
    unsigned a,b,c,d;
    if (sscanf(s, "%u.%u.%u.%u", &a,&b,&c,&d) != 4) { fprintf(stderr, "bad ip %s\n", s); exit(1); }
    return (a << 24) | (b << 16) | (c << 8) | d;
}

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: %s <tap-ifname> <stack-ip> [port]\n", argv[0]); return 1; }
    const char *ifname = argv[1];
    uint32_t ip = parse_ip(argv[2]);
    uint16_t port = (argc > 3) ? (uint16_t)atoi(argv[3]) : 7;

    g_fd = tap_open(ifname);
    if (g_fd < 0) return 1;

    static const uint8_t mac[6] = { 0x52,0x54,0x00,0x11,0x22,0x33 };
    NetIf nif;
    netif_init(&nif, mac, ip, port);
    nif.tx = tap_tx;

    printf("stack up on %s: ip=%s mac=52:54:00:11:22:33 tcp echo port %u\n",
           ifname, argv[2], port);
    printf("try:  ping %s   |   nc %s %u\n", argv[2], argv[2], port);

    uint8_t frame[2048];
    for (;;) {
        ssize_t n = read(g_fd, frame, sizeof frame);
        if (n <= 0) { if (n < 0) perror("read"); break; }
        netif_rx(&nif, frame, (size_t)n);
    }
    close(g_fd);
    return 0;
}
