# minitcp

![Language: C](https://img.shields.io/badge/language-C99-blue.svg)
![Platform: Linux](https://img.shields.io/badge/platform-Linux-lightgrey.svg)
![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)

A **userspace TCP/IP stack** in C — it speaks the wire format directly, with no
kernel sockets. From the bottom up it implements **Ethernet**, **ARP**, **IPv4**
(with checksums), **ICMP** (ping replies), and a real **TCP state machine**
(passive open → data → teardown) driving an echo server.

And it's not just self-consistent — **the real Linux kernel TCP stack can connect
to it** over a TAP device and exchange data:

```
$ sudo make live
[live] kernel TCP connected to the userspace stack at 10.0.0.2:7
[live] sent 21 bytes, stack echoed: b'hello from the kernel'
[live] result: PASS - real kernel TCP interoperated with the stack
```

That's the strongest test there is: the kernel's production TCP implementation
completing a genuine 3-way handshake, data transfer, and teardown against this
hand-written stack.

## The TCP state machine

TCP is the hard part, and it comes down to sequence-number bookkeeping. The stack
tracks `snd_nxt` (next byte we'll send), `snd_una` (oldest unacked), and
`rcv_nxt` (next byte we expect), and moves through:

```
        SYN  →                LISTEN
   ← SYN,ACK                  SYN_RCVD      (our ISN, ack = their seq + 1)
        ACK  →                ESTABLISHED
   data → ← data (echo+ACK)   ESTABLISHED   (piggybacked ACK)
        FIN  → ← FIN,ACK      LAST_ACK
        ACK  →                CLOSED
```

Each reply carries correct sequence/ack numbers and a valid TCP checksum
(computed over the pseudo-header + segment). The offline harness asserts all of
it, byte for byte.

## Two ways it's verified

**1. Offline harness (`make test`)** — no root, fully deterministic. A test
"peer" hand-builds inbound frames and asserts on every response — flags,
sequence/ack numbers, payload, and that the checksums the stack emitted are
actually valid:

```
== ARP ==            [PASS] ARP reply: 10.0.0.2 is-at 52:54:00:11:22:33
== ICMP ==           [PASS] ICMP echo reply: id=0xABCD payload="ping!" (cksum ok)
== TCP handshake ==  [PASS] SYN,ACK  seq=1000 ack=5001 (cksum ok)
                     [PASS] bare ACK completes handshake -> ESTABLISHED
== TCP data ==       [PASS] PSH,ACK  seq=1001 ack=5006 payload="hello" echoed
== TCP teardown ==   [PASS] FIN,ACK  seq=1006 ack=5007 (cksum ok)
                     [PASS] final ACK -> CLOSED
```

**2. Live interop (`sudo make live`)** — the stack runs on a real TAP device and
the Linux kernel is the client (an ordinary `socket.connect()` from Python). No
`iproute2` needed; the interface is configured with raw `ioctl`s.

## Architecture

The stack is decoupled from the wire by a single callback:

```c
struct NetIf {
    uint8_t  mac[6];
    uint32_t ip;
    void   (*tx)(NetIf *, const uint8_t *frame, size_t len);  // put a frame on the link
    ...
};
void netif_rx(NetIf *, const uint8_t *frame, size_t len);     // feed one inbound frame
```

`netif_rx` is a pure function of (frame, state) → (frames out via `tx`). That's
what makes it testable offline: the harness just makes `tx` push into a queue it
inspects. The TAP driver makes `tx` write to the device. Same stack, different
edge.

## Build & run

```sh
git clone https://github.com/b17w1z4rd/minitcp.git
cd minitcp

make            # builds ./demo (the offline harness)
make test       # run it — the full ARP/ICMP/TCP conversation, asserted
make tap        # builds ./tap, the live TAP driver
sudo make live  # live interop test against the kernel's TCP
```

### Running it live yourself

```sh
make tap
sudo ip tuntap add dev tap0 mode tap    # or let livetest.py configure via ioctl
sudo ip addr add 10.0.0.1/24 dev tap0
sudo ip link set tap0 up
sudo ./tap tap0 10.0.0.2                 # stack answers for 10.0.0.2, echo on port 7
# elsewhere:
ping 10.0.0.2
printf 'hi\n' | nc 10.0.0.2 7
```

## Project layout

| File          | What it is                                                  |
|---------------|-------------------------------------------------------------|
| `proto.c/.h`  | Checksums (incl. TCP pseudo-header) and packet builders.    |
| `minitcp.c/.h`| The stack: NetIf, ARP, ICMP, and the TCP state machine.     |
| `demo.c`      | Offline harness — injects a conversation, asserts replies.  |
| `tap.c`       | Live driver over a Linux TAP device.                        |
| `livetest.py` | Live interop test driven by the kernel's own TCP.           |
| `Makefile`    | `test`, `tap`, `live`, `clean`.                             |

## Scope & limitations

A teaching stack — correct where it counts, honestly simplified elsewhere:

- One TCP connection at a time; a fixed initial sequence number.
- No retransmission timers (it answers immediately, so the kernel peer never
  needs to retransmit in the tested flows).
- No congestion or flow control beyond a fixed advertised window; in-order
  segments only.
- TCP options in an inbound SYN are skipped (data offset is honored); our own
  segments carry none.

## Roadmap

- [ ] Retransmission queue + RTO timers
- [ ] Sliding window / flow control, and out-of-order reassembly
- [ ] Multiple simultaneous connections (a real connection table)
- [ ] Active open (`connect`) and a tiny sockets-style API
- [ ] UDP, and TCP options (MSS, window scale)

## References

- [RFC 793 — Transmission Control Protocol](https://www.rfc-editor.org/rfc/rfc793)
- Stevens, *TCP/IP Illustrated, Vol. 1*
- [saminiir — Let's code a TCP/IP stack](https://www.saminiir.com/lets-code-tcp-ip-stack-1-ethernet-arp/)

## License

MIT — see [LICENSE](LICENSE).
