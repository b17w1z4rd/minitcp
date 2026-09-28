#!/usr/bin/env python3
"""
livetest.py - prove the stack against the real Linux kernel TCP implementation.

This runs the userspace stack on a real TAP device, configures the host side of
that device with raw ioctls (so it needs neither iproute2 nor root's `ip`
command, just root), and then does an ordinary socket connect() to the stack's
address. That connect() is the *kernel's* TCP stack acting as the client: if our
hand-written handshake, sequence numbers, and checksums are correct, the kernel
completes the connection and the echo round-trips.

Run:  sudo make live      (or:  make tap && sudo python3 livetest.py)
"""
import socket, fcntl, struct, subprocess, time, sys

IFN = b'tap0'
HOST_IP, STACK_IP, PORT = '10.0.0.1', '10.0.0.2', 7
SIOCSIFADDR, SIOCSIFNETMASK = 0x8916, 0x891c
SIOCGIFFLAGS, SIOCSIFFLAGS  = 0x8913, 0x8914
IFF_UP, IFF_RUNNING = 0x1, 0x40

def ifreq_addr(ip):
    return struct.pack('16sH2s4s8s', IFN, socket.AF_INET, b'\0\0',
                       socket.inet_aton(ip), b'\0' * 8)

def main():
    tap = subprocess.Popen(['./tap', 'tap0', STACK_IP, str(PORT)],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    time.sleep(0.7)  # give it a moment to create tap0

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    fcntl.ioctl(s, SIOCSIFADDR,    ifreq_addr(HOST_IP))
    fcntl.ioctl(s, SIOCSIFNETMASK, ifreq_addr('255.255.255.0'))
    flags = struct.unpack('16sh', fcntl.ioctl(s, SIOCGIFFLAGS,
                          struct.pack('16sh', IFN, 0)))[1]
    fcntl.ioctl(s, SIOCSIFFLAGS, struct.pack('16sh', IFN, flags | IFF_UP | IFF_RUNNING))
    time.sleep(0.3)

    rc = 1
    try:
        c = socket.create_connection((STACK_IP, PORT), timeout=3.0)
        print('[live] kernel TCP connected to the userspace stack at %s:%d' % (STACK_IP, PORT))
        msg = b'hello from the kernel'
        c.sendall(msg)
        echoed = c.recv(100)
        print('[live] sent %d bytes, stack echoed:' % len(msg), echoed)
        rc = 0 if echoed == msg else 2
        c.close()
    except Exception as e:
        print('[live] FAILED:', type(e).__name__, e)
        rc = 3
    finally:
        tap.terminate()
        try: tap.wait(timeout=2)
        except Exception: tap.kill()

    print('[live] result:', 'PASS - real kernel TCP interoperated with the stack' if rc == 0
                            else 'FAIL (%d)' % rc)
    return rc

if __name__ == '__main__':
    sys.exit(main())
