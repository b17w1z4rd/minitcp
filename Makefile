CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra
CORE     = proto.c minitcp.c
HDRS     = proto.h minitcp.h

demo: demo.c $(CORE) $(HDRS)
	$(CC) $(CFLAGS) demo.c $(CORE) -o demo

# Live driver over a real TAP device. Needs root and a configured tap0
# (see the README); builds everywhere but only runs with privileges.
tap: tap.c $(CORE) $(HDRS)
	$(CC) $(CFLAGS) tap.c $(CORE) -o tap

test: demo
	./demo

# Live interop test: the real kernel TCP stack connects to ours over a TAP
# device. Needs root (configures the interface via ioctl; no iproute2 required).
live: tap
	python3 livetest.py

clean:
	rm -f demo tap

.PHONY: test clean
