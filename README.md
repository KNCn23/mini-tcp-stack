# mini-tcp-stack

A small, readable **TCP/IP stack written from scratch in C**. It parses and
builds Ethernet, ARP, IPv4, ICMP and TCP, implements the TCP three-way
handshake and teardown as a proper state machine, and ties everything together
in a userspace program that answers `ping` and runs a TCP echo server over a
Linux TAP device.

It is built for *learning*: every layer is a self-contained module with unit
tests, the code favours clarity over micro-optimisation, and the simplifications
are documented rather than hidden.

```
$ make test
Running build/test_checksum   ...  4 checks, 0 failures
Running build/test_headers    ... 33 checks, 0 failures
Running build/test_tcp        ... 37 checks, 0 failures
ALL TESTS PASSED
```

---

## Table of contents

1. [What's inside](#whats-inside)
2. [The layer cake](#the-layer-cake)
3. [Build & test](#build--test)
4. [Tutorial 1 — Read the checksum module first](#tutorial-1--read-the-checksum-module-first)
5. [Tutorial 2 — Follow a packet through the layers](#tutorial-2--follow-a-packet-through-the-layers)
6. [Tutorial 3 — The TCP state machine](#tutorial-3--the-tcp-state-machine)
7. [Tutorial 4 — Run the live demo on a TAP device (Linux)](#tutorial-4--run-the-live-demo-on-a-tap-device-linux)
8. [Project layout](#project-layout)
9. [What is and isn't implemented](#what-is-and-isnt-implemented)
10. [References](#references)

---

## What's inside

| Module | Header | Does |
|--------|--------|------|
| Checksum | [`checksum.h`](include/netstack/checksum.h) | The RFC 1071 Internet checksum, incremental + one-shot. |
| Ethernet | [`ethernet.h`](include/netstack/ethernet.h) | Parse/build the 14-byte L2 header. |
| ARP | [`arp.h`](include/netstack/arp.h) | who-has/is-at request & reply, plus a small cache. |
| IPv4 | [`ipv4.h`](include/netstack/ipv4.h) | 20-byte header with header-checksum validation. |
| ICMP | [`icmp.h`](include/netstack/icmp.h) | Echo request → echo reply (i.e. ping). |
| TCP | [`tcp.h`](include/netstack/tcp.h) | Header + pseudo-header checksum, full connection state machine. |

## The layer cake

A frame coming off the wire is peeled one layer at a time:

```
+--------------------------------------------------------------+
| Ethernet header | IPv4 header | TCP header | application data |
+--------------------------------------------------------------+
       eth_parse()    ipv4_parse()   tcp_parse()     -> your bytes
```

Each `*_parse()` validates its header (length, version, checksum) and hands the
remaining payload to the next layer. On the way out, each `*_build()` writes its
header and fixes up the checksum.

## Build & test

You need a C11 compiler (`gcc` or `clang`) and `make`.

```bash
git clone https://github.com/KNCn23/mini-tcp-stack.git
cd mini-tcp-stack
make            # builds the static library and the test binaries
make test       # runs every unit test
```

There are no third-party dependencies. The library and tests are portable
(macOS, Linux, BSD); only the live TAP demo is Linux-specific.

---

## Tutorial 1 — Read the checksum module first

Every protocol here relies on the same 16-bit one's-complement checksum, so it
is the best place to start.

1. Open [`src/checksum.c`](src/checksum.c). The whole algorithm is: sum the data
   as a sequence of 16-bit big-endian words, fold the carries back in, then take
   the one's complement.

2. The clever property is that a block which *includes* a correct checksum sums
   back to zero. That is exactly how a receiver validates a header — and how our
   parsers do it:

   ```c
   if (ns_checksum(buf, IPV4_HDR_LEN) != 0)
       return -1;   // header is corrupt
   ```

3. See it in the test [`tests/test_checksum.c`](tests/test_checksum.c): the
   `test_rfc1071_example` case reproduces the worked example from RFC 1071 (the
   words `0001 f203 f4f5 f6f7` checksum to `0x220d`).

## Tutorial 2 — Follow a packet through the layers

Suppose a ping arrives. Here is the journey, all of which you can read in
[`apps/taptcp.c`](apps/taptcp.c):

1. **Ethernet** — `eth_parse()` reads the 14-byte header and reports
   `ethertype == 0x0800` (IPv4). The payload pointer now sits at the IP header.
2. **IPv4** — `ipv4_parse()` checks the version, rejects packets with options or
   a bad header checksum, and tells us `protocol == 1` (ICMP).
3. **ICMP** — `icmp_make_echo_reply()` validates the echo *request* checksum,
   flips the type byte from 8 to 0, and recomputes the checksum.
4. **On the way out** — `ipv4_build()` and `eth_build()` wrap the reply, swapping
   source/destination so it heads back to the sender.

Each step is one function call with no hidden global state, so you can unit-test
or reuse any layer on its own.

## Tutorial 3 — The TCP state machine

TCP is the heart of the project. The connection block `tcp_conn_t` tracks the
sequence-number bookkeeping; `tcp_input()` is the state machine.

A passive-open server walks through these states:

```
                 recv SYN / send SYN+ACK
  LISTEN ───────────────────────────────────▶ SYN_RECEIVED
                                                    │ recv ACK
                                                    ▼
                                              ESTABLISHED ◀── data in/out
                                                    │ recv FIN / send ACK
                                                    ▼
                                              CLOSE_WAIT
                                                    │ app close / send FIN
                                                    ▼
                                               LAST_ACK
                                                    │ recv ACK
                                                    ▼
                                                CLOSED
```

The test [`tests/test_tcp.c`](tests/test_tcp.c) drives a server connection
through this *entire* lifecycle by hand-crafting the client's segments, and
asserts the sequence/ack numbers at every step. Read `test_tcp_full_lifecycle`
to see the protocol unfold:

```c
tcp_listen(&srv, SRV_IP, 80, /*iss=*/1000);

tcp_segment_t syn = client_seg(TCP_SYN, 500, 0, NULL);
tcp_input(&srv, &syn, &out);
// out is SYN+ACK, seq=1000, ack=501; state is now SYN_RECEIVED
```

The key sequence-number rules to notice:

* A `SYN` and a `FIN` each consume **one** sequence number (that is why the ACK
  numbers are `seq + 1`).
* Data advances the sequence number by its byte length.
* The receiver's ACK number is always "the next byte I expect" (`rcv_nxt`).

## Tutorial 4 — Run the live demo on a TAP device (Linux)

A TAP device is a virtual Ethernet interface: bytes you write to the file
descriptor appear as frames on `tap0`, and frames sent to `tap0` come back out
of the descriptor. This lets our userspace stack speak to the real Linux kernel
networking tools. **TAP is Linux-only**, so this section needs a Linux machine
(a VM or container is fine).

1. **Build the demo:**

   ```bash
   make taptcp
   ```

2. **Start the stack** (it needs root to create the TAP device):

   ```bash
   sudo ./build/taptcp
   ```

   It prints `mini-tcp-stack listening as 10.0.0.2 on tap0` and waits.

3. **Configure the host side of the link** in a second terminal:

   ```bash
   sudo ip addr add 10.0.0.1/24 dev tap0
   sudo ip link set tap0 up
   ```

   Now the Linux kernel is `10.0.0.1` and our stack is `10.0.0.2` on the same
   virtual wire.

4. **Ping it:**

   ```bash
   ping 10.0.0.2
   ```

   You should get replies. In the first terminal you'll see the ARP exchange and
   each `ICMP: echo reply` logged.

5. **Talk to the echo server** (TCP port 7):

   ```bash
   nc 10.0.0.2 7
   hello
   hello          # the stack echoes it back
   ```

   The first terminal logs the state transitions
   `LISTEN -> SYN_RECEIVED -> ESTABLISHED`, the echoed bytes, and the teardown
   when you press Ctrl-C / Ctrl-D.

6. **Clean up:**

   ```bash
   sudo ip link delete tap0    # (the device disappears when taptcp exits anyway)
   ```

> **Wireshark tip:** run `sudo tcpdump -i tap0 -X` (or open `tap0` in Wireshark)
> while you ping/connect to watch the exact bytes this stack puts on the wire.

## Project layout

```
mini-tcp-stack/
├── include/netstack/    # public headers, one per layer
├── src/                 # the implementation (checksum, eth, arp, ipv4, icmp, tcp)
├── tests/               # dependency-free unit tests + a tiny harness
├── apps/taptcp.c        # Linux TAP integration demo (ARP + ping + TCP echo)
└── Makefile
```

## What is and isn't implemented

This is a teaching stack. It deliberately keeps the parts that make the
protocols *click* and omits the parts that are mostly engineering grind.

**Implemented**
- Ethernet II, ARP (with cache), IPv4 (no options), ICMP echo.
- TCP: pseudo-header checksum, passive-open handshake, in-order data with
  cumulative ACKs, application send, graceful close from either side, RST.

**Not implemented (on purpose)**
- Retransmission timers and RTT estimation — segments are assumed delivered.
- Congestion control and dynamic flow control (the window is static).
- Out-of-order segment reassembly — only in-order data is accepted.
- TCP options (MSS, window scaling, SACK, timestamps) and IP fragmentation.
- Active open (`connect`) — the demo is a server. The state enum includes
  `SYN_SENT` so the path is easy to add.

These omissions are why it is a few hundred readable lines instead of tens of
thousands. Each would be a good exercise to add.

## References

- RFC 791 — Internet Protocol (IPv4)
- RFC 792 — Internet Control Message Protocol (ICMP)
- RFC 793 — Transmission Control Protocol (TCP)
- RFC 826 — Address Resolution Protocol (ARP)
- RFC 1071 — Computing the Internet Checksum

## License

[MIT](LICENSE)
