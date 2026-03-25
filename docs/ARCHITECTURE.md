# SockFuzzer Architecture

## Overview

SockFuzzer compiles the real XNU BSD networking code into a userland library
(`libxnu`) and drives it with structure-aware fuzzing via libprotobuf-mutator
and libFuzzer.

```
 ┌──────────────────────────────────────────────────────────┐
 │                    libFuzzer Engine                       │
 │  (coverage-guided mutation of protobuf Session messages)  │
 └──────────────┬───────────────────────────────────────────┘
                │ protobuf binary input
                ▼
 ┌──────────────────────────────────────────────────────────┐
 │              net_fuzzer.cc  (C++ harness)                 │
 │                                                          │
 │  ┌─────────────┐  ┌──────────────┐  ┌────────────────┐  │
 │  │ Syscall      │  │ Packet       │  │ NECP/ioctl     │  │
 │  │ Handlers     │  │ Injection    │  │ Handlers       │  │
 │  │ (socket,     │  │ (ip_input,   │  │ (necp_open,    │  │
 │  │  bind, ...)  │  │  ip6_input)  │  │  diocstart,..) │  │
 │  └──────┬──────┘  └──────┬───────┘  └───────┬────────┘  │
 └─────────┼────────────────┼───────────────────┼───────────┘
           │                │                   │
           ▼                ▼                   ▼
 ┌──────────────────────────────────────────────────────────┐
 │              libxnu  (real XNU BSD kernel code)           │
 │                                                          │
 │  bsd/kern/     — socket, pipe, descriptor management     │
 │  bsd/net/      — interface, routing, PF, NECP, bridge    │
 │  bsd/netinet/  — IPv4, TCP, UDP, ICMP, IGMP, IPsec      │
 │  bsd/netinet6/ — IPv6, ICMPv6, NDP, MLD, frag6          │
 │  bsd/netkey/   — PF_KEY, SA/SP database                  │
 │                                                          │
 └──────────────┬───────────────────────────────────────────┘
                │ calls into faked subsystems
                ▼
 ┌──────────────────────────────────────────────────────────┐
 │                   Fake Subsystems                         │
 │                                                          │
 │  fake_impls.c  — copyin/copyout, time, UUID, permissions │
 │  zalloc.c      — zone allocator → malloc/calloc          │
 │  mbuf.c        — mbuf creation and lifecycle             │
 │  thread.c      — single fake thread                      │
 │  stubs.c       — 500+ unimplemented function stubs       │
 │  osfmk_stubs.c — Mach/OSFMK layer stubs                 │
 │  san.c         — KASAN bridge to ASAN                    │
 └──────────────────────────────────────────────────────────┘
```

## Build Pipeline

```
XNU source (third_party/xnu/)
        │
        ├── bsd objects ──────┐
        │   (XNU_C_FLAGS,     │
        │    BSD_DEFINES)     │
        │                     ├──► ld -r ──► nmedit -s ──► libxnu_relocatable.o
        ├── osfmk objects ────┘       │         │
        │   (XNU_C_FLAGS,             │         └── only exported symbols visible
        │    OSFMK_DEFINES)           │
        │                             │
net_fuzzer.cc ────────────────────────┼──► net_fuzzer executable
net_fuzzer.proto ──► protoc ──────────┘
libprotobuf-mutator ──────────────────┘
```

**Symbol isolation** is critical: XNU defines its own `printf`, `read`, `write`,
`ioctl`, `sigaction`, etc. Without symbol localization, these override libc and
break libFuzzer/protobuf. On macOS we use `nmedit -s` with an explicit export
list; on Linux we use `objcopy --localize-hidden`.

## Protobuf Grammar

The fuzzer input is a `Session` message containing a sequence of `Command`
messages plus a `data_provider` bytes field for supplementary fuzzed data.

Each `Command` is a oneof covering:
- **Socket lifecycle**: socket, bind, listen, connect, accept, close, shutdown
- **Data transfer**: sendmsg, sendto, recvmsg, recvfrom
- **Configuration**: setsockopt, getsockopt, ioctl, ioctl_real
- **Packet injection**: TCP/UDP/ICMP over IPv4/IPv6, raw packets
- **NECP**: client management, session management, policy matching
- **PF firewall**: start/stop
- **Advanced**: connectx, disconnectx, peeloff, socketpair, pipe

## State Management

Each fuzzer iteration:
1. Runs all commands from the protobuf `Session`
2. Closes all tracked file descriptors
3. Calls `clear_all()` which:
   - Runs kernel timers (inpcb, key, frag, nd6, igmp, mld, tcp, route)
   - Resets mbuf page pool
   - Resets progressive time counter
   - Resets UUID counter
   - Clears fake thread state

## Key Design Decisions

1. **Single-threaded model**: All lock operations are no-ops. This is intentional
   — it eliminates nondeterminism and makes crashes reproducible. Race condition
   detection requires the coroutine executor (planned for v5.0).

2. **Fuzzed kernel responses**: copyin/copyout, permission checks, and random
   functions use `get_fuzzed_bool()`/`get_fuzzed_bytes()` to exercise both
   success and failure paths.

3. **Progressive time**: Time functions advance by 100us per call, enabling
   timer-driven code paths (TCP retransmit, keepalive, route expiry).

4. **ASAN instrumentation**: All zone allocations go through malloc/calloc,
   which ASAN instruments. This catches heap buffer overflows, use-after-free,
   and double-free in XNU code.
