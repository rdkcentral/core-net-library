# core-net-library — Component Overview

## Purpose

`core-net-library` (published as **libnet**) is a C shared library that provides a
stable, safe, and thread-safe API for Linux network configuration.  It abstracts
the raw libnl3 / Netlink Route (RTNL) socket API behind a set of clearly named
functions covering:

- Network interface lifecycle (create, up/down, rename, delete)
- VLAN management (802.1Q sub-interfaces)
- Bridge management (Linux software bridge + STP)
- IP address management (IPv4 and IPv6)
- Routing table management (unicast routes + policy rules)
- Neighbour (ARP/NDP) table queries and deletions
- Interface statistics collection
- IPv4-in-IPv6 tunnel creation (`ip6tnl`)
- Kernel parameter injection via `/sys` and `/proc`

The library is used by higher-level RDK-B daemons (e.g. CcspPandMSsp) that
require programmatic network configuration without spawning shell commands.

## Repository Structure

```
core-net-library/
├── source/
│   ├── libnet.h            Public API header
│   ├── libnet.c            API implementation (all Netlink operations)
│   ├── libnet_util.h       Internal libnl3 helper declarations
│   ├── libnet_util.c       Internal libnl3 helper implementations
│   ├── corenetlib_api.c    XML-driven CLI / functional test harness
│   └── corenetlib_tests.xml  Test-case definitions consumed by corenetlib_api
├── test/
│   ├── libnet_test.cpp     GTest integration test suite
│   ├── TestUtils.hpp/.cpp  Shared test helpers (system-command validation)
│   └── gtest_main.cpp      GTest entry point
├── configure.ac            Autoconf build configuration
├── source/Makefile.am      Automake rules (libnet.la + corenetlib_api binary)
└── CHANGELOG.md            Release history
```

## Key Deliverables

| Artifact | Type | Description |
|---|---|---|
| `libnet.la` | Shared library | The primary deliverable consumed by upstream components |
| `libnet.h` | Public header | Only file callers need to include |
| `corenetlib_api` | Binary | XML-driven functional test tool; logs to `/rdklogs/logs/corenetlib_api.log` |

## Version History (abridged)

| Version | Notable change |
|---|---|
| 1.0.0 | Initial import (stable2) |
| 1.1.0 | stdlib.h include fix; wwan0 IPv6 route crash fix |
| 2.0.0 | Thread-safe redesign (per-call socket allocation) |
| 2.1.0 | Klocwork fix — bounded copy in `interface_set_mac` |
| 2.2.0 | `corenetlib_api` test harness added; Coverity CI integration |
| 2.3.0 | `libnet_util` refactor — decoupled from libnl CLI reference code |

## License

Apache-2.0 — Copyright 2020 Comcast Cable Communications Management, LLC
