# Developer Guide

## Build

```bash
# Prerequisites: autoconf, automake, libtool, libnl3-dev, safec_lib, libxml2-dev

autoreconf -fi
./configure
make
sudo make install
```

To build with the GTest integration suite:
```bash
./configure --enable-gtestapp
make
```

### Cross-compilation
Set `PKG_CONFIG_SYSROOT_DIR` for the sysroot containing libnl3 headers:
```bash
./configure PKG_CONFIG_SYSROOT_DIR=/path/to/sysroot
```

---

## Running the Functional Test Harness (`corenetlib_api`)

```bash
./corenetlib_api corenetlib_tests.xml
```

- Test cases are defined in `source/corenetlib_tests.xml`.
- Results are printed to stdout and appended to `/rdklogs/logs/corenetlib_api.log`.
- Return code: 0 = all passed, non-zero = failures.

To run a single API:
```bash
./corenetlib_api addr_add "dev brlan0 192.168.1.100/24"
./corenetlib_api interface_up lo
./corenetlib_api bridge_create mybridge
```

---

## Running the GTest Suite (`libnet_test`)

```bash
# Requires root / CAP_NET_ADMIN and a suitable test interface
sudo ./libnet_test dummy0 dummy 100 testBridge0000 dummy1
```

Parameters (in order):
1. Interface name (default: `dummy0`)
2. Interface type (default: `dummy`)
3. VLAN ID (default: `100`)
4. Bridge name (default: `testBridge0000`)
5. Ephemeral interface name (default: `dummy1`)

Test setup creates `dummy0` and `dummy1` using `ip link add type dummy`.

---

## Logging

All library log output goes to **stderr** using these macros:

```c
CNL_LOG_INFO("Entering with args: '%s'\n", args);
CNL_LOG_ERROR("Unable to add vlan link %s: %s (err=%d)\n", name, nl_geterror(ret), ret);
CNL_LOG_WARNING("...");
CNL_LOG_NOTICE("...");
```

Format: `<function>:<line> <message>`

To capture library logs at runtime:
```bash
your_program 2>/tmp/libnet.log
# or
your_program 2>&1 | grep -E "libnet|CNL"
```

**Level mapping**: All four macros (`INFO`, `ERROR`, `NOTICE`, `WARNING`) use
`fprintf(stderr, ...)` — there is no log-level filtering.  If level filtering
is required, callers should redirect or filter stderr themselves.

---

## Debug Commands

### Inspect a network interface
```bash
ip link show <interface>
ip addr show <interface>
ip -6 addr show <interface>
cat /sys/class/net/<interface>/address   # MAC
cat /sys/class/net/<interface>/mtu
cat /sys/class/net/<interface>/operstate
```

### Inspect routing tables
```bash
ip route show table main
ip route show table all
ip rule list
```

### Inspect neighbour/ARP table
```bash
ip neigh show
ip neigh show dev eth0
arp -n
```

### Inspect bridges
```bash
bridge link show
bridge vlan show
cat /sys/class/net/<bridge>/bridge/stp_state
```

### Verify Netlink connectivity
```bash
# If strace is available, trace Netlink socket calls:
strace -e trace=socket,connect,sendto,recvfrom -p <pid>
```

### Check interface statistics
```bash
ip -s link show <interface>
cat /proc/net/dev | grep <interface>
```

---

## Validation Steps for New Integrations

1. **Link layer**: Verify `interface_exist()` returns SUCCESS before any operation.
2. **Address**: Verify with `ip addr show <interface>` after `addr_add`.
3. **Route**: Verify with `ip route show table <table>` after `route_add`.
4. **Rule**: Verify with `ip rule list` after `rule_add`.
5. **Bridge**: Verify with `bridge link show` after `interface_add_to_bridge`.
6. **Stats**: Cross-check `interface_get_stats` output against `ip -s link show`.
7. **Thread safety**: Confirmed since v2.0.0 — each call is fully independent.

---

## Common Pitfalls

| Pitfall | Detail |
|---|---|
| `interface_get_ip` returns stale pointer | Returns `inet_ntoa()` static buffer — copy immediately |
| `bridge_get_info` silently truncates | Only first 8 slave interfaces are stored |
| `addr_add` with NLM_F_EXCL | Fails if address already exists — use `addr_delete` first |
| `tunnel_add_ip4ip6` ignores `encaplimit` | Parameter accepted but not applied |
| `interface_rename` on UP interface | Not recommended — may cause unpredictable behavior |
| `neighbour_free_neigh` ownership | Frees the struct itself — do not use the pointer after calling |
| `interface_set_ip` macro | Expands to `addr_add("dev <if> <addr>")` — no broadcast auto-derived |

---

## Adding a New API Function

1. Declare in `libnet.h` with a doc comment matching the existing style.
2. Implement in `libnet.c` following the canonical pattern:
   - alloc socket → connect → alloc cache → alloc object → operate → goto cleanup chain
3. Add helper parsers in `libnet_util.c` / `libnet_util.h` if needed.
4. Add handler in `corenetlib_api.c` (`handle_<name>`) and register in `handler_table[]`.
5. Add test cases to `corenetlib_tests.xml` (positive + negative cases).
6. Add GTest coverage in `test/libnet_test.cpp`.
