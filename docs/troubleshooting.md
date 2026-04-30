# Troubleshooting Guide

All log lines are emitted to **stderr** with the format:
```
<function>:<line> <message>
```

---

## Issue 1: Interface operation fails with "Unable to allocate memory for socket"

### Symptom
```
interface_up:42 Unable to allocate memory for socket
```

### Logs
Any function that allocates a Netlink socket.

### Root Cause
`nl_socket_alloc()` returned NULL — system is out of memory, or the process
has hit its file-descriptor limit.

### Debug Steps
```bash
# Check available memory
free -m

# Check open file descriptors for the calling process
ls -l /proc/<pid>/fd | wc -l
cat /proc/sys/fs/file-max
ulimit -n
```

### Resolution
- Increase process FD limit in the relevant systemd unit:
  `LimitNOFILE=65536`
- Investigate memory pressure; check `dmesg` for OOM events.

---

## Issue 2: Interface operation fails with "Unable to connect socket"

### Symptom
```
interface_up:55 Unable to connect socket
libnet_connect:38 Failed to connect netlink socket (proto=0): Operation not permitted (err=-33)
```

### Root Cause
`nl_connect(sk, NETLINK_ROUTE)` failed. Most commonly the process lacks
`CAP_NET_ADMIN` capability.

### Debug Steps
```bash
# Check capabilities of the running process
cat /proc/<pid>/status | grep Cap
capsh --decode=<CapEff value>

# Or test directly
ip link show  # if this works, kernel netlink is up
```

### Resolution
Grant `CAP_NET_ADMIN` to the process in its systemd unit:
```
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN
```

---

## Issue 3: Interface not found in cache

### Symptom
```
interface_up:72 Interface 'eth0' not found
bridge_create:202 Unable to find the bridge 'br0'
```

### Root Cause
The interface does not exist in the kernel at the time of the call. The Netlink
link cache is populated at call time (not cached persistently).

### Debug Steps
```bash
ip link show eth0
ls /sys/class/net/
# Check if interface was renamed
ip link show | grep -v LOOPBACK
```

### Resolution
- Ensure the interface is created before calling `interface_up`.
- If using `interface_exist()` as a guard, note it checks `/sys/class/net/`
  which is updated slightly before the Netlink cache is consistent — add a
  short retry or use `interface_exist()` as the canonical check.

---

## Issue 4: VLAN creation fails with "Unable to add vlan link"

### Symptom
```
vlan_create:140 Unable to add vlan link eth0.100: File exists (err=-17)
```

### Root Cause
`NLM_F_EXCL` causes failure if the VLAN sub-interface already exists (errno 17 = `EEXIST`).

### Debug Steps
```bash
ip link show eth0.100
```

### Resolution
Check existence before creating:
```c
if (interface_exist("eth0.100") != CNL_STATUS_SUCCESS)
    vlan_create("eth0", 100);
```

---

## Issue 5: `addr_add` fails with "Unable to add addr"

### Symptom
```
addr_add:910 dev eth0 192.168.1.1/24: Unable to add addr: File exists (err=-17)
```

### Root Cause
`NLM_F_EXCL` prevents adding a duplicate address.

### Debug Steps
```bash
ip addr show eth0
```

### Resolution
Delete the existing address first with `addr_delete("dev eth0 192.168.1.1/24")`,
then re-add.

---

## Issue 6: `route_add` silently replaces existing route

### Symptom
Previous route on the same destination is overwritten without error.

### Root Cause
`route_add` uses `NLM_F_CREATE | NLM_F_REPLACE` — this is by design (upsert).

### Debug Steps
```bash
ip route show table <table>
ip route show table main
```

### Resolution
This is the intended behavior. To detect prior routes:
```bash
ip route get <destination>
```

---

## Issue 7: `rule_add` fails with "No such table"

### Symptom
```
rule_add:1550 No such table myroutingtable
```

### Root Cause
`rtnl_route_str2table("myroutingtable")` could not find the name in
`/etc/iproute2/rt_tables`.

### Debug Steps
```bash
cat /etc/iproute2/rt_tables
grep myroutingtable /etc/iproute2/rt_tables
```

### Resolution
Either add the table name to `/etc/iproute2/rt_tables`, or use a numeric
table ID directly:
```c
rule_add("from 10.0.0.0/8 table 200");
```

---

## Issue 8: `bridge_set_stp` fails with "does not exist or is not writeable"

### Symptom
```
bridge_set_stp:420 file_name /sys/class/net/br0/bridge/stp_state does not exist or is not writeable
```

### Root Cause
Either the bridge does not exist, or the kernel was compiled without bridge STP
support, or the sysfs path is not present.

### Debug Steps
```bash
ls /sys/class/net/br0/bridge/
cat /sys/class/net/br0/bridge/stp_state
```

### Resolution
- Verify bridge is created: `bridge_create("br0")` first.
- Verify kernel has `CONFIG_BRIDGE=y` and `CONFIG_BRIDGE_STP=y`.

---

## Issue 9: `interface_get_ip` returns NULL

### Symptom
Function returns NULL, with log:
```
interface_get_ip:650 Failed to get eth0 IP Address
```

### Root Cause
`ioctl(SIOCGIFADDR)` failed — interface may be DOWN, have no IPv4 address
assigned, or the socket creation failed.

### Debug Steps
```bash
ip addr show eth0
ip link show eth0   # check if UP
```

### Resolution
- Bring the interface up with `interface_up("eth0")`.
- Assign an address with `addr_add("dev eth0 <ip>/prefix")`.
- **Important**: `interface_get_ip` returns a pointer to `inet_ntoa()`'s
  static buffer. Copy the result immediately before another call overwrites it.

---

## Issue 10: Neighbour list is empty despite active ARP table

### Symptom
`neighbour_get_list` returns SUCCESS but `arr->neigh_count == 0`.

### Root Cause
All neighbour entries are in `NUD_PERMANENT`, `NUD_NOARP`, or `NUD_NONE`
state — these are explicitly filtered out.

### Debug Steps
```bash
ip neigh show
# Look for entries NOT in "permanent" or "noarp" state
arp -n
```

### Resolution
This is correct behavior — static/permanent ARP entries are excluded.
To include permanent entries, a separate query with different filtering
would be required (not currently exposed by the API).

---

## Issue 11: `tunnel_add_ip4ip6` fails with "Invalid local/remote IPV6 address"

### Symptom
```
tunnel_add_ip4ip6:1820 Invalid local IPV6 address
```

### Root Cause
`inet_pton(AF_INET6, local_ip6, &addr)` returned ≠ 1 — the address string
is not a valid IPv6 address.

### Debug Steps
```bash
python3 -c "import ipaddress; ipaddress.ip_address('<addr>')"
```

### Resolution
Validate IPv6 address format before calling. Ensure the string is in full or
compressed IPv6 notation (e.g. `2001:db8::1`), not a mapped IPv4 address.

---

## Issue 12: Memory leak in neighbour / bridge info

### Symptom
Valgrind reports leaked memory after calls to `neighbour_get_list` or
`bridge_get_info`.

### Root Cause
Caller did not call `neighbour_free_neigh()` or `bridge_free_info()`.

### Resolution
Always pair:
```c
struct neighbour_info *info = init_neighbour_info();
neighbour_get_list(info, NULL, NULL, 0);
// ... use info ...
neighbour_free_neigh(info);   // MANDATORY — frees struct + all strings

bridge_get_info(bridge_name, &bridge);
// ... use bridge ...
bridge_free_info(&bridge);    // MANDATORY — even on failure path
```

---

## Issue 13: `get_ipv6_address` returns address from wrong interface

### Symptom
`get_ipv6_address("eth0", buf, sizeof(buf))` returns an IPv6 address that
belongs to a different interface (e.g., `eth1` or `lo`).

### Logs
No error logged — function returns SUCCESS with a valid but unexpected address.

### Root Cause
`get_ipv6_address` iterates the **full** kernel address cache (all interfaces),
not filtered to `if_name`. It returns the first global-scope IPv6 address found
system-wide. The `if_name` parameter is only used to verify the interface exists.

### Debug Steps
```bash
ip -6 addr show scope global
# Check which interface holds the returned address
```

### Resolution
This is a known behavioral limitation of the current implementation. If per-interface
IPv6 address query is needed, callers must cross-reference the returned address
against `ip -6 addr show <if>` output, or use a separate Netlink address cache
filtered by ifindex.

---

## Issue 14: `bridge_get_info` returns only 8 slaves despite more being attached

### Symptom
`bridge->slave_count` caps at 8 even when the bridge has more enslaved interfaces.

### Root Cause
`bridge_info.slave_name` is a fixed array of 8 (`MAX_SLAVE_COUNT`). The callback
`bridge_get_slave_name_cb` will overwrite `slave_name[8]` onwards and corrupt
memory if more than 8 slaves are present.

### Resolution
Limit enslaved interfaces to ≤7 active slaves on a single bridge, or track slave
count before calling `bridge_get_info` and use a different approach (e.g.
parsing `bridge link show` output) for bridges with more slaves.

---

## Issue 15: `interface_status` vs operational state

### Symptom
`interface_status` returns 1 (UP) but the interface has no carrier / is not
passing traffic.

### Root Cause
`interface_status` checks the **administrative** state (the `IFF_UP` flag),
not the operational/carrier state. An interface can be administratively UP but
have no physical link.

### Debug Steps
```bash
cat /sys/class/net/<if>/operstate   # "up", "down", "unknown"
ip link show <if>                    # look for "state UP" vs "state UNKNOWN/DOWN"
```

### Resolution
To check carrier state, read `/sys/class/net/<if>/carrier` or parse
`/sys/class/net/<if>/operstate` directly via `file_read()`.

