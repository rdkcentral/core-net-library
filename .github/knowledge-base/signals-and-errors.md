# Knowledge Base — Signals, Errors, and Failure Patterns

## Known Error Signals

| Signal | Source | Meaning |
|---|---|---|
| `CNL_STATUS_FAILURE (-1)` | All functions | Any failure — check preceding stderr log |
| NULL return | `interface_get_ip`, `init_neighbour_info`, libnet_util alloc funcs | Allocation or ioctl failure |
| `neigh_count == 0` | `neighbour_get_list` | No active reachable neighbours (NUD_NONE/NOARP/PERMANENT excluded) |

---

## libnl3 Error Codes

See `docs/troubleshooting.md` for full per-issue analysis and resolution steps.
Quick reference:
- `-17` EEXIST — NLM_F_EXCL reject (duplicate resource)
- `-19` ENODEV — interface not found
- `-1`  EPERM  — CAP_NET_ADMIN required
- `-12` ENOMEM — memory/FD exhaustion
- `-22` EINVAL — invalid argument
- `-16` EBUSY  — device in use

---

## Failure Patterns

### Pattern: Cascade failure on missing parent

```
vlan_create("eth0.100")  FAILS → "Unable to lookup interface eth0 (master_index=0)"
└── Root cause: eth0 does not exist yet
└── Pattern: child resource created before parent

Same applies to:
- interface_add_to_bridge() → bridge must exist first
- tunnel_add_ip4ip6()       → dev_name must exist first
```

### Pattern: Race between interface creation and Netlink cache

```
interface_exist("/sys/class/net/eth0") returns SUCCESS
interface_up("eth0") returns FAILURE with "Interface 'eth0' not found"

Root cause: sysfs (/sys/class/net/) reflects kernel state faster than
            Netlink link cache which is populated on cache alloc.
Resolution: Add retry with brief delay in caller, or use Netlink directly
            for existence check instead of interface_exist().
```

### Pattern: Leaked memory on error path

```c
// BUG: bridge_get_info succeeds but bridge_free_info not called on error exit
if (bridge_get_info(name, &bridge) != CNL_STATUS_SUCCESS) {
    return -1;           // <- LEAK: bridge.slave_name[] not freed
}
bridge_free_info(&bridge);   // only called on success path

// FIX: Call bridge_free_info unconditionally after bridge_get_info
bridge_get_info(name, &bridge);   // proceed regardless
// ... use bridge ...
bridge_free_info(&bridge);        // always
```

### Pattern: `interface_get_ip` dangling pointer

```c
// BUG: Static buffer overwritten by second call
char *ip1 = interface_get_ip("eth0");
char *ip2 = interface_get_ip("eth1");  // ip1 now points to ip2's value!
printf("%s %s\n", ip1, ip2);           // both print eth1's IP

// FIX: Copy immediately
char buf[INET_ADDRSTRLEN];
char *tmp = interface_get_ip("eth0");
if (tmp) strncpy(buf, tmp, sizeof(buf));
```

### Pattern: `addr_add` EEXIST on restart

```
Component restarts but does not clear previous address.
addr_add with NLM_F_EXCL returns EEXIST.

FIX: Use defensive addr_delete before addr_add, or check existence first.
Or use: ip addr replace (not directly exposed — would need route_add NLM_F_REPLACE equivalent for addrs)
```

### Pattern: `rule_add` NLM_F_EXCL duplicate

```
rule_add returns FAILURE if exact same rule already exists.
This can happen on:
  - Component restart without cleanup
  - Multiple components adding the same rule

FIX: Caller should:
  1. rule_delete first (ignore failure if not found)
  2. rule_add fresh
Or: check `ip rule list` for the rule before adding.
```

---

## Behavioral Quirks

### `get_ipv6_address` returns address from a different interface

```
get_ipv6_address("eth0", buf, ...) may return SUCCESS with an address from eth1.

Root cause: Iterates the ENTIRE kernel address cache — eth0 existence is verified
but the address lookup is NOT filtered to eth0.

Resolution: Cross-reference with ip -6 addr show <if> if per-interface accuracy
is required. Or check scope and ifindex of the returned address.
```

### `bridge_get_info` silent slave count truncation

```
MAX_SLAVE_COUNT is hard-coded as 8. Only the first 8 slaves are stored.
Bridges with >8 slaves return slave_count=8 with remaining entries missing.

Resolution: Only use bridge_get_info for bridges with ≤8 slaves.
```

### `interface_status` checks administrative state only

```
interface_status() checks IFF_UP (administrative/configured state), not carrier.
*status=1 (UP) with no physical link is possible.

For carrier state: read /sys/class/net/<if>/carrier or /sys/class/net/<if>/operstate.
```

---

## Dependency Signals

See `docs/dependencies.md` for the complete failure matrix and debug commands.
Key symptoms:
- All funcs fail at connect → Missing CAP_NET_ADMIN
- interface_exist unreliable → sysfs not mounted
- Named table lookup fails → Missing `/etc/iproute2/rt_tables` entry
- Build fails on `sprintf_s` → safec_lib not found

---

## NUD State Reference

| State | Value | Meaning | Included in neighbour_get_list |
|---|---|---|---|
| NUD_INCOMPLETE | 0x01 | ARP in progress | Yes |
| NUD_REACHABLE | 0x02 | Confirmed reachable | Yes |
| NUD_STALE | 0x04 | Validity expired | Yes |
| NUD_DELAY | 0x08 | Delay before probe | Yes |
| NUD_PROBE | 0x10 | Reachability probe | Yes |
| NUD_FAILED | 0x20 | Failed to resolve | Yes |
| NUD_NOARP | 0x40 | No ARP (static/loopback) | **NO** |
| NUD_PERMANENT | 0x80 | Static entry | **NO** |
| NUD_NONE | 0x00 | No state | **NO** |
