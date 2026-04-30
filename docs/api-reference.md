# API Reference

## Return Types

```c
typedef enum {
    CNL_STATUS_SUCCESS = 0,
    CNL_STATUS_FAILURE = -1
} libnet_status;
```

---

## File I/O

### `file_write`
```c
libnet_status file_write(const char *file_name, const char *buf, size_t count);
```
Opens `file_name` in write mode, writes `count` bytes from `buf`. Used internally
to write kernel parameters via `/sys` or `/proc`.

**Macro**: `write_kernel_param(KERNEL_PARAM, VAL)` → `file_write(KERNEL_PARAM, VAL, strlen(VAL)+1)`

### `file_read`
```c
libnet_status file_read(const char *file_name, char *buf, size_t count);
```
Opens `file_name` in read mode, reads up to `count` bytes into `buf` (zeroed first
via `memset_s`).

---

## Interface Lifecycle

### `interface_up` / `interface_down`
```c
libnet_status interface_up(char *if_name);
libnet_status interface_down(char *if_name);
```
Set interface administrative state. **Idempotent**: returns SUCCESS if already
in the target state.

### `interface_exist`
```c
libnet_status interface_exist(const char *iface_name);
```
Checks `/sys/class/net/<iface_name>` existence via `access()`.

### `interface_status`
```c
libnet_status interface_status(char *if_name, int *status);
```
Queries operational link state. Sets `*status = 1` (UP) or `0` (DOWN).

### `interface_rename`
```c
libnet_status interface_rename(char *if_name, char *new_name);
```
Renames interface. **Not recommended** on a running interface with configured addresses.

### `interface_status`
```c
libnet_status interface_status(char *if_name, int *status);
```
Queries the link-layer (administrative) state via Netlink. Sets `*status = 1`
if `IFF_UP` flag is set, `0` otherwise. Does NOT reflect carrier/operational state.

### `interface_delete`
```c
libnet_status interface_delete(char *name);
```
Deletes any interface type (physical, virtual, tunnel, VLAN, bridge).

### `interface_set_flags`
```c
libnet_status interface_set_flags(char *if_name, unsigned int flags);
```
Sets arbitrary netdevice `IFF_*` flags via `rtnl_link_change`.

**Macro**: `interface_set_allmulticast(if_name)` → `interface_set_flags(if_name, IFF_ALLMULTI)`

---

## Interface Configuration

### `interface_set_mtu`
```c
libnet_status interface_set_mtu(const char *if_name, char *val);
```
Writes string `val` to `/sys/class/net/<if_name>/mtu`.

### `interface_get_mac` / `interface_set_mac`
```c
libnet_status interface_get_mac(const char *if_name, char *mac, size_t size);
libnet_status interface_set_mac(const char *if_name, char *mac);
```
- `get_mac`: reads from `/sys/class/net/<if>/address`, strips trailing newline.
- `set_mac`: validates format `XX:XX:XX:XX:XX:XX` (17 chars, 6 hex pairs), uses
  `ioctl(SIOCSIFHWADDR)`.

### `interface_get_ip`
```c
char *interface_get_ip(const char *if_name);
```
Uses `ioctl(SIOCGIFADDR)` to get IPv4 address. Returns pointer to static
`inet_ntoa()` buffer — **not thread-safe, copy immediately**.

### `interface_set_netmask`
```c
libnet_status interface_set_netmask(const char *if_name, const char *netmask);
```
Uses `ioctl(SIOCSIFNETMASK)`. Accepts dotted-decimal netmask string.

### `get_ipv6_address`
```c
libnet_status get_ipv6_address(char *if_name, char *ipv6_addr, size_t addr_len);
```
Retrieves the first global-scope (`RT_SCOPE_UNIVERSE`) IPv6 address found in
the kernel address cache.

**Behavioral note**: The implementation verifies that `if_name` exists in the
link cache, then iterates the **entire** address cache (all interfaces) to find
the first global IPv6 address. It is **not** filtered to addresses assigned to
`if_name`. If multiple interfaces have global IPv6 addresses, the returned
address may belong to any of them.

`addr_len` must be `≥ INET6_ADDRSTRLEN` (46); the function returns
`CNL_STATUS_FAILURE` if the buffer is too small.

If `ipv6_addr` is NULL, the function allocates a buffer internally; on failure
it is freed and the caller receives `CNL_STATUS_FAILURE`.

### `interface_get_stats`
```c
libnet_status interface_get_stats(cnl_ifstats_mask ifstats_mask,
                                  const char *if_name,
                                  cnl_iface_stats *stats);
```
Populates `stats` fields gated by `ifstats_mask` bitmask.

| Mask bit | Fields |
|---|---|
| `IFSTAT_RXTX_PACKET` | `rx_packet`, `tx_packet` |
| `IFSTAT_RXTX_BYTES` | `rx_bytes`, `tx_bytes` |
| `IFSTAT_RXTX_ERRORS` | `rx_errors`, `tx_errors` |
| `IFSTAT_RXTX_DROPPED` | `rx_dropped`, `tx_dropped` |
| `IFSTAT_RXTX_ALL` | All of the above |

**Macro**: `interface_set_ip(if_name, address)` → `addr_add("dev <if_name> <address>")`

---

## VLAN

### `vlan_create`
```c
libnet_status vlan_create(const char *if_name, int vid);
```
Creates `<if_name>.<vid>` as a VLAN sub-interface. Fails if already exists (`NLM_F_EXCL`).

### `vlan_delete`
```c
libnet_status vlan_delete(const char *vlan_name);
```
Removes the named VLAN interface.

---

## Bridge

### `bridge_create` / `bridge_delete`
```c
libnet_status bridge_create(const char *bridge_name);
libnet_status bridge_delete(const char *bridge_name);
```

### `bridge_set_stp`
```c
libnet_status bridge_set_stp(const char *bridge_name, char *val);
```
`val` must be `"on"` or `"off"`. Writes to
`/sys/class/net/<bridge>/bridge/stp_state`.

### `interface_add_to_bridge` / `interface_remove_from_bridge`
```c
libnet_status interface_add_to_bridge(const char *bridge_name, const char *if_name);
libnet_status interface_remove_from_bridge(const char *if_name);
```

### `bridge_get_info` / `bridge_free_info`
```c
libnet_status bridge_get_info(char *bridge_name, struct bridge_info *bridge);
void          bridge_free_info(struct bridge_info *bridge);
```
Populates `bridge->slave_name[]` (heap-allocated, max 8 slaves) and
`bridge->slave_count`. Caller must call `bridge_free_info()` to release memory,
**regardless of whether `get_info` succeeded or failed**.

---

## Address Management

### `addr_add` / `addr_delete`
```c
libnet_status addr_add(char *args);
libnet_status addr_delete(char *args);
```
Space-delimited argument string; recognised tokens:

| Token | Meaning |
|---|---|
| `dev <name>` | Target interface (required) |
| `<ip>[/prefix]` | Local address (required) |
| `broadcast <ip>` | Broadcast address |
| `valid_lft <t\|forever>` | Valid lifetime |
| `preferred_lft <t\|forever>` | Preferred lifetime |
| `-4` / `inet` | Force IPv4 family |
| `-6` / `inet6` | Force IPv6 family |

**Macros**:
```c
addr_add_va_arg(FMT, ...)         // printf-style args → addr_add
interface_set_ip(if_name, addr)   // addr_add("dev <if> <addr>")
addr_delete_va_arg(FMT, ...)      // printf-style args → addr_delete
```

### `addr_derive_broadcast`
```c
libnet_status addr_derive_broadcast(char *ip, unsigned int prefix_len, char *bcast, int size);
```

---

## Routing

### `route_add` / `route_delete`
```c
libnet_status route_add(char *args);
libnet_status route_delete(char *args);
```
Space-delimited argument string; recognised tokens:

| Token | Meaning |
|---|---|
| `default` | Destination = 0.0.0.0/0 |
| `<prefix>` | Destination network |
| `dev <name>` | Nexthop output interface |
| `via <ip>` | Nexthop gateway |
| `src <ip>` | Preferred source address |
| `metric <n>` | Route priority |
| `mtu <n>` | RTAX_MTU metric |
| `table <id\|name>` | Routing table |
| `proto <id\|name>` | Route protocol |
| `scope <name>` | Route scope |
| `type <name>` | Route type (unicast, blackhole, …) |
| `-4\|4\|inet` | IPv4 |
| `-6\|6\|inet6` | IPv6 |

`route_add` uses `NLM_F_CREATE | NLM_F_REPLACE` (upsert semantics).
`route_delete` uses cache-filter + callback delete.

**Macros**: `route_add_va_arg`, `route_delete_va_arg`

---

## Policy Routing

### `rule_add` / `rule_delete`
```c
libnet_status rule_add(char *arg);
libnet_status rule_delete(char *arg);
```
Recognised tokens: `from`, `to`, `iif`, `oif`, `lookup`/`table`, `prio`,
`-4/-6/inet/inet6`.

Default source is `all` (matches any source). Default action is `RTN_UNICAST`;
overridden to `FR_ACT_TO_TBL` when `lookup`/`table` is specified.

`rule_add` uses `NLM_F_EXCL`. `rule_delete` uses cache-filter + callback delete.

**Macros**: `rule_add_va_arg`, `rule_delete_va_arg`

---

## Tunnel

### `tunnel_add_ip4ip6`
```c
libnet_status tunnel_add_ip4ip6(const char *tunnel_name, const char *dev_name,
                                const char *local_ip6, const char *remote_ip6,
                                const char *encaplimit);
```
Creates an `ip6tnl` (IPv4-in-IPv6) tunnel. `encaplimit` parameter is accepted
but not currently applied in the implementation.

**Macro**: `tunnel_delete_ip4ip6(name)` → `interface_delete(name)`

---

## Neighbour Table

### `init_neighbour_info`
```c
struct neighbour_info *init_neighbour_info(void);
```
Allocates `neighbour_info` with initial capacity of 32 entries.
Returns NULL on allocation failure.

### `neighbour_get_list`
```c
libnet_status neighbour_get_list(struct neighbour_info *arr,
                                 char *mac, char *if_name, int af_filter);
```
- `mac`: optional MAC filter (format `XX:XX:XX:XX:XX:XX`); NULL = no filter
- `if_name`: optional interface filter; NULL = all interfaces
- `af_filter`: `0` (all), `AF_INET`, or `AF_INET6`

Excludes `NUD_NONE`, `NUD_NOARP`, `NUD_PERMANENT` entries.
Array grows automatically (doubles capacity) if 32-entry initial size is exceeded.

### `neighbour_delete`
```c
libnet_status neighbour_delete(char *dev, char *ip);
```

### `neighbour_free_neigh`
```c
void neighbour_free_neigh(struct neighbour_info *neigh_info);
```
Frees all `strdup`-allocated strings, the array, and the struct itself.
