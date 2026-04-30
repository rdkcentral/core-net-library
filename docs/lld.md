# Low-Level Design (LLD)

## Module Breakdown

### 1. `libnet_util.c` — Internal Netlink Helper Layer

This module provides safe wrappers around every libnl3 allocation/connect/parse
call. Each wrapper logs the error with `CNL_LOG_ERROR` and returns NULL or a
negative error code rather than aborting.

#### Common helpers

| Function | Wraps | On failure |
|---|---|---|
| `libnet_alloc_socket()` | `nl_socket_alloc()` | Returns NULL, logs error |
| `libnet_connect(sk, proto)` | `nl_connect()` | Returns negative err, logs |
| `libnet_alloc_cache(sk, name, ac)` | `ac(sk, &cache)` | Returns NULL, logs |
| `libnet_alloc_cache_flags(sk, name, flags, ac)` | `ac(sk, &cache, flags)` | Returns NULL, logs |

#### Link helpers

| Function | Purpose |
|---|---|
| `libnet_link_alloc()` | Allocate `rtnl_link` |
| `libnet_link_alloc_cache(sk)` | Allocate full link cache (AF_UNSPEC) |
| `libnet_link_alloc_cache_family(sk, family)` | Filtered by address family |
| `libnet_link_alloc_cache_family_flags(sk, family, flags)` | With cache flags |

#### Address helpers

| Function | Purpose |
|---|---|
| `libnet_addr_alloc()` | Allocate `rtnl_addr` |
| `libnet_addr_parse(str, family, &addr)` | Parse IP string to `nl_addr` |
| `libnet_addr_parse_local(addr, arg)` | Set local address field |
| `libnet_addr_parse_dev(addr, cache, arg)` | Resolve device name → ifindex |
| `libnet_addr_parse_broadcast(addr, arg)` | Set broadcast address |
| `libnet_addr_parse_preferred(addr, arg)` | Set preferred lifetime (parses "forever" or time string) |
| `libnet_addr_parse_valid(addr, arg)` | Set valid lifetime |

Internal helper `parse_lifetime()`: converts "forever" → `0xFFFFFFFF`,
or `nl_str2msec(arg) / 1000` → seconds.

#### Route helpers

| Function | Purpose |
|---|---|
| `libnet_route_alloc()` | Allocate `rtnl_route` |
| `libnet_route_alloc_cache(sk, flags)` | Allocate route cache |
| `libnet_route_parse_dst(route, args)` | Set destination (parses "default" → 0.0.0.0/0) |
| `libnet_route_parse_metric(route, opts)` | Parse `name=value,...` metric options against RTAX_* table |
| `libnet_route_parse_nexthop(route, subopts, link_cache)` | Parse `dev=X,via=Y,weight=Z` subopt form → attach nexthop |
| `libnet_route_parse_pref_src(route, args)` | Set preferred source |
| `libnet_route_parse_prio(route, str)` | Set route priority (numeric only) |
| `libnet_route_parse_protocol(route, str)` | Numeric or named protocol (e.g. "kernel", "static") |
| `libnet_route_parse_scope(route, str)` | Named scope via `rtnl_str2scope` |
| `libnet_route_parse_table(route, str)` | Numeric or named table |
| `libnet_route_parse_type(route, str)` | Route type (unicast, blackhole, …) |

#### Rule helpers

| Function | Purpose |
|---|---|
| `libnet_rule_alloc()` | Allocate `rtnl_rule` |
| `libnet_rule_alloc_cache(sk)` | Allocate rule cache (AF_UNSPEC) |

#### Neighbour helpers

| Function | Purpose |
|---|---|
| `libnet_neigh_alloc()` | Allocate `rtnl_neigh` |
| `libnet_neigh_parse_dst(neigh, arg)` | Set destination IP |
| `libnet_neigh_parse_dev(neigh, cache, arg)` | Set interface index |

---

### 2. `libnet.c` — API Implementation

#### Per-call resource lifecycle pattern

Every function follows this canonical pattern:

```
alloc_socket → connect(NETLINK_ROUTE) → alloc_cache → alloc_object
     → configure object → kernel operation
     → goto-labelled cleanup chain (free in reverse alloc order)
     → nl_socket_free(sk)
```

No resources are shared between calls. Cleanup labels (`FREE_SOCKET`,
`FREE_CACHE`, `FREE_LINK`, etc.) maintain reverse-allocation order via `goto`.

#### Interface UP/DOWN (idempotent)

```
interface_up(if_name):
  1. alloc_socket, connect, alloc_cache
  2. rtnl_link_get_by_name(cache, if_name)  → CNL_STATUS_FAILURE if not found
  3. Check IFF_UP flag: if already set → return SUCCESS immediately
  4. alloc change_link, set IFF_UP flag
  5. rtnl_link_change(sk, link, change, 0)
  6. cleanup
```

`interface_down` is symmetric: checks if `IFF_UP` is already absent → returns
SUCCESS immediately (idempotent).

#### VLAN Create

```
vlan_create(if_name, vid):
  1. Build name: sprintf_s(name, "%s.%d", if_name, vid)
  2. alloc_socket, connect, alloc_cache
  3. rtnl_link_name2i(cache, if_name)   → master_index
  4. rtnl_link_vlan_alloc()             → link
  5. rtnl_link_set_link(link, master_index)
  6. rtnl_link_set_name(link, name)
  7. rtnl_link_vlan_set_id(link, vid)
  8. rtnl_link_add(sk, link, NLM_F_CREATE | NLM_F_EXCL)
  9. cleanup
```

#### Bridge STP

Uses `file_write` to `/sys/class/net/<bridge>/bridge/stp_state`.
Accepts "on" (→ `STP_LISTENING = 1`) or "off" (→ `STP_DISABLED = 0`).
Validates file accessibility (`access(F_OK | W_OK)`) before writing.

#### addr_add / addr_delete

These parse a space-delimited argument string using `strtok_r`, recognising
tokens: `dev`, `broadcast`, `valid_lft`, `preferred_lft`, `-4`/`inet`,
`-6`/`inet6`, and a bare IP/CIDR as the local address.

`addr_add` uses `rtnl_addr_add(sock, addr, NLM_F_EXCL)` — fails if address
already exists.

`addr_delete` uses `rtnl_addr_delete(sock, addr, 0)` after setting up a filter
from the parsed args.

#### route_add / route_delete

Both parse a space-delimited arg string with tokens: `-4/-6/inet/inet6`,
`default`, `dev`, `via`, `src`, `metric`, `mtu`, `table`, `proto/protocol`,
`scope`, `type`.

`route_add` uses `rtnl_route_add(sock, route, NLM_F_CREATE | NLM_F_REPLACE)` —
replaces any existing matching route.

`route_delete` calls `nl_cache_foreach_filter(route_cache, route, route_delete_cb, sock)`
which invokes `rtnl_route_delete` for each cache entry matching the filter.

#### rule_add / rule_delete

`rule_add` tokens: `from`, `to`, `iif`, `oif`, `lookup`/`table`, `prio`,
`-4/-6/inet/inet6`.  Reads `/etc/iproute2/rt_tables` for named table lookup.
Uses `rtnl_rule_add(sock, rule, NLM_F_EXCL)`.

`rule_delete` uses `nl_cache_foreach_filter` + `rule_delete_cb`.

#### neighbour_get_list

```
neighbour_get_list(arr, mac, if_name, af_filter):
  1. alloc_socket, connect
  2. libnet_neigh_alloc_cache(sock) with NL_CACHE_AF_ITER flag
  3. libnet_neigh_alloc(); optionally set MAC filter; optionally set ifindex filter
  4. nl_cache_foreach_filter(cache, neigh, neighbour_get_cb, &cb_data)
  5. In neighbour_get_cb (receives rtnl_neigh* object):
     a. Retrieves IP address via rtnl_addr_get_local() — note: object is cast
        from rtnl_neigh* to rtnl_addr* to access the common nl_object address
        field; this is an implementation detail tied to libnl3 object layout
     b. Apply af_filter (skip non-matching address families)
     c. Dynamic array growth: realloc(neigh_arr, capacity * 2) on overflow
     d. Filter out NUD_NONE, NUD_NOARP, NUD_PERMANENT pseudostates
     e. Populate local IP (from rtnl_addr_get_local cast), MAC
        (from rtnl_neigh_get_lladdr), ifname (via separate link cache lookup
        using rtnl_neigh_get_ifindex), and state (rtnl_neigh_get_state)
     f. Per-entry link cache alloc/free inside the callback (performance cost)
  6. cleanup
```

#### interface_get_stats

Uses a bitmask (`cnl_ifstats_mask`) to selectively fill `cnl_iface_stats`:

| Bit | Fields populated |
|---|---|
| `IFSTAT_RXTX_PACKET` | `rx_packet`, `tx_packet` |
| `IFSTAT_RXTX_BYTES` | `rx_bytes`, `tx_bytes` |
| `IFSTAT_RXTX_ERRORS` | `rx_errors`, `tx_errors` |
| `IFSTAT_RXTX_DROPPED` | `rx_dropped`, `tx_dropped` |
| `IFSTAT_RXTX_ALL` | All of the above |

---

### 3. `corenetlib_api.c` — XML-Driven Test Harness

Parses `corenetlib_tests.xml` at runtime. Each `<testcase>` specifies:
- `<handler>` — lookup key into static `handler_table[]`
- `<argv>` — argument vector passed to the handler
- `<is_negative>` — expected failure (1) or success (0)

Test results are logged to `/rdklogs/logs/corenetlib_api.log` and printed to
stdout. `run_all_tests()` iterates all test cases and tracks pass/fail counts.

---

## Key Data Structures

### `bridge_info`

```c
struct bridge_info {
    int slave_count;           // number of enslaved interfaces
    struct nl_cache *link_cache; // reference to the link cache (freed on get_info return)
    char *slave_name[8];       // heap-allocated slave names (up to 8)
};
```

Free with `bridge_free_info()` which `free()`s each `slave_name` slot.

### `neighbour_info` / `_neighbour_info`

```c
struct neighbour_info {
    int neigh_count;
    int neigh_capacity;        // starts at 32, doubles on overflow
    struct _neighbour_info *neigh_arr; // heap-allocated, dynamic array
};

struct _neighbour_info {
    int state;     // NUD_* bitmask
    char *local;   // heap-allocated IP string
    char *mac;     // heap-allocated MAC string
    char *ifname;  // heap-allocated interface name
};
```

Caller must call `init_neighbour_info()` before use and `neighbour_free_neigh()`
after.

### `cnl_iface_stats`

```c
typedef struct _cnl_iface_stats {
    uint64_t rx_packet, tx_packet;
    uint64_t rx_bytes,  tx_bytes;
    uint64_t rx_errors, tx_errors;
    uint64_t rx_dropped, tx_dropped;
} cnl_iface_stats;
```

---

## Error Handling

All errors produce a `CNL_LOG_ERROR` entry on `stderr` containing
`function:line` context, a human-readable description, and where applicable
the libnl3 error string (`nl_geterror(err)`) and numeric error code.

No retry logic exists at the library level.  Callers are responsible for
retry and recovery decisions.
