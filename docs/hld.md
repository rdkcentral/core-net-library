# High-Level Design (HLD)

## System View

```
┌─────────────────────────────────────────────────────────────────┐
│                       RDK-B Daemons / Components                │
│  (CcspPandMSsp, CcspEthAgent, WAN Manager, Bridge Manager, …)  │
└───────────────────────────┬─────────────────────────────────────┘
                            │  #include "libnet.h"
                            │  libnet_status = func(args)
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                        libnet  (libnet.la)                       │
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────────┐ │
│  │  Interface   │  │   Address /  │  │  Routing / Rules /     │ │
│  │  Lifecycle   │  │   VLAN /     │  │  Neighbour / Tunnel    │ │
│  │  (up/down/   │  │   Bridge     │  │  (route_add,           │ │
│  │   rename/    │  │   (addr_add, │  │   rule_add,            │ │
│  │   delete)    │  │   vlan_      │  │   neighbour_get_list,  │ │
│  │              │  │   create, …) │  │   tunnel_add_ip4ip6)   │ │
│  └──────┬───────┘  └──────┬───────┘  └──────────┬─────────────┘ │
│         │                 │                      │               │
│  ┌──────▼─────────────────▼──────────────────────▼─────────────┐ │
│  │              libnet_util  (internal helper layer)            │ │
│  │  socket alloc/connect, cache alloc, object alloc/parse       │ │
│  └──────────────────────────┬───────────────────────────────────┘ │
└─────────────────────────────┼───────────────────────────────────┘
                              │  libnl3 API calls
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     libnl3  (libnl-route-3 / libnl-3)           │
│  rtnl_link_*, rtnl_addr_*, rtnl_route_*, rtnl_neigh_*, …        │
└───────────────────────────┬─────────────────────────────────────┘
                            │  Netlink messages (NETLINK_ROUTE)
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                  Linux Kernel — RTNL subsystem                   │
│   /sys/class/net/<if>/   ioctl(SIOCGIFADDR / SIOCSIFHWADDR)      │
└─────────────────────────────────────────────────────────────────┘
```

## Major Functional Subsystems

| Subsystem | Primary Functions | Kernel Mechanism |
|---|---|---|
| Interface Lifecycle | `interface_up/down`, `interface_exist`, `interface_status`, `interface_rename`, `interface_delete`, `interface_set_flags` | Netlink RTNL link change / ioctl |
| Interface Config | `interface_set_mtu`, `interface_get/set_mac`, `interface_get_ip`, `interface_set_netmask`, `interface_get_stats`, `get_ipv6_address` | `/sys/class/net/`, `ioctl`, RTNL addr+link cache |
| VLAN | `vlan_create`, `vlan_delete` | RTNL link add/delete (type=vlan, 802.1Q) |
| Bridge | `bridge_create/delete`, `bridge_set_stp`, `bridge_get_info/free_info` | RTNL link (type=bridge), `/sys/class/net/<br>/bridge/stp_state` |
| Bridge Membership | `interface_add_to_bridge`, `interface_remove_from_bridge` | RTNL `rtnl_link_enslave` / `rtnl_link_release` |
| Address Mgmt | `addr_add`, `addr_delete`, `addr_derive_broadcast` | RTNL address add/delete |
| Routing | `route_add`, `route_delete` | RTNL route add/delete |
| Policy Rules | `rule_add`, `rule_delete` | RTNL rule add/delete; `/etc/iproute2/rt_tables` |
| Neighbour | `neighbour_delete`, `neighbour_get_list`, `init_neighbour_info`, `neighbour_free_neigh` | RTNL neighbour cache |
| Tunnel | `tunnel_add_ip4ip6`, `tunnel_delete_ip4ip6` | RTNL ip6tnl link add |
| File I/O | `file_read`, `file_write`, `write_kernel_param` | POSIX fopen/fread/fwrite |

## External Dependencies

| Dependency | Usage | Failure Impact |
|---|---|---|
| `libnl-route-3` | All RTNL operations | All network config APIs fail |
| `libnl-3` | Socket allocation, address parsing | All APIs fail |
| `libnl-nf-3` | Linked but not directly called (transitively required) | Build / link failure |
| `safec_lib` | Safe string functions (`memset_s`, `sprintf_s`) | Build failure; protects against buffer overflows |
| `libxml2` | XML parsing in `corenetlib_api` test harness only | Test harness fails; libnet unaffected |
| Linux kernel ≥ 3.x | Netlink RTNL route socket, bridge/vlan support | N/A — OS requirement |
| `/sys/class/net/` | `interface_exist`, `interface_set_mtu`, `interface_get_mac`, `bridge_set_stp` | Returns CNL_STATUS_FAILURE if sysfs not mounted |
| `/etc/iproute2/rt_tables` | `rule_add` (table name resolution) | Rule add with named table fails |

## Threading Model

Since v2.0.0, every API call independently allocates its own `nl_sock`, connects,
performs the operation, and frees all resources before returning.  There is no
shared global state.  Calls are safe to invoke concurrently from multiple threads.

## Return Value Convention

All functions return `libnet_status`:

```c
typedef enum {
    CNL_STATUS_SUCCESS = 0,
    CNL_STATUS_FAILURE = -1
} libnet_status;
```

`interface_get_ip()` is the only exception — it returns a `char*` (NULL on failure),
pointing to a static buffer inside `inet_ntoa()`.
