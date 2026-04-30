# External Dependencies

## 1. libnl3 (libnl-route-3, libnl-3, libnl-nf-3)

**Role**: All Netlink RTNL socket operations — link, address, route, rule, and
neighbour management.

**Header path**: `${PKG_CONFIG_SYSROOT_DIR}/usr/include/libnl3/`

**Used APIs**:

| libnl3 API | Used by |
|---|---|
| `nl_socket_alloc/free`, `nl_connect` | Every function |
| `rtnl_link_alloc_cache`, `rtnl_link_get_by_name`, `rtnl_link_name2i` | Interface, VLAN, bridge, route ops |
| `rtnl_link_alloc`, `rtnl_link_set_type`, `rtnl_link_add`, `rtnl_link_delete` | bridge_create/delete, vlan_create/delete |
| `rtnl_link_vlan_alloc`, `rtnl_link_vlan_set_id` | vlan_create |
| `rtnl_link_enslave`, `rtnl_link_release` | interface_add/remove_from_bridge |
| `rtnl_link_ip6_tnl_alloc`, `rtnl_link_ip6_tnl_set_*` | tunnel_add_ip4ip6 |
| `rtnl_link_get_stat` | interface_get_stats |
| `rtnl_addr_alloc/put`, `rtnl_addr_add/delete` | addr_add, addr_delete |
| `rtnl_route_alloc/put`, `rtnl_route_add/delete`, `rtnl_route_nh_alloc` | route_add, route_delete |
| `rtnl_rule_alloc/put`, `rtnl_rule_add/delete/alloc_cache` | rule_add, rule_delete |
| `rtnl_neigh_alloc/put`, `rtnl_neigh_alloc_cache_flags` | neighbour_*  |
| `nl_cache_foreach_filter`, `nl_cache_free/put` | addr_delete, route_delete, rule_delete, neighbour_get_list |
| `nl_addr_parse`, `nl_addr2str`, `nl_addr_put` | Address parsing throughout |
| `nl_geterror` | All error logging |
| `nl_str2msec`, `rtnl_route_str2proto`, `rtnl_str2scope`, `nl_str2rtntype` | Route/rule parsing |
| `rtnl_route_str2table`, `rtnl_route_read_table_names` | rule_add |

**Failure impact**: If libnl3 is absent or returns errors (e.g., ENOMEM,
`NETLINK_ROUTE` connection failure), **all** library operations return
`CNL_STATUS_FAILURE`. The library has no fallback path.

**Debugging**:
```bash
# Verify libnl3 is installed
pkg-config --modversion libnl-route-3

# Check library is loadable
ldconfig -p | grep libnl-route
```

---

## 2. safec_lib (safec_lib_common.h)

**Role**: Safe C string/memory operations — `memset_s`, `sprintf_s`, `ERR_CHK`.

**Used for**:
- `sprintf_s`: building `/sys` file paths (buffer-overflow safe)
- `memset_s`: zeroing structs (`bridge_info`, `ifreq`)
- `ERR_CHK(rc)`: asserts `rc >= EOK` (terminates on violation in debug builds)

**Failure impact**: Build failure if not present. If `sprintf_s` returns `< EOK`,
affected functions return `CNL_STATUS_FAILURE` immediately.

---

## 3. libxml2

**Role**: Used exclusively by `corenetlib_api` to parse `corenetlib_tests.xml`.

**Not linked into libnet.la** — only affects the `corenetlib_api` test binary.

**Failure impact**: `corenetlib_api` binary fails to parse test configuration.
`libnet.la` is unaffected.

---

## 4. Linux Kernel — `sysfs` (`/sys/class/net/`)

**Role**: Interface existence checks, MTU setting, MAC address reading, bridge
STP configuration.

| Function | sysfs path |
|---|---|
| `interface_exist` | `/sys/class/net/<if>/` |
| `interface_set_mtu` | `/sys/class/net/<if>/mtu` |
| `interface_get_mac` | `/sys/class/net/<if>/address` |
| `bridge_set_stp` | `/sys/class/net/<bridge>/bridge/stp_state` |

**Failure impact**: Returns `CNL_STATUS_FAILURE` with `CNL_LOG_ERROR` if sysfs
path is not accessible (`access()` check fails).

```bash
# Verify sysfs is mounted
mount | grep sysfs
ls /sys/class/net/
```

---

## 5. Linux Kernel — `ioctl` (socket-based)

**Role**: IPv4 address get/set, netmask set, MAC set.

| Function | ioctl | Socket family |
|---|---|---|
| `interface_get_ip` | `SIOCGIFADDR` | `AF_INET / SOCK_DGRAM` |
| `interface_set_netmask` | `SIOCSIFNETMASK` | `AF_INET / SOCK_DGRAM` |
| `interface_set_mac` | `SIOCSIFHWADDR` | `AF_INET / SOCK_DGRAM` |

**Failure impact**: Socket creation or ioctl failure → `CNL_STATUS_FAILURE`.
`interface_get_ip` returns NULL on failure.

---

## 6. `/etc/iproute2/rt_tables`

**Role**: Named routing table resolution in `rule_add`.

**Usage**: `rtnl_route_read_table_names("/etc/iproute2/rt_tables")` then
`rtnl_route_str2table(name)`.

**Failure impact**: `rule_add` with a named table (non-numeric) fails if the
file is missing or the name is not in the file.

```bash
cat /etc/iproute2/rt_tables
# Verify custom tables are listed
```

---

## Dependency Failure Matrix

| Dependency | Missing / Failed | Affected Functions | Fallback |
|---|---|---|---|
| libnl3 | Build/link fails or ENOMEM at runtime | ALL | None |
| `NETLINK_ROUTE` socket | `nl_connect` fails | ALL | None |
| safec_lib | Build fails | ALL | None |
| sysfs `/sys/class/net/` | Not mounted | `interface_exist`, `interface_set_mtu`, `interface_get_mac`, `bridge_set_stp` | None |
| ioctl on loopback socket | Kernel denies | `interface_get_ip`, `interface_set_netmask`, `interface_set_mac` | None |
| `/etc/iproute2/rt_tables` | File missing | `rule_add` (named table only) | Use numeric table ID |
| libxml2 | Build of corenetlib_api fails | `corenetlib_api` binary only | None (libnet unaffected) |
