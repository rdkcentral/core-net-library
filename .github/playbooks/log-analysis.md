# Log Analysis Playbook

## Log Format

```
<function_name>:<line_number> <message>
```

All output goes to **stderr** using `fprintf`. There is no severity filtering at
the library level — all four macros (`CNL_LOG_INFO`, `CNL_LOG_ERROR`,
`CNL_LOG_NOTICE`, `CNL_LOG_WARNING`) produce stderr output in the same format.

`CNL_LOG_INFO` is emitted at entry of `addr_add`, `addr_delete`, `route_add`,
`route_delete`, `rule_add`, `rule_delete` showing the full argument string.

---

## Parsing a Log Sequence

Example failure in `addr_add`:
```
addr_add:860 Entering with args: 'dev eth0 192.168.X.Y/24'
addr_add:910 dev eth0 192.168.X.Y/24: Unable to add addr: File exists (err=-17)
```

**Reading this**:
1. `addr_add:860` — function entered, args logged
2. `addr_add:910` — `rtnl_addr_add` returned `-17` (EEXIST)
3. `-17` = `EEXIST` = address already configured on `eth0`

---

## Error Code Reference

| libnl3 error / errno | Meaning | Common cause in libnet |
|---|---|---|
| `-17` / `EEXIST` | File exists | NLM_F_EXCL on addr_add, vlan_create, bridge_create, rule_add |
| `-19` / `ENODEV` | No such device | Interface not found in cache |
| `-1` / `EPERM` | Operation not permitted | Missing CAP_NET_ADMIN |
| `-12` / `ENOMEM` | Out of memory | nl_socket_alloc, cache alloc failed |
| `EINVAL` | Invalid argument | Bad IP/route/metric format |
| `ENOENT` | No such entry | Interface name not in link cache |
| `-16` / `EBUSY` | Device/resource busy | Trying to delete enslaved interface |

---

## Key Log Patterns and Meanings

| Pattern | Meaning |
|---|---|
| `Entering with args: '<args>'` | Normal entry into addr/route/rule functions |
| `Unable to allocate memory for socket` | nl_socket_alloc() returned NULL |
| `Unable to connect socket` | nl_connect failed, often permissions |
| `Unable to allocate cache` | rtnl_*_alloc_cache failed |
| `Unable to lookup interface <name> (master_index=0)` | Parent interface not found for VLAN |
| `Unable to find the bridge '<name>'` | Bridge object not found in link cache |
| `Unable to find the interface '<name>'` | Slave interface missing for bridge operation |
| `Unable to enslave <if> to bridge <br>` | rtnl_link_enslave failed (already enslaved, etc.) |
| `Unable to set vlan id <id>`: `...` | rtnl_link_vlan_set_id rejected the VLAN ID |
| `val must be on or off` | bridge_set_stp called with invalid string |
| `file_name <path> does not exist or is not writeable` | sysfs path inaccessible |
| `Failed to parse address '<str>'` | Invalid IP address / CIDR string |
| `Metric token "..." is not in name=value form` | Malformed metric suboption |
| `Unknown nexthop token <tok>` | Invalid subopt in route nexthop string |
| `Link device '<name>' does not exist` | Device referenced in route nexthop not found |

---

## Correlating Logs to Call Sites

All logs include `function:line`.  To find the source:

```bash
grep -n "CNL_LOG_ERROR" source/libnet.c | grep "<keyword>"
grep -n "CNL_LOG_ERROR" source/libnet_util.c | grep "<keyword>"
```

---

## Extracting Logs from a Running System

```bash
# If journald captures stderr:
journalctl -u <service-name> | grep -E "<function>|CNL_LOG"

# If logging to a file:
grep -E "addr_add|route_add|bridge_create|interface_up" /rdklogs/logs/<logfile>

# corenetlib_api specific:
tail -f /rdklogs/logs/corenetlib_api.log
```
