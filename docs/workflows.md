# Functional Workflows

## 1. Interface Bring-Up

```
Caller                      libnet                    libnl3              Kernel
  │                            │                         │                   │
  │ interface_up("eth0")        │                         │                   │
  │──────────────────────────► │                         │                   │
  │                            │ nl_socket_alloc()        │                   │
  │                            │──────────────────────► │                   │
  │                            │ nl_connect(NETLINK_ROUTE)│                   │
  │                            │──────────────────────► │──────────────────►│
  │                            │ rtnl_link_alloc_cache() │                   │
  │                            │──────────────────────► │──────────────────►│
  │                            │ rtnl_link_get_by_name() │                   │
  │                            │──────────────────────► │                   │
  │                            │ check IFF_UP flag       │                   │
  │                  [already UP]────────────────────────────────────────────│
  │                            │ return SUCCESS (no-op)  │                   │
  │◄──────────────────────────│                         │                   │
  │                  [not UP] │                         │                   │
  │                            │ rtnl_link_alloc(change) │                   │
  │                            │ rtnl_link_set_flags(IFF_UP)                 │
  │                            │ rtnl_link_change()      │                   │
  │                            │──────────────────────► │──────────────────►│
  │                            │──── cleanup chain ─────│                   │
  │◄──────────────────────────│ SUCCESS                 │                   │
```

## 2. VLAN Sub-Interface Creation

```
Caller                        libnet
  │                              │
  │ vlan_create("eth0", 100)      │
  │─────────────────────────────►│
  │                              │ sprintf_s(name, "eth0.100")
  │                              │ alloc_socket → connect
  │                              │ rtnl_link_alloc_cache()
  │                              │ master_index = rtnl_link_name2i("eth0")
  │                              │ rtnl_link_vlan_alloc()
  │                              │ rtnl_link_set_link(master_index)
  │                              │ rtnl_link_set_name("eth0.100")
  │                              │ rtnl_link_vlan_set_id(100)
  │                              │ rtnl_link_add(NLM_F_CREATE|NLM_F_EXCL)
  │                              │ FREE_VLAN → FREE_CACHE → FREE_SOCKET
  │◄─────────────────────────────│ SUCCESS / FAILURE
```

**Note**: `NLM_F_EXCL` means the call fails if the VLAN already exists.
Callers should check `interface_exist("eth0.100")` first if idempotency is required.

## 3. Bridge Creation and Slave Attachment

```
1. bridge_create("br0")
   │ rtnl_link_set_type("bridge")
   │ rtnl_link_add(NLM_F_CREATE|NLM_F_EXCL)

2. interface_up("eth0")           -- ensure slave is UP first

3. interface_add_to_bridge("br0", "eth0")
   │ alloc_cache
   │ link(br0)  = rtnl_link_get_by_name("br0")
   │ ltap(eth0) = rtnl_link_get_by_name("eth0")
   │ rtnl_link_enslave(sk, link, ltap)

4. bridge_set_stp("br0", "on")
   │ file_write("/sys/class/net/br0/bridge/stp_state", "1", 2)

5. interface_up("br0")
```

## 4. IPv4 Address Configuration

```
addr_add("dev eth0.100 192.168.1.1/24 broadcast 192.168.1.255")

Token parsing loop (strtok_r on space):
  "dev"       → next token = "eth0.100" → libnet_addr_parse_dev()
  "192.168.1.1/24" → libnet_addr_parse_local()
  "broadcast" → next token = "192.168.1.255" → libnet_addr_parse_broadcast()

rtnl_addr_add(sock, addr, NLM_F_EXCL)
```

Convenience macros:
```c
interface_set_ip("eth0.100", "192.168.1.1/24")
// expands to: addr_add("dev eth0.100 192.168.1.1/24")

addr_add_va_arg("dev %s %s broadcast %s", iface, ip, bcast)
```

## 5. Default Route Addition

```
route_add("default via 192.168.1.254 dev eth0 metric 100")

Token parsing:
  "default" → libnet_route_parse_dst()     (0.0.0.0/0)
  "via"     → nexthop += "via=192.168.1.254,"
  "dev"     → nexthop += "dev=eth0,"
  "metric"  → libnet_route_parse_prio(100)

libnet_route_parse_nexthop(route, "via=192.168.1.254,dev=eth0,")
rtnl_route_add(sock, route, NLM_F_CREATE|NLM_F_REPLACE)
```

## 6. Policy Routing Rule

```
rule_add("from 10.0.0.0/8 iif eth1 lookup 100 prio 1000")

Token parsing:
  "from"   → libnet_addr_parse("10.0.0.0/8") → rtnl_rule_set_src()
  "iif"    → rtnl_rule_set_iif("eth1")
  "lookup" → rtnl_route_read_table_names("/etc/iproute2/rt_tables")
             tableId = rtnl_route_str2table("100")
             rtnl_rule_set_table() + rtnl_rule_set_action(FR_ACT_TO_TBL)
  "prio"   → rtnl_rule_set_prio(1000)

rtnl_rule_add(sock, rule, NLM_F_EXCL)
```

## 7. Neighbour Table Query

```
// Caller allocates
struct neighbour_info *info = init_neighbour_info();   // capacity=32

// Fetch all IPv4 neighbours on eth0
neighbour_get_list(info, NULL, "eth0", AF_INET);

// Inside: nl_cache_foreach_filter → neighbour_get_cb per entry
//   - Skips NUD_NONE, NUD_NOARP, NUD_PERMANENT
//   - Auto-grows array if neigh_count >= neigh_capacity (doubles capacity)
//   - Fills: local (IP), mac, ifname, state

// Iterate entries
for (int i = 0; i < info->neigh_count; i++) {
    printf("%s %s state=0x%x\n",
        info->neigh_arr[i].local,
        info->neigh_arr[i].mac,
        info->neigh_arr[i].state);
}

// Caller frees (frees array + all strdup strings + struct itself)
neighbour_free_neigh(info);
```

## 8. IPv4-in-IPv6 Tunnel Creation

```
tunnel_add_ip4ip6("tun0", "eth0", "2001:db8::1", "2001:db8::2", NULL)

1. Resolve dev_name → if_index
2. rtnl_link_ip6_tnl_alloc()
3. rtnl_link_set_name("tun0")
4. rtnl_link_ip6_tnl_set_link(if_index)
5. inet_pton(AF_INET6, local_ip6, &addr) → rtnl_link_ip6_tnl_set_local()
6. inet_pton(AF_INET6, remote_ip6, &addr) → rtnl_link_ip6_tnl_set_remote()
7. rtnl_link_add(sk, link, NLM_F_CREATE|NLM_F_EXCL)

Teardown: tunnel_delete_ip4ip6("tun0")
       → interface_delete("tun0")
       → rtnl_link_delete(sk, link)
```

## 9. Interface Statistics Collection

```c
cnl_iface_stats stats;
interface_get_stats(IFSTAT_RXTX_ALL, "eth0", &stats);
// stats.rx_bytes, stats.tx_bytes, stats.rx_errors, … populated
```

Bitmask allows selective fetching:
```c
interface_get_stats(IFSTAT_RXTX_BYTES | IFSTAT_RXTX_ERRORS, "eth0", &stats);
```

## 10. Broadcast Address Derivation

```c
char bcast[INET_ADDRSTRLEN];
addr_derive_broadcast("192.168.1.1", 24, bcast, sizeof(bcast));
// bcast = "192.168.1.255"
// Logic: addr.s_addr |= htonl(~(~0U << (32 - prefix_len)))
```
