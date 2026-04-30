# Recovery Playbook

## Scenario 1: Interface Stuck in DOWN State

```bash
# Verify state
ip link show <if>

# Recovery via libnet caller (idempotent — safe to call even if already UP)
interface_up("<if>")

# Verification
ip link show <if> | grep "state UP"
```

---

## Scenario 2: Address Missing After Reboot / Restart

```bash
# Check current state
ip addr show <if>

# Re-apply (addr_add with NLM_F_EXCL — safe if not yet assigned)
addr_add("dev <if> <ip>/<prefix> broadcast <bcast>")

# If address already exists (from previous run) and needs refresh:
addr_delete("dev <if> <ip>/<prefix>")
addr_add("dev <if> <ip>/<prefix> broadcast <bcast>")
```

---

## Scenario 3: Default Route Missing

```bash
# Check routing table
ip route show table main | grep default

# Recovery:
# route_add uses NLM_F_REPLACE — safe to call even if route exists
route_add("default via <gateway> dev <if> metric <n>")

# Verify
ip route get 8.8.8.8
```

---

## Scenario 4: Bridge Slave Lost After Interface Bounce

```bash
# Check bridge membership
bridge link show

# Re-enslave:
# 1. Bring slave UP first
interface_up("<slave>")

# 2. Re-add to bridge (safe — rtnl_link_enslave will fail if already enslaved)
interface_add_to_bridge("<bridge>", "<slave>")

# Verify
bridge link show | grep "<slave>"
```

---

## Scenario 5: VLAN Sub-Interface Missing

```bash
# Check
ip link show type vlan

# Recovery:
# vlan_create uses NLM_F_EXCL — only call after checking:
if (interface_exist("<if>.<vid>") != CNL_STATUS_SUCCESS)
    vlan_create("<if>", <vid>)
interface_up("<if>.<vid>")
addr_add("dev <if>.<vid> <ip>/<prefix>")
```

---

## Scenario 6: Policy Rule Not Active

```bash
# Check
ip rule list

# Recovery:
# rule_add uses NLM_F_EXCL — will fail if rule already exists with same params
# If rule is missing, re-add:
rule_add("from <src_net> iif <if> table <id> prio <priority>")

# Verify
ip rule list | grep "lookup <id>"
```

---

## Scenario 7: Stale Neighbour Entry

```bash
# Check
ip neigh show dev <if>

# Recovery — delete stale entry:
neighbour_delete("<if>", "<ip>")

# Let kernel re-learn naturally, or trigger:
ping -c1 -I <if> <ip>

# Verify
ip neigh show dev <if>
```

---

## Scenario 8: Full Network Stack Re-initialization Order

For a complete stack rebuild (e.g., after firmware update or crash):

```
1. bridge_delete / vlan_delete     -- clean up virtual interfaces
2. interface_down (physical)       -- bring down before reconfiguration
3. interface_set_mac (if needed)   -- MAC before UP
4. interface_up (physical)
5. vlan_create                     -- create VLAN sub-interfaces
6. interface_up (VLANs)
7. bridge_create                   -- create bridge
8. interface_add_to_bridge         -- enslave ports
9. bridge_set_stp                  -- configure STP
10. interface_up (bridge)
11. addr_add (bridge/VLAN)          -- assign addresses
12. route_add (default/static)      -- install routes
13. rule_add                        -- install policy rules
```
