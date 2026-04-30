# Issue Triage Playbook

## Step 1: Identify Failure Class

Scan the stderr log for the first `CNL_LOG_ERROR` line.

| Log Pattern | Failure Class |
|---|---|
| `Unable to allocate memory for socket` | Resource — FD exhaustion or OOM |
| `Unable to connect socket` | Permission — CAP_NET_ADMIN missing or Netlink unavailable |
| `Unable to allocate cache` | Resource or kernel RTNL unavailable |
| `Interface '...' not found` | Not-found — interface missing or wrong netns |
| `Unable to lookup interface ... (master_index=0)` | Not-found — parent interface missing |
| `File exists (err=-17)` | Duplicate — NLM_F_EXCL reject |
| `Unable to add addr: ... (err=-17)` | Duplicate address |
| `Unable to add route: ...` | Route conflict or invalid args |
| `No such table ...` | Missing `/etc/iproute2/rt_tables` entry |
| `does not exist or is not writeable` | sysfs path missing (bridge/interface not created) |
| `Invalid local/remote IPV6 address` | Invalid argument — bad IPv6 string format |
| `Input MAC Address must be of format` | Invalid argument — bad MAC format |

---

## Step 2: Collect Evidence

```bash
# 1. Interface state
ip link show
ip addr show

# 2. Routing state
ip route show table all
ip rule list

# 3. Bridge / VLAN state
bridge link show
ip link show type vlan

# 4. Neighbour table
ip neigh show

# 5. Process capabilities
cat /proc/<pid>/status | grep -E "Cap|Uid|Gid"
capsh --decode=<CapEff>

# 6. File descriptors
ls /proc/<pid>/fd | wc -l
cat /proc/sys/fs/file-max

# 7. Memory
free -m
dmesg | grep -i oom
```

---

## Step 3: Triage Decision Tree

```
CNL_STATUS_FAILURE returned
├── Log: "Unable to allocate memory for socket"
│   ├── FD count near limit → Increase LimitNOFILE in systemd unit
│   └── OOM → Investigate memory pressure
├── Log: "Unable to connect socket"
│   └── Missing CAP_NET_ADMIN → Add to AmbientCapabilities
├── Log: "Unable to allocate cache"
│   ├── ENOMEM → Memory pressure
│   └── RTNL socket error → Check if kernel Netlink module is loaded
├── Log: "not found" / "does not exist"
│   ├── Interface never created → Create it first
│   ├── Wrong netns → Check /proc/<pid>/ns/net
│   └── Race condition → Add interface_exist() guard in caller
├── Log: "File exists (err=-17)"
│   └── NLM_F_EXCL → Resource already exists → Use existence check before create
└── No log output
    └── Function returned FAILURE without logging → Check return value of alloc steps
```

---

## Step 4: Escalation Criteria

Escalate to kernel/platform team if:
- `nl_connect` fails with `EAFNOSUPPORT` (Netlink not compiled into kernel)
- `/sys/class/net/` is not mounted
- Bridge STP write fails despite bridge existing (kernel config issue)
- Interface operations fail inside a container/namespace with unclear ns mapping
