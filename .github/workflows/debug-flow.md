# AI Workflow: Debug Flow

## Workflow: Step-by-step debug of a libnet failure

### Precondition
You have: function name, args, error log output, and system state (ip link/addr/route).

---

### Step 1: Locate the failure point

Identify the first `CNL_LOG_ERROR` line.  The format is `function:line message`.
Look up the line number in `libnet.c` to confirm which stage failed:

| Stage | Approximate lines (libnet.c) | Indicator |
|---|---|---|
| Socket alloc | Early in function (first ~5 lines after locals) | "Unable to allocate memory for socket" |
| Connect | Next step | "Unable to connect socket" |
| Cache alloc | After connect | "Unable to allocate cache" |
| Object lookup | After cache | "not found" / "does not exist" |
| Kernel operation | Near end | "Unable to add/delete/change/enslave" |

---

### Step 2: Correlate to resource state

```bash
# For interface operations:
ip link show <if_name>
interface_exist("<if_name>")   → checks /sys/class/net/<if_name>

# For bridge:
bridge link show

# For address:
ip addr show <if_name>

# For route:
ip route show table <table>

# For rule:
ip rule list

# For neighbour:
ip neigh show
```

---

### Step 3: Reproduce in isolation

Use `corenetlib_api` to reproduce without the full daemon:
```bash
./corenetlib_api <operation> "<args>"
# e.g.:
./corenetlib_api addr_add "dev eth0 192.168.1.1/24"
./corenetlib_api route_add "default via 192.168.1.254 dev eth0"
./corenetlib_api interface_up eth0
```

Check `/rdklogs/logs/corenetlib_api.log` and stderr.

---

### Step 4: Verify capabilities

```bash
capsh --print   # for current shell
cat /proc/<daemon-pid>/status | grep Cap
capsh --decode=<CapEff hex value>
# Must include cap_net_admin
```

---

### Step 5: Verify argument format

For `addr_add` / `route_add` / `rule_add`, trace the argument string token by token:
- Each space-delimited token should match a keyword or a valid IP/prefix string
- Unknown tokens are treated as the primary field (local address or route destination)
- For route nexthop: tokens must form `dev=<name>,via=<ip>,` (comma-separated subopt form)

---

### Step 6: Confirm fix

After applying the fix, verify with:
```bash
# Re-run corenetlib_api
./corenetlib_api <operation> "<fixed-args>"

# Cross-check with system tools
ip addr show / ip route show / bridge link show / ip rule list
```
