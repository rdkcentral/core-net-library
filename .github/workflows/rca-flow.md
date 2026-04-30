# AI Workflow: RCA Flow

## Workflow: Structured Root Cause Analysis

### Input required
1. Function(s) that failed
2. Complete stderr log (or excerpt with the failing lines)
3. System state snapshot (ip link, ip addr, ip route, ip rule, ip neigh, bridge link)
4. Process identity (PID, uid, capabilities)
5. Whether failure is consistent or intermittent

---

### Phase 1: Immediate Cause

Answer: Which exact stage of the function failed, and what error code?

```
Stage checklist (evaluate in order):
□ Socket allocation failed → ENOMEM or FD limit
□ Netlink connect failed  → EPERM (capabilities) or kernel unavailable
□ Cache allocation failed → ENOMEM
□ Object lookup failed    → ENODEV/ENOENT (interface/bridge not found)
□ Kernel operation failed → EEXIST / EPERM / EINVAL / EBUSY / other
```

---

### Phase 2: Root Cause

Answer: Why did the precondition for that stage fail?

| Immediate Cause | Root Cause Hypotheses |
|---|---|
| ENOMEM at socket alloc | FD leak in caller; memory pressure; ulimit too low |
| EPERM at connect | Missing CAP_NET_ADMIN; wrong user; systemd sandboxing |
| Object not found | Parent not created; wrong boot sequence; interface renamed; wrong netns |
| EEXIST at create | Previous run left state; restart without cleanup; duplicate caller |
| EBUSY at delete | Interface still enslaved; interface still has addresses configured |
| EINVAL | Malformed argument; unsupported kernel feature |

---

### Phase 3: Contributing Factors

```
□ Boot ordering: Is the calling component starting before the interface is ready?
□ Concurrent callers: Multiple components trying to manage the same resource?
□ State persistence: Is cleanup happening on component restart?
□ Kernel version: Is the feature supported on this kernel?
□ Network namespace: Is the caller in the correct netns?
```

---

### Phase 4: Remediation

For each confirmed root cause, apply the fix from recovery.md or troubleshooting.md.

Immediate:
1. Manual recovery command sequence
2. Component restart with corrected configuration

Long-term:
1. Fix caller to check existence before creating (defensive pattern)
2. Fix cleanup on restart (destroy → recreate)
3. Fix systemd unit capabilities or ordering dependencies
4. Add retry logic with backoff in caller for race-prone scenarios

---

### Phase 5: Verification

```bash
# Confirm the operation succeeds post-fix
./corenetlib_api <operation> "<args>"
# Confirm system state is correct
ip link show / ip addr show / ip route show table all / ip rule list
# Monitor for recurrence
journalctl -u <service> -f | grep CNL_LOG
```

---

### RCA Template Output

```
## RCA Report

**Component**: <caller>
**Function**: <libnet function>
**Arguments**: <args>

### Immediate Cause
<stage that failed> returned <error code> (<errno name>)

### Root Cause
<why the precondition was not met>

### Contributing Factors
<any secondary factors>

### Timeline
<if known: sequence of events leading to failure>

### Remediation
**Immediate**: <steps taken or recommended>
**Long-term**: <code/config changes required>

### Prevention
<how to prevent recurrence>

### Verification
<commands used to confirm resolution>
```
