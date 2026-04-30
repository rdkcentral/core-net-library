# AI Workflow: Triage

## Workflow: Given a bug report, determine severity and owner

### Input
- Bug report text or log excerpt with libnet function names and error messages

### Step 1 — Extract signals
```
From the input, identify:
1. Which libnet function(s) failed
2. The error message pattern (match against signals-and-errors.md)
3. The error code (EEXIST, EPERM, ENODEV, ENOMEM, EINVAL, EBUSY)
```

### Step 2 — Classify
```
Map to class:
- EEXIST  → Caller logic issue (not cleaning up before re-init)
- EPERM   → Deployment/capability configuration issue
- ENODEV  → Initialization ordering issue (parent not created first)
- ENOMEM  → System resource issue
- EINVAL  → Integration bug (bad argument format)
- EBUSY   → Ordering issue (deleting before releasing)
```

### Step 3 — Determine owner
```
- Caller logic / argument issue  → Upstream component team
- Capability / deployment        → Platform/BSP team
- Library behavior incorrect     → core-net-library team
- Kernel support missing         → Linux/kernel team
```

### Step 4 — Assign severity
```
- All network config broken (socket connect fails)   → P1 — Critical
- Single operation fails, workaround available       → P2 — High
- Intermittent failure under load                    → P2 — High
- Memory leak                                        → P3 — Medium
- Log or doc issue                                   → P4 — Low
```

### Step 5 — Suggest immediate mitigation
```
From recovery.md, identify the matching scenario and state the recovery steps.
```
