# AI Debugging Prompts

## Prompt: Diagnose a `CNL_STATUS_FAILURE` Return

```
You are debugging a failure in core-net-library (libnet). 

Context:
- Function that failed: <FUNCTION_NAME>
- Arguments passed: <ARGS>
- Stderr/log output: <LOG_LINES>
- System state: ip link show, ip addr show, ip route show (paste output)
- Process capabilities: output of `cat /proc/<pid>/status | grep Cap`

Task:
1. Identify the exact failure point from the log (function:line format)
2. Map the error to the specific libnl3/kernel error code
3. Determine if the failure is due to: missing interface, permissions, duplicate resource, or invalid args
4. Provide the specific resolution step
5. State whether the call is safe to retry immediately
```

---

## Prompt: Diagnose "Unable to connect socket"

```
A libnet function is failing with:
  <function>:<line> Unable to connect socket

1. Confirm the error is from `libnet_connect` → `nl_connect(sk, NETLINK_ROUTE)`
2. Check if the error indicates: CAP_NET_ADMIN missing, NETLINK not supported, or resource exhaustion
3. Provide the exact capability check command for the affected process
4. State the resolution (systemd unit change, namespace issue, or root requirement)
```

---

## Prompt: Analyze a Routing Failure

```
Route operation failed. Provide:
- Function: route_add or route_delete
- Arguments string: <args>
- Error log lines from stderr

Task:
1. Parse the argument string token by token per the libnet token table
2. Identify which token caused the parse or kernel rejection
3. Check if the failure is: invalid destination, non-existent dev/via, missing table, or NLM_F_REPLACE/CREATE mismatch
4. Provide the corrected argument string
```

---

## Prompt: Memory Leak Investigation

```
Valgrind reports a memory leak in a caller of libnet. 

Checklist:
1. Is `neighbour_free_neigh()` called after `neighbour_get_list()`?
   - neigh_info struct, neigh_arr, and all .local/.mac/.ifname strings are heap-allocated
2. Is `bridge_free_info()` called after `bridge_get_info()`?
   - slave_name[] elements are strdup'd
3. Is `init_neighbour_info()` return value checked for NULL before use?

For each unchecked item above, quote the leaked allocation site from the source and the missing free call.
```

---

## Prompt: Thread Safety Audit

```
Audit a code path for thread safety with core-net-library.

Rules:
1. All libnet functions are thread-safe since v2.0.0 (per-call socket)
2. EXCEPTION: interface_get_ip() returns inet_ntoa() static buffer — NOT thread-safe
3. interface_set_flags(), interface_rename() — safe to call but race-prone if caller
   makes existence/state assumptions without locking at a higher level

For the code path provided:
<code snippet>

Identify any thread-unsafe patterns and provide the fix.
```
