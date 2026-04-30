# Feature Development Prompts

## Prompt: Add a New libnet API Function

```
Design a new API function for core-net-library.

Requirements:
- Feature: <describe what the function should do>
- Inputs: <parameters>
- Expected output: libnet_status (or describe exception if different)

Follow these library patterns:
1. Return type: libnet_status (CNL_STATUS_SUCCESS=0, CNL_STATUS_FAILURE=-1)
2. Resource lifecycle: alloc_socket → connect(NETLINK_ROUTE) → alloc_cache → operate → goto-cleanup-chain → nl_socket_free
3. Error logging: CNL_LOG_ERROR("<function>:<description>: %s (err=%d)\n", nl_geterror(ret), ret)
4. No shared state — every call must be fully independent (thread-safe)
5. Use libnet_util helpers (libnet_alloc_socket, libnet_connect, libnet_link_alloc_cache, etc.)
6. Use safec_lib (sprintf_s, memset_s) for any string/buffer operations
7. Document in libnet.h with the existing doc comment style

Output:
1. Function signature for libnet.h
2. Implementation skeleton for libnet.c (with proper cleanup labels)
3. handler_ wrapper for corenetlib_api.c
4. XML test case (positive + negative) for corenetlib_tests.xml
```

---

## Prompt: Extend `addr_add` / `route_add` Argument Parsing

```
A new token needs to be supported in the addr_add or route_add argument string parser.

New token: <token_name>
Semantics: <what it does>
libnl3 setter: <rtnl_addr_set_*/rtnl_route_set_* function>

Task:
1. Add the token to the strtok_r parsing loop in the correct function (addr_add or route_add in libnet.c)
2. Add a corresponding parser helper in libnet_util.c / libnet_util.h if it involves address/object parsing
3. Ensure the cleanup `goto FREE_ADDR` / `goto FREE_ROUTE` path is preserved on parse failure
4. Add an XML test case for the new token
```

---

## Prompt: Validate a Code Change Against Library Invariants

```
Review this proposed change to core-net-library:

<diff or code snippet>

Validate against these invariants:
1. No shared global state introduced
2. All allocated objects freed in reverse order via goto cleanup chain
3. All error paths set err = CNL_STATUS_FAILURE before goto
4. CNL_LOG_ERROR emitted before every goto on error path
5. safec_lib used for string operations (sprintf_s, not snprintf)
6. No new dependency on static buffers (thread-safety)
7. nl_geterror(ret) used in error messages where libnl3 error code is available
8. Header updated if signature changes

List any violations with the exact line and the required fix.
```
