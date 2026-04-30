# RCA Prompt Templates

## Prompt: Full RCA for a Network Configuration Failure

```
Perform RCA for a core-net-library failure in production.

Input:
1. Component/daemon that called libnet: <caller>
2. libnet function called: <function>
3. Arguments: <args>
4. Full stderr log excerpt: <logs>
5. System state at time of failure:
   - ip link show: <output>
   - ip addr show: <output>
   - ip route show table all: <output>
   - cat /proc/<pid>/status | grep -E "Cap|Uid": <output>

RCA steps:
1. Identify the failure stage (socket alloc / connect / cache alloc / object lookup / kernel op)
2. Map to the error class: resource, permission, not-found, duplicate, invalid-arg, kernel-reject
3. State the immediate cause
4. State the root cause (why the precondition was not met)
5. Identify any contributing factors (race condition, boot ordering, dependency not ready)
6. Provide remediation steps (immediate + long-term)
7. State verification commands to confirm resolution
```

---

## Prompt: RCA for Intermittent Failure

```
A libnet function fails intermittently (not every call). 

Input:
- Function: <function>
- Frequency: <occurrence rate>
- System characteristics: <SMP, high-load, concurrent callers>

Hypotheses to evaluate (in order):
1. File descriptor exhaustion (nl_socket_alloc fails) — check with:
   cat /proc/sys/fs/file-nr
   ls /proc/<pid>/fd | wc -l
2. Kernel RTNL lock contention — look for -EAGAIN in logs
3. Interface appearing/disappearing (hotplug race) — check udev events
4. Multiple callers operating on same interface (no external locking)

For each hypothesis, state: how to confirm, how to reproduce, how to fix.
```

---

## Prompt: RCA – "Interface not found" on a Known Interface

```
libnet returns: "<function>:<line> Interface '<name>' not found"
but `ip link show <name>` shows the interface exists.

Possible root causes (evaluate all):
1. Timing race: interface was just created and Netlink cache not yet consistent
   → Resolution: add interface_exist() guard with brief retry in caller
2. Wrong network namespace: process is in a different netns
   → Check: ls -la /proc/<pid>/ns/net vs ls -la /proc/1/ns/net
3. Interface name truncation: IFNAMSIZ is 16 chars; names > 15 chars are silently truncated
   → Check: echo -n "<name>" | wc -c
4. Interface exists in parent netns only (bridge or vlan created there)

State which hypothesis applies and the verification command.
```
