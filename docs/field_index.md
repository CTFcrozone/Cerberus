# Cerberus Event Fields

Field reference for rule authoring. Types are `int`, `string`, `ip`, or `bool`.
Every event type carries the COMMON process fields; type-specific fields are
listed under each. Fields whose value is an enumerated code have their meanings
listed inline - match on the number (e.g. `inode.op == 0` for unlink).

## COMMON (present on all event types)

- `process.pid` - int
- `process.uid` - int
- `process.tgid` - int
- `process.comm` - string
- `process.parent.comm` - string

---

## Generic

- COMMON
- `process.filepath` - string

---

## InetSock

- COMMON
- `socket.old_state` - string
- `socket.new_state` - string
- `socket.port` - int
- `socket.family` - int
- `socket.op` - int
- `network.saddr` - ip
- `network.daddr` - ip
- `network.sport` - int
- `network.dport` - int
- `network.protocol` - string

---

## Socket

- COMMON
- `socket.port` - int
- `socket.family` - int
- `socket.op` - int
  - `0` = bind
  - `1` = connect

---

## Module

- COMMON
- `module.name` - string
- `module.op` - int
  - `0` = init (load)
  - `1` = delete (unload)
  - `2` = request

---

## BpfProgLoad

- COMMON
- `bpf.prog.type` - int
- `bpf.prog.attach_type` - int
- `bpf.prog.flags` - int

---

## BpfMap

- COMMON
- `bpf.map.name` - string
- `bpf.map.type` - string
- `bpf.map.id` - int

---

## Inode

- COMMON
- `inode.filename` - string
- `inode.old_filename` - string
- `inode.new_filename` - string
- `inode.op` - int
  - `0` = unlink
  - `1` = mkdir
  - `2` = rmdir

---

## InodeMutation

- COMMON
- `inode.filename` - string
- `inode.old_filename` - string
- `inode.new_filename` - string
- `inode.op` - int
- `inode.mutation.type` - int
  - `0` = rename
  - `1` = link
  - `2` = symlink

---

## Bprm

- COMMON
- `process.filepath` - string

---

## PtraceAccessCheck

- COMMON
- `process.target.pid` - int
- `process.target.tgid` - int
- `process.target.uid` - int
- `process.target.comm` - string
- `ptrace.mode` - int
- `ptrace.stage` - int
  - `0` = request
  - `1` = decision

---

## Tamper (orthrus watchdog)

- COMMON _(synthetic header: comm = "orthrus", pid = agent pid)_
- `orthrus.tamper.reason` - string _(e.g. "heartbeat-stale", "bpf-progs-dropped-3-of-7")_
- `orthrus.tamper.severity` - int _(mirrors cerberus Severity)_
  - `0` = info
  - `1` = very-low
  - `2` = low
  - `3` = medium
  - `4` = high
  - `5` = critical
- `orthrus.tamper.kind` - int
  - `0` = heartbeat-stale
  - `1` = progs-dropped
  - `2` = progs-zero (alive but blind)
  - `3` = watchdog-unloading

---

## Appendix: other enumerated codes

Not exposed as matchable fields, but present in the event schema / wire format:

**Event type codes** (internal event discriminator):
`1` kill · `2` io_uring · `3` socket · `4` commit_creds · `5` module ·
`6` inet_sock_set_state · `7` enter_ptrace · `8` bprm_check_sec ·
`9` bpf_prog_load · `10` inode · `11` bpf_map · `12` inode_mutate ·
`13` ptrace_access_check

**Generic meta types:** `0` kill-signal · `1` ptrace-success
