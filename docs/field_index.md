# Cerberus Event Fields

## Generic

- `process.uid`
- `process.pid`
- `process.tgid`
- `process.comm`

---

## InetSock

- `socket.old_state`
- `socket.new_state`
- `network.sport`
- `network.dport`
- `network.protocol`

---

## Socket

- `socket.port`
- `socket.family`
- `socket.op`

---

## Module

- `process.uid`
- `process.pid`
- `process.tgid`
- `process.comm`
- `module.name`
- `module.op`

---

## BpfProgLoad

- `process.uid`
- `process.pid`
- `process.tgid`
- `process.comm`
- `bpf.prog.type`
- `bpf.prog.attach_type`
- `bpf.prog.flags`
- `bpf.prog.tag`

---

## BpfMap

- `process.uid`
- `process.pid`
- `process.tgid`
- `process.comm`
- `bpf.map.name`
- `bpf.map.type`
- `bpf.map.id`

---

## Inode

- `process.uid`
- `process.pid`
- `process.tgid`
- `process.comm`
- `inode.filename`
- `inode.op`

---

## InodeMutate

- `process.uid`
- `process.pid`
- `process.tgid`
- `process.comm`
- `inode.new_filename`
- `inode.old_filename`
- `inode.mutation.type`

---

## Bprm

- `process.uid`
- `process.pid`
- `process.tgid`
- `process.comm`
- `process.filepath`

---

## PtraceAccessCheck

- `process.uid`
- `process.pid`
- `process.tgid`
- `process.comm`
- `process.target.pid`
- `process.target.tgid`
- `process.target.uid`
- `process.target.comm`
- `ptrace.mode`
- `ptrace.stage`
