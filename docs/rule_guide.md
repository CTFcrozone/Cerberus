# Cerberus Rule Writing Guide

This guide explains how to write detection rules for the **Cerberus rule
engine**.

Rules are written in **TOML** and stored in the `rules/` directory.

---

# Rule File Structure

Every rule file contains a `[rule]` section.

```toml
[rule]
id = "example-rule"
description = "Example rule"
type = "exec"
severity = "medium"
category = "process"

[[rule.conditions]]
field = "process.uid"
op = "equals"
value = 0
```

---

# Required Rule Fields

## id

Unique identifier for the rule.

```toml
id = "suspicious-bpf-load"
```

Must be **unique across all rules**.

---

## description

Human readable explanation of what the rule detects.

```toml
description = "Detect suspicious BPF program loads"
```

---

## type

Defines what **event type** the rule applies to.

Examples:

    exec
    network
    bpf_prog_load
    file_event
    kernel

---

# Optional Fields

## severity

Indicates alert importance.

Recommended values:

    very-low
    low
    medium
    high
    critical

Example:

```toml
severity = "high"
```

---

## category

Used to group rules.

Examples:

    process
    network
    kernel
    filesystem
    container

Example:

```toml
category = "kernel"
```

---

# Conditions

Rules contain one or more **conditions**.

```toml
[[rule.conditions]]
field = "process.uid"
op = "equals"
value = 0
```

Each condition has:

---

- field - event field
- op - operator
- value - value to compare

---

# Available Fields

## Process Fields

    process.pid
    process.tgid
    process.uid
    process.comm
    process.filepath

---

## Network Fields

    network.sport
    network.dport
    network.protocol

---

## Socket Fields

    socket.port
    socket.family
    socket.op
    socket.old_state
    socket.new_state

---

## Module Fields

    module.name

---

## BPF Fields

    bpf.prog.type
    bpf.prog.flags
    bpf.prog.attach_type
    bpf.prog.tag

---

## Other

    inode.filename

---

# Condition Operators

## equals

```toml
op = "equals"
value = 0
```

---

## not_equals

```toml
op = "not_equals"
```

---

## in

```toml
op = "in"
value = [1,2,3]
```

---

## not_in

```toml
op = "not_in"
value = ["systemd", "bpftool"]
```

---

## starts_with

```toml
op = "starts_with"
value = "/usr/bin"
```

---

## contains

```toml
op = "contains"
value = "--verbose"
```

---

## bit_and

```toml
op = "bit_and"
value = 4
```

---

## regex / matches_regex

```toml
op = "regex"
value = "^/tmp"
```

## not_regex

```toml
op = "not_regex"
value = "^/tmp"
```

---

## Greater than

```toml
op = "gt"
value = 1000
```

---

## Less than

```toml
op = "lt"
value = 5000
```

---

## Greater than or equal

```toml
op = "gte"
value = 1000
```

---

## Less than or equal

```toml
op = "lte"
value = 5000
```

---

## exists

```toml
op = "exists"
value = true
```

---

# Example Rule

Detect execution from `/tmp` by non-root users.

```toml
[rule]
id = "tmp-exec"
description = "Detect execution from /tmp"
type = "exec"
severity = "medium"
category = "filesystem"

[[rule.conditions]]
field = "process.filepath"
op = "regex"
value = "^/tmp"

[[rule.conditions]]
field = "process.uid"
op = "not_in"
value = [0]
```

---

# BPF Detection Example

```toml
[rule]
id = "suspicious-bpf-tracing-load"
description = "Detect tracing/kprobe BPF program load"
type = "bpf_prog_load"
severity = "high"
category = "kernel"

[[rule.conditions]]
field = "bpf.prog.type"
op = "in"
value = [2, 5, 26, 29]

[[rule.conditions]]
field = "bpf.prog.attach_type"
op = "in"
value = [24, 25, 26, 27]

[[rule.conditions]]
field = "process.comm"
op = "not_in"
value = ["systemd", "bpftool", "cilium-agent"]
```

---

# Rule Sequences (Correlation)

Sequences detect **multi-stage attacks**.

Important:

**The rule that defines the sequence is the ROOT rule.**

Sequence starts **after the root rule matches**.

Then steps must occur in order within time windows.

---

## Example Sequence

```toml
[rule]
id = "attack-chain"
description = "Detect multi-stage attack"
type = "exec"
severity = "high"

[rule.sequence]
kind = "rule"

[[rule.sequence.steps]]
rule_id = "rule-a"
within = "5s"

[[rule.sequence.steps]]
rule_id = "rule-b"
within = "10s"
```

Execution flow:

    1. root rule matches
    2. rule-a must occur within 5 seconds
    3. rule-b must occur within 10 seconds after rule-a

Timeline:

    root → (5s) → rule-a → (10s) → rule-b

If a step does not occur in time, the sequence resets.

---

# Responses (Not fully implemented yet)

Rules may trigger automatic responses.

Example:

```toml
[rule.response]
type = "kill_process"
```

Supported responses:

    kill_process
    deny_exec
    isolate_container
    throttle_network
    emit_signal
    notify
    kvm_action

---

## Emit Signal

```toml
[rule.response]
type = "emit_signal"
signal = 9
```

---

## Notify

```toml
[rule.response]
type = "notify"
message = "Suspicious activity detected"
```

---

# Best Practices

Use normalized fields:

    process.pid
    process.uid
    bpf.prog.type

Keep rules simple.

Prefer multiple rules + sequences instead of complex single rules.

---

# Minimal Rule Example

```toml
[rule]
id = "pid-exists"
description = "Detect any process event"
type = "exec"
severity = "low"

[[rule.conditions]]
field = "process.pid"
op = "not_equals"
value = 0
```
