# Cerberus Rule Writing Guide

This guide explains how to write detection rules for the **Cerberus rule engine**.

Rules are written in **TOML**.

---

# Rule File Structure

Every rule file contains a `[rule]` section.

```toml
[rule]
id = "example-rule"
description = "Example rule"
severity = "medium"

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

## severity

Indicates alert importance.

Recommended values:

    info
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

# Conditions

Rules contain one or more **conditions**.

```toml
[[rule.conditions]]
field = "process.uid"
op = "equals"
value = 0
```

Each condition has:

- `field` — event field
- `op` — operator
- `value` — value to compare

---

# Condition Operators

## equals / ==

```toml
op = "equals"
value = 0
```

```toml
op = "=="
value = "lkm"
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

---

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
severity = "medium"

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
severity = "high"

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
severity = "high"

[rule.sequence]
id = "example-seq"
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

# Response Chains

Rules may trigger automatic **response chains**. A response chain consists of a `trigger` and a list of `actions`.

```toml
[rule.response_chain]
trigger = "sequence_finished"

[[rule.response_chain.actions]]
type = "block_ip"
params = { ip = "1.1.1.1" }
```

---

## Triggers

The `trigger` field determines when the response chain executes.

| Trigger             | Description                                         |
| ------------------- | --------------------------------------------------- |
| `sequence_finished` | Fires when all sequence steps complete successfully |
| `rule_match`        | Fires when the rule itself matches                  |

---

## Actions

Each action has a `type` and a `params` map.

### kill_process

Terminate a process by PID.

```toml
[[rule.response_chain.actions]]
type = "kill_process"
params = { pid = 1234 }
```

Use a **field reference** (prefix with `$`) to bind the PID from the event:

```toml
[[rule.response_chain.actions]]
type = "kill_process"
params = { pid = "$process.pid" }
```

---

### block_ip

Block an IPv4 address.

```toml
[[rule.response_chain.actions]]
type = "block_ip"
params = { ip = "10.0.0.5" }
```

Use a **field reference** to bind the IP from the event:

```toml
[[rule.response_chain.actions]]
type = "block_ip"
params = { ip = "$network.dst_ip" }
```

---

## Action Parameters

Action parameters accept either:

- **Literal values** — hard-coded strings, integers, or IPs
- **Field references** — strings prefixed with `$` that bind to event fields at runtime

Field references are validated at rule-compile time against the expected type for that action parameter.

---

## Full Response Chain Example

```toml
[rule.response_chain]
trigger = "sequence_finished"

[[rule.response_chain.actions]]
type = "block_ip"
params = { ip = "1.1.1.1" }

[[rule.response_chain.actions]]
type = "block_ip"
params = { ip = "8.8.8.8" }

[[rule.response_chain.actions]]
type = "kill_process"
params = { pid = "$process.pid" }
```

---

## Sequence + Response Chain Example

```toml
[rule]
id = "kernel-module-loader"
description = "Detect kernel module loading followed by exec"
severity = "critical"

[[rule.conditions]]
field = "module.name"
op = "=="
value = "lkm"

[rule.sequence]
id = "lkm-loader-seq"
kind = "rule"

[[rule.sequence.steps]]
rule_id = "rk-load"
within = "10s"

[[rule.sequence.steps]]
rule_id = "sus-exec"
within = "10s"

[rule.response_chain]
trigger = "sequence_finished"

[[rule.response_chain.actions]]
type = "block_ip"
params = { ip = "1.1.1.1" }

[[rule.response_chain.actions]]
type = "block_ip"
params = { ip = "8.8.8.8" }
```

---

# Best Practices

Keep rules simple.

Prefer multiple rules + sequences instead of complex single rules.

Use field references (`$field.name`) in actions to make responses dynamic and context-aware.

---

# Minimal Rule Example

```toml
[rule]
id = "pid-exists"
description = "Detect any process event"
severity = "low"

[[rule.conditions]]
field = "process.pid"
op = "not_equals"
value = 0
```
