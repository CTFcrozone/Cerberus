use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use lib_common::event::{CerberusEvent, EventHeader, InodeEvent};
use lib_rules::{RuleEngine, RuleSet};
use std::sync::Arc;

fn build_engine_with_n_rules(n: usize) -> RuleEngine {
	let dir = std::env::temp_dir().join(format!("cerberus_bench_spread_{n}"));
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();

	// one discriminating field per kind - cycling these spreads rules across
	// kinds, so kind-bucketing can isolate them. (field, op, value)
	let specs: &[(&str, &str, &str)] = &[
		("inode.op", "equals", "0"),              // Inode
		("socket.op", "equals", "1"),             // Socket
		("module.op", "equals", "1"),             // Module
		("bpf.map.id", "equals", "7"),            // BpfMap
		("bpf.prog.type", "equals", "2"),         // BpfProgLoad
		("network.sport", "equals", "80"),        // InetSock
		("ptrace.stage", "equals", "1"),          // PtraceAccessCheck
		("inode.mutation.type", "equals", "0"),   // InodeMutation
		("process.filepath", "equals", "\"/x\""), // Bprm / Generic (string!)
	];

	for i in 0..n {
		let (field, op, value) = specs[i % specs.len()];
		let toml = format!(
			r#"[rule]
id = "bench-rule-{i}"
description = "synthetic benchmark rule {i}"
severity = "low"

[[rule.conditions]]
field = "{field}"
op = "{op}"
value = {value}
"#,
		);
		std::fs::write(dir.join(format!("rule_{i}.toml")), toml).unwrap();
	}

	let ruleset = RuleSet::load_from_dir(&dir).unwrap();
	RuleEngine::new_from_ruleset(ruleset).unwrap()
}

fn make_test_event() -> CerberusEvent {
	let header = EventHeader {
		container: None,
		comm: Arc::from("bench"),
		parent_comm: Arc::from("init"),
		ts: 0,
		cgroup_id: 0,
		mnt_ns: 0,
		pid: 1234,
		ppid: 1,
		uid: 0,
		tgid: 1234,
	};
	CerberusEvent::Inode(InodeEvent {
		header,
		filename: Arc::from("/tmp/bench"),
		filename_len: 10,
		op: 99,
	})
}

fn bench_throughput(c: &mut Criterion) {
	let event = make_test_event();
	let mut group = c.benchmark_group("process_event");
	for rule_count in [33usize, 100, 500, 1000] {
		let engine = build_engine_with_n_rules(rule_count);
		let mut out = Vec::with_capacity(16);
		group.bench_with_input(BenchmarkId::from_parameter(rule_count), &rule_count, |b, _| {
			b.iter(|| {
				out.clear();
				engine.process_event_into(black_box(&event), &mut out);
				black_box(&out);
			});
		});
	}
	group.finish();
}

criterion_group!(benches, bench_throughput);
criterion_main!(benches);
