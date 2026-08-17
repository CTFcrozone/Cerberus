//! The property under test: `process_event_into` performs **zero** heap allocations
//! per event when the caller supplies a buffer with spare capacity. That holds for
//! both the no-match path and the match-without-response path, and it is what the
//! lazy `LazyFields` cell and the deferred `Instant::now()` buy

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use lib_common::event::{CerberusEvent, EventHeader, RingBufEvent};
use lib_rules::{Rule, RuleEngine, RuleSet};

// region:    --- Counting allocator

static ALLOCS: AtomicUsize = AtomicUsize::new(0);

struct Counting;

unsafe impl GlobalAlloc for Counting {
	unsafe fn alloc(&self, l: Layout) -> *mut u8 {
		ALLOCS.fetch_add(1, Ordering::Relaxed);
		unsafe { System.alloc(l) }
	}

	unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
		unsafe { System.dealloc(p, l) }
	}

	unsafe fn realloc(&self, p: *mut u8, l: Layout, new_size: usize) -> *mut u8 {
		ALLOCS.fetch_add(1, Ordering::Relaxed);
		unsafe { System.realloc(p, l, new_size) }
	}
}

#[global_allocator]
static A: Counting = Counting;

// endregion: --- Counting allocator

// region:    --- Fixtures

/// `process.pid == 0` only. No kind-specific field, so it is placed in the universal
/// set and is a candidate for every event kind - the condition actually gets
/// evaluated rather than being skipped by placement.
const NEVER_MATCHES: &str = r#"
[rule]
id = "pid-zero-only"
description = "matches only pid 0"
severity = "low"

[[rule.conditions]]
field = "process.pid"
op = "equals"
value = 0
"#;

/// `process.uid == 1000`. Same placement, but matches the fixture event, so the
/// match branch runs: an EvaluatedEvent is built and pushed.
const ALWAYS_MATCHES: &str = r#"
[rule]
id = "uid-1000"
description = "matches uid 1000"
severity = "low"

[[rule.conditions]]
field = "process.uid"
op = "equals"
value = 1000
"#;

fn generic_event(pid: u32, uid: u32) -> CerberusEvent {
	CerberusEvent::Generic(RingBufEvent {
		name: "KILL",
		header: EventHeader {
			cgroup_id: 0,
			container: None,
			ts: 0,
			mnt_ns: 0,
			pid,
			ppid: 1,
			tgid: pid,
			uid,
			comm: Arc::from("bash"),
		},
		meta_type: 0,
		meta: 0,
	})
}

fn engine_from(contents: &str) -> RuleEngine {
	let rule = Rule::from_str(contents).expect("parse rules");
	let ruleset = RuleSet::new(vec![rule]).expect("parse rules");
	RuleEngine::new_from_ruleset(ruleset).expect("compile rules")
}

fn allocs_over(engine: &RuleEngine, event: &CerberusEvent, iters: usize) -> usize {
	let mut buf = Vec::with_capacity(64);

	// Warm up: the first calls touch arc_swap's thread-local debt slot and grow the
	// buffer. Neither is per-event work, so neither should be measured.
	for _ in 0..16 {
		buf.clear();
		engine.process_event_into(event, &mut buf);
	}
	buf.clear();

	let before = ALLOCS.load(Ordering::Relaxed);

	for _ in 0..iters {
		buf.clear();
		engine.process_event_into(std::hint::black_box(event), &mut buf);
	}

	let after = ALLOCS.load(Ordering::Relaxed);

	std::hint::black_box(&buf);

	after - before
}

// endregion: --- Fixtures

const ITERS: usize = 1000;

#[test]
fn hot_path_does_not_allocate() {
	// -- Setup & Fixtures
	let miss_engine = engine_from(NEVER_MATCHES);
	let hit_engine = engine_from(ALWAYS_MATCHES);

	let event = generic_event(4242, 1000);

	// -- Exec
	let miss_allocs = allocs_over(&miss_engine, &event, ITERS);
	let hit_allocs = allocs_over(&hit_engine, &event, ITERS);

	let miss_out = miss_engine.process_event(&event);
	let hit_out = hit_engine.process_event(&event);

	// -- Check
	assert!(
		miss_out.is_empty(),
		"the no-match fixture matched; test is measuring the wrong path"
	);
	assert_eq!(
		hit_out.len(),
		1,
		"the match fixture did not match; test is measuring the wrong path"
	);

	assert_eq!(
		miss_allocs, 0,
		"no-match path allocated {miss_allocs} times over {ITERS} events"
	);

	assert_eq!(
		hit_allocs, 0,
		"match path (no response chain) allocated {hit_allocs} times over {ITERS} events"
	);
}
