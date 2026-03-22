use arc_swap::ArcSwap;
use lib_common::event::{CerberusEvent, Event, EventMeta};
use parking_lot::Mutex;
use std::time::Instant;
use std::{path::Path, sync::Arc};

use crate::engine::correlator::ShardedCorrelator;
use crate::engine::{
	CorrelatedEvent, Correlator, EngineEvent, EvalCtx, EvaluatedEvent, Evaluator, EventKind, RuleIndex,
};
use crate::error::Result;
use crate::rule::Rule;
use crate::{Error, RuleSet};

pub struct RuleEngine {
	pub ruleset: ArcSwap<RuleSet>,
	pub index: ArcSwap<RuleIndex>,
	correlator: ShardedCorrelator,
}

impl RuleEngine {
	pub fn new(dir: impl AsRef<Path>) -> Result<Self> {
		let ruleset = RuleSet::load_from_dir(&dir)?;

		if ruleset.rule_count() == 0 {
			return Err(Error::NoRulesInDir(dir.as_ref().display().to_string()));
		}

		let index = RuleIndex::build(&ruleset);

		Ok(Self {
			ruleset: ArcSwap::from_pointee(ruleset),
			correlator: ShardedCorrelator::new(),
			index: ArcSwap::from_pointee(index),
		})
	}

	pub fn reload_ruleset(&self, dir: impl AsRef<Path>) -> Result<()> {
		let ruleset = Arc::new(RuleSet::load_from_dir(dir)?);
		let index = Arc::new(RuleIndex::build(&ruleset));

		self.ruleset.store(ruleset);
		self.index.store(index);

		Ok(())
	}

	pub fn new_from_ruleset(ruleset: RuleSet) -> Result<Self> {
		let index = RuleIndex::build(&ruleset);

		Ok(Self {
			ruleset: ArcSwap::from_pointee(ruleset),
			correlator: ShardedCorrelator::new(),

			index: ArcSwap::from_pointee(index),
		})
	}

	fn event_meta<E: Event>(event: &E) -> EventMeta {
		let header = event.header();
		EventMeta {
			uid: header.uid,
			pid: header.pid,
			comm: Arc::clone(&header.comm),
		}
	}

	pub fn rule_count(&self) -> usize {
		self.ruleset.load().rule_count()
	}

	fn find_rule_by_id<'a>(ruleset: &'a RuleSet, rule_id: &str) -> Option<&'a Rule> {
		let idx = ruleset.by_id.get(rule_id)?;
		ruleset.ruleset.get(*idx)
	}

	fn advance_sequences(
		&self,
		matched_rule: &Rule,
		now: Instant,
		ruleset: &RuleSet,
		index: &RuleIndex,
		out: &mut Vec<EngineEvent>,
		event: &CerberusEvent,
	) {
		let key: Arc<str> = matched_rule.inner.id.as_str().into();
		let Some(root_ids) = index.seq_listeners.get(&key) else {
			return;
		};

		for root_id in root_ids {
			let Some(root_rule) = Self::find_rule_by_id(ruleset, root_id) else {
				continue;
			};

			let Some(seq) = &root_rule.inner.sequence else {
				continue;
			};

			if self
				.correlator
				.on_rule_match(
					event.header().ppid,
					&matched_rule.inner.id,
					seq,
					&root_rule.inner.id,
					now,
				)
				.is_some()
			{
				out.push(
					CorrelatedEvent {
						base_rule_id: root_rule.inner.id.as_str().into(),
						seq_rule_id: matched_rule.inner.id.as_str().into(),
						base_rule_hash: root_rule.hash_hex(),
						seq_rule_hash: matched_rule.hash_hex(),
						event_meta: Self::event_meta(event),
					}
					.into(),
				);
			}
		}
	}

	pub fn process_event(&self, event: &CerberusEvent) -> Result<Vec<EngineEvent>> {
		let ctx = Self::event_to_ctx(event);
		let ruleset = self.ruleset.load();

		let mut out = Vec::<EngineEvent>::new();
		let index = self.index.load();
		let now = Instant::now();
		// let mut corr = self.correlator.lock();
		let evt_kind = EventKind::from(event);

		if let Some(candidates) = index.by_evt_kind.get(&evt_kind) {
			for rule_id in candidates {
				let Some(rule) = Self::find_rule_by_id(&ruleset, rule_id) else {
					continue;
				};

				if !Evaluator::rule_matches(&rule.inner, &ctx) {
					continue;
				}

				out.push(Self::rule_to_eval_event(rule, Self::event_meta(event)).into());

				if let Some(seq) = &rule.inner.sequence {
					self.correlator.on_root_match(event.header().ppid, &rule.inner.id, seq, now);
				}
				self.advance_sequences(rule, now, &ruleset, &index, &mut out, event);
			}
		}

		Ok(out)
	}

	fn event_to_ctx<E: Event>(event: &E) -> EvalCtx {
		EvalCtx::new(event.to_fields())
	}

	fn rule_to_eval_event(rule: &Rule, event_meta: EventMeta) -> EvaluatedEvent {
		EvaluatedEvent {
			rule_id: Arc::from(rule.inner.id.as_str()),
			rule_hash: rule.hash_hex(),
			severity: Arc::from(rule.inner.severity.as_deref().unwrap_or("unknown")),
			rule_type: rule.inner.r#type.as_str().into(),
			event_meta,
		}
	}
}

// region:    --- Tests

#[cfg(test)]
mod tests {
	type Result<T> = core::result::Result<T, Box<dyn std::error::Error>>;

	use super::*;
	use lib_common::event::{Event, EventHeader, RingBufEvent};
	use std::{collections::HashMap, sync::Arc};
	use toml::Value;

	fn expect_matched(ev: &EngineEvent) -> &EvaluatedEvent {
		match ev {
			EngineEvent::Matched(e) => e,
			_ => panic!("expected EngineEvent::Matched"),
		}
	}

	#[test]
	fn process_event_matches_rule() -> Result<()> {
		let ruleset = RuleSet::load_from_dir("./rules/")?;
		let engine = RuleEngine::new_from_ruleset(ruleset)?;

		let event = CerberusEvent::Generic(RingBufEvent {
			name: "KILL",
			header: EventHeader {
				cgroup_id: 0,
				container: None,
				ts: 0,
				mnt_ns: 0,
				pid: 1,
				ppid: 1,
				tgid: 4242,
				uid: 0,
				comm: Arc::from("bash"),
			},
			meta: 0,
		});

		let res = engine.process_event(&event)?;
		assert!(!res.is_empty());

		let matched = expect_matched(&res[0]);
		let header = event.header(); // via Event trait
		assert_eq!(matched.rule_id, "pid-exists".into());
		assert_eq!(matched.severity, "low".into());
		assert_eq!(matched.rule_type, "exec".into());
		assert_eq!(matched.event_meta.pid, header.pid);

		Ok(())
	}

	#[test]
	fn process_event_no_match() -> Result<()> {
		let rule = crate::rule::Rule {
			inner: crate::rule::RuleInner {
				id: "pid-zero-only".to_string(),
				description: "Matches only pid=0".to_string(),
				r#type: "exec".to_string(),
				severity: Some("high".to_string()),
				category: None,
				conditions: vec![crate::rule::Condition {
					field: "process.pid".to_string(),
					op: "equals".to_string(),
					value: Value::Integer(0),
				}],
				sequence: None,
				response: None,
			},
			hash: [0u8; 32],
		};

		let mut by_id = HashMap::new();
		by_id.insert(rule.inner.id.clone().into(), 0);

		let ruleset = crate::RuleSet {
			ruleset: vec![rule],
			by_id,
		};

		let engine = RuleEngine::new_from_ruleset(ruleset)?;

		let event = CerberusEvent::Generic(RingBufEvent {
			name: "COMMIT_CREDS",
			header: EventHeader {
				cgroup_id: 0,
				container: None,
				ts: 0,
				mnt_ns: 0,
				ppid: 1,

				pid: 4242,
				tgid: 4242,
				uid: 1000,
				comm: Arc::from("bash"),
			},
			meta: 0,
		});

		let res = engine.process_event(&event)?;
		assert!(res.is_empty());

		Ok(())
	}

	#[test]
	fn process_event_network_rule_match() -> Result<()> {
		let rule = crate::rule::Rule {
			inner: crate::rule::RuleInner {
				id: "tcp-state-change".to_string(),
				description: "Detect TCP state transitions".to_string(),
				r#type: "network".to_string(),
				severity: Some("medium".to_string()),
				category: None,
				conditions: vec![
					crate::rule::Condition {
						field: "network.protocol".to_string(),
						op: "equals".to_string(),
						value: Value::String("TCP".to_string()),
					},
					crate::rule::Condition {
						field: "socket.new_state".to_string(),
						op: "equals".to_string(),
						value: Value::String("TCP_ESTABLISHED".to_string()),
					},
				],
				sequence: None,
				response: None,
			},
			hash: [0u8; 32],
		};

		let mut by_id = HashMap::new();
		by_id.insert(rule.inner.id.clone().into(), 0);

		let ruleset = crate::RuleSet {
			ruleset: vec![rule],
			by_id,
		};

		let engine = RuleEngine::new_from_ruleset(ruleset)?;

		let inet_evt = lib_common::event::InetSockEvent {
			header: EventHeader {
				cgroup_id: 0,
				container: None,
				ts: 0,
				ppid: 1,

				mnt_ns: 0,
				pid: 0,
				tgid: 0,
				uid: 0,
				comm: Arc::from(""),
			},
			old_state: Arc::from("TCP_SYN_SENT"),
			new_state: Arc::from("TCP_ESTABLISHED"),
			sport: 4444,
			dport: 22,
			protocol: Arc::from("TCP"),
			saddr: 0,
			daddr: 0,
		};

		let event = CerberusEvent::InetSock(inet_evt);
		let res = engine.process_event(&event)?;

		assert_eq!(res.len(), 1);
		let matched = expect_matched(&res[0]);
		assert_eq!(matched.rule_id, "tcp-state-change".into());
		assert_eq!(matched.rule_type, "network".into());

		Ok(())
	}

	#[test]
	fn load_rule_from_file_and_match_event() -> Result<()> {
		let engine = RuleEngine::new("rules/")?;

		let event = CerberusEvent::Generic(lib_common::event::RingBufEvent {
			name: "OPEN_FILE",
			header: EventHeader {
				cgroup_id: 0,
				container: None,
				ts: 0,
				ppid: 1,

				mnt_ns: 0,
				pid: 2222,
				tgid: 2222,
				uid: 1001,
				comm: Arc::from("testproc"),
			},
			meta: 0,
		});

		let mut ctx = RuleEngine::event_to_ctx(&event);
		ctx.insert("process.filepath".into(), toml::Value::String("/tmp/test.txt".into()));

		let ruleset = engine.ruleset.load();
		let matched_rule = ruleset
			.ruleset
			.iter()
			.find(|r| r.inner.id == "test-rule")
			.expect("rule not loaded");

		let matched = Evaluator::rule_matches(&matched_rule.inner, &ctx);
		assert!(matched);
		assert_eq!(matched_rule.inner.severity.as_deref(), Some("very-low"));
		assert_eq!(matched_rule.inner.category.as_deref(), Some("test"));

		Ok(())
	}
}

// endregion: --- Tests
