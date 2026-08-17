use arc_swap::ArcSwap;
use lib_common::event::{CerberusEvent, Event, EventMeta};
use lib_event_schema::{Field, FieldValue};
use std::time::Instant;
use std::{path::Path, sync::Arc};
use strum::EnumCount;

use crate::engine::correlator::ShardedCorrelator;
use crate::engine::identity::ShardKey;
use crate::engine::snapshot::RuleSnapshot;
use crate::engine::{EngineEvent, EvalCtx, EvaluatedEvent, Evaluator, EventKind};
use crate::error::Result;
use crate::rule::compiled::rule::CompiledRule;
use crate::rule::compiled::ruleset::CompiledRuleSet;
use crate::{CorrelationEvent, Error, ResponseRequest, RuleSet, Trigger};

type LazyFields = Option<Arc<[Option<FieldValue>; Field::COUNT]>>;

pub struct RuleEngine {
	snapshot: ArcSwap<RuleSnapshot>,
	correlator: ShardedCorrelator,
}

impl RuleEngine {
	pub fn new(dir: impl AsRef<Path>) -> Result<Self> {
		let ruleset = RuleSet::load_from_dir(&dir)?;

		if ruleset.rule_count() == 0 {
			return Err(Error::NoRulesInDir(dir.as_ref().display().to_string()));
		}

		let ruleset = CompiledRuleSet::compile(ruleset)?;
		let snapshot = RuleSnapshot::from_ruleset(ruleset);

		Ok(Self {
			snapshot: ArcSwap::from_pointee(snapshot),
			correlator: ShardedCorrelator::new(),
		})
	}

	pub async fn reload_ruleset_async(&self, dir: impl AsRef<Path>) -> Result<()> {
		let dir = dir.as_ref().to_path_buf();

		let snapshot = tokio::task::spawn_blocking(move || -> Result<_> {
			let raw = RuleSet::load_from_dir(&dir)?;
			let ruleset = CompiledRuleSet::compile(raw)?;
			let snapshot = RuleSnapshot::from_ruleset(ruleset);

			Ok(snapshot)
		})
		.await
		.map_err(|e| Error::Custom(format!("reload task panicked: {e}")))??;

		self.snapshot.store(Arc::new(snapshot));

		Ok(())
	}

	pub fn reload_ruleset(&self, dir: impl AsRef<Path>) -> Result<()> {
		let ruleset = RuleSet::load_from_dir(dir)?;
		let ruleset = CompiledRuleSet::compile(ruleset)?;
		let snapshot = Arc::new(RuleSnapshot::from_ruleset(ruleset));

		self.snapshot.store(snapshot);

		Ok(())
	}

	pub fn new_from_ruleset(ruleset: RuleSet) -> Result<Self> {
		let ruleset = CompiledRuleSet::compile(ruleset)?;
		let snapshot = RuleSnapshot::from_ruleset(ruleset);

		Ok(Self {
			correlator: ShardedCorrelator::new(),
			snapshot: ArcSwap::from_pointee(snapshot),
		})
	}

	#[inline]
	fn fields_for_response(lazy: &mut LazyFields, ctx: &EvalCtx) -> Arc<[Option<FieldValue>; Field::COUNT]> {
		Arc::clone(lazy.get_or_insert_with(|| Arc::new(ctx.fields().clone())))
	}

	fn event_meta<E: Event>(event: &E) -> EventMeta {
		let header = event.header();
		EventMeta {
			uid: header.uid,
			pid: header.pid,
			comm: Arc::clone(&header.comm),
		}
	}

	pub fn snapshot(&self) -> Arc<RuleSnapshot> {
		self.snapshot.load_full()
	}

	fn advance_sequences(
		&self,
		shard_key: &ShardKey,
		matched_rule: &CompiledRule,
		now: Instant,
		rules: &[CompiledRule],
		roots: &[u32],
		out: &mut Vec<EngineEvent>,
		meta: &EventMeta,
		ctx: &EvalCtx,
		fields: &mut LazyFields,
	) {
		for &root_idx in roots {
			let Some(root_rule) = rules.get(root_idx as usize) else {
				continue;
			};

			let Some(seq) = &root_rule.inner.sequence else {
				continue;
			};

			let matches =
				self.correlator
					.on_rule_match(shard_key, &matched_rule.inner.id, seq, &root_rule.inner.id, now, meta);

			for m in matches {
				if let CorrelationEvent::Completed {
					root_rule_id,
					event_meta,
					..
				} = &m
				{
					if let Some(chain) = &root_rule.inner.response_chain {
						if matches!(chain.trigger, Trigger::SequenceFinished) {
							out.push(
								ResponseRequest {
									id: 0,
									rule_id: root_rule_id.clone(),
									response_chain: Arc::clone(chain),
									event_meta: event_meta.clone(),
									fields: Self::fields_for_response(fields, ctx),
								}
								.into(),
							);
						}
					}
				}
				out.push(m.into());
			}
		}
	}

	pub fn process_event_into(&self, event: &CerberusEvent, out: &mut Vec<EngineEvent>) {
		let snapshot = self.snapshot.load();
		let index = snapshot.index();

		let evt_kind = EventKind::from(event);
		let candidates = index.candidates(evt_kind);
		if candidates.is_empty() {
			return;
		}

		let rules = snapshot.ruleset().rules();

		let ctx = EvalCtx::new(event.to_fields());
		let meta = Self::event_meta(event);
		let shard_key = ShardKey::from(event.header());

		let mut now: Option<Instant> = None;
		let mut fields: LazyFields = None;

		for cand in candidates {
			let Some(rule) = rules.get(cand.idx as usize) else {
				continue;
			};

			if !Evaluator::rule_matches_compiled(&rule.inner, &ctx) {
				continue;
			}

			out.push(Self::rule_to_eval_event(rule, meta.clone()).into());

			if let Some(chain) = &rule.inner.response_chain {
				if matches!(chain.trigger, Trigger::RuleMatch) {
					out.push(
						ResponseRequest {
							id: 0,
							rule_id: rule.inner.id.clone(),
							response_chain: Arc::clone(chain),
							event_meta: meta.clone(),
							fields: Self::fields_for_response(&mut fields, &ctx),
						}
						.into(),
					);
				}
			}

			let roots = index.seq_roots(cand.idx);

			if rule.inner.sequence.is_some() || !roots.is_empty() {
				let now = *now.get_or_insert_with(Instant::now);

				if let Some(seq) = &rule.inner.sequence {
					self.correlator.on_root_match(&shard_key, &rule.inner.id, seq, now, meta.pid);
				}

				if !roots.is_empty() {
					self.advance_sequences(&shard_key, rule, now, rules, roots, out, &meta, &ctx, &mut fields);
				}
			}
		}
	}

	pub fn process_event(&self, event: &CerberusEvent) -> Vec<EngineEvent> {
		let mut out = Vec::new();
		self.process_event_into(event, &mut out);
		out
	}

	fn rule_to_eval_event(rule: &CompiledRule, event_meta: EventMeta) -> EvaluatedEvent {
		EvaluatedEvent {
			rule_id: rule.inner.id.clone(),
			rule_hash: rule.hash_hex.clone(),
			severity: rule.inner.severity,
			event_meta,
		}
	}
}

// region:    --- Tests

#[cfg(test)]
mod tests {
	type Result<T> = core::result::Result<T, Box<dyn std::error::Error>>;

	use crate::rule::Severity;

	use super::*;
	use lib_common::event::{Event, EventHeader, RingBufEvent};
	use std::sync::Arc;
	use toml::Value;

	fn expect_matched(ev: &EngineEvent) -> &EvaluatedEvent {
		match ev {
			EngineEvent::Matched(e) => e,
			_ => panic!("expected EngineEvent::Matched"),
		}
	}

	fn generic_event(pid: u32, uid: u32, comm: &str) -> CerberusEvent {
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
				parent_comm: Arc::from("bash"),
				comm: Arc::from(comm),
			},
			meta_type: 0,
			meta: 0,
		})
	}

	fn raw_rule(id: &str, conditions: Vec<crate::rule::Condition>) -> crate::rule::Rule {
		crate::rule::Rule {
			inner: crate::rule::RuleInner {
				id: id.to_string(),
				description: "test".to_string(),
				severity: Severity::Low,
				conditions,
				sequence: None,
				response_chain: None,
			},
			hash: [0u8; 32],
			hash_hex: Arc::from("0".repeat(64)),
		}
	}

	fn cond(field: &str, op: &str, value: Value) -> crate::rule::Condition {
		crate::rule::Condition {
			field: field.to_string(),
			op: op.to_string(),
			value,
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
				parent_comm: Arc::from("bash"),

				comm: Arc::from("bash"),
			},
			meta_type: 0,
			meta: 0,
		});

		let res = engine.process_event(&event);
		assert!(!res.is_empty());

		let matched = expect_matched(&res[0]);
		let header = event.header();
		assert_eq!(matched.rule_id, "pid-exists".into());
		assert_eq!(matched.severity, Severity::Low);
		assert_eq!(matched.event_meta.pid, header.pid);

		Ok(())
	}

	#[test]
	fn process_event_no_match() -> Result<()> {
		let rule = crate::rule::Rule {
			inner: crate::rule::RuleInner {
				id: "pid-zero-only".to_string(),
				description: "Matches only pid=0".to_string(),
				severity: Severity::High,
				conditions: vec![crate::rule::Condition {
					field: "process.pid".to_string(),
					op: "equals".to_string(),
					value: Value::Integer(0),
				}],
				sequence: None,
				response_chain: None,
			},
			hash: [0u8; 32],
			hash_hex: Arc::from("0".repeat(64)),
		};

		let ruleset = crate::RuleSet::new(vec![rule])?;

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
				parent_comm: Arc::from("bash"),

				comm: Arc::from("bash"),
			},
			meta_type: 0,

			meta: 0,
		});

		let res = engine.process_event(&event);
		assert!(res.is_empty());

		Ok(())
	}

	#[test]
	fn process_event_network_rule_match() -> Result<()> {
		let rule = crate::rule::Rule {
			inner: crate::rule::RuleInner {
				id: "tcp-state-change".to_string(),
				description: "Detect TCP state transitions".to_string(),
				severity: Severity::Medium,
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
				response_chain: None,
			},
			hash: [0u8; 32],
			hash_hex: Arc::from("0".repeat(64)),
		};

		let ruleset = crate::RuleSet::new(vec![rule])?;

		let engine = RuleEngine::new_from_ruleset(ruleset)?;

		let inet_evt = lib_common::event::InetSockEvent {
			header: EventHeader {
				cgroup_id: 0,
				container: None,
				ts: 0,
				ppid: 1,
				parent_comm: Arc::from("bash"),

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
		let res = engine.process_event(&event);

		assert_eq!(res.len(), 1);
		let matched = expect_matched(&res[0]);
		assert_eq!(matched.rule_id, "tcp-state-change".into());

		Ok(())
	}

	#[test]
	fn rules_needing_absent_fields_are_not_candidates() -> Result<()> {
		// -- Setup & Fixtures
		// inode.filename is only supplied by Inode events, so placement files this
		// rule under Inode alone — a Generic event never lists it as a candidate.
		let rule = raw_rule(
			"inode-rule",
			vec![cond("inode.filename", "starts_with", Value::String("/tmp".to_string()))],
		);
		let engine = RuleEngine::new_from_ruleset(crate::RuleSet::new(vec![rule])?)?;

		// -- Exec & Check
		assert!(engine.process_event(&generic_event(1, 0, "bash")).is_empty());

		Ok(())
	}

	#[test]
	fn not_in_does_not_match_when_field_is_absent() -> Result<()> {
		// -- Setup & Fixtures
		// not_in requires presence: "the field exists and is not in this set".
		let rule = raw_rule(
			"not-in-absent",
			vec![
				cond("process.pid", "equals", Value::Integer(1)),
				cond(
					"inode.filename",
					"not_in",
					Value::Array(vec![Value::String("/etc/shadow".to_string())]),
				),
			],
		);
		let engine = RuleEngine::new_from_ruleset(crate::RuleSet::new(vec![rule])?)?;

		// -- Exec & Check
		assert!(
			engine.process_event(&generic_event(1, 0, "bash")).is_empty(),
			"not_in must not match an event lacking the field"
		);

		Ok(())
	}

	#[test]
	fn process_event_into_appends_without_clearing() -> Result<()> {
		let ruleset = RuleSet::load_from_dir("./rules/")?;
		let engine = RuleEngine::new_from_ruleset(ruleset)?;

		let event = generic_event(1, 0, "bash");

		let mut buf = Vec::new();
		engine.process_event_into(&event, &mut buf);
		let first = buf.len();
		assert!(first > 0);

		engine.process_event_into(&event, &mut buf);
		assert_eq!(buf.len(), first * 2, "process_event_into must append, not clear");

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
				parent_comm: Arc::from("bash"),

				mnt_ns: 0,
				pid: 2222,
				tgid: 2222,
				uid: 1001,
				comm: Arc::from("testproc"),
			},
			meta_type: 0,

			meta: 0,
		});

		let mut ctx = EvalCtx::new(event.to_fields());
		ctx.insert(
			lib_event_schema::Field::ProcessFilepath,
			lib_event_schema::FieldValue::String("/tmp/test.txt".into()),
		);

		let snapshot = engine.snapshot.load();
		let matched_rule = snapshot
			.ruleset()
			.rules()
			.iter()
			.find(|r| r.inner.id == "test-rule".into())
			.expect("rule not loaded");

		let matched = Evaluator::rule_matches_compiled(&matched_rule.inner, &ctx);
		assert!(matched);
		assert_eq!(matched_rule.inner.severity, Severity::VeryLow);

		Ok(())
	}
}

// endregion: --- Tests
