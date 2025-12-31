use arc_swap::ArcSwap;
use std::{collections::HashMap, path::Path, sync::Arc};

use lib_event::app_evt_types::{CerberusEvent, EvaluatedEvent, EventMeta};

use crate::{ctx::EvalCtx, error::Result};
use crate::{evaluator::Evaluator, ruleset::RuleSet};

pub struct RuleEngine {
	pub ruleset: ArcSwap<RuleSet>,
}

impl RuleEngine {
	pub fn new(dir: impl AsRef<Path>) -> Result<Self> {
		let ruleset = RuleSet::load_from_dir(dir)?;
		Ok(Self {
			ruleset: ArcSwap::from_pointee(ruleset),
		})
	}

	pub fn reload_ruleset(&self, dir: impl AsRef<Path>) -> Result<()> {
		let new = Arc::new(RuleSet::load_from_dir(dir)?);
		self.ruleset.store(new);

		Ok(())
	}

	pub fn new_from_ruleset(ruleset: RuleSet) -> Result<Self> {
		Ok(Self {
			ruleset: ArcSwap::from_pointee(ruleset),
		})
	}

	fn event_meta(event: &CerberusEvent) -> EventMeta {
		match event {
			CerberusEvent::Generic(evt) => EventMeta {
				uid: evt.uid,
				pid: evt.pid,
				comm: Arc::clone(&evt.comm),
			},
			CerberusEvent::InetSock(_) => EventMeta {
				uid: 0,
				pid: 0,
				comm: "".into(),
			},
			CerberusEvent::Module(evt) => EventMeta {
				uid: evt.uid,
				pid: evt.pid,
				comm: Arc::clone(&evt.comm),
			},
			CerberusEvent::Bprm(evt) => EventMeta {
				uid: evt.uid,
				pid: evt.pid,
				comm: Arc::clone(&evt.comm),
			},
		}
	}

	pub fn rule_count(&self) -> usize {
		self.ruleset.load().rule_count()
	}

	pub fn process_event(&self, event: &CerberusEvent) -> Result<Vec<EvaluatedEvent>> {
		let ctx = Self::event_to_ctx(event);
		let ruleset = self.ruleset.load();
		let mut matches = Vec::new();

		for rule in &ruleset.ruleset {
			if Evaluator::rule_matches(&rule.inner, &ctx) {
				matches.push(EvaluatedEvent {
					rule_id: Arc::from(rule.inner.id.as_str()),
					rule_hash: rule.hash_hex(),
					severity: Arc::from(rule.inner.severity.as_deref().unwrap_or("unknown")),
					rule_type: rule.inner.r#type.as_str().into(),
					event_meta: Self::event_meta(event),
				});
			}
		}

		Ok(matches)
	}

	fn event_to_ctx(event: &CerberusEvent) -> EvalCtx {
		let mut fields = HashMap::new();
		match event {
			CerberusEvent::Generic(e) => {
				fields.insert("name".into(), toml::Value::String(e.name.into()));
				fields.insert("uid".into(), toml::Value::Integer(e.uid as i64));
				fields.insert("pid".into(), toml::Value::Integer(e.pid as i64));
				fields.insert("tgid".into(), toml::Value::Integer(e.tgid as i64));
				fields.insert("comm".into(), toml::Value::String(e.comm.to_string()));
			}
			CerberusEvent::Module(e) => {
				fields.insert("uid".into(), toml::Value::Integer(e.uid as i64));
				fields.insert("pid".into(), toml::Value::Integer(e.pid as i64));
				fields.insert("tgid".into(), toml::Value::Integer(e.tgid as i64));
				fields.insert("comm".into(), toml::Value::String(e.comm.to_string()));
				fields.insert("module_name".into(), toml::Value::String(e.module_name.to_string()));
			}
			CerberusEvent::InetSock(e) => {
				fields.insert("old_state".into(), toml::Value::String(e.old_state.to_string()));
				fields.insert("new_state".into(), toml::Value::String(e.new_state.to_string()));
				fields.insert("sport".into(), toml::Value::Integer(e.sport as i64));
				fields.insert("dport".into(), toml::Value::Integer(e.dport as i64));
				fields.insert("protocol".into(), toml::Value::String(e.protocol.to_string()));
			}
			CerberusEvent::Bprm(e) => {
				fields.insert("uid".into(), toml::Value::Integer(e.uid as i64));
				fields.insert("pid".into(), toml::Value::Integer(e.pid as i64));
				fields.insert("tgid".into(), toml::Value::Integer(e.tgid as i64));
				fields.insert("comm".into(), toml::Value::String(e.comm.to_string()));
				fields.insert("filepath".into(), toml::Value::String(e.filepath.to_string()));
			}
		}
		EvalCtx::new(fields)
	}
}

// region:    --- Tests

#[cfg(test)]
mod tests {
	type Result<T> = core::result::Result<T, Box<dyn std::error::Error>>; // For tests.

	use super::*;
	use lib_event::app_evt_types::{CerberusEvent, RingBufEvent};
	use std::sync::Arc;
	use toml::Value;

	#[test]
	fn process_event_matches_rule() -> Result<()> {
		// -- Setup & Fixtures
		//

		let ruleset = RuleSet::load_from_dir("./rules/")?;

		let engine = RuleEngine::new_from_ruleset(ruleset)?;

		let event = CerberusEvent::Generic(RingBufEvent {
			name: "KILL",
			uid: 0,
			pid: 1,
			tgid: 4242,
			comm: Arc::from("bash"),
			meta: 0,
		});

		// -- Exec
		let res = engine.process_event(&event)?;

		// -- Check
		assert!(!res.is_empty());
		let matched = &res[0];
		assert_eq!(matched.rule_id, "pid-exists".into());
		assert_eq!(matched.severity, "low".into());
		assert_eq!(matched.rule_type, "exec".into());
		assert_eq!(matched.event_meta.pid, 1);

		Ok(())
	}

	#[test]
	fn process_event_no_match() -> Result<()> {
		// -- Setup & Fixtures
		let rule = crate::rule::Rule {
			inner: crate::rule::RuleInner {
				id: "pid-zero-only".to_string(),
				description: "Matches only pid=0".to_string(),
				r#type: "exec".to_string(),
				severity: Some("high".to_string()),
				category: None,
				conditions: vec![crate::rule::Condition {
					field: "pid".to_string(),
					op: "equals".to_string(),
					value: Value::Integer(0),
				}],
				sequence: None,
			},

			hash: [0u8; 32],
		};

		let ruleset = RuleSet { ruleset: vec![rule] };
		let engine = RuleEngine::new_from_ruleset(ruleset)?;

		let event = CerberusEvent::Generic(RingBufEvent {
			name: "COMMIT_CREDS",
			uid: 1000,
			pid: 4242,
			tgid: 4242,
			comm: Arc::from("bash"),
			meta: 0,
		});

		// -- Exec
		let res = engine.process_event(&event)?;

		// -- Check
		assert!(res.is_empty());

		Ok(())
	}

	#[test]
	fn process_event_network_rule_match() -> Result<()> {
		// -- Setup & Fixtures
		let rule = crate::rule::Rule {
			inner: crate::rule::RuleInner {
				id: "tcp-state-change".to_string(),
				description: "Detect TCP state transitions".to_string(),
				r#type: "network".to_string(),
				severity: Some("medium".to_string()),
				category: None,
				conditions: vec![
					crate::rule::Condition {
						field: "protocol".to_string(),
						op: "equals".to_string(),
						value: Value::String("TCP".to_string()),
					},
					crate::rule::Condition {
						field: "new_state".to_string(),
						op: "equals".to_string(),
						value: Value::String("TCP_ESTABLISHED".to_string()),
					},
				],
				sequence: None,
			},
			hash: [0u8; 32],
		};

		let ruleset = RuleSet { ruleset: vec![rule] };

		let engine = RuleEngine::new_from_ruleset(ruleset)?;

		let inet_evt = lib_event::app_evt_types::InetSockEvent {
			old_state: Arc::from("TCP_SYN_SENT"),
			new_state: Arc::from("TCP_ESTABLISHED"),
			sport: 4444,
			dport: 22,
			protocol: Arc::from("TCP"),
			saddr: 0,
			daddr: 0,
		};

		let event = CerberusEvent::InetSock(inet_evt);

		// -- Exec
		let res = engine.process_event(&event)?;

		// -- Check

		assert_eq!(res.len(), 1);
		let matched = &res[0];

		assert_eq!(matched.rule_id, "tcp-state-change".into());
		assert_eq!(matched.rule_type, "network".into());

		Ok(())
	}

	#[test]
	fn load_rule_from_file_and_match_event() -> Result<()> {
		let engine = RuleEngine::new("rules/")?;

		let event = CerberusEvent::Generic(lib_event::app_evt_types::RingBufEvent {
			name: "OPEN_FILE",
			uid: 1001,
			pid: 2222,
			tgid: 2222,
			comm: Arc::from("testproc"),
			meta: 0,
		});

		let mut ctx = RuleEngine::event_to_ctx(&event);
		ctx.insert("path".into(), toml::Value::String("/tmp/test.txt".into()));

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
