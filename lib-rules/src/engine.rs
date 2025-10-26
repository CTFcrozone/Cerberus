use std::{
	collections::HashMap,
	path::Path,
	sync::{Arc, RwLock},
};

use lib_event::app_evt_types::{CerberusEvent, EvaluatedEvent, EventMeta, RuleType};

use crate::{ctx::EvalCtx, error::Result};
use crate::{evaluator::Evaluator, ruleset::RuleSet};

pub struct RuleEngine {
	ruleset: Arc<RwLock<RuleSet>>,
}

impl RuleEngine {
	pub fn new(dir: impl AsRef<Path>) -> Result<Self> {
		let ruleset = Arc::new(RwLock::new(RuleSet::load_from_dir(dir)?));

		println!("{ruleset:?}");

		Ok(Self { ruleset })
	}

	pub fn process_event(&self, event: &CerberusEvent) -> Option<EvaluatedEvent> {
		let ctx = Self::event_to_ctx(event);
		let ruleset = self.ruleset.read().unwrap();

		for rule in &ruleset.ruleset {
			if Evaluator::rule_matches(&rule.rule, &ctx) {
				let meta = match &event {
					CerberusEvent::Generic(evt) => EventMeta {
						uid: evt.uid,
						pid: evt.pid,
						comm: Arc::clone(&evt.comm),
					},
					CerberusEvent::InetSock(_) => EventMeta {
						uid: 0,
						pid: 0,
						comm: Arc::from(""),
					},
				};

				return Some(EvaluatedEvent {
					rule_id: rule.rule.id.clone(),
					severity: rule.rule.severity.clone().unwrap_or("unknown".into()),
					rule_type: match rule.rule.r#type.as_str() {
						"fs" => RuleType::Fs,
						"network" => RuleType::Network,
						"exec" => RuleType::Exec,
						_ => RuleType::Exec,
					},
					event_meta: meta,
				});
			}
		}
		None
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
			CerberusEvent::InetSock(e) => {
				fields.insert("old_state".into(), toml::Value::String(e.old_state.to_string()));
				fields.insert("new_state".into(), toml::Value::String(e.new_state.to_string()));
				fields.insert("sport".into(), toml::Value::Integer(e.sport as i64));
				fields.insert("dport".into(), toml::Value::Integer(e.dport as i64));
				fields.insert("protocol".into(), toml::Value::String(e.protocol.to_string()));
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

		let engine = RuleEngine {
			ruleset: Arc::new(RwLock::new(ruleset)),
		};

		let event = CerberusEvent::Generic(RingBufEvent {
			name: "KILL",
			uid: 0,
			pid: 1,
			tgid: 4242,
			comm: Arc::from("bash"),
			meta: 0,
		});

		// -- Exec
		let res = engine.process_event(&event);

		// -- Check
		assert!(res.is_some());
		let matched = res.unwrap();
		assert_eq!(matched.rule_id, "pid-exists");
		assert_eq!(matched.severity, "low");
		assert_eq!(matched.rule_type, RuleType::Exec);
		assert_eq!(matched.event_meta.pid, 1);

		Ok(())
	}

	#[test]
	fn process_event_no_match() -> Result<()> {
		// -- Setup & Fixtures
		let rule = crate::rule::Rule {
			rule: crate::rule::RuleInner {
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
			},
		};

		let ruleset = RuleSet { ruleset: vec![rule] };

		let engine = RuleEngine {
			ruleset: Arc::new(RwLock::new(ruleset)),
		};

		let event = CerberusEvent::Generic(RingBufEvent {
			name: "COMMIT_CREDS",
			uid: 1000,
			pid: 4242,
			tgid: 4242,
			comm: Arc::from("bash"),
			meta: 0,
		});

		// -- Exec
		let res = engine.process_event(&event);

		// -- Check
		assert!(res.is_none());

		Ok(())
	}

	#[test]
	fn process_event_network_rule_match() -> Result<()> {
		// -- Setup & Fixtures
		let rule = crate::rule::Rule {
			rule: crate::rule::RuleInner {
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
			},
		};

		let ruleset = RuleSet { ruleset: vec![rule] };

		let engine = RuleEngine {
			ruleset: Arc::new(RwLock::new(ruleset)),
		};

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
		let res = engine.process_event(&event);

		// -- Check
		assert!(res.is_some());
		let matched = res.unwrap();
		assert_eq!(matched.rule_id, "tcp-state-change");
		assert_eq!(matched.rule_type, RuleType::Network);

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

		let ruleset = engine.ruleset.read().unwrap();
		let matched_rule = ruleset
			.ruleset
			.iter()
			.find(|r| r.rule.id == "test-rule")
			.expect("rule not loaded");

		let matched = Evaluator::rule_matches(&matched_rule.rule, &ctx);

		assert!(matched);
		assert_eq!(matched_rule.rule.severity.as_deref(), Some("very-low"));
		assert_eq!(matched_rule.rule.category.as_deref(), Some("test"));

		Ok(())
	}
}

// endregion: --- Tests
