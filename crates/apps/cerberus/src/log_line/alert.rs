use lib_rules::{CorrelationEvent, EngineEvent, Severity};

pub fn alert_from_engine_event(e: &EngineEvent) -> String {
	match e {
		EngineEvent::Matched(ev) => {
			format!(
				"[RULE: {}] severity={} (PID: {}, UID: {})",
				ev.rule_id,
				ev.severity.as_str(),
				ev.event_meta.pid,
				ev.event_meta.uid,
			)
		}

		EngineEvent::Correlation(c) => match c {
			CorrelationEvent::Step {
				root_rule_id,
				seq_id,
				step_idx,
				matched_rule_id,
				..
			} => {
				format!(
					"[CORRELATION] {}::{} step {}/{} matched {}",
					root_rule_id,
					seq_id,
					step_idx + 1,
					"?",
					matched_rule_id,
				)
			}

			CorrelationEvent::Completed {
				root_rule_id,
				seq_id,
				steps,
				path,
				..
			} => {
				format!(
					"[CORRELATION] {}::{} completed ({} steps): {}",
					root_rule_id,
					seq_id,
					steps,
					path.iter().map(|p| p.as_ref()).collect::<Vec<_>>().join(" → "),
				)
			}
		},

		EngineEvent::Response(r) => {
			format!("[RESPONSE] rule={} action={:?}", r.rule_id, r.response)
		}
	}
}

pub fn severity_from_engine_event(e: &EngineEvent) -> Option<Severity> {
	match e {
		EngineEvent::Matched(ev) => Some(ev.severity),
		_ => None,
	}
}
