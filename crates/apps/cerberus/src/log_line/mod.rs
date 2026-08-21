pub mod alert;
pub mod format;
mod utils;

use lib_rules::EngineEvent;
use tracing::{info, warn};

pub fn log_engine_event(evt: &EngineEvent) {
	match evt {
		EngineEvent::Matched(e) => {
			info!(
				event.kind = "rule_match",

				rule.id = %e.rule_id,
				rule.severity = %e.severity.as_str(),

				process.uid = e.event_meta.uid,
				process.pid = e.event_meta.pid,
				process.comm = %e.event_meta.comm,
			);
		}

		EngineEvent::Correlation(c) => match c {
			lib_rules::CorrelationEvent::Step { .. } => {
				tracing::debug!(event = "correlation_step",);
			}

			lib_rules::CorrelationEvent::Completed {
				root_rule_id,
				seq_id,
				seq_instance_id,
				path,
				steps,
				event_meta,
			} => {
				warn!(
					event.kind = "correlation",

					correlation.root_rule_id = %root_rule_id,
					correlation.seq_id = %seq_id,
					correlation.instance_id = %seq_instance_id,
					correlation.path = %path.join("->"),
					correlation.steps = steps,

					process.uid = event_meta.uid,
					process.pid = event_meta.pid,
					process.comm = %event_meta.comm,
				);
			}
		},

		EngineEvent::Response(r) => {
			warn!(
				event.kind = "response",

				rule.id = %r.rule_id,
				response.action = %format!("{:?}", r.response_chain),
			);
		}
	}
}
