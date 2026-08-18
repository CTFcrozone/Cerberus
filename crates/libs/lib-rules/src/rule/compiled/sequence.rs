use std::{sync::Arc, time::Duration};

use crate::{
	Error,
	error::Result,
	rule::{
		Sequence,
		common::{Scope, SequenceKind},
	},
};

#[derive(Debug, Clone)]
pub struct CompiledSequence {
	pub id: Arc<str>,
	pub kind: SequenceKind,
	pub threshold: Option<u32>,
	pub scope: Option<Scope>,
	pub steps: Vec<CompiledStep>,
}

#[derive(Debug, Clone)]
pub struct CompiledStep {
	pub rule_id: Arc<str>,
	pub within: Duration,
}

pub fn compile_sequence(raw: Sequence) -> Result<CompiledSequence> {
	match (&raw.kind, raw.threshold) {
		(SequenceKind::Threshold, None) => {
			return Err(Error::ThresholdKindNeedsCount { sequence_id: raw.id });
		}
		(SequenceKind::Threshold, Some(n)) if n < 2 => {
			return Err(Error::ThresholdTooLow {
				sequence_id: raw.id,
				threshold: n,
			});
		}
		(SequenceKind::Threshold, Some(_)) if raw.steps.len() != 1 => {
			return Err(Error::ThresholdNeedsSingleStep { sequence_id: raw.id });
		}
		(SequenceKind::Rule | SequenceKind::Event, Some(_)) => {
			return Err(Error::ThresholdOnNonThresholdKind { sequence_id: raw.id });
		}
		_ => {}
	}
	Ok(CompiledSequence {
		id: raw.id.into(),

		kind: raw.kind,

		scope: raw.scope,
		threshold: raw.threshold,
		steps: raw
			.steps
			.into_iter()
			.map(|s| CompiledStep {
				rule_id: s.rule_id.into(),
				within: s.within,
			})
			.collect(),
	})
}
