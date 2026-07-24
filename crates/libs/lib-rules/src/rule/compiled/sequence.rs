use std::{sync::Arc, time::Duration};

use crate::{
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
	pub scope: Option<Scope>,
	pub steps: Vec<CompiledStep>,
}

#[derive(Debug, Clone)]
pub struct CompiledStep {
	pub rule_id: Arc<str>,
	pub within: Duration,
}

pub fn compile_sequence(raw: Sequence) -> Result<CompiledSequence> {
	Ok(CompiledSequence {
		id: raw.id.into(),

		kind: raw.kind,

		scope: raw.scope,

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
