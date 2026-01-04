use std::{sync::Arc, time::Instant};

use serde::Deserialize;

#[cfg_attr(test, derive(PartialEq))]
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum SequenceKind {
	Rule,
	Event,
}

#[cfg_attr(test, derive(PartialEq))]
#[derive(Debug, Deserialize, Clone)]
pub struct Sequence {
	pub kind: SequenceKind,
	pub steps: Vec<Step>,
}

#[cfg_attr(test, derive(PartialEq))]
#[derive(Debug, Deserialize, Clone)]
pub struct Step {
	pub rule_id: String,
	#[serde(with = "humantime_serde")]
	pub within: std::time::Duration,
}

pub struct SequenceProgress {
	pub step_idx: usize,
	pub last_match: Instant,
}
