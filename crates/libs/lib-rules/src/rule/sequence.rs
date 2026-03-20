use std::time::Instant;

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
#[serde(rename_all = "lowercase")]
pub enum Scope {
	Pid,
}

#[cfg_attr(test, derive(PartialEq))]
#[derive(Debug, Deserialize, Clone)]
pub struct Sequence {
	pub kind: SequenceKind,
	pub steps: Vec<Step>,
	#[serde(default)]
	pub scope: Option<Scope>,
}

#[cfg_attr(test, derive(PartialEq))]
#[derive(Debug, Deserialize, Clone)]
pub struct Step {
	pub rule_id: String,
	#[serde(with = "humantime_serde")]
	pub within: std::time::Duration,
}

#[cfg_attr(test, derive(PartialEq))]
#[derive(Debug, Clone)]
pub struct SequenceProgress {
	pub step_idx: usize,
	pub last_match: Instant,
	pub expiry: Instant,
}
