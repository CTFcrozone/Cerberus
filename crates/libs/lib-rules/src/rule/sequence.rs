use serde::Deserialize;

use crate::rule::common::{Scope, SequenceKind};

#[cfg_attr(test, derive(PartialEq))]
#[derive(Debug, Deserialize, Clone)]
pub struct Sequence {
	pub id: String,
	pub kind: SequenceKind,
	#[serde(default)]
	pub threshold: Option<u32>,
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
