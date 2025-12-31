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
	#[serde(default)]
	pub ordered: bool,
	pub steps: Vec<Step>,
}
#[cfg_attr(test, derive(PartialEq))]
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum StepTarget {
	Rule { id: String },
	Event { name: String },
}
#[cfg_attr(test, derive(PartialEq))]
#[derive(Debug, Deserialize, Clone)]
pub struct Step {
	pub target: StepTarget,
	#[serde(with = "humantime_serde")]
	pub within: std::time::Duration,
}
