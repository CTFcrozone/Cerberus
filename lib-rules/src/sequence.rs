use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum SequenceKind {
	Rule,
	Event,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Sequence {
	pub kind: SequenceKind,
	#[serde(default)]
	pub ordered: bool,
	pub steps: Vec<Step>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum StepTarget {
	Rule { id: String },
	Event { name: String },
}

#[derive(Debug, Deserialize, Clone)]
pub struct Step {
	pub target: StepTarget,
	#[serde(with = "humantime_serde")]
	pub within: std::time::Duration,
}
