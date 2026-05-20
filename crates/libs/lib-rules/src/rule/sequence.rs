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
	pub id: String,
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
