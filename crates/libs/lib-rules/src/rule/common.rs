use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Severity {
	Info,
	VeryLow,
	Low,
	Medium,
	High,
	Critical,
}

#[cfg_attr(test, derive(PartialEq))]
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum Trigger {
	RuleMatch,
	SequenceFinished,
}

impl Severity {
	pub const COUNT: usize = 6;

	pub const ALL: [Severity; Self::COUNT] = [
		Severity::Info,
		Severity::VeryLow,
		Severity::Low,
		Severity::Medium,
		Severity::High,
		Severity::Critical,
	];

	pub const fn index(self) -> usize {
		match self {
			Severity::Info => 0,
			Severity::VeryLow => 1,
			Severity::Low => 2,
			Severity::Medium => 3,
			Severity::High => 4,
			Severity::Critical => 5,
		}
	}

	pub const fn as_str(self) -> &'static str {
		match self {
			Severity::Info => "info",
			Severity::VeryLow => "very-low",
			Severity::Low => "low",
			Severity::Medium => "medium",
			Severity::High => "high",
			Severity::Critical => "critical",
		}
	}
}

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
