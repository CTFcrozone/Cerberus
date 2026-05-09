use crate::Severity;

impl Severity {
	pub fn as_str(&self) -> &'static str {
		match self {
			Severity::Info => "Info",
			Severity::VeryLow => "Very low",
			Severity::Low => "Low",
			Severity::Medium => "Medium",
			Severity::High => "High",
			Severity::Critical => "Critical",
		}
	}
}
