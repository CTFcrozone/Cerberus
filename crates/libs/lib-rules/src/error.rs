use std::net::AddrParseError;

use derive_more::{Display, From};

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Display, From)]
#[display("{self:?}")]
pub enum Error {
	#[from(String, &String, &str)]
	#[display("{_0}")]
	Custom(String),

	#[from]
	#[display("Failed to read glob pattern: {_0}")]
	Glob(glob::GlobError),

	#[from]
	#[display("Invalid glob pattern: {_0}")]
	GlobPattern(glob::PatternError),

	#[from]
	#[display("Failed to parse TOML: {_0}")]
	TomlDe(toml::de::Error),

	#[display("No rule file found at '{_0}'")]
	RulePathNotFound(String),

	#[from]
	#[display("Filesystem error: {_0}")]
	SimpleFs(simple_fs::Error),

	#[display("No rules found in '{_0}'")]
	NoRulesInDir(String),

	#[from]
	#[display("Invalid regex: {_0}")]
	Regex(regex::Error),

	#[display("Duplicate rule id '{id}'")]
	DuplicateRuleId { id: String },

	#[display("Duplicate sequence id '{id}'")]
	DuplicateSequenceId { id: String },

	#[display("Unknown field '{field}'")]
	UnknownField { field: String },

	#[display("Unknown operation '{op}'")]
	UnknownOp { op: String },

	#[display("Encountered a sequence_finished trigger outside of a sequence in rule '{rule_id}'")]
	SequenceFinishedTriggerWithoutSequence { rule_id: String },

	#[display(
		"Rule '{rule_id}' has no conditions, so it would match every event. \
		 Give it at least one condition; if it exists only to host a sequence, \
		 model that explicitly rather than matching everything."
	)]
	RuleWithoutConditions { rule_id: String },

	#[display("Rule '{rule_id}' declares sequence '{sequence_id}' with no steps, so it can never fire")]
	SequenceWithoutSteps { rule_id: String, sequence_id: String },
	#[display("Rule '{rule_id}': sequence '{sequence_id}' step {step_idx} references unknown rule '{step_rule_id}'")]
	UnknownSequenceStepRule {
		rule_id: String,
		sequence_id: String,
		step_idx: usize,
		step_rule_id: String,
	},

	#[display("Invalid value '{value}' for field '{field}'")]
	InvalidFieldValue { field: String, value: String },

	#[display("Invalid regex '{pattern}': {reason}")]
	InvalidRegex { pattern: String, reason: String },

	#[display("Field '{field}' has type '{actual}', but '{expected}' was expected")]
	InvalidBinding {
		field: String,
		expected: String,
		actual: String,
	},

	#[display("Expected {expected}, found {found}")]
	ExpectedType { expected: String, found: String },

	#[display("Missing required field '{field}'")]
	MissingField { field: String },
	#[display("Cannot resolve action parameter: expected {expected}, got {actual}")]
	InvalidActionParamValue { expected: String, actual: String },
	#[from]
	#[display("Failed to parse the address: {_0}")]
	IpParse(AddrParseError),
	#[from]
	#[display("IO error: {_0}")]
	Io(std::io::Error),

	#[display("Poisoned lock")]
	LockPoison,
}

impl<T> From<std::sync::PoisonError<T>> for Error {
	fn from(_val: std::sync::PoisonError<T>) -> Self {
		Self::LockPoison
	}
}

// region:    --- Custom

// impl Error {
// 	pub fn custom_from_err(err: impl std::error::Error) -> Self {
// 		Self::Custom(err.to_string())
// 	}

// 	pub fn custom(val: impl Into<String>) -> Self {
// 		Self::Custom(val.into())
// 	}
// }

// endregion: --- Custom

// region:    --- Error Boilerplate

impl std::error::Error for Error {}

// endregion: --- Error Boilerplate
