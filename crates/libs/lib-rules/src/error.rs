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

	#[display("Encountered a sequence_finished trigger outside of a sequence")]
	SequenceFinishedTriggerWithoutSequence,

	#[display("Invalid value '{value}' for field '{field}'")]
	InvalidFieldValue { field: String, value: String },

	#[display("Invalid regex '{pattern}': {reason}")]
	InvalidRegex { pattern: String, reason: String },

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
