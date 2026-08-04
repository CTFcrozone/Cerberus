use std::sync::Arc;

use derive_more::{Display, From};

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Display, From)]
#[display("{self:?}")]
pub enum Error {
	#[from(String, &String, &str)]
	#[display("{_0}")]
	Custom(String),
	#[display("eBPF program '{program}' was not found")]
	EbpfProgNotFound { program: Arc<str> },
	#[display("eBPF map '{map}' was not found")]
	EbpfMapNotFound { map: String },
	#[display("Hook for program '{program}' is already disabled")]
	HookAlreadyDisabled { program: String },
	#[display("Hook '{hook}' was not found")]
	HookNotFound { hook: Arc<str> },
	#[display("Hook '{hook}' already exists")]
	HookAlreadyExists { hook: Arc<str> },
	#[display("Invalid event size")]
	InvalidEventSize,
	#[display("Timed run is only possible in 'agent' mode")]
	InvalidTimeMode,
	#[display("No time specified for 'agent' mode")]
	NoTimeSpecified,
	#[display("Invalid event rate")]
	InvalidRate,
	#[display("No rules found in '{_0}'")]
	NoRulesInDir(String),
	#[display("Unknown event type '{_0}'")]
	UnknownEventType(u8),
	#[from]
	#[display("System time error: {_0}")]
	SystemTime(std::time::SystemTimeError),
	#[from]
	#[display("eBPF error: {_0}")]
	AyaEbpf(aya::EbpfError),
	#[from]
	#[display("BTF error: {_0}")]
	AyaBtf(aya::BtfError),
	#[from]
	#[display("eBPF map error: {_0}")]
	AyaMaps(aya::maps::MapError),
	#[from]
	#[display("Container resolver error: {_0}")]
	LibContainer(lib_container::Error),
	#[from]
	#[display("eBPF program error: {_0}")]
	AyaProgram(aya::programs::ProgramError),
	#[from]
	#[display("Event TRX error: {_0}")]
	EventTrx(lib_event::Error),
	#[from]
	#[display("Rule engine error: {_0}")]
	RuleEngine(lib_rules::Error),
	#[from]
	#[display("IO error: {_0}")]
	Io(std::io::Error),
	#[from]
	#[display("Notify error: {_0}")]
	Notify(notify::Error),
	#[display("Lock poisoned")]
	LockPoison,
}

impl<T> From<std::sync::PoisonError<T>> for Error {
	fn from(_val: std::sync::PoisonError<T>) -> Self {
		Self::LockPoison
	}
}

// region:    --- Custom

impl Error {
	pub fn custom_from_err(err: impl std::error::Error) -> Self {
		Self::Custom(err.to_string())
	}

	pub fn custom(val: impl Into<String>) -> Self {
		Self::Custom(val.into())
	}
}

// endregion: --- Custom

// region:    --- Error Boilerplate

impl std::error::Error for Error {}

// endregion: --- Error Boilerplate
