use std::str::Utf8Error;

use derive_more::{Display, From};
use flume::{RecvError, SendError};
use tokio::task::JoinError;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Display, From)]
#[display("{self:?}")]
pub enum Error {
	#[from(String, &String, &str)]
	Custom(String),
	EventSend(String),
	EventRecv(RecvError),
	EbpfProgNotFound,
	InvalidEventAlign,
	InvalidEventSize,
	#[display("Timed run is only possible in 'agent' mode")]
	InvalidTimeMode,
	#[display("No time specified for 'agent' mode")]
	NoTimeSpecified,
	InvalidRate,

	UnknownEventType(u8),
	MutexPoison,
	// -- Externals
	//
	#[from]
	Var(std::env::VarError),
	#[from]
	Oneshot(tokio::sync::oneshot::error::RecvError),
	#[from]
	JoinError(JoinError),
	#[from]
	Utf8(Utf8Error),
	#[from]
	AyaEbpf(aya::EbpfError),
	#[from]
	AyaBtf(aya::BtfError),
	#[from]
	AyaMaps(aya::maps::MapError),
	#[from]
	LibContainer(lib_container::Error),
	#[from]
	AyaProgram(aya::programs::ProgramError),
	#[from]
	Event(lib_event::Error),
	#[display("Rule engine error: {_0}")]
	#[from]
	RuleEngine(lib_rules::Error),
	#[from]
	Io(std::io::Error), // as example
	#[from]
	Notify(notify::Error),
	LockPoison,
}

impl<T> From<std::sync::PoisonError<T>> for Error {
	fn from(_val: std::sync::PoisonError<T>) -> Self {
		Self::LockPoison
	}
}

impl<T> From<SendError<T>> for Error {
	fn from(value: SendError<T>) -> Self {
		Self::EventSend(value.to_string())
	}
}

impl From<RecvError> for Error {
	fn from(err: RecvError) -> Self {
		Self::EventRecv(err)
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
