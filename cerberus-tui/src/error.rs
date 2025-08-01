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
	UnknownEventType(u8),
	MutexPoison,
	#[from]
	Rusqlite(rusqlite::Error),
	// -- Externals
	//
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
	AyaProgram(aya::programs::ProgramError),
	#[from]
	Io(std::io::Error), // as example
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
