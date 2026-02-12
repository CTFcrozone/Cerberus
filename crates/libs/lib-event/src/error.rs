use derive_more::{Display, From};
use flume::{RecvError, RecvTimeoutError, SendError};

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Display, From)]
#[display("{self:?}")]
pub enum Error {
	#[from(String, &String, &str)]
	Custom(String),
	EventSend(String),
	EventRecv(RecvError),
	EventRecvTimeout(RecvTimeoutError),
	EbpfProgNotFound,
	InvalidEventAlign,
	InvalidEventSize,
	UnknownEventType(u8),
	MutexPoison,

	#[from]
	Io(std::io::Error), // as example
}

impl<T> From<SendError<T>> for Error {
	fn from(value: SendError<T>) -> Self {
		Self::EventSend(value.to_string())
	}
}

impl From<RecvTimeoutError> for Error {
	fn from(err: RecvTimeoutError) -> Self {
		Self::EventRecvTimeout(err)
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
