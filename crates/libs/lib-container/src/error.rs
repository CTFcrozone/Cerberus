use derive_more::{Display, From};

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Display, From)]
#[display("{self:?}")]
pub enum Error {
	#[from(String, &String, &str)]
	#[display("{_0}")]
	Custom(String),

	#[from]
	#[display("Failed to connect using tonic transport: {_0}")]
	TonicTrx(tonic::transport::Error),

	#[display("Cgroup filesystem is not mounted")]
	CgroupFsNotMounted,

	#[display("Tonic error: {status}")]
	TonicW { status: String },
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
