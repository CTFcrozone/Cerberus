use derive_more::{Display, From};

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Display, From)]
#[display("{self:?}")]
pub enum Error {
	#[from(String, &String, &str)]
	Custom(String),
	#[from]
	Glob(glob::GlobError),
	#[from]
	GlobPattern(glob::PatternError),
	#[from]
	TomlDe(toml::de::Error),
	#[display("No rule file found at '{_0}'")]
	RulePathNotFound(String),
	#[from]
	SimpleFs(simple_fs::Error),
	// -- Externals
	#[from]
	Io(std::io::Error), // as example
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
