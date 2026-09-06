use derive_more::{Display, From};

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Display, From)]
#[display("{self:?}")]
pub enum Error {
	#[from(String, &String, &str)]
	Custom(String),

	#[from]
	#[display("Failed to parse TOML: {_0}")]
	TomlDe(toml::de::Error),

	#[from]
	#[display("Zip archive error: {_0}")]
	Zip(zip::result::ZipError),

	#[display("pack '{pack}' has no conf.toml manifest")]
	MissingManifest { pack: String },

	// #[display("failed to open pack '{path}': {source}")]
	// PackOpenFailed { path: String, source: std::io::Error },

	// #[display("pack '{path}' is not a valid archive: {source}")]
	// InvalidPackArchive { path: String, source: String },

	// -- Externals
	#[from]
	Io(std::io::Error), // as example
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
