use crate::error::Result;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct PackManifest {
	pub id: String,
	pub version: String,
	#[serde(default)]
	pub authors: Vec<String>,
	#[serde(default)]
	pub description: Option<String>,
	#[serde(default)]
	pub license: Option<String>,
	#[serde(default)]
	#[serde(rename = "cerberus-version")]
	pub cerberus_version: Option<String>,
}

impl PackManifest {
	pub fn from_str(s: &str) -> Result<Self> {
		let manifest = toml::from_str::<Self>(s)?;
		Ok(manifest)
	}
}

// region:    --- Tests

#[cfg(test)]
mod tests {
	type Result<T> = core::result::Result<T, Box<dyn std::error::Error>>; // For tests.

	use super::*;

	#[test]
	fn parse_manifest() -> Result<()> {
		// -- Setup & Fixtures
		let toml = r#"
id = "test-id"
version = "0.0.1"
authors = ["a@b.com"]
description = "..."
license = "MIT"
cerberus-version = "0.0.1"
"#;
		// -- Exec
		let manifest = PackManifest::from_str(toml)?;

		// -- Check
		assert_eq!(manifest.id, "test-id");
		assert_eq!(manifest.version, "0.0.1");
		assert_eq!(manifest.cerberus_version, Some("0.0.1".into()));

		Ok(())
	}
}

// endregion: --- Tests
