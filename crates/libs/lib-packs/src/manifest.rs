use std::{io::Read, path::Path};

use crate::{Error, error::Result};
use serde::Deserialize;
use zip::ZipArchive;

#[derive(Deserialize)]
pub struct PackFile {
	pub pack: PackManifest,
}

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
		let file = toml::from_str::<PackFile>(s)?;
		Ok(file.pack)
	}

	fn read_from_zip(path: &Path) -> Result<Self> {
		let file = std::fs::File::open(path)?;
		let mut archive = ZipArchive::new(std::io::BufReader::new(file))?;
		let mut entry = archive.by_name("conf.toml").map_err(|_| Error::MissingManifest {
			pack: path.display().to_string(),
		})?;
		let mut buf = String::new();
		entry.read_to_string(&mut buf)?;
		Self::from_str(&buf)
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
		[pack]
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

	#[test]
	fn missing_manifest_errors() -> Result<()> {
		// a .cerby with NO conf.toml
		let result = PackManifest::read_from_zip(Path::new("test-fixtures/no-manifest.cerby"));
		assert!(matches!(result, Err(Error::MissingManifest { .. })));
		Ok(())
	}

	#[test]
	fn parse_manifest_from_cerby() -> Result<()> {
		let manifest = PackManifest::read_from_zip(Path::new("test-fixtures/test.cerby"))?;

		assert_eq!(manifest.id, "test-id");
		assert_eq!(manifest.version, "0.0.1");
		assert_eq!(manifest.cerberus_version, Some("0.0.1".into()));

		Ok(())
	}
}

// endregion: --- Tests
