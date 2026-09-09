use std::{
	io::{BufWriter, Read, Write},
	path::Path,
};

use crate::{Error, error::Result};
use glob::glob;
use lib_rules::{Rule, RuleSet};
use serde::Deserialize;
use zip::{ZipArchive, ZipWriter, write::SimpleFileOptions};

#[derive(Deserialize)]
pub struct PackFile {
	pub pack: PackManifest,
}

pub struct Pack {
	pub manifest: PackManifest,
	pub ruleset: RuleSet,
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

impl Pack {
	pub fn pack(src_dir: &Path, out_path: &Path) -> Result<()> {
		let file = std::fs::File::create(out_path)?;
		let mut writer = ZipWriter::new(BufWriter::new(file));
		let options = SimpleFileOptions::default();
		let manifest_path = src_dir.join("conf.toml");
		let manifest_str = std::fs::read_to_string(manifest_path)?;
		// validate
		let _ = PackManifest::from_str(&manifest_str)?;
		writer.start_file("conf.toml", options)?;
		writer.write_all(manifest_str.as_bytes())?;

		let pattern = src_dir.join("rules").join("**").join("*.toml");
		let pattern = pattern.to_string_lossy();

		let mut parsed_rules = Vec::new();

		for entry in glob(&pattern)? {
			let path = entry?;
			let content = std::fs::read_to_string(&path)?;
			parsed_rules.push(Rule::from_str(&content)?);
			let rel = path
				.strip_prefix(src_dir)
				.map_err(|_| Error::Custom("rule path outside src_dir".into()))?;

			let entry_name = rel.to_string_lossy().replace('\\', "/");

			writer.start_file(&entry_name, options)?;
			writer.write_all(content.as_bytes())?;
		}

		if parsed_rules.is_empty() {
			return Err(Error::EmptyPack {
				pack: src_dir.display().to_string(),
			});
		}
		// validate
		let _ = RuleSet::new(parsed_rules)?;

		writer.finish()?;
		Ok(())
	}
	pub fn load(path: &Path) -> Result<Self> {
		let file = std::fs::File::open(path)?;
		let mut archive = ZipArchive::new(std::io::BufReader::new(file))?;
		let manifest = {
			let mut entry = archive.by_name("conf.toml").map_err(|_| Error::MissingManifest {
				pack: path.display().to_string(),
			})?;
			let mut buf = String::new();
			entry.read_to_string(&mut buf)?;
			PackManifest::from_str(&buf)?
		};
		let rule_names: Vec<_> = archive
			.file_names()
			.filter(|n| n.starts_with("rules/") && n.ends_with(".toml"))
			.map(|n| n.to_owned())
			.collect();
		let mut rules = Vec::with_capacity(rule_names.len());
		for name in rule_names {
			let mut rule_entry = archive.by_name(&name)?;
			let mut buf = String::new();
			rule_entry.read_to_string(&mut buf)?;
			rules.push(Rule::from_str(&buf)?)
		}
		if rules.is_empty() {
			return Err(Error::EmptyPack {
				pack: path.display().to_string(),
			});
		}
		let ruleset = RuleSet::new(rules)?;
		Ok(Self { manifest, ruleset })
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
	fn pack_then_load_roundtrips() -> Result<()> {
		let out = Path::new("test-fixtures/roundtrip.cerby");
		Pack::pack(Path::new("test-fixtures/testpack"), out)?;

		let loaded = Pack::load(out)?;
		assert_eq!(loaded.manifest.id, "test-id");
		assert_eq!(loaded.ruleset.rule_count(), 7);

		let _ = std::fs::remove_file(out);
		Ok(())
	}

	#[test]
	fn load_pack_with_rules() -> Result<()> {
		let pack = Pack::load(Path::new("test-fixtures/test.cerby"))?;
		assert_eq!(pack.manifest.id, "test-id");
		assert_eq!(pack.ruleset.rule_count(), 7);
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
