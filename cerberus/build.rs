use aya_build::cargo_metadata;
use derive_more::{Display, From};

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Display, From)]
#[display("{self:?}")]
pub enum Error {
	#[from(String, &String, &str)]
	Custom(String),
	ExecFail,
	BuildFail,
}

fn main() -> Result<()> {
	let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
		.no_deps()
		.exec()
		.map_err(|_| Error::ExecFail)?;
	let ebpf_package = packages
		.into_iter()
		.find(|cargo_metadata::Package { name, .. }| name == "lib-ebpf")
		.ok_or_else(|| Error::Custom("cerberus-ebpf package not found".to_string()))?;
	aya_build::build_ebpf([ebpf_package]).map_err(|_| Error::BuildFail)?;
	Ok(())
}
