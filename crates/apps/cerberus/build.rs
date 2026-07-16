use aya_build::Toolchain;
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
		.find(|cargo_metadata::Package { name, .. }| name.as_str() == "lib-ebpf")
		.ok_or_else(|| Error::Custom("cerberus-ebpf package not found".into()))?;
	let cargo_metadata::Package {
		name, manifest_path, ..
	} = ebpf_package;

	let ebpf_package = aya_build::Package {
		name: name.as_str(),
		root_dir: manifest_path
			.parent()
			.ok_or_else(|| Error::Custom("no parent for {manifest_path}".into()))?
			.as_str(),
		..Default::default()
	};
	aya_build::build_ebpf([ebpf_package], Toolchain::default()).map_err(|_| Error::BuildFail)?;
	Ok(())
}
