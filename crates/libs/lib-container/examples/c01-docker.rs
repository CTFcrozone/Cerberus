use std::os::unix::fs::MetadataExt;

use lib_container::container_manager::ContainerManager;

pub type Result<T> = core::result::Result<T, Error>;
pub type Error = Box<dyn std::error::Error>; // For early dev.

fn main() -> Result<()> {
	// let mut mgr = ContainerManager::new().unwrap();

	// // grab your own cgroup id
	// let meta = std::fs::metadata("/sys/fs/cgroup").unwrap();
	// let id = meta.ino();

	// println!("testing cgroup id: {}", id);

	// let res = mgr.resolve(id);

	// println!("{:?}", res);
	Ok(())
}
