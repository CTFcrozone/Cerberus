use crate::error::{Error, Result};
use std::{
	collections::{hash_map::Entry, HashMap},
	path::PathBuf,
	sync::Arc,
};

use crate::container::{ContainerInfo, ContainerRuntime};

pub struct ContainerManager {
	cache: HashMap<u64, ContainerInfo>,
	cgroup_root: PathBuf,
}

const CGROUP_DIR: &str = "/sys/fs/cgroup";
impl ContainerManager {
	pub fn new() -> Result<Self> {
		let cgroup_root = PathBuf::from(CGROUP_DIR);

		if !cgroup_root.exists() {
			return Err(Error::CgroupFsNotMounted);
		}

		Ok(Self {
			cache: HashMap::with_capacity(1024),
			cgroup_root,
		})
	}

	pub fn resolve(&mut self, cgroup_id: u64) -> Option<&ContainerInfo> {
		match self.cache.entry(cgroup_id) {
			Entry::Occupied(entry) => Some(entry.into_mut()),
			Entry::Vacant(entry) => {
				let info = Self::resolve_container(cgroup_id)?;
				Some(entry.insert(info))
			}
		}
	}

	pub fn cache_size(&self) -> usize {
		self.cache.len()
	}

	pub fn clear(&mut self) {
		self.cache.clear();
	}
}

// private fns
impl ContainerManager {
	fn extract_container_id(cgroup_path: &str) -> Option<String> {
		todo!();

		None
	}

	fn resolve_container(cgroup_id: u64) -> Option<ContainerInfo> {
		let cgroup_path = Self::read_cgroup_path(cgroup_id)?;
		let container_id = Self::extract_container_id(&cgroup_path)?;
		let runtime = Self::detect_runtime(&cgroup_path);

		Some(ContainerInfo {
			cgroup_id,
			container_id: Arc::from(container_id),
			image: Arc::from("<unknown>"),
			pod: None,
			namespace: None,
			runtime,
		})
	}

	fn read_cgroup_path(cgroup_id: u64) -> Option<String> {
		todo!();
		None
	}

	fn detect_runtime(cgroup_path: &str) -> ContainerRuntime {
		if cgroup_path.contains("/docker/") || cgroup_path.contains("docker-") {
			ContainerRuntime::Docker
		} else if cgroup_path.contains("/kubepods/") || cgroup_path.contains("k8s") {
			ContainerRuntime::Kubernetes
		} else if cgroup_path.contains("/containerd/") || cgroup_path.contains("containerd-") {
			ContainerRuntime::Containerd
		} else if cgroup_path.contains("/crio/") || cgroup_path.contains("crio-") {
			ContainerRuntime::Crio
		} else {
			ContainerRuntime::Unknown
		}
	}
}
