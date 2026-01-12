use std::{collections::HashMap, fs, hash::Hash};

use crate::container::ContainerRuntime;

pub struct ContainerManager {
	cache: HashMap<u64, ContainerManager>,
}

impl ContainerManager {
	pub fn new() -> Self {
		Self {
			cache: HashMap::with_capacity(1024),
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
		for part in cgroup_path.split("/") {
			let id = part
				.trim_start_matches("docker-")
				.trim_start_matches("cri-containerd-")
				.trim_start_matches("crio-")
				.trim_end_matches(".scope");

			if id.len() >= 64 && id.chars().all(|c| c.is_ascii_hexdigit()) {
				return Some(id.to_string());
			}
		}
		None
	}

	fn detect_runtime(cgroup_path: &str) -> ContainerRuntime {
		if cgroup_path.contains("docker") {
			ContainerRuntime::Docker
		} else if cgroup_path.contains("containerd") {
			ContainerRuntime::Containerd
		} else if cgroup_path.contains("crio") {
			ContainerRuntime::Crio
		} else {
			ContainerRuntime::Unknown
		}
	}
}
