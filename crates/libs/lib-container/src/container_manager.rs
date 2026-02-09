use crate::{
	error::{Error, Result},
	runtime::{
		k8s_connect, Container, ContainerFilter, K8sRtServiceClient, ListContainersRequest, ListPodSandboxRequest,
		PodSandbox, PodSandboxFilter,
	},
};
use std::{
	collections::{hash_map::Entry, HashMap},
	os::unix::fs::MetadataExt,
	path::{Path, PathBuf},
	sync::Arc,
};

use crate::container::{ContainerInfo, ContainerRuntime};

pub struct ContainerManager {
	client: K8sRtServiceClient,
	// inode -> container
	cache: HashMap<u64, ContainerInfo>,

	// container_id -> k8s metadata
	k8s_cache: HashMap<String, K8sMetadata>,
	_cgroup_root: PathBuf,
}

const CGROUP_DIR: &str = "/sys/fs/cgroup";

#[derive(Clone)]
pub struct K8sMetadata {
	pub pod_name: String,
	pub namespace: String,
	pub image: String,
}

impl ContainerManager {
	pub fn new(client: K8sRtServiceClient) -> Result<Self> {
		let cgroup_root = PathBuf::from(CGROUP_DIR);

		if !cgroup_root.exists() {
			return Err(Error::CgroupFsNotMounted);
		}

		Ok(Self {
			client,
			cache: HashMap::with_capacity(1024),
			k8s_cache: HashMap::with_capacity(1024),
			_cgroup_root: cgroup_root,
		})
	}

	pub async fn resolve(&mut self, cgroup_id: u64) -> Option<&ContainerInfo> {
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
		self.k8s_cache.clear();
	}
}

// private fns
impl ContainerManager {
	fn extract_container_id(cgroup_path: &str) -> Option<String> {
		for part in cgroup_path.split('/') {
			if let Some(id) = part.strip_prefix("docker-") {
				return Some(id.trim_end_matches(".scope").to_string());
			}

			if part.len() >= 32 && part.chars().all(|c| c.is_ascii_hexdigit()) {
				return Some(part.to_string());
			}
		}

		None
	}

	async fn resolve_k8s(&mut self, container_id: &str) -> Result<Option<K8sMetadata>> {
		if let Some(meta) = self.k8s_cache.get(container_id) {
			return Ok(Some(meta.clone()));
		}

		let container = match self.get_container_by_id(container_id).await? {
			Some(container) => container,
			None => return Ok(None),
		};

		let image = container.image.map(|img| img.image).unwrap_or_default();

		let sandbox = match self.get_sandbox_by_id(container.pod_sandbox_id).await? {
			Some(sandbox) => sandbox,
			None => return Ok(None),
		};

		let (namespace, pod_name) = sandbox.metadata.map(|m| (m.namespace, m.name)).unwrap_or_default();

		let meta = K8sMetadata {
			pod_name,
			namespace,
			image,
		};

		self.k8s_cache.insert(container_id.to_string(), meta.clone());

		Ok(Some(meta))
	}

	async fn get_container_by_id(&mut self, container_id: &str) -> Result<Option<Container>> {
		let resp = self
			.client
			.list_containers(ListContainersRequest {
				filter: Some(ContainerFilter {
					id: container_id.to_string(),
					..Default::default()
				}),
			})
			.await
			.map_err(|status| Error::TonicW {
				status: status.to_string(),
			})?
			.into_inner();

		Ok(resp.containers.into_iter().next())
	}

	async fn get_sandbox_by_id(&mut self, pod_sandbox_id: String) -> Result<Option<PodSandbox>> {
		let sandbox_resp = self
			.client
			.list_pod_sandbox(ListPodSandboxRequest {
				filter: Some(PodSandboxFilter {
					id: pod_sandbox_id,
					..Default::default()
				}),
			})
			.await
			.map_err(|status| Error::TonicW {
				status: status.to_string(),
			})?;

		Ok(sandbox_resp.into_inner().items.into_iter().next())
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

	fn walk(dir: &Path, target: u64) -> Option<String> {
		for entry in std::fs::read_dir(dir).ok()? {
			let entry = entry.ok()?;
			let path = entry.path();
			let meta = entry.metadata().ok()?;

			if meta.ino() == target {
				return Some(path.to_string_lossy().to_string());
			}

			if meta.is_dir() {
				if let Some(found) = Self::walk(&path, target) {
					return Some(found);
				}
			}
		}

		None
	}

	fn read_cgroup_path(cgroup_id: u64) -> Option<String> {
		Self::walk(Path::new(CGROUP_DIR), cgroup_id)
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
