use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct ContainerInfo {
	pub cgroup_id: u64,
	pub container_id: Arc<str>,
	pub image: Arc<str>,
	pub pod: Option<Arc<str>>,
	pub namespace: Option<Arc<str>>,
	pub runtime: ContainerRuntime,
}

#[derive(Debug, Clone, Copy)]
pub enum ContainerRuntime {
	Docker,
	Containerd,
	Crio,
	Kubernetes,
	Unknown,
}
