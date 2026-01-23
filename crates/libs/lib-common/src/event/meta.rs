use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct EventMeta {
	pub uid: u32,
	pub pid: u32,
	pub comm: Arc<str>,
}
