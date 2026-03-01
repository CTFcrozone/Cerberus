use lib_container::container::ContainerInfo;
use std::sync::Arc;

use derive_more::From;

#[derive(From, Clone, Debug)]
pub enum CerberusEvent {
	#[from]
	Generic(RingBufEvent),
	#[from]
	InetSock(InetSockEvent),
	#[from]
	Socket(SocketEvent),
	#[from]
	Module(ModuleEvent),
	#[from]
	Bprm(BprmSecurityEvent),
	#[from]
	BpfProgLoad(BpfProgLoadEvent),
}

// TODO: add unified EventHeader struct

impl CerberusEvent {
	pub fn meta_mut(&mut self) -> &mut ContainerMeta {
		match self {
			CerberusEvent::Generic(e) => &mut e.container_meta,
			CerberusEvent::Module(e) => &mut e.container_meta,
			CerberusEvent::Bprm(e) => &mut e.container_meta,
			CerberusEvent::InetSock(e) => &mut e.container_meta,
			CerberusEvent::Socket(e) => &mut e.container_meta,
			CerberusEvent::BpfProgLoad(e) => &mut e.container_meta,
		}
	}
}

#[derive(Debug, Clone)]
pub struct ContainerMeta {
	pub container: Option<ContainerInfo>,
	pub cgroup_id: u64,
}

#[derive(Debug, Clone)]
pub struct InetSockEvent {
	pub container_meta: ContainerMeta,
	pub old_state: Arc<str>,
	pub new_state: Arc<str>,
	pub protocol: Arc<str>,
	pub saddr: u32,
	pub daddr: u32,
	pub sport: u16,
	pub dport: u16,
}

#[derive(Debug, Clone)]
pub struct SocketEvent {
	pub container_meta: ContainerMeta,
	pub addr: u32,
	pub port: u16,
	pub family: u16,
	pub op: u8,
}

#[derive(Debug, Clone)]
pub struct BpfProgLoadEvent {
	pub container_meta: ContainerMeta,
	pub comm: Arc<str>,
	pub tag: Arc<str>,
	pub pid: u32,
	pub uid: u32,
	pub tgid: u32,
	pub prog_type: u32,
	pub attach_type: u32,
	pub flags: u32,
}

#[derive(Debug, Clone)]
pub struct ModuleEvent {
	pub container_meta: ContainerMeta,
	pub comm: Arc<str>,
	pub module_name: Arc<str>,
	pub pid: u32,
	pub uid: u32,
	pub tgid: u32,
}

#[derive(Debug, Clone)]
pub struct BprmSecurityEvent {
	pub container_meta: ContainerMeta,
	pub comm: Arc<str>,
	pub filepath: Arc<str>,
	pub pid: u32,
	pub uid: u32,
	pub tgid: u32,
	pub path_len: u32,
}

#[derive(Debug, Clone)]
pub struct RingBufEvent {
	pub container_meta: ContainerMeta,
	pub name: &'static str,
	pub comm: Arc<str>,
	pub uid: u32,
	pub pid: u32,
	pub tgid: u32,
	pub meta: u32,
}
