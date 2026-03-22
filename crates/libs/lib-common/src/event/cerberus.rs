use lib_container::container::ContainerInfo;
use std::{collections::HashMap, sync::Arc};

use derive_more::From;

#[derive(From, Clone, Debug)]
pub enum CerberusEvent {
	#[from]
	Generic(RingBufEvent),
	#[from]
	InetSock(InetSockEvent),
	#[from]
	InodeUnlink(InodeUnlinkEvent),
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

pub trait Event {
	fn header(&self) -> &EventHeader;
	fn header_mut(&mut self) -> &mut EventHeader;
	fn to_fields(&self) -> HashMap<String, toml::Value>;
}

#[derive(Debug, Clone)]
pub struct EventHeader {
	pub container: Option<ContainerInfo>,
	pub comm: Arc<str>,
	pub ts: u64,
	pub cgroup_id: u64,
	pub mnt_ns: u32,
	pub pid: u32,
	pub ppid: u32,
	pub uid: u32,
	pub tgid: u32,
}

#[derive(Debug, Clone)]
pub struct InetSockEvent {
	pub header: EventHeader,
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
	pub header: EventHeader,
	pub addr: u32,
	pub port: u16,
	pub family: u16,
	pub op: u8,
}

#[derive(Debug, Clone)]
pub struct BpfProgLoadEvent {
	pub header: EventHeader,
	pub tag: Arc<str>,
	pub prog_type: u32,
	pub attach_type: u32,
	pub flags: u32,
}

#[derive(Debug, Clone)]
pub struct ModuleEvent {
	pub header: EventHeader,
	pub module_name: Arc<str>,
}

#[derive(Debug, Clone)]
pub struct BprmSecurityEvent {
	pub header: EventHeader,
	pub filepath: Arc<str>,
	pub path_len: u32,
}

#[derive(Debug, Clone)]
pub struct InodeUnlinkEvent {
	pub header: EventHeader,
	pub filename: Arc<str>,
	pub filename_len: u32,
}

#[derive(Debug, Clone)]
pub struct RingBufEvent {
	pub header: EventHeader,
	pub name: &'static str,
	pub meta: u32,
}
