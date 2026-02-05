use std::sync::Arc;

use derive_more::From;

#[derive(From, Clone, Debug)]
pub enum CerberusEvent {
	#[from]
	Generic(RingBufEvent),
	#[from]
	InetSock(InetSockEvent),
	#[from]
	SocketConnect(SocketConnectEvent),
	#[from]
	Module(ModuleEvent),
	#[from]
	Bprm(BprmSecurityEvent),
}

#[derive(Debug, Clone)]
pub struct InetSockEvent {
	pub old_state: Arc<str>,
	pub new_state: Arc<str>,
	pub protocol: Arc<str>,
	pub saddr: u32,
	pub daddr: u32,
	pub sport: u16,
	pub dport: u16,
}

#[derive(Debug, Clone)]
pub struct SocketConnectEvent {
	pub addr: u32,
	pub port: u16,
	pub family: u16,
}

#[derive(Debug, Clone)]
pub struct ModuleEvent {
	pub comm: Arc<str>,
	pub module_name: Arc<str>,
	pub pid: u32,
	pub uid: u32,
	pub tgid: u32,
}

#[derive(Debug, Clone)]
pub struct BprmSecurityEvent {
	pub comm: Arc<str>,
	pub filepath: Arc<str>,
	pub pid: u32,
	pub uid: u32,
	pub tgid: u32,
}

#[derive(Debug, Clone)]
pub struct RingBufEvent {
	pub name: &'static str,
	pub comm: Arc<str>,
	pub uid: u32,
	pub pid: u32,
	pub tgid: u32,
	pub meta: u32,
}
