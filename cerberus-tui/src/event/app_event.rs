use std::sync::Arc;

use derive_more::From;

#[derive(From)]
pub enum AppEvent {
	#[from]
	Term(crossterm::event::Event),

	#[from]
	Cerberus(CerberusEvent),

	#[from]
	LoadedHooks,

	#[from]
	Action(ActionEvent),
}

#[derive(Debug)]
pub enum ActionEvent {
	Quit,
}

#[derive(From, Clone, Debug)]
pub enum CerberusEvent {
	#[from]
	Generic(RingBufEvent),
	#[from]
	InetSock(InetSockEvent),
}

#[derive(Debug, Clone)]
pub struct InetSockEvent {
	pub old_state: Arc<str>,
	pub new_state: Arc<str>,
	pub sport: u16,
	pub dport: u16,
	pub protocol: Arc<str>,
	pub saddr: u32,
	pub daddr: u32,
}

#[derive(Debug, Clone)]
pub struct RingBufEvent {
	pub name: &'static str,
	pub uid: u32,
	pub pid: u32,
	pub tgid: u32,
	pub comm: Arc<str>,
	pub meta: u32,
}
