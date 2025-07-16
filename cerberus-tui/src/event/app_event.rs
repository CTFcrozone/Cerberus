use std::sync::Arc;

use derive_more::From;

#[derive(From)]
pub enum AppEvent {
	#[from]
	Term(crossterm::event::Event),

	#[from]
	Cerberus(RingBufEvent),

	#[from]
	LoadedHooks,

	#[from]
	Action(ActionEvent),
}

#[derive(Debug)]
pub enum ActionEvent {
	Quit,
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
