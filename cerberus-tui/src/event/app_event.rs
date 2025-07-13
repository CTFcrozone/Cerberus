use derive_more::From;

#[derive(From, Debug)]
pub enum AppEvent {
	#[from]
	Term(crossterm::event::Event),

	#[from]
	Cerberus(RingBufEvent),

	#[from]
	Action(ActionEvent),
}

#[derive(Debug)]
pub enum ActionEvent {
	Quit,
}

#[derive(Debug, Clone)]
pub struct RingBufEvent {
	pub name: String,
	pub uid: u32,
	pub pid: u32,
	pub tgid: u32,
	pub comm: String,
	pub meta: u32,
}
