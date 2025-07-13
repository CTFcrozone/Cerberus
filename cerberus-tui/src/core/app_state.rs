use aya::Ebpf;

use crate::core::sys_state::SysState;
use crate::event::{LastAppEvent, RingBufEvent};
use crate::Result;

use super::format_size_xfixed;

pub struct AppState {
	pub(in crate::core) ebpf: Ebpf,
	pub(in crate::core) sys_state: SysState,
	pub(in crate::core) memory: u64,
	pub(in crate::core) loaded_hooks: Vec<String>,
	pub(in crate::core) last_app_event: LastAppEvent,
	pub(in crate::core) cerberus_evts: Vec<RingBufEvent>,

	pub event_scroll: u16,
}

impl AppState {
	pub fn new(ebpf: Ebpf, last_app_event: LastAppEvent) -> Result<Self> {
		let sys_state = SysState::new()?;
		Ok(Self {
			ebpf,
			sys_state,
			memory: 0,
			loaded_hooks: Vec::new(),
			event_scroll: 0,
			last_app_event,
			cerberus_evts: Vec::new(),
		})
	}

	pub(in crate::core) fn refresh_sys_state(&mut self) {
		let mem = self.sys_state.memory();
		self.memory = mem;
	}

	pub fn memory(&self) -> u64 {
		self.memory
	}
}

impl AppState {
	pub fn loaded_hooks(&self) -> &[String] {
		&self.loaded_hooks
	}
	pub fn last_app_event(&self) -> &LastAppEvent {
		&self.last_app_event
	}
	pub fn cerberus_evts(&self) -> &[RingBufEvent] {
		&self.cerberus_evts
	}
}

impl AppState {
	pub fn memory_fmt(&self) -> String {
		let mem = self.memory();
		format_size_xfixed(mem)
	}
}
