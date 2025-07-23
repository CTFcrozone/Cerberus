use aya::maps::{MapData, RingBuf};
use aya::Ebpf;
use tokio::io::unix::AsyncFd;

use crate::core::sys_state::SysState;
use crate::event::{CerberusEvent, LastAppEvent};
use crate::Result;

use super::format_size_xfixed;

pub enum View {
	Splash,
	Main,
}

pub struct AppState {
	pub(in crate::core) ebpf: Ebpf,
	pub(in crate::core) sys_state: SysState,
	pub(in crate::core) memory: u64,
	pub(in crate::core) loaded_hooks: Vec<String>,
	pub(in crate::core) last_app_event: LastAppEvent,
	pub(in crate::core) cerberus_evts: Vec<CerberusEvent>,
	pub(in crate::core) hooks_loaded: bool,
	pub current_view: View,
	pub event_scroll: u16,
	pub ringbuf_fd: Option<AsyncFd<RingBuf<MapData>>>,
	pub worker_up: bool,
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
			cerberus_evts: Vec::with_capacity(500),
			hooks_loaded: false,
			current_view: View::Splash,
			ringbuf_fd: None,
			worker_up: false,
		})
	}

	pub(in crate::core) fn refresh_sys_state(&mut self) {
		if self.memory != self.sys_state.memory() {
			self.memory = self.sys_state.memory();
		}
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
	pub fn cerberus_evts(&self) -> &[CerberusEvent] {
		&self.cerberus_evts
	}
	pub fn event_scroll(&self) -> u16 {
		self.event_scroll
	}

	pub fn set_event_scroll(&mut self, scroll: u16) {
		self.event_scroll = scroll;
	}

	pub fn worker_up(&self) -> bool {
		self.worker_up
	}

	pub fn current_view(&self) -> &View {
		&self.current_view
	}

	pub fn ringbuf_fd(&mut self) -> Option<AsyncFd<RingBuf<MapData>>> {
		self.ringbuf_fd.take()
	}

	pub fn set_view(&mut self, view: View) {
		self.current_view = view;
	}
}

impl AppState {
	pub fn memory_fmt(&self) -> String {
		let mem = self.memory();
		format_size_xfixed(mem)
	}
}
