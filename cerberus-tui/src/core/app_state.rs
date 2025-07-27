use std::collections::VecDeque;

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

#[derive(Clone, Copy, Debug)]
pub enum Tab {
	Network,
	General,
}

impl Tab {
	pub fn next(self) -> Self {
		match self {
			Tab::General => Tab::Network,
			Tab::Network => Tab::General,
		}
	}

	pub fn as_index(self) -> i32 {
		match self {
			Tab::General => 0,
			Tab::Network => 1,
		}
	}
}

pub struct AppState {
	pub(in crate::core) ebpf: Ebpf,
	pub(in crate::core) sys_state: SysState,
	pub(in crate::core) memory: u64,
	pub(in crate::core) loaded_hooks: Vec<String>,
	pub(in crate::core) last_app_event: LastAppEvent,
	pub(in crate::core) cerberus_evts_general: VecDeque<CerberusEvent>,
	pub(in crate::core) cerberus_evts_network: VecDeque<CerberusEvent>,
	pub(in crate::core) hooks_loaded: bool,
	pub current_view: View,
	pub tab: Tab,
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
			cerberus_evts_general: VecDeque::with_capacity(250),
			cerberus_evts_network: VecDeque::with_capacity(250),
			hooks_loaded: false,
			current_view: View::Splash,
			tab: Tab::General,
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
	pub fn current_tab(&self) -> &Tab {
		&self.tab
	}

	pub fn set_tab(&mut self, tab: Tab) {
		self.tab = tab;
	}
}

impl AppState {
	pub fn event_scroll(&self) -> u16 {
		self.event_scroll
	}

	pub fn set_event_scroll(&mut self, scroll: u16) {
		self.event_scroll = scroll;
	}
}

impl AppState {
	// pub fn cerberus_evts_general(&self) -> &[CerberusEvent] {
	// 	&self.cerberus_evts_general
	// }

	pub fn cerberus_evts_general(&self) -> impl Iterator<Item = &CerberusEvent> {
		self.cerberus_evts_general.iter()
	}

	// Similarly for network events:
	pub fn cerberus_evts_network(&self) -> impl Iterator<Item = &CerberusEvent> {
		self.cerberus_evts_network.iter()
	}

	// pub fn cerberus_evts_network(&self) -> &[CerberusEvent] {
	// 	&self.cerberus_evts_network
	// }
}

impl AppState {
	pub fn loaded_hooks(&self) -> &[String] {
		&self.loaded_hooks
	}
	pub fn last_app_event(&self) -> &LastAppEvent {
		&self.last_app_event
	}

	pub fn worker_up(&self) -> bool {
		self.worker_up
	}

	pub fn ringbuf_fd(&mut self) -> Option<AsyncFd<RingBuf<MapData>>> {
		self.ringbuf_fd.take()
	}
}

impl AppState {
	pub fn current_view(&self) -> &View {
		&self.current_view
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
