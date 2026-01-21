use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use aya::Ebpf;
use lib_rules::RuleEngine;

use crate::event::LastAppEvent;
use crate::Result;
use lib_event::app_evt_types::{CerberusEvent, CorrelatedEvent, EvaluatedEvent};

#[derive(Clone, Debug)]
pub struct EvaluatedEntry {
	pub event: EvaluatedEvent,
	pub count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EvaluatedKey {
	pub rule_id: Arc<str>,
	pub rule_type: Arc<str>,
}

pub enum View {
	Main,
	Summary,
}

#[derive(Clone, Copy, Debug)]
pub enum Tab {
	Network,
	General,
	MatchedRules,
	CorrelatedRules,
}

impl Tab {
	pub fn next(self) -> Self {
		match self {
			Tab::General => Tab::Network,
			Tab::Network => Tab::MatchedRules,
			Tab::MatchedRules => Tab::CorrelatedRules,
			Tab::CorrelatedRules => Tab::General,
		}
	}

	pub fn as_index(self) -> i32 {
		match self {
			Tab::General => 0,
			Tab::Network => 1,
			Tab::MatchedRules => 2,
			Tab::CorrelatedRules => 3,
		}
	}
}

pub struct AppState {
	pub(in crate::core) ebpf: Ebpf,
	pub(in crate::core) loaded_hooks: Vec<String>,
	pub(in crate::core) last_app_event: LastAppEvent,
	pub(in crate::core) cerberus_evts_general: VecDeque<CerberusEvent>,
	pub(in crate::core) cerberus_evts_correlated: VecDeque<CorrelatedEvent>,
	pub(in crate::core) cerberus_evts_network: VecDeque<CerberusEvent>,
	pub(in crate::core) cerberus_evts_matched: HashMap<EvaluatedKey, EvaluatedEntry>,
	pub(in crate::core) rule_type_counts: HashMap<Arc<str>, u64>,
	pub(in crate::core) severity_counts: HashMap<Arc<str>, u64>,

	pub current_view: View,
	pub tab: Tab,
	pub event_scroll: u16,
	pub rule_engine: Option<Arc<RuleEngine>>,
	pub popup_show: bool,
	pub selected_rule: usize,
}

impl AppState {
	pub fn new(ebpf: Ebpf, last_app_event: LastAppEvent) -> Result<Self> {
		Ok(Self {
			ebpf,
			loaded_hooks: Vec::new(),
			event_scroll: 0,
			last_app_event,
			cerberus_evts_correlated: VecDeque::with_capacity(250),
			cerberus_evts_general: VecDeque::with_capacity(250),
			cerberus_evts_network: VecDeque::with_capacity(250),
			cerberus_evts_matched: HashMap::new(),
			rule_type_counts: HashMap::new(),
			severity_counts: HashMap::new(),
			current_view: View::Main,
			rule_engine: None,
			tab: Tab::General,
			popup_show: false,
			selected_rule: 0,
		})
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
	//
	pub fn barchart_rule_type(&self) -> Vec<(&str, u64)> {
		self.rule_type_counts.iter().map(|(k, v)| (k.as_ref(), *v)).collect()
	}

	pub fn barchart_severity(&self) -> Vec<(&str, u64)> {
		self.severity_counts.iter().map(|(k, v)| (k.as_ref(), *v)).collect()
	}

	pub fn cerberus_evts_correlated(&self) -> impl Iterator<Item = &CorrelatedEvent> {
		self.cerberus_evts_correlated.iter()
	}

	pub fn cerberus_evts_general(&self) -> impl Iterator<Item = &CerberusEvent> {
		self.cerberus_evts_general.iter()
	}

	pub fn cerberus_evts_network(&self) -> impl Iterator<Item = &CerberusEvent> {
		self.cerberus_evts_network.iter()
	}

	pub fn cerberus_evts_matched(&self) -> impl Iterator<Item = &EvaluatedEntry> {
		self.cerberus_evts_matched.values()
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
}

impl AppState {
	pub fn selected_rule(&self) -> usize {
		self.selected_rule
	}

	pub fn next_rule(&mut self, max: usize) {
		if max == 0 {
			return;
		}
		self.selected_rule = (self.selected_rule + 1) % max;
	}

	pub fn prev_rule(&mut self, max: usize) {
		if max == 0 {
			return;
		}
		if self.selected_rule == 0 {
			self.selected_rule = max - 1;
		} else {
			self.selected_rule -= 1;
		}
	}

	pub fn toggle_rule_popup(&mut self) {
		self.popup_show = !self.popup_show;
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
