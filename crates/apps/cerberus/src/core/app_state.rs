use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use lib_rules::{CorrelationEvent, EvaluatedEvent, Severity};

use crate::event::LastAppEvent;
use crate::hook_registry::HookView;
use crate::Result;
use lib_common::event::CerberusEvent;

pub struct AppState {
	pub(in crate::core) loaded_hooks: Vec<HookView>,
	pub(in crate::core) hook_index: HashMap<Arc<str>, usize>,
	pub(in crate::core) loaded_rules: Arc<[String]>,
	pub(in crate::core) last_app_event: LastAppEvent,
	pub(in crate::core) cerberus_evts_general: VecDeque<CerberusEvent>,
	pub(in crate::core) cerberus_evts_correlated: VecDeque<CorrelationEvent>,
	pub(in crate::core) cerberus_evts_network: VecDeque<CerberusEvent>,
	pub(in crate::core) cerberus_evts_matched: HashMap<EvaluatedKey, EvaluatedEntry>,
	pub(in crate::core) rule_type_counts: HashMap<Arc<str>, u64>,
	pub(in crate::core) severity_counts: HashMap<Severity, u64>,
	pub(in crate::core) expanded_correlations: HashSet<(Arc<str>, Arc<str>)>,
	pub selected_hook: usize,
	pub current_view: View,
	pub tab: Tab,
	pub event_scroll: u16,
	pub popup_show: bool,
	pub selected_rule: usize,
}

impl AppState {
	pub fn new(loaded_rules: Arc<[String]>, loaded_hooks: Vec<HookView>, last_app_event: LastAppEvent) -> Result<Self> {
		let hook_index = loaded_hooks
			.iter()
			.enumerate()
			.map(|(idx, h)| (h.name.clone(), idx))
			.collect::<HashMap<_, _>>();

		Ok(Self {
			loaded_hooks,
			loaded_rules,
			hook_index,
			event_scroll: 0,
			last_app_event,
			cerberus_evts_correlated: VecDeque::with_capacity(250),
			cerberus_evts_general: VecDeque::with_capacity(250),
			cerberus_evts_network: VecDeque::with_capacity(250),
			cerberus_evts_matched: HashMap::new(),
			expanded_correlations: HashSet::new(),
			rule_type_counts: HashMap::new(),
			severity_counts: HashMap::new(),
			current_view: View::Main,
			tab: Tab::General,
			popup_show: false,
			selected_rule: 0,
			selected_hook: 0,
		})
	}
}

impl AppState {
	pub fn current_tab(&self) -> &Tab {
		&self.tab
	}

	pub fn clear_current_tab(&mut self) {
		match self.current_tab() {
			Tab::General => {
				self.cerberus_evts_general.clear();
			}
			Tab::Network => {
				self.cerberus_evts_network.clear();
			}
			Tab::MatchedRules => {
				self.cerberus_evts_matched.clear();
			}
			Tab::CorrelatedRules => {
				self.cerberus_evts_correlated.clear();
			}
		}
		self.event_scroll = 0;
	}

	pub fn active_event_rule_count(&self) -> usize {
		match self.tab {
			Tab::MatchedRules => self.cerberus_evts_matched.len(),
			Tab::CorrelatedRules => self.cerberus_evts_correlated.len(),
			_ => 0,
		}
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

	pub fn toggle_correlation_group(&mut self, root_rule_id: Arc<str>, seq_id: Arc<str>) {
		let key = (root_rule_id, seq_id);

		if !self.expanded_correlations.insert(key.clone()) {
			self.expanded_correlations.remove(&key);
		}
	}

	pub fn is_correlation_expanded(&self, root_rule_id: &Arc<str>, seq_id: &Arc<str>) -> bool {
		self.expanded_correlations.contains(&(root_rule_id.clone(), seq_id.clone()))
	}

	pub fn correlated_groups(&self) -> Vec<CorrelationGroup> {
		let mut map: HashMap<(Arc<str>, Arc<str>), Vec<CorrelationEvent>> = HashMap::new();

		for evt in self.cerberus_evts_correlated() {
			let key = event_key(evt);
			map.entry(key).or_default().push(evt.clone());
		}

		map.into_iter()
			.map(|((root_rule_id, seq_id), events)| CorrelationGroup {
				root_rule_id,
				seq_id,
				events,
			})
			.collect()
	}

	pub fn barchart_severity(&self) -> Vec<(&str, u64)> {
		self.severity_counts.iter().map(|(k, v)| (k.as_str(), *v)).collect()
	}

	pub fn cerberus_evts_correlated(&self) -> impl Iterator<Item = &CorrelationEvent> {
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
	pub fn loaded_hooks(&self) -> &[HookView] {
		&self.loaded_hooks
	}
	pub fn loaded_rules(&self) -> &[String] {
		&self.loaded_rules
	}

	pub fn last_app_event(&self) -> &LastAppEvent {
		&self.last_app_event
	}
}

impl AppState {
	pub fn selected_rule(&self) -> usize {
		self.selected_rule
	}

	pub fn next_rule(&mut self) {
		let max = self.active_event_rule_count();
		if max == 0 {
			return;
		}

		self.selected_rule = (self.selected_rule + 1) % max;
	}

	pub fn prev_rule(&mut self) {
		let max = self.active_event_rule_count();
		if max == 0 {
			return;
		}
		self.selected_rule = self.selected_rule.checked_sub(1).unwrap_or(max - 1);
	}

	pub fn toggle_rule_popup(&mut self) {
		self.popup_show = !self.popup_show;
	}
}

impl AppState {
	pub fn current_view(&self) -> &View {
		&self.current_view
	}

	pub fn toggle_view(&mut self) {
		self.current_view = match self.current_view {
			View::Main => View::Summary,
			View::Summary => View::Main,
		};
	}
}

#[derive(Clone, Debug)]
pub struct EvaluatedEntry {
	pub event: EvaluatedEvent,
	pub count: u64,
}

pub struct CorrelationGroup {
	pub root_rule_id: Arc<str>,
	pub seq_id: Arc<str>,
	pub events: Vec<CorrelationEvent>,
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

fn event_key(evt: &CorrelationEvent) -> (Arc<str>, Arc<str>) {
	match evt {
		CorrelationEvent::Step {
			root_rule_id, seq_id, ..
		} => (root_rule_id.clone(), seq_id.clone()),
		CorrelationEvent::Completed {
			root_rule_id, seq_id, ..
		} => (root_rule_id.clone(), seq_id.clone()),
	}
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
