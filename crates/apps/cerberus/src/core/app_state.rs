use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::SystemTime;

use indexmap::IndexMap;
use lib_rules::{CorrelationEvent, EvaluatedEvent, ResolvedAction, Severity};
use ratatui::layout::Rect;
use time::OffsetDateTime;

use crate::Result;
use crate::core::scroll::{ScrollIden, ScrollZone, ScrollZones};
use crate::event::LastAppEvent;
use crate::hook_registry::HookView;
use lib_common::event::CerberusEvent;

const MAX_CORRELATIONS: usize = 250;

pub struct AppState {
	pub(in crate::core) loaded_hooks: Vec<HookView>,
	pub(in crate::core) hook_index: HashMap<Arc<str>, u32>,
	pub(in crate::core) loaded_rules: Arc<[Arc<str>]>,
	pub(in crate::core) last_app_event: LastAppEvent,
	pub(in crate::core) cerberus_evts_general: VecDeque<CerberusEvent>,
	// pub(in crate::core) cerberus_evts_correlated: VecDeque<CorrelationEvent>,
	pub(in crate::core) cerberus_evts_network: VecDeque<CerberusEvent>,
	pub(in crate::core) cerberus_evts_matched: HashMap<Arc<str>, EvaluatedEntry>,
	pub(in crate::core) response_evts: VecDeque<ResponseItem>,
	pub(in crate::core) severity_counts: [u64; Severity::COUNT],
	pub correlated_groups: HashMap<(Arc<str>, Arc<str>), CorrelationGroup>,
	scroll_zones: ScrollZones,
	pub selected_matched_rule: usize,
	pub selected_correlation_group: usize,
	pub selected_correlation_event: usize,
	pub selected_hook: usize,
	pub current_view: View,
	pub tab: Tab,
	pub popup_show: bool,
}

impl AppState {
	pub fn new(
		loaded_rules: Arc<[Arc<str>]>,
		loaded_hooks: Vec<HookView>,
		last_app_event: LastAppEvent,
	) -> Result<Self> {
		let hook_index = loaded_hooks
			.iter()
			.enumerate()
			.map(|(idx, h)| (h.name.clone(), idx as u32))
			.collect::<HashMap<_, _>>();

		Ok(Self {
			loaded_hooks,
			loaded_rules,
			hook_index,
			correlated_groups: HashMap::new(),
			last_app_event,
			scroll_zones: ScrollZones::default(),
			// cerberus_evts_correlated: VecDeque::with_capacity(250),
			cerberus_evts_general: VecDeque::with_capacity(250),
			cerberus_evts_network: VecDeque::with_capacity(250),
			response_evts: VecDeque::with_capacity(250),

			cerberus_evts_matched: HashMap::new(),
			severity_counts: [0; Severity::COUNT],
			current_view: View::Main,
			tab: Tab::General,
			selected_correlation_event: 0,
			selected_correlation_group: 0,
			selected_matched_rule: 0,
			selected_hook: 0,
			popup_show: false,
		})
	}
}

impl AppState {
	pub fn current_tab(&self) -> &Tab {
		&self.tab
	}

	pub fn clear_current_tab(&mut self) {
		match self.current_tab() {
			Tab::General => self.cerberus_evts_general.clear(),
			Tab::Network => self.cerberus_evts_network.clear(),
			Tab::MatchedRules => {
				self.cerberus_evts_matched.clear();
				self.selected_matched_rule = 0;
			}

			Tab::CorrelatedRules => {
				self.correlated_groups.clear();
				self.selected_correlation_group = 0;
				self.selected_correlation_event = 0;
			}
		}
	}

	pub fn active_event_rule_count(&self) -> usize {
		match self.tab {
			Tab::MatchedRules => self.cerberus_evts_matched.len(),
			Tab::CorrelatedRules => self.correlated_groups.len(),
			_ => 0,
		}
	}

	pub fn set_tab(&mut self, tab: Tab) -> bool {
		if self.tab == tab {
			return false;
		}

		self.tab = tab;
		true
	}
}

impl AppState {
	pub fn set_scroll_area(&mut self, iden: ScrollIden, area: Rect) {
		if let Some(zone) = self.get_zone_mut(&iden) {
			zone.set_area(area);
		}
	}

	pub fn get_zone_mut(&mut self, iden: &ScrollIden) -> Option<&mut ScrollZone> {
		self.scroll_zones.zones.get_mut(iden)
	}
	pub fn get_scroll(&self, iden: ScrollIden) -> u16 {
		self.scroll_zones.zones.get(&iden).and_then(|z| z.pos()).unwrap_or_default()
	}

	#[allow(unused)]
	pub fn set_scroll(&mut self, iden: ScrollIden, scroll: u16) {
		if let Some(zone) = self.get_zone_mut(&iden) {
			zone.set_pos(scroll);
		}
	}

	pub fn inc_scroll(&mut self, iden: ScrollIden, scroll: u16) -> u16 {
		let val = self.get_scroll(iden);
		let val = val.saturating_add(scroll);
		if let Some(z) = self.get_zone_mut(&iden) {
			z.set_pos(val);
		}
		val
	}

	pub fn clamp_scroll(&mut self, iden: ScrollIden, line_count: usize) -> u16 {
		let Some(scroll_zone) = self.get_zone_mut(&iden) else {
			return 0;
		};
		let area_height = scroll_zone.area().map(|a| a.height).unwrap_or_default();
		let max_scroll = line_count.saturating_sub(area_height as usize) as u16;
		let scroll = scroll_zone.pos().unwrap_or_default();
		if scroll > max_scroll {
			scroll_zone.set_pos(max_scroll);
			max_scroll
		} else {
			scroll
		}
	}
	#[allow(unused)]
	pub fn clear_scroll_zone_area(&mut self, iden: &ScrollIden) {
		if let Some(zone) = self.get_zone_mut(iden) {
			zone.clear_area();
		}
	}
	#[allow(unused)]
	pub fn clear_scroll_zone_areas(&mut self, idens: &[&ScrollIden]) {
		for iden in idens {
			self.clear_scroll_zone_area(iden);
		}
	}

	pub fn dec_scroll(&mut self, iden: ScrollIden, scroll: u16) -> u16 {
		let val = self.get_scroll(iden);
		let val = val.saturating_sub(scroll);
		if let Some(z) = self.get_zone_mut(&iden) {
			z.set_pos(val);
		}
		val
	}
}

impl AppState {
	pub fn toggle_correlation_group(&mut self, root_rule_id: Arc<str>, seq_id: Arc<str>) {
		if let Some(group) = self.correlated_groups.get_mut(&(root_rule_id, seq_id)) {
			group.expanded = !group.expanded;
		}
	}

	pub fn push_correlation_event(&mut self, evt: CorrelationEvent) {
		let (r, s) = event_key(&evt);
		let key = (Arc::clone(r), Arc::clone(s));

		let group = self.correlated_groups.entry(key).or_insert_with(|| CorrelationGroup {
			expanded: false,
			events: VecDeque::new(),
		});

		if group.events.len() >= MAX_CORRELATIONS {
			group.events.pop_front();
		}

		group.events.push_back(evt);
	}
	pub fn correlated_groups(&self) -> &HashMap<(Arc<str>, Arc<str>), CorrelationGroup> {
		&self.correlated_groups
	}
	pub fn barchart_severity(&self) -> [(&str, u64); Severity::COUNT] {
		let mut out = [("", 0u64); Severity::COUNT];
		for (i, s) in Severity::ALL.iter().enumerate() {
			out[i] = (s.as_str(), self.severity_counts[s.index()]);
		}
		out
	}

	pub fn cerberus_evts_general(&self) -> impl Iterator<Item = &CerberusEvent> {
		self.cerberus_evts_general.iter()
	}

	pub fn cerberus_evts_network(&self) -> impl Iterator<Item = &CerberusEvent> {
		self.cerberus_evts_network.iter()
	}
	pub fn response_evts(&self) -> impl Iterator<Item = &ResponseItem> {
		self.response_evts.iter().rev()
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
	pub fn loaded_rules(&self) -> &[Arc<str>] {
		&self.loaded_rules
	}

	pub fn last_app_event(&self) -> &LastAppEvent {
		&self.last_app_event
	}
}

impl AppState {
	pub fn selected_matched_rule(&self) -> usize {
		self.selected_matched_rule
	}

	pub fn selected_correlation_group(&self) -> usize {
		self.selected_correlation_group
	}

	// pub fn selected_correlation_event(&self) -> usize {
	// 	self.selected_correlation_event
	// }

	pub fn selected_event(&self) -> Option<&CorrelationEvent> {
		let group = self.correlated_groups.values().nth(self.selected_correlation_group)?;

		group.events.get(self.selected_correlation_event)
	}

	pub fn next_selected(&mut self) {
		match self.tab {
			Tab::MatchedRules => {
				let max = self.cerberus_evts_matched.len();

				if max > 0 {
					self.selected_matched_rule = (self.selected_matched_rule + 1) % max;
				}
			}

			Tab::CorrelatedRules => {
				let max = self.correlated_groups.len();

				if max > 0 {
					self.selected_correlation_group = (self.selected_correlation_group + 1) % max;

					self.selected_correlation_event = 0;
				}
			}

			_ => {}
		}
	}

	pub fn prev_selected(&mut self) {
		match self.tab {
			Tab::MatchedRules => {
				let max = self.cerberus_evts_matched.len();

				if max > 0 {
					self.selected_matched_rule = self.selected_matched_rule.checked_sub(1).unwrap_or(max - 1);
				}
			}

			Tab::CorrelatedRules => {
				let max = self.correlated_groups.len();

				if max > 0 {
					self.selected_correlation_group = self.selected_correlation_group.checked_sub(1).unwrap_or(max - 1);

					self.selected_correlation_event = 0;
				}
			}

			_ => {}
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
	pub expanded: bool,
	pub events: VecDeque<CorrelationEvent>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum View {
	Main,
	Summary,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tab {
	Network,
	General,
	MatchedRules,
	CorrelatedRules,
}

fn event_key(evt: &CorrelationEvent) -> (&Arc<str>, &Arc<str>) {
	match evt {
		CorrelationEvent::Step {
			root_rule_id, seq_id, ..
		} => (root_rule_id, seq_id),
		CorrelationEvent::Completed {
			root_rule_id, seq_id, ..
		} => (root_rule_id, seq_id),
	}
}

impl Tab {
	pub const fn next(self) -> Self {
		match self {
			Tab::General => Tab::Network,
			Tab::Network => Tab::MatchedRules,
			Tab::MatchedRules => Tab::CorrelatedRules,
			Tab::CorrelatedRules => Tab::General,
		}
	}

	pub const fn as_index(self) -> usize {
		match self {
			Tab::General => 0,
			Tab::Network => 1,
			Tab::MatchedRules => 2,
			Tab::CorrelatedRules => 3,
		}
	}
}

#[derive(Debug, Clone)]
pub struct ResponseItem {
	pub rule_id: Arc<str>,
	pub status: ResponseStatus,
	pub actions: Arc<[ResolvedAction]>,
	pub completed: OffsetDateTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseStatus {
	Done,
	Failed,
}
