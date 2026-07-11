use std::collections::HashMap;

use ratatui::layout::Rect;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum ScrollIden {
	LoadedHookScroll,
	LoadedRuleScroll,
	GenericEventScroll,
	NetworkEventScroll,
	EvaluatedEventScroll,
	CorrelatedEventScroll,
}
#[derive(Default)]
pub struct ScrollZone {
	area: Option<Rect>,
	pos: Option<u16>,
}

impl ScrollZone {
	pub fn area(&self) -> Option<Rect> {
		self.area
	}
	pub fn pos(&self) -> Option<u16> {
		self.pos
	}
}

impl ScrollZone {
	pub fn set_area(&mut self, area: Rect) {
		self.area = Some(area);
	}
	pub fn set_pos(&mut self, pos: u16) {
		self.pos = Some(pos);
	}

	pub fn clear_area(&mut self) {
		self.area = None;
	}
	#[allow(unused)]
	pub fn clear_pos(&mut self) {
		self.pos = None;
	}
}

pub(in crate::core) struct ScrollZones {
	pub zones: HashMap<ScrollIden, ScrollZone>,
}

impl Default for ScrollZones {
	fn default() -> Self {
		let mut zones = HashMap::new();
		zones.insert(ScrollIden::GenericEventScroll, ScrollZone::default());
		zones.insert(ScrollIden::EvaluatedEventScroll, ScrollZone::default());
		zones.insert(ScrollIden::CorrelatedEventScroll, ScrollZone::default());
		zones.insert(ScrollIden::NetworkEventScroll, ScrollZone::default());
		zones.insert(ScrollIden::LoadedRuleScroll, ScrollZone::default());
		zones.insert(ScrollIden::LoadedHookScroll, ScrollZone::default());
		Self { zones }
	}
}
