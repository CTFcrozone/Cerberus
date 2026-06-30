use std::collections::HashMap;

use ratatui::layout::Rect;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum ScrollIden {
	LoadedHooksScroll,
	LoadedRulesScroll,
	EventsScroll,
}
#[derive(Default)]
pub struct ScrollZone {
	area: Option<Rect>,
	pos: Option<u16>,
	is_bottom: bool,
}

impl ScrollZone {
	pub fn area(&self) -> Option<Rect> {
		self.area
	}
	pub fn pos(&self) -> Option<u16> {
		self.pos
	}
	pub fn is_bottom(&self) -> bool {
		self.is_bottom
	}
}

impl ScrollZone {
	pub fn set_area(&mut self, area: Rect) {
		self.area = Some(area);
	}
	pub fn set_pos(&mut self, pos: u16) {
		self.pos = Some(pos);
	}
	pub fn set_is_bottom(&mut self, is_bottom: bool) {
		self.is_bottom = is_bottom;
	}

	pub fn clear_area(&mut self) {
		self.area = None;
	}
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
		zones.insert(ScrollIden::EventsScroll, ScrollZone::default());
		zones.insert(ScrollIden::LoadedRulesScroll, ScrollZone::default());
		zones.insert(ScrollIden::LoadedHooksScroll, ScrollZone::default());
		Self { zones }
	}
}
