use super::AppEvent;
use derive_more::From;
use std::sync::Arc;

#[derive(Clone, Debug, Default, From)]
pub struct LastAppEvent {
	last_event: Option<Arc<AppEvent>>,
}

#[allow(unused)]
impl LastAppEvent {
	pub fn get(&self) -> Option<Arc<AppEvent>> {
		self.last_event.clone()
	}

	pub fn take(&mut self) -> LastAppEvent {
		match self.last_event.take() {
			Some(e) => LastAppEvent { last_event: Some(e) },
			None => LastAppEvent::default(),
		}
	}

	pub fn as_term_event(&self) -> Option<&crossterm::event::Event> {
		self.last_event.as_ref().and_then(|e| match e.as_ref() {
			AppEvent::Term(event) => Some(event),
			_ => None,
		})
	}

	pub fn as_key_event(&self) -> Option<&crossterm::event::KeyEvent> {
		self.last_event.as_ref().and_then(|e| match e.as_ref() {
			AppEvent::Term(crossterm::event::Event::Key(event)) => Some(event),
			_ => None,
		})
	}

	pub fn as_key_code(&self) -> Option<&crossterm::event::KeyCode> {
		self.last_event.as_ref().and_then(|e| match e.as_ref() {
			AppEvent::Term(crossterm::event::Event::Key(event)) => Some(&event.code),
			_ => None,
		})
	}

	pub fn as_mouse_event(&self) -> Option<&crossterm::event::MouseEvent> {
		self.last_event.as_ref().and_then(|e| match e.as_ref() {
			AppEvent::Term(crossterm::event::Event::Mouse(event)) => Some(event),
			_ => None,
		})
	}
}

impl From<AppEvent> for LastAppEvent {
	fn from(event: AppEvent) -> Self {
		Self {
			last_event: Some(Arc::new(event)),
		}
	}
}

impl From<Option<AppEvent>> for LastAppEvent {
	fn from(event: Option<AppEvent>) -> Self {
		Self {
			last_event: event.map(Arc::new),
		}
	}
}
