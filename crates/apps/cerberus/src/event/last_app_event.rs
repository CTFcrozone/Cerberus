use super::AppEvent;
use derive_more::From;
use std::sync::Arc;

#[derive(Clone, Default, From)]
pub struct LastAppEvent {
	last_event: Option<Arc<AppEvent>>,
}

impl LastAppEvent {
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

// region:    --- Froms

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

// endregion: --- Froms
