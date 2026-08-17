use lib_common::event::Event;
use lib_event_schema::{Field, FieldValue};
use strum::EnumCount;

#[derive(Debug)]
pub struct EvalCtx {
	fields: [Option<FieldValue>; Field::COUNT],
}

impl EvalCtx {
	pub fn new(fields: [Option<FieldValue>; Field::COUNT]) -> Self {
		Self { fields }
	}

	#[inline]
	pub fn get_field(&self, field: Field) -> Option<&FieldValue> {
		self.fields[field.index()].as_ref()
	}

	pub fn fields(&self) -> &[Option<FieldValue>; Field::COUNT] {
		&self.fields
	}

	#[inline]
	pub fn insert(&mut self, field: Field, value: FieldValue) {
		self.fields[field.index()] = Some(value);
	}
}

impl<T: Event> From<&T> for EvalCtx {
	fn from(event: &T) -> Self {
		Self::new(event.to_fields())
	}
}
