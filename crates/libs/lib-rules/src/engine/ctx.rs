use lib_common::event::Event;
use lib_event_schema::{Field, FieldValue};
use std::collections::HashMap;

#[derive(Debug)]
pub struct EvalCtx {
	fields: HashMap<Field, FieldValue>,
}

impl EvalCtx {
	pub fn new(fields: HashMap<Field, FieldValue>) -> Self {
		Self { fields }
	}
	#[allow(unused)]
	pub fn get(&self, key: &Field) -> Option<&FieldValue> {
		self.fields.get(key)
	}
	pub fn get_field(&self, field: &Field) -> Option<&FieldValue> {
		self.fields.get(field)
	}

	#[allow(dead_code)]
	pub fn fields(&self) -> &HashMap<Field, FieldValue> {
		&self.fields
	}

	#[allow(dead_code)]
	pub fn insert(&mut self, key: Field, value: FieldValue) -> Option<FieldValue> {
		self.fields.insert(key, value)
	}
}

impl<T: Event> From<&T> for EvalCtx {
	fn from(event: &T) -> Self {
		let fields: HashMap<Field, FieldValue> = event.to_fields();
		EvalCtx::new(fields)
	}
}
