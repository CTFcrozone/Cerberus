use lib_common::event::Event;
use std::{collections::HashMap, net::IpAddr};
use toml::Value as TomlValue;

use crate::rule::compiled::field::Field;

#[derive(Debug)]
pub struct EvalCtx {
	fields: HashMap<String, TomlValue>,
}
#[allow(unused)]
pub enum FieldValue<'a> {
	Bool(bool),
	Int(i64),
	Str(&'a str),
	Ip(IpAddr),
}

impl EvalCtx {
	pub fn new(fields: HashMap<String, TomlValue>) -> Self {
		Self { fields }
	}
	#[allow(unused)]
	pub fn get(&self, key: &str) -> Option<&TomlValue> {
		self.fields.get(key)
	}
	pub fn get_field(&self, field: &Field) -> Option<&TomlValue> {
		self.fields.get(field.as_str())
	}

	#[allow(dead_code)]
	pub fn fields(&self) -> &HashMap<String, TomlValue> {
		&self.fields
	}

	#[allow(dead_code)]
	pub fn insert(&mut self, key: String, value: TomlValue) -> Option<TomlValue> {
		self.fields.insert(key, value)
	}
}

impl<T: Event> From<&T> for EvalCtx {
	fn from(event: &T) -> Self {
		let fields: HashMap<String, TomlValue> = event.to_fields();
		EvalCtx::new(fields)
	}
}
