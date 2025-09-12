use std::collections::HashMap;
use toml::Value as TomlValue;

#[derive(Debug)]
pub struct EvalCtx {
	fields: HashMap<String, TomlValue>,
}

impl EvalCtx {
	pub fn new(fields: HashMap<String, TomlValue>) -> Self {
		Self { fields }
	}
	pub fn get(&self, key: &str) -> Option<&TomlValue> {
		self.fields.get(key)
	}
}
