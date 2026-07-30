use std::sync::Arc;

use regex::Regex;

use crate::FieldType;

pub type IpRepr = u32;

#[derive(Debug, Clone)]
pub enum FieldValue {
	Bool(bool),
	Int(i64),
	String(Arc<str>),
	Regex(Arc<Regex>),
	IntSet(Vec<i64>),
	StringSet(Vec<Arc<str>>),
	Ip(IpRepr),
	IpSet(Vec<IpRepr>),
}

impl FieldValue {
	pub fn ty(&self) -> FieldType {
		match self {
			Self::Bool(_) => FieldType::Bool,

			Self::Int(_) | Self::IntSet(_) => FieldType::Int,

			Self::String(_) | Self::StringSet(_) | Self::Regex(_) => FieldType::String,

			Self::Ip(_) | Self::IpSet(_) => FieldType::Ip,
		}
	}
}
