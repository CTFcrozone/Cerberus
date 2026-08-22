use crate::{Error, error::Result};

#[derive(Clone, Copy)]
pub enum Op {
	Eq,
	NotEq,
	Gt,
	Gte,
	Lt,
	Lte,
	In,
	NotIn,
	Contains,
	StartsWith,
	Regex,
	BitAnd,
	Exists,
}

pub fn compile_op(s: &str) -> Result<Op> {
	Ok(match s {
		"==" | "equals" | "eq" => Op::Eq,
		"!=" | "not_equals" | "not_eq" => Op::NotEq,
		">" | "gt" => Op::Gt,
		">=" | "gte" => Op::Gte,
		"<" | "lt" => Op::Lt,
		"<=" | "lte" => Op::Lte,
		"in" => Op::In,
		"not_in" => Op::NotIn,
		"contains" => Op::Contains,
		"starts_with" => Op::StartsWith,
		"regex" | "matches_regex" => Op::Regex,
		"bit_and" => Op::BitAnd,
		"exists" => Op::Exists,
		_ => return Err(Error::UnknownOp { op: s.into() }),
	})
}
