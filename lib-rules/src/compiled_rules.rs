use regex::Regex;

use crate::error::{Error, Result};
use std::sync::Arc;

#[derive(Clone, Copy)]
pub enum Op {
	Eq,
	StartsWith,
	BitAnd,
	Contains,
	In,
	NotIn,
	Regex,
	NotEq,
	Gt,
	Lt,
	Gte,
	Lte,
	Exists,
}

#[derive(Clone, Copy)]
pub enum Field {
	Pid,
	Uid,
	Tgid,
	Comm,
	Filepath,
	ModuleName,
	OldState,
	NewState,
	Protocol,
	Sport,
	Dport,
	Saddr,
	Daddr,
	Meta,
}

pub enum CompiledValue {
	Int(i64),
	Str(Arc<str>),
	Regex(regex::Regex),
	IntSet(Vec<i64>),
	StrSet(Vec<Arc<str>>),
}

pub enum ConditionValue {
	Plain(toml::Value),
	Regex(Regex),
}

fn compile_field(s: &str) -> Result<Field> {
	match s {
		"pid" => Ok(Field::Pid),
		"uid" => Ok(Field::Uid),
		"tgid" => Ok(Field::Tgid),
		"comm" => Ok(Field::Comm),
		"filepath" => Ok(Field::Filepath),
		"module_name" => Ok(Field::ModuleName),
		"old_state" => Ok(Field::OldState),
		"new_state" => Ok(Field::NewState),
		"sport" => Ok(Field::Sport),
		"dport" => Ok(Field::Dport),
		"saddr" => Ok(Field::Saddr),
		"daddr" => Ok(Field::Daddr),
		"meta" => Ok(Field::Meta),
		"protocol" => Ok(Field::Protocol),
		_ => Err(Error::UnknownField { field: s.to_string() }),
	}
}

fn compile_op(s: &str) -> Result<Op> {
	match s {
		"==" | "equals" => Ok(Op::Eq),
		"starts_with" => Ok(Op::StartsWith),
		"bit_and" => Ok(Op::BitAnd),
		"contains" => Ok(Op::Contains),
		"in" => Ok(Op::In),
		"not_in" => Ok(Op::NotIn),
		"regex" | "matches_regex" => Ok(Op::Regex),
		"!=" | "not_equals" => Ok(Op::NotEq),
		">" | "gt" => Ok(Op::Gt),
		"<" | "lt" => Ok(Op::Lt),
		">=" | "gte" => Ok(Op::Gte),
		"<=" | "lte" => Ok(Op::Lte),
		"exists" => Ok(Op::Exists),
		_ => Err(Error::UnknownOp { op: s.to_string() }),
	}
}
