use std::collections::HashMap;
use std::sync::Arc;

use crate::{
	RuleSet,
	error::{Error, Result},
	rule::compiled::rule::{CompiledRule, compile_rule},
};

pub struct CompiledRuleSet {
	rules: Vec<CompiledRule>,
	by_id: HashMap<Arc<str>, usize>,
}

impl CompiledRuleSet {
	pub fn new(rules: Vec<CompiledRule>) -> Result<Self> {
		let mut by_id = HashMap::new();
		let mut seq_by_id = HashMap::new();

		for (idx, rule) in rules.iter().enumerate() {
			let id = rule.inner.id.clone();

			if by_id.insert(id.clone(), idx).is_some() {
				return Err(Error::DuplicateRuleId { id: id.to_string() });
			}

			if let Some(seq) = &rule.inner.sequence {
				if seq_by_id.insert(seq.id.clone(), idx).is_some() {
					return Err(Error::DuplicateSequenceId { id: seq.id.to_string() });
				}
			}
		}

		Ok(Self { rules, by_id })
	}
	pub fn compile(raw: RuleSet) -> Result<Self> {
		let mut compiled = Vec::with_capacity(raw.rules().len());

		for rule in raw.into_rules() {
			let hash = rule.hash;
			let hash_hex = rule.hash_hex.clone();

			compiled.push(compile_rule(rule, hash, hash_hex)?);
		}

		Self::new(compiled)
	}

	pub fn find_rule_by_id(&self, id: &str) -> Option<&CompiledRule> {
		let idx = self.by_id.get(id)?;
		self.rules.get(*idx)
	}

	pub fn rules(&self) -> &[CompiledRule] {
		&self.rules
	}

	pub fn rule_count(&self) -> usize {
		self.rules.len()
	}
}
