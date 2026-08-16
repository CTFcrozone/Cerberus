use std::sync::Arc;

use crate::{
	RuleSet,
	error::{Error, Result},
	hash_utils::{FastMap, new_fast_map},
	rule::compiled::rule::{CompiledRule, compile_rule},
};

pub struct CompiledRuleSet {
	rules: Vec<CompiledRule>,
	by_id: FastMap<Arc<str>, usize>,
}

impl CompiledRuleSet {
	pub fn new(rules: Vec<CompiledRule>) -> Result<Self> {
		let mut by_id: FastMap<Arc<str>, usize> = new_fast_map();
		let mut seq_by_id: FastMap<Arc<str>, usize> = new_fast_map();

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

		for rule in rules.iter() {
			let Some(seq) = &rule.inner.sequence else { continue };

			if seq.steps.is_empty() {
				return Err(Error::SequenceWithoutSteps {
					rule_id: rule.inner.id.to_string(),
					sequence_id: seq.id.to_string(),
				});
			}

			for (step_idx, step) in seq.steps.iter().enumerate() {
				if !by_id.contains_key(step.rule_id.as_ref()) {
					return Err(Error::UnknownSequenceStepRule {
						rule_id: rule.inner.id.to_string(),
						sequence_id: seq.id.to_string(),
						step_idx,
						step_rule_id: step.rule_id.to_string(),
					});
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

	#[inline]
	pub fn index_of(&self, id: &str) -> Option<usize> {
		self.by_id.get(id).copied()
	}

	pub fn rules(&self) -> &[CompiledRule] {
		&self.rules
	}

	pub fn rule_count(&self) -> usize {
		self.rules.len()
	}
}
