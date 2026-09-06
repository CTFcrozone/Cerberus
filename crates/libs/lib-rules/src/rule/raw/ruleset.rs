use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use crate::Error;
use crate::error::Result;
use crate::rule::raw::Rule;
use glob::glob;
use serde::Deserialize;
use tracing::warn;

#[cfg_attr(test, derive(PartialEq))]
#[derive(Debug, Deserialize, Clone)]
pub struct RuleSet {
	rules: Vec<Rule>,
	#[serde(skip)]
	by_id: HashMap<Arc<str>, usize>,
}

impl RuleSet {
	pub fn new(rules: Vec<Rule>) -> Result<RuleSet> {
		let mut by_id = HashMap::new();
		let mut seq_by_id = HashMap::new();
		for (idx, rule) in rules.iter().enumerate() {
			let rule_id: Arc<str> = rule.inner.id.as_str().into();

			if by_id.contains_key(&rule_id) {
				return Err(crate::Error::DuplicateRuleId {
					id: rule_id.to_string(),
				});
			}

			by_id.insert(rule_id.clone(), idx);

			if let Some(seq) = &rule.inner.sequence {
				let seq_id: Arc<str> = seq.id.as_str().into();

				if seq_by_id.insert(seq_id, idx).is_some() {
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
				let step_rule_id: Arc<str> = step.rule_id.as_str().into();

				if !by_id.contains_key(&step_rule_id) {
					return Err(Error::UnknownSequenceStepRule {
						rule_id: rule.inner.id.to_string(),
						sequence_id: seq.id.to_string(),
						step_idx,
						step_rule_id: step.rule_id.to_string(),
					});
				}
			}
		}
		Ok(RuleSet { rules, by_id })
	}

	pub fn load_from_dir(dir: impl AsRef<Path>) -> Result<RuleSet> {
		let pattern = dir.as_ref().join("**").join("*.toml");
		let pattern = pattern.to_string_lossy();

		let mut paths = Vec::new();
		for entry in glob(&pattern)? {
			match entry {
				Ok(path) => paths.push(path),
				Err(e) => warn!("Glob pattern error: {:?}", e),
			}
		}

		let mut rules = Vec::with_capacity(paths.len());
		for path in paths {
			let rule = Rule::from_file(&path).map_err(|e| Error::RuleLoadFailed {
				path: path.display().to_string(),
				source: e.to_string(),
			})?;
			rules.push(rule);
		}

		Self::new(rules)
	}

	pub fn find_rule_by_id(&self, rule_id: &str) -> Option<&Rule> {
		let idx = self.by_id.get(rule_id)?;
		self.rules.get(*idx)
	}

	pub fn rules(&self) -> &[Rule] {
		&self.rules
	}

	pub fn into_rules(self) -> Vec<Rule> {
		self.rules
	}

	pub fn rule_count(&self) -> usize {
		self.rules.len()
	}
}

// region:    --- Tests

#[cfg(test)]
mod tests {
	type Result<T> = core::result::Result<T, Box<dyn std::error::Error>>; // For tests.

	use super::*;

	#[test]
	fn load_ruleset_from_dir() -> Result<()> {
		// -- Setup & Fixtures
		let fx_rule_dir = "test-rules/";
		let fx_rule_count = 4;
		// -- Exec
		let ruleset = RuleSet::load_from_dir(fx_rule_dir)?;
		// -- Check
		assert_eq!(fx_rule_count, ruleset.rule_count());

		Ok(())
	}
}

// endregion: --- Tests
