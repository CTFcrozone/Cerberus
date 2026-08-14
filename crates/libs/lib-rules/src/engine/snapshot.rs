use crate::{engine::rule_index::RuleIndex, rule::compiled::ruleset::CompiledRuleSet};

pub struct RuleSnapshot {
	ruleset: CompiledRuleSet,
	index: RuleIndex,
}

impl RuleSnapshot {
	pub fn from_ruleset(ruleset: CompiledRuleSet) -> Self {
		let index = RuleIndex::build(&ruleset);
		Self { ruleset, index }
	}

	pub fn from_ruleset_and_index(ruleset: CompiledRuleSet, index: RuleIndex) -> Self {
		Self { ruleset, index }
	}
}

impl RuleSnapshot {
	pub fn ruleset(&self) -> &CompiledRuleSet {
		&self.ruleset
	}

	pub fn index(&self) -> &RuleIndex {
		&self.index
	}
}
