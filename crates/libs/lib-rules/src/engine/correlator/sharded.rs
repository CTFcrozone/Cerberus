use std::time::Instant;

use dashmap::DashMap;

use crate::{
	engine::correlator::{CorrelatedMatch, Correlator},
	rule::Sequence,
};

type ShardKey = u32; // pid

pub struct ShardedCorrelator {
	shards: DashMap<ShardKey, Correlator>,
}

impl ShardedCorrelator {
	pub fn new() -> Self {
		Self { shards: DashMap::new() }
	}

	fn get_correlator(&self, pid: u32) -> dashmap::mapref::entry::Entry<'_, ShardKey, Correlator> {
		self.shards.entry(pid)
	}

	pub fn on_root_match(&self, pid: u32, root_rule_id: &str, seq: &Sequence, now: Instant) {
		let mut correlator = self.get_correlator(pid).or_insert_with(Correlator::new);
		correlator.on_root_match(root_rule_id, seq, now);
	}

	pub fn on_rule_match(
		&self,
		pid: u32,
		matched_rule_id: &str,
		seq: &Sequence,
		root_rule_id: &str,
		now: Instant,
	) -> Option<CorrelatedMatch> {
		let mut correlator = self.shards.get_mut(&pid)?;
		correlator.on_rule_match(matched_rule_id, seq, root_rule_id, now)
	}
}
