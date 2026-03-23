use std::time::Instant;

use dashmap::DashMap;

use crate::{
	engine::correlator::{CorrelatedMatch, Correlator},
	rule::Sequence,
};

type ShardKey = u64; // ppid

pub struct ShardedCorrelator {
	shards: DashMap<ShardKey, Correlator>,
}

impl ShardedCorrelator {
	pub fn new() -> Self {
		Self { shards: DashMap::new() }
	}

	fn get_correlator(&self, ppid: u32, cgroup_id: u64) -> dashmap::mapref::entry::Entry<'_, ShardKey, Correlator> {
		let key = shard_key(ppid, cgroup_id);
		self.shards.entry(key)
	}

	pub fn on_root_match(&self, ppid: u32, cgroup_id: u64, root_rule_id: &str, seq: &Sequence, now: Instant) {
		let mut correlator = self.get_correlator(ppid, cgroup_id).or_insert_with(Correlator::new);
		correlator.on_root_match(root_rule_id, seq, now);
	}

	pub fn on_rule_match(
		&self,
		ppid: u32,
		cgroup_id: u64,
		matched_rule_id: &str,
		seq: &Sequence,
		root_rule_id: &str,
		now: Instant,
	) -> Option<CorrelatedMatch> {
		let key = shard_key(ppid, cgroup_id);
		let mut correlator = self.shards.get_mut(&key)?;
		correlator.on_rule_match(matched_rule_id, seq, root_rule_id, now)
	}
}

fn shard_key(ppid: u32, cgroup_id: u64) -> u64 {
	(ppid as u64) ^ cgroup_id
}
