use std::time::Instant;

use dashmap::{mapref::one::RefMut, DashMap};

use crate::{
	engine::{
		correlator::{CorrelatedMatch, Correlator},
		identity::ShardKey,
	},
	rule::Sequence,
};

pub struct ShardedCorrelator {
	shards: DashMap<ShardKey, Correlator>,
}

impl ShardedCorrelator {
	pub fn new() -> Self {
		Self { shards: DashMap::new() }
	}

	#[allow(unused)]
	pub fn shard_count(&self) -> usize {
		self.shards.len()
	}

	fn get_or_create(&self, shard_key: &ShardKey) -> RefMut<'_, ShardKey, Correlator> {
		use dashmap::mapref::entry::Entry;
		match self.shards.entry(shard_key.clone()) {
			Entry::Occupied(o) => o.into_ref(),
			Entry::Vacant(v) => v.insert(Correlator::new()),
		}
	}

	pub fn on_root_match(&self, shard_key: &ShardKey, root_rule_id: &str, seq: &Sequence, now: Instant) {
		let mut correlator = self.get_or_create(shard_key);
		correlator.on_root_match(root_rule_id, seq, now);
	}

	pub fn on_rule_match(
		&self,
		shard_key: &ShardKey,
		matched_rule_id: &str,
		seq: &Sequence,
		root_rule_id: &str,
		now: Instant,
	) -> Vec<CorrelatedMatch> {
		let mut correlator = self.get_or_create(shard_key);
		correlator.on_rule_match(matched_rule_id, seq, root_rule_id, now)
	}
}

// fn shard_key(ppid: u32, cgroup_id: u64) -> u64 {
// 	(cgroup_id << 32) | ppid as u64 // TODO: switch to key from identity.rs
// }
