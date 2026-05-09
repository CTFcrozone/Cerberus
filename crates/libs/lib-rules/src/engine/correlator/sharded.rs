use std::time::Instant;

use dashmap::DashMap;
use lib_common::event::EventHeader;

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

	pub fn shard_count(&self) -> usize {
		self.shards.len()
	}

	fn get_correlator(&self, header: &EventHeader) -> dashmap::mapref::entry::Entry<'_, ShardKey, Correlator> {
		let key = ShardKey::from(header);
		self.shards.entry(key)
	}

	pub fn on_root_match(&self, header: &EventHeader, root_rule_id: &str, seq: &Sequence, now: Instant) {
		let mut correlator = self.get_correlator(header).or_insert_with(Correlator::new);
		correlator.on_root_match(root_rule_id, seq, now);
	}

	pub fn on_rule_match(
		&self,
		header: &EventHeader,
		matched_rule_id: &str,
		seq: &Sequence,
		root_rule_id: &str,
		now: Instant,
	) -> Vec<CorrelatedMatch> {
		let key = ShardKey::from(header);
		let Some(mut correlator) = self.shards.get_mut(&key) else {
			return Vec::new();
		};
		correlator.on_rule_match(matched_rule_id, seq, root_rule_id, now)
	}
}

// fn shard_key(ppid: u32, cgroup_id: u64) -> u64 {
// 	(cgroup_id << 32) | ppid as u64 // TODO: switch to key from identity.rs
// }
