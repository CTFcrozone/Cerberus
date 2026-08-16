use std::{sync::Arc, time::Instant};

use dashmap::mapref::one::RefMut;
use lib_common::event::EventMeta;

use crate::{
	engine::{CorrelationEvent, correlator::Correlator, identity::ShardKey},
	hash_utils::{FastDashMap, new_fast_dashmap},
	rule::compiled::sequence::CompiledSequence,
};

pub struct ShardedCorrelator {
	shards: FastDashMap<ShardKey, Correlator>,
}

impl ShardedCorrelator {
	pub fn new() -> Self {
		Self {
			shards: new_fast_dashmap(),
		}
	}

	#[allow(unused)]
	pub fn shard_count(&self) -> usize {
		self.shards.len()
	}
	#[inline]
	fn get_or_create(&self, shard_key: &ShardKey) -> RefMut<'_, ShardKey, Correlator> {
		use dashmap::mapref::entry::Entry;
		match self.shards.entry(*shard_key) {
			Entry::Occupied(o) => o.into_ref(),
			Entry::Vacant(v) => v.insert(Correlator::new()),
		}
	}

	pub fn on_root_match(&self, shard_key: &ShardKey, root_rule_id: &Arc<str>, seq: &CompiledSequence, now: Instant) {
		if seq.steps.is_empty() {
			return;
		}
		self.get_or_create(shard_key).on_root_match(root_rule_id, seq, now);
	}

	pub fn on_rule_match(
		&self,
		shard_key: &ShardKey,
		matched_rule_id: &Arc<str>,
		seq: &CompiledSequence,
		root_rule_id: &Arc<str>,
		now: Instant,
		event_meta: &EventMeta,
	) -> Vec<CorrelationEvent> {
		let Some(mut correlator) = self.shards.get_mut(shard_key) else {
			return Vec::new();
		};
		let out = correlator.on_rule_match(matched_rule_id, seq, root_rule_id, now, event_meta);
		let drained = correlator.is_empty();
		drop(correlator);
		if drained {
			self.shards.remove_if(shard_key, |_, c| c.is_empty());
		}
		out
	}
}

// fn shard_key(ppid: u32, cgroup_id: u64) -> u64 {
// 	(cgroup_id << 32) | ppid as u64 // TODO: switch to key from identity.rs
// }
