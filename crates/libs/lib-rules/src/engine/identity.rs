use lib_common::event::EventHeader;

#[derive(Debug, Clone, PartialEq, Copy, Hash, Eq)]
pub struct ShardKey {
	pub mnt_ns: u32,
	pub cgroup_id: u64,
}

impl From<EventHeader> for ShardKey {
	fn from(value: EventHeader) -> Self {
		ShardKey {
			mnt_ns: value.mnt_ns,
			cgroup_id: value.cgroup_id,
		}
	}
}

impl From<&EventHeader> for ShardKey {
	fn from(value: &EventHeader) -> Self {
		ShardKey {
			mnt_ns: value.mnt_ns,
			cgroup_id: value.cgroup_id,
		}
	}
}
