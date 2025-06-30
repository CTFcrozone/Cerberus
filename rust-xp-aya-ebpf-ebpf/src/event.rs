#[repr(C)]
pub struct Event {
	pub pid: u32,
	pub uid: u32,
	pub sig: u64,
	pub comm: [u8; 16],
	pub event_type: u8, // 1 = kill, 2 = exec, 3 = openat
}
