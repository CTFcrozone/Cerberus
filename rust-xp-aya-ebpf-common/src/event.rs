#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Event {
	pub pid: u32,          //  4
	pub uid: u32,          //  4 => 8
	pub sig: u64,          //  8 => 16 (use 0 if unused)
	pub comm: [u8; 16],    // 16 => 32
	pub event_type: u8,    //  1
	pub syscall_nr: u8,    //  1 => can record __syscall_nr (like 62 for kill)
	pub exit_code: u16,    //  2 => used for execve/openat exit codes
	pub timestamp_ns: u32, //  4 => e.g. bpf_ktime_get_ns() >> 32 for lossy short timestamp
}
