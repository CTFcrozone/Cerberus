use zerocopy_derive::{FromBytes, Immutable, KnownLayout};

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, KnownLayout)]
pub struct Event {
	pub pid: u32,       //  4
	pub uid: u32,       //  4
	pub tgid: u32,      //  4
	pub sig: u64,       //  8
	pub comm: [u8; 16], // 16
	pub event_type: u8, //  1
	pub syscall_nr: u8, //  1
}
