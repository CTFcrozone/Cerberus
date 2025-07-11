use zerocopy_derive::{FromBytes, Immutable, KnownLayout};

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, KnownLayout)]
pub struct Event {
	pub pid: u32,
	pub uid: u32,
	pub tgid: u32,
	pub comm: [u8; 16],
	pub event_type: u8, // 1 => kill, 2 => IO_URING, 3 => SOCKET_CONNECT, 4 => COMMIT_CREDS
	pub meta: u32,      // Sometimes syscall num, exitcode, some permission flags..etc
}
