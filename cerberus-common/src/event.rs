use zerocopy_derive::{FromBytes, Immutable, KnownLayout};

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, KnownLayout)]
pub struct EventHeader {
	pub event_type: u8, // 1 => kill, 2 => IO_URING, 3 => SOCKET_CONNECT, 4 => COMMIT_CREDS
	pub _padding: [u8; 3],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, KnownLayout)]
pub struct GenericEvent {
	pub header: EventHeader,
	pub pid: u32,
	pub uid: u32,
	pub tgid: u32,
	pub comm: [u8; 16],
	pub meta: u32, // Sometimes syscall num, exitcode, some permission flags..etc
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, KnownLayout)]
pub struct InetSockSetStateEvent {
	pub header: EventHeader,
	pub oldstate: i32,
	pub newstate: i32,
	pub sport: u16,
	pub dport: u16,
	pub protocol: u16,
	pub saddr: u32,
	pub daddr: u32,
}

#[derive(Clone, Copy, Debug)]
pub enum EbpfEvent {
	Generic(GenericEvent),
	InetSock(InetSockSetStateEvent),
}
