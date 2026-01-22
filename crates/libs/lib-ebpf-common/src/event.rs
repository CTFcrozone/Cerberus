use zerocopy_derive::{FromBytes, Immutable, KnownLayout};

// 1 => "KILL",
// 2 => "IO_URING",
// 3 => "SOCKET_CONNECT",
// 4 => "COMMIT_CREDS",
// 5 => "MODULE_INIT",
// 6 => "INET_SOCK_SET_STATE",
// 7 => "ENTER_PTRACE"
// 8  => EXEC (bprm_check_security)

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, KnownLayout)]
pub struct EventHeader {
	pub cgroup_id: u64, // 0..8
	pub mnt_ns: u32,    // 8..12
	pub event_type: u8, // 12..13
	pub _pad0: [u8; 3], // 13..16
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, KnownLayout)]
pub struct GenericEvent {
	pub header: EventHeader, // 0..16
	pub pid: u32,            // 16..20
	pub uid: u32,            // 20..24
	pub tgid: u32,           // 24..28
	pub comm: [u8; 16],      // 28..44
	pub meta: u32,           // 44..48 | Meta - Sometimes syscall num, exitcode, some permission flags..etc
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, KnownLayout)]
pub struct ModuleInitEvent {
	pub header: EventHeader,   // 0..16
	pub pid: u32,              // 16..20
	pub uid: u32,              // 20..24
	pub tgid: u32,             // 24..28
	pub comm: [u8; 16],        // 28..44
	pub module_name: [u8; 56], // 44..100
	pub _pad0: [u8; 4],        // 100..104
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, KnownLayout)]
pub struct BprmSecurityCheckEvent {
	pub header: EventHeader, // 0..16
	pub pid: u32,            // 16..20
	pub uid: u32,            // 20..24
	pub tgid: u32,           // 24..28
	pub comm: [u8; 16],      // 28..44
	pub filepath: [u8; 132], // 44..176
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, KnownLayout)]
pub struct InetSockSetStateEvent {
	pub header: EventHeader, // 0..16
	pub oldstate: i32,       // 16..20
	pub newstate: i32,       // 20..24
	pub saddr: u32,          // 24..28
	pub daddr: u32,          // 28..32
	pub sport: u16,          // 32..34
	pub dport: u16,          // 34..36
	pub protocol: u16,       // 36..38
	pub _pad0: [u8; 2],      // 38..40
}

#[derive(Clone, Copy, Debug)]
pub enum NetworkEbpfEvent {
	InetSock(InetSockSetStateEvent),
	SocketConnect(),
}

#[derive(Clone, Copy, Debug)]
pub enum EbpfEvent {
	Generic(GenericEvent),
	InetSock(InetSockSetStateEvent),
	ModuleInit(ModuleInitEvent),
	BprmSecurityCheck(BprmSecurityCheckEvent),
}
