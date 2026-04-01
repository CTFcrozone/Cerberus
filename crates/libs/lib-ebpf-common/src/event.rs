use zerocopy_derive::{FromBytes, Immutable, KnownLayout};

// 1 => KILL,
// 2 => IO_URING,
// 3 => SOCKET,
// 4 => COMMIT_CREDS,
// 5 => MODULE,
// 6 => INET_SOCK_SET_STATE,
// 7 => ENTER_PTRACE
// 8 => EXEC (bprm_check_security)
// 9 => BPF_PROG_LOAD
// 10 => INODE
// 11 => BPF_MAP
// 12 => INODE_RENAME

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, KnownLayout)]
pub struct EventHeader {
	pub ts: u64,        // 0..8
	pub cgroup_id: u64, // 8..16
	pub mnt_ns: u32,    // 16..20
	pub pid: u32,       // 20..24
	pub ppid: u32,      // 24..28
	pub uid: u32,       // 28..32
	pub tgid: u32,      // 32..36
	pub event_type: u8, // 36..37
	pub comm: [u8; 16], // 37..53
	pub _pad0: [u8; 3], // 53..56
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, KnownLayout)]
pub struct GenericEvent {
	pub header: EventHeader,
	pub meta: u32, // syscall num, exit code, permission flags, etc
	pub _pad0: [u8; 4],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, KnownLayout)]
pub struct ModuleEvent {
	pub header: EventHeader,
	pub module_name: [u8; 56],
	pub op: u8, // 0 = init, 1 = delete, etc.
	pub _pad0: [u8; 7],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, KnownLayout)]
pub struct BprmSecurityCheckEvent {
	pub header: EventHeader,
	pub filepath: [u8; 128],
	pub path_len: u32,
	pub _pad0: [u8; 4],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, KnownLayout)]
pub struct BpfMapEvent {
	pub header: EventHeader,
	pub map_name: [u8; 64],
	pub map_id: u32,
	pub map_type: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, KnownLayout)]
pub struct InetSockSetStateEvent {
	pub header: EventHeader,
	pub oldstate: i32,
	pub newstate: i32,
	pub saddr: u32,
	pub daddr: u32,
	pub sport: u16,
	pub dport: u16,
	pub protocol: u16,
	pub _pad0: [u8; 2],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, KnownLayout)]
pub struct SocketConnectEvent {
	pub header: EventHeader,
	pub addr: u32,
	pub port: u16,
	pub family: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, KnownLayout)]
pub struct SocketEvent {
	pub header: EventHeader,
	pub addr: u32,
	pub port: u16,
	pub family: u16,
	pub op: u8, // 0 = bind, 1 = connect, etc.
	pub _pad0: [u8; 7],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, KnownLayout)]
pub struct InodeEvent {
	pub header: EventHeader,
	pub filename: [u8; 64],
	pub filename_len: u32,
	pub op: u8, // 0 = unlink, 1 = mkdir, 2 = rmdir, 3 = symlink, 4 = rename etc.
	pub _pad0: [u8; 3],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, KnownLayout)]
pub struct InodeRenameEvent {
	pub header: EventHeader,
	pub new_filename: [u8; 64],
	pub old_filename: [u8; 64],
	pub new_filename_len: u32,
	pub old_filename_len: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, KnownLayout)]
pub struct BpfProgLoadEvent {
	pub header: EventHeader,
	pub prog_type: u32,
	pub attach_type: u32,
	pub flags: u32,
	pub tag: [u8; 8],
	pub _pad0: [u8; 4],
}

#[derive(Clone, Copy, Debug)]
pub enum EbpfEvent {
	Generic(GenericEvent),
	InetSock(InetSockSetStateEvent),
	Socket(SocketEvent),
	Inode(InodeEvent),
	InodeRename(InodeRenameEvent),
	Module(ModuleEvent),
	BprmSecurityCheck(BprmSecurityCheckEvent),
	BpfProgLoad(BpfProgLoadEvent),
	BpfMap(BpfMapEvent),
}
