pub const FILE_PATH_LEN: usize = 128;
pub const FILE_NAME_LEN: usize = 64;
// =========================
// Event Types
// =========================

pub const EVT_KILL: u8 = 1;
pub const EVT_IO_URING: u8 = 2;
pub const EVT_SOCKET: u8 = 3;
pub const EVT_COMMIT_CREDS: u8 = 4;
pub const EVT_MODULE: u8 = 5;
pub const EVT_INET_SOCK_SET_STATE: u8 = 6;
pub const EVT_ENTER_PTRACE: u8 = 7;
pub const EVT_BPRM_CHECK_SEC: u8 = 8;
pub const EVT_BPF_PROG_LOAD: u8 = 9;
pub const EVT_INODE: u8 = 10;
pub const EVT_BPF_MAP: u8 = 11;
pub const EVT_INODE_MUTATE: u8 = 12;
pub const EVT_PTRACE_ACCESS_CHECK: u8 = 13;

// =========================
// Generic Event Meta Types
// =========================

pub const META_KILL_SIG: u16 = 0;
pub const META_PTRACE_SUCCESS: u16 = 1;

// =========================
// Module Operations
// =========================

pub const MODULE_OP_INIT: u8 = 0;
pub const MODULE_OP_DELETE: u8 = 1;
pub const MODULE_OP_REQUEST: u8 = 2;

// =========================
// Socket Operations
// =========================

pub const SOCKET_OP_BIND: u8 = 0;
pub const SOCKET_OP_CONNECT: u8 = 1;

// =========================
// Inode Operations
// =========================

pub const INODE_OP_UNLINK: u8 = 0;
pub const INODE_OP_MKDIR: u8 = 1;
pub const INODE_OP_RMDIR: u8 = 2;

// =========================
// Inode Mutation Operations
// =========================

pub const INODE_MUTATION_RENAME: u8 = 0;
pub const INODE_MUTATION_LINK: u8 = 1;
pub const INODE_MUTATION_SYMLINK: u8 = 2;

// =========================
// Ptrace Stages
// =========================

pub const PTRACE_STAGE_REQUEST: u8 = 0;
pub const PTRACE_STAGE_DECISION: u8 = 1;
