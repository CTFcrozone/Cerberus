use crate::{Error, error::Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Field {
	ProcessPid,
	ProcessUid,
	ProcessTgid,
	ProcessComm,
	ProcessFilepath,

	ProcessTargetPid,
	ProcessTargetTgid,
	ProcessTargetUid,
	ProcessTargetComm,

	SocketOldState,
	SocketNewState,
	SocketPort,
	SocketFamily,
	SocketOp,

	NetworkSport,
	NetworkDport,
	NetworkProtocol,

	ModuleName,
	ModuleOp,

	InodeFilename,
	InodeOldFilename,
	InodeNewFilename,
	InodeOp,
	InodeMutationType,

	PtraceMode,
	PtraceStage,

	BpfProgType,
	BpfProgAttachType,
	BpfProgFlags,

	BpfMapName,
	BpfMapType,
	BpfMapId,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FieldType {
	Bool,
	Int,
	String,
	Ip,
}

impl Field {
	pub const fn as_str(&self) -> &'static str {
		match self {
			Field::ProcessPid => "process.pid",
			Field::ProcessUid => "process.uid",
			Field::ProcessTgid => "process.tgid",
			Field::ProcessComm => "process.comm",
			Field::ProcessFilepath => "process.filepath",

			Field::ProcessTargetPid => "process.target.pid",
			Field::ProcessTargetTgid => "process.target.tgid",
			Field::ProcessTargetUid => "process.target.uid",
			Field::ProcessTargetComm => "process.target.comm",

			Field::SocketOldState => "socket.old_state",
			Field::SocketNewState => "socket.new_state",
			Field::SocketPort => "socket.port",
			Field::SocketFamily => "socket.family",
			Field::SocketOp => "socket.op",

			Field::NetworkSport => "network.sport",
			Field::NetworkDport => "network.dport",
			Field::NetworkProtocol => "network.protocol",

			Field::ModuleName => "module.name",
			Field::ModuleOp => "module.op",

			Field::InodeFilename => "inode.filename",
			Field::InodeOldFilename => "inode.old_filename",
			Field::InodeNewFilename => "inode.new_filename",
			Field::InodeOp => "inode.op",
			Field::InodeMutationType => "inode.mutation.type",

			Field::PtraceMode => "ptrace.mode",
			Field::PtraceStage => "ptrace.stage",

			Field::BpfProgType => "bpf.prog.type",
			Field::BpfProgAttachType => "bpf.prog.attach_type",
			Field::BpfProgFlags => "bpf.prog.flags",

			Field::BpfMapName => "bpf.map.name",
			Field::BpfMapType => "bpf.map.type",
			Field::BpfMapId => "bpf.map.id",
		}
	}
	pub const fn ty(self) -> FieldType {
		match self {
			// Process
			Field::ProcessPid
			| Field::ProcessUid
			| Field::ProcessTgid
			| Field::ProcessTargetPid
			| Field::ProcessTargetTgid
			| Field::ProcessTargetUid => FieldType::Int,

			Field::ProcessComm | Field::ProcessFilepath | Field::ProcessTargetComm => FieldType::String,

			// Socket
			Field::SocketOldState | Field::SocketNewState => FieldType::String,

			Field::SocketPort | Field::SocketFamily | Field::SocketOp => FieldType::Int,

			// Network
			Field::NetworkSport | Field::NetworkDport => FieldType::Int,

			Field::NetworkProtocol => FieldType::String,

			// When you expose saddr/daddr later:
			// Field::NetworkSaddr
			// | Field::NetworkDaddr => FieldType::Ip,

			// Module
			Field::ModuleName => FieldType::String,
			Field::ModuleOp => FieldType::Int,

			// Inode
			Field::InodeFilename | Field::InodeOldFilename | Field::InodeNewFilename => FieldType::String,

			Field::InodeOp | Field::InodeMutationType => FieldType::Int,

			// Ptrace
			Field::PtraceMode | Field::PtraceStage => FieldType::Int,

			// BPF
			Field::BpfProgType | Field::BpfProgAttachType | Field::BpfProgFlags | Field::BpfMapId => FieldType::Int,

			Field::BpfMapName | Field::BpfMapType => FieldType::String,
		}
	}
}

pub fn compile_field(s: &str) -> Result<Field> {
	Ok(match s {
		"process.uid" => Field::ProcessUid,
		"process.pid" => Field::ProcessPid,
		"process.tgid" => Field::ProcessTgid,
		"process.comm" => Field::ProcessComm,
		"process.filepath" => Field::ProcessFilepath,
		"process.target.pid" => Field::ProcessTargetPid,
		"process.target.tgid" => Field::ProcessTargetTgid,
		"process.target.uid" => Field::ProcessTargetUid,
		"process.target.comm" => Field::ProcessTargetComm,
		"socket.old_state" => Field::SocketOldState,
		"socket.new_state" => Field::SocketNewState,
		"socket.port" => Field::SocketPort,
		"socket.family" => Field::SocketFamily,
		"socket.op" => Field::SocketOp,
		"network.sport" => Field::NetworkSport,
		"network.dport" => Field::NetworkDport,
		"network.protocol" => Field::NetworkProtocol,
		"module.name" => Field::ModuleName,
		"module.op" => Field::ModuleOp,
		"inode.filename" => Field::InodeFilename,
		"inode.op" => Field::InodeOp,
		"inode.new_filename" => Field::InodeNewFilename,
		"inode.old_filename" => Field::InodeOldFilename,
		"inode.mutation.type" => Field::InodeMutationType,
		"ptrace.mode" => Field::PtraceMode,
		"ptrace.stage" => Field::PtraceStage,
		"bpf.prog.type" => Field::BpfProgType,
		"bpf.prog.attach_type" => Field::BpfProgAttachType,
		"bpf.prog.flags" => Field::BpfProgFlags,
		"bpf.map.name" => Field::BpfMapName,
		"bpf.map.type" => Field::BpfMapType,
		"bpf.map.id" => Field::BpfMapId,
		_ => return Err(Error::UnknownField { field: s.into() }),
	})
}
