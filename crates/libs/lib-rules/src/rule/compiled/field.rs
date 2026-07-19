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
	BpfProgTag,

	BpfMapName,
	BpfMapType,
	BpfMapId,
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
		"bpf.prog.tag" => Field::BpfProgTag,
		"bpf.map.name" => Field::BpfMapName,
		"bpf.map.type" => Field::BpfMapType,
		"bpf.map.id" => Field::BpfMapId,
		_ => return Err(Error::UnknownField { field: s.into() }),
	})
}
