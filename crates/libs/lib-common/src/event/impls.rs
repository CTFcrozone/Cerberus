use std::sync::Arc;

use lib_event_schema::{Field, FieldValue};
use strum::EnumCount;

use crate::event::{
	BpfMapEvent, BpfProgLoadEvent, BprmSecurityEvent, CerberusEvent, Event, EventHeader, InetSockEvent, InodeEvent,
	InodeMutationEvent, ModuleEvent, PtraceAccessCheckEvent, RingBufEvent, SocketEvent, TamperEvent,
};

impl Event for RingBufEvent {
	fn header(&self) -> &EventHeader {
		&self.header
	}
	fn header_mut(&mut self) -> &mut EventHeader {
		&mut self.header
	}

	fn to_fields(&self) -> [Option<FieldValue>; Field::COUNT] {
		let mut f = [const { None }; Field::COUNT];
		f[Field::ProcessUid.index()] = Some(FieldValue::Int(self.header.uid as i64));
		f[Field::ProcessPid.index()] = Some(FieldValue::Int(self.header.pid as i64));
		f[Field::ProcessTgid.index()] = Some(FieldValue::Int(self.header.tgid as i64));
		f[Field::ProcessComm.index()] = Some(FieldValue::String(self.header.comm.clone()));
		f[Field::ProcessParentComm.index()] = Some(FieldValue::String(self.header.parent_comm.clone()));
		f
	}
}

impl Event for BpfMapEvent {
	fn header(&self) -> &EventHeader {
		&self.header
	}
	fn header_mut(&mut self) -> &mut EventHeader {
		&mut self.header
	}
	fn to_fields(&self) -> [Option<FieldValue>; Field::COUNT] {
		let mut f = [const { None }; Field::COUNT];
		f[Field::ProcessUid.index()] = Some(FieldValue::Int(self.header.uid as i64));
		f[Field::ProcessPid.index()] = Some(FieldValue::Int(self.header.pid as i64));
		f[Field::ProcessTgid.index()] = Some(FieldValue::Int(self.header.tgid as i64));
		f[Field::ProcessComm.index()] = Some(FieldValue::String(self.header.comm.clone()));
		f[Field::ProcessParentComm.index()] = Some(FieldValue::String(self.header.parent_comm.clone()));
		f[Field::BpfMapId.index()] = Some(FieldValue::Int(self.map_id as i64));
		f[Field::BpfMapName.index()] = Some(FieldValue::String(self.map_name.clone()));
		f[Field::BpfMapType.index()] = Some(FieldValue::String(self.map_type.clone()));
		f
	}
}

impl Event for ModuleEvent {
	fn header(&self) -> &EventHeader {
		&self.header
	}
	fn header_mut(&mut self) -> &mut EventHeader {
		&mut self.header
	}
	fn to_fields(&self) -> [Option<FieldValue>; Field::COUNT] {
		let mut f = [const { None }; Field::COUNT];
		f[Field::ProcessUid.index()] = Some(FieldValue::Int(self.header.uid as i64));
		f[Field::ProcessPid.index()] = Some(FieldValue::Int(self.header.pid as i64));
		f[Field::ProcessTgid.index()] = Some(FieldValue::Int(self.header.tgid as i64));
		f[Field::ProcessComm.index()] = Some(FieldValue::String(self.header.comm.clone()));
		f[Field::ProcessParentComm.index()] = Some(FieldValue::String(self.header.parent_comm.clone()));
		f[Field::ModuleName.index()] = Some(FieldValue::String(self.module_name.clone()));
		f[Field::ModuleOp.index()] = Some(FieldValue::Int(self.op as i64));
		f
	}
}

impl Event for BprmSecurityEvent {
	fn header(&self) -> &EventHeader {
		&self.header
	}
	fn header_mut(&mut self) -> &mut EventHeader {
		&mut self.header
	}
	fn to_fields(&self) -> [Option<FieldValue>; Field::COUNT] {
		let mut f = [const { None }; Field::COUNT];

		f[Field::ProcessUid.index()] = Some(FieldValue::Int(self.header.uid as i64));
		f[Field::ProcessPid.index()] = Some(FieldValue::Int(self.header.pid as i64));
		f[Field::ProcessTgid.index()] = Some(FieldValue::Int(self.header.tgid as i64));
		f[Field::ProcessComm.index()] = Some(FieldValue::String(self.header.comm.clone()));
		f[Field::ProcessParentComm.index()] = Some(FieldValue::String(self.header.parent_comm.clone()));
		f[Field::ProcessFilepath.index()] = Some(FieldValue::String(self.filepath.clone()));
		f
	}
}

impl Event for InodeMutationEvent {
	fn header(&self) -> &EventHeader {
		&self.header
	}
	fn header_mut(&mut self) -> &mut EventHeader {
		&mut self.header
	}
	fn to_fields(&self) -> [Option<FieldValue>; Field::COUNT] {
		let mut f = [const { None }; Field::COUNT];
		f[Field::ProcessUid.index()] = Some(FieldValue::Int(self.header.uid as i64));
		f[Field::ProcessPid.index()] = Some(FieldValue::Int(self.header.pid as i64));
		f[Field::ProcessTgid.index()] = Some(FieldValue::Int(self.header.tgid as i64));
		f[Field::ProcessComm.index()] = Some(FieldValue::String(self.header.comm.clone()));
		f[Field::ProcessParentComm.index()] = Some(FieldValue::String(self.header.parent_comm.clone()));
		f[Field::InodeNewFilename.index()] = Some(FieldValue::String(self.new_filename.clone()));
		f[Field::InodeOldFilename.index()] = Some(FieldValue::String(self.old_filename.clone()));
		f[Field::InodeMutationType.index()] = Some(FieldValue::Int(self.mutation as i64));
		f
	}
}

impl Event for PtraceAccessCheckEvent {
	fn header(&self) -> &EventHeader {
		&self.header
	}
	fn header_mut(&mut self) -> &mut EventHeader {
		&mut self.header
	}
	fn to_fields(&self) -> [Option<FieldValue>; Field::COUNT] {
		let mut f = [const { None }; Field::COUNT];
		f[Field::ProcessUid.index()] = Some(FieldValue::Int(self.header.uid as i64));
		f[Field::ProcessPid.index()] = Some(FieldValue::Int(self.header.pid as i64));
		f[Field::ProcessTgid.index()] = Some(FieldValue::Int(self.header.tgid as i64));
		f[Field::ProcessComm.index()] = Some(FieldValue::String(self.header.comm.clone()));
		f[Field::ProcessParentComm.index()] = Some(FieldValue::String(self.header.parent_comm.clone()));
		f[Field::ProcessTargetPid.index()] = Some(FieldValue::Int(self.target_pid as i64));
		f[Field::ProcessTargetTgid.index()] = Some(FieldValue::Int(self.target_tgid as i64));
		f[Field::ProcessTargetUid.index()] = Some(FieldValue::Int(self.target_uid as i64));
		f[Field::ProcessTargetComm.index()] = Some(FieldValue::String(self.target_comm.clone()));
		f[Field::PtraceMode.index()] = Some(FieldValue::Int(self.mode as i64));
		f[Field::PtraceStage.index()] = Some(FieldValue::Int(self.stage as i64));

		f
	}
}

impl Event for InodeEvent {
	fn header(&self) -> &EventHeader {
		&self.header
	}
	fn header_mut(&mut self) -> &mut EventHeader {
		&mut self.header
	}
	fn to_fields(&self) -> [Option<FieldValue>; Field::COUNT] {
		let mut f = [const { None }; Field::COUNT];
		f[Field::ProcessUid.index()] = Some(FieldValue::Int(self.header.uid as i64));
		f[Field::ProcessPid.index()] = Some(FieldValue::Int(self.header.pid as i64));
		f[Field::ProcessTgid.index()] = Some(FieldValue::Int(self.header.tgid as i64));
		f[Field::ProcessComm.index()] = Some(FieldValue::String(self.header.comm.clone()));
		f[Field::ProcessParentComm.index()] = Some(FieldValue::String(self.header.parent_comm.clone()));
		f[Field::InodeFilename.index()] = Some(FieldValue::String(self.filename.clone()));
		f[Field::InodeOp.index()] = Some(FieldValue::Int(self.op as i64));
		f
	}
}

impl Event for InetSockEvent {
	fn header(&self) -> &EventHeader {
		&self.header
	}
	fn header_mut(&mut self) -> &mut EventHeader {
		&mut self.header
	}
	fn to_fields(&self) -> [Option<FieldValue>; Field::COUNT] {
		let mut f = [const { None }; Field::COUNT];
		f[Field::ProcessUid.index()] = Some(FieldValue::Int(self.header.uid as i64));
		f[Field::ProcessPid.index()] = Some(FieldValue::Int(self.header.pid as i64));
		f[Field::ProcessTgid.index()] = Some(FieldValue::Int(self.header.tgid as i64));
		f[Field::ProcessComm.index()] = Some(FieldValue::String(self.header.comm.clone()));
		f[Field::ProcessParentComm.index()] = Some(FieldValue::String(self.header.parent_comm.clone()));
		f[Field::NetworkSport.index()] = Some(FieldValue::Int(self.sport as i64));
		f[Field::NetworkDport.index()] = Some(FieldValue::Int(self.dport as i64));
		f[Field::NetworkSaddr.index()] = Some(FieldValue::Ip(self.saddr));
		f[Field::NetworkDaddr.index()] = Some(FieldValue::Ip(self.daddr));
		f[Field::NetworkProtocol.index()] = Some(FieldValue::String(self.protocol.clone()));
		f[Field::SocketOldState.index()] = Some(FieldValue::String(self.old_state.clone()));
		f[Field::SocketNewState.index()] = Some(FieldValue::String(self.new_state.clone()));

		f
	}
}

impl Event for SocketEvent {
	fn header(&self) -> &EventHeader {
		&self.header
	}
	fn header_mut(&mut self) -> &mut EventHeader {
		&mut self.header
	}
	fn to_fields(&self) -> [Option<FieldValue>; Field::COUNT] {
		let mut f = [const { None }; Field::COUNT];
		f[Field::ProcessUid.index()] = Some(FieldValue::Int(self.header.uid as i64));
		f[Field::ProcessPid.index()] = Some(FieldValue::Int(self.header.pid as i64));
		f[Field::ProcessTgid.index()] = Some(FieldValue::Int(self.header.tgid as i64));
		f[Field::ProcessComm.index()] = Some(FieldValue::String(self.header.comm.clone()));
		f[Field::ProcessParentComm.index()] = Some(FieldValue::String(self.header.parent_comm.clone()));
		f[Field::SocketPort.index()] = Some(FieldValue::Int(self.port as i64));
		f[Field::SocketFamily.index()] = Some(FieldValue::Int(self.family as i64));
		f[Field::SocketOp.index()] = Some(FieldValue::Int(self.op as i64));
		f
	}
}

impl Event for BpfProgLoadEvent {
	fn header(&self) -> &EventHeader {
		&self.header
	}
	fn header_mut(&mut self) -> &mut EventHeader {
		&mut self.header
	}
	fn to_fields(&self) -> [Option<FieldValue>; Field::COUNT] {
		let mut f = [const { None }; Field::COUNT];
		f[Field::ProcessUid.index()] = Some(FieldValue::Int(self.header.uid as i64));
		f[Field::ProcessPid.index()] = Some(FieldValue::Int(self.header.pid as i64));
		f[Field::ProcessTgid.index()] = Some(FieldValue::Int(self.header.tgid as i64));
		f[Field::ProcessComm.index()] = Some(FieldValue::String(self.header.comm.clone()));
		f[Field::ProcessParentComm.index()] = Some(FieldValue::String(self.header.parent_comm.clone()));
		f[Field::BpfProgType.index()] = Some(FieldValue::Int(self.prog_type as i64));
		f[Field::BpfProgFlags.index()] = Some(FieldValue::Int(self.flags as i64));
		f[Field::BpfProgAttachType.index()] = Some(FieldValue::Int(self.attach_type as i64));
		f
	}
}

impl TamperEvent {
	pub fn new(source: &'static str, severity: u8, kind: u8, reason: Arc<str>, age_ms: u64, pid: u32) -> Self {
		let now = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.map(|d| d.as_nanos() as u64)
			.unwrap_or(0);

		let header = EventHeader {
			container: None,
			comm: Arc::from(source),
			parent_comm: Arc::from(""),
			ts: now,
			cgroup_id: 0,
			mnt_ns: 0,
			pid,
			ppid: 0,
			uid: 0,
			tgid: pid,
		};

		TamperEvent {
			header,
			severity,
			kind,
			reason,
			age_ms,
			source,
		}
	}
}

impl Event for TamperEvent {
	fn header(&self) -> &EventHeader {
		&self.header
	}

	fn header_mut(&mut self) -> &mut EventHeader {
		&mut self.header
	}

	fn to_fields(&self) -> [Option<FieldValue>; Field::COUNT] {
		let mut f = [const { None }; Field::COUNT];
		f[Field::ProcessUid.index()] = Some(FieldValue::Int(self.header.uid as i64));
		f[Field::ProcessPid.index()] = Some(FieldValue::Int(self.header.pid as i64));
		f[Field::ProcessTgid.index()] = Some(FieldValue::Int(self.header.tgid as i64));
		f[Field::ProcessComm.index()] = Some(FieldValue::String(self.header.comm.clone()));
		f[Field::ProcessParentComm.index()] = Some(FieldValue::String(self.header.parent_comm.clone()));
		f[Field::OrthrusTamperReason.index()] = Some(FieldValue::String(self.reason.clone()));
		f[Field::OrthrusTamperSeverity.index()] = Some(FieldValue::Int(self.severity as i64));
		f[Field::OrthrusTamperKind.index()] = Some(FieldValue::Int(self.kind as i64));
		f
	}
}

impl Event for CerberusEvent {
	fn header(&self) -> &EventHeader {
		match self {
			CerberusEvent::Generic(e) => e.header(),
			CerberusEvent::Module(e) => e.header(),
			CerberusEvent::Bprm(e) => e.header(),
			CerberusEvent::Inode(e) => e.header(),
			CerberusEvent::InetSock(e) => e.header(),
			CerberusEvent::Socket(e) => e.header(),
			CerberusEvent::BpfProgLoad(e) => e.header(),
			CerberusEvent::BpfMap(e) => e.header(),
			CerberusEvent::InodeMutation(e) => e.header(),
			CerberusEvent::PtraceAccessCheck(e) => e.header(),
			CerberusEvent::Tamper(e) => e.header(),
		}
	}

	fn header_mut(&mut self) -> &mut EventHeader {
		match self {
			CerberusEvent::Generic(e) => e.header_mut(),
			CerberusEvent::Module(e) => e.header_mut(),
			CerberusEvent::Bprm(e) => e.header_mut(),
			CerberusEvent::Inode(e) => e.header_mut(),
			CerberusEvent::InetSock(e) => e.header_mut(),
			CerberusEvent::Socket(e) => e.header_mut(),
			CerberusEvent::BpfProgLoad(e) => e.header_mut(),
			CerberusEvent::BpfMap(e) => e.header_mut(),
			CerberusEvent::InodeMutation(e) => e.header_mut(),
			CerberusEvent::PtraceAccessCheck(e) => e.header_mut(),
			CerberusEvent::Tamper(e) => e.header_mut(),
		}
	}

	fn to_fields(&self) -> [Option<FieldValue>; Field::COUNT] {
		match self {
			CerberusEvent::Generic(e) => e.to_fields(),
			CerberusEvent::Module(e) => e.to_fields(),
			CerberusEvent::Bprm(e) => e.to_fields(),
			CerberusEvent::Inode(e) => e.to_fields(),
			CerberusEvent::InetSock(e) => e.to_fields(),
			CerberusEvent::Socket(e) => e.to_fields(),
			CerberusEvent::BpfProgLoad(e) => e.to_fields(),
			CerberusEvent::BpfMap(e) => e.to_fields(),
			CerberusEvent::InodeMutation(e) => e.to_fields(),
			CerberusEvent::PtraceAccessCheck(e) => e.to_fields(),
			CerberusEvent::Tamper(e) => e.to_fields(),
		}
	}
}
