use std::collections::HashMap;

use lib_event_schema::{Field, FieldValue};

use crate::event::{
	BpfMapEvent, BpfProgLoadEvent, BprmSecurityEvent, CerberusEvent, Event, EventHeader, InetSockEvent, InodeEvent,
	InodeMutationEvent, ModuleEvent, PtraceAccessCheckEvent, RingBufEvent, SocketEvent,
};

impl Event for RingBufEvent {
	fn header(&self) -> &EventHeader {
		&self.header
	}
	fn header_mut(&mut self) -> &mut EventHeader {
		&mut self.header
	}

	fn to_fields(&self) -> HashMap<Field, FieldValue> {
		let mut fields = HashMap::new();
		fields.insert(Field::ProcessUid, FieldValue::Int(self.header.uid as i64));
		fields.insert(Field::ProcessPid, FieldValue::Int(self.header.pid as i64));
		fields.insert(Field::ProcessTgid, FieldValue::Int(self.header.tgid as i64));
		fields.insert(Field::ProcessComm, FieldValue::String(self.header.comm.clone()));
		fields
	}
}

impl Event for BpfMapEvent {
	fn header(&self) -> &EventHeader {
		&self.header
	}
	fn header_mut(&mut self) -> &mut EventHeader {
		&mut self.header
	}
	fn to_fields(&self) -> HashMap<Field, FieldValue> {
		let mut f = HashMap::new();
		f.insert(Field::ProcessUid, FieldValue::Int(self.header.uid as i64));
		f.insert(Field::ProcessPid, FieldValue::Int(self.header.pid as i64));
		f.insert(Field::ProcessTgid, FieldValue::Int(self.header.tgid as i64));
		f.insert(Field::ProcessComm, FieldValue::String(self.header.comm.clone()));

		f.insert(Field::BpfMapId, FieldValue::Int(self.map_id as i64));
		f.insert(Field::BpfMapName, FieldValue::String(self.map_name.clone()));
		f.insert(Field::BpfMapType, FieldValue::String(self.map_type.clone()));

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
	fn to_fields(&self) -> HashMap<Field, FieldValue> {
		let mut f = HashMap::new();
		f.insert(Field::ProcessUid, FieldValue::Int(self.header.uid as i64));
		f.insert(Field::ProcessPid, FieldValue::Int(self.header.pid as i64));
		f.insert(Field::ProcessTgid, FieldValue::Int(self.header.tgid as i64));
		f.insert(Field::ProcessComm, FieldValue::String(self.header.comm.clone()));

		f.insert(Field::ModuleName, FieldValue::String(self.module_name.clone()));
		f.insert(Field::ModuleOp, FieldValue::Int(self.op as i64));
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
	fn to_fields(&self) -> HashMap<Field, FieldValue> {
		let mut f = HashMap::new();
		f.insert(Field::ProcessUid, FieldValue::Int(self.header.uid as i64));
		f.insert(Field::ProcessPid, FieldValue::Int(self.header.pid as i64));
		f.insert(Field::ProcessTgid, FieldValue::Int(self.header.tgid as i64));
		f.insert(Field::ProcessComm, FieldValue::String(self.header.comm.clone()));

		f.insert(Field::ProcessFilepath, FieldValue::String(self.filepath.clone()));

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
	fn to_fields(&self) -> HashMap<Field, FieldValue> {
		let mut f = HashMap::new();
		f.insert(Field::ProcessUid, FieldValue::Int(self.header.uid as i64));
		f.insert(Field::ProcessPid, FieldValue::Int(self.header.pid as i64));
		f.insert(Field::ProcessTgid, FieldValue::Int(self.header.tgid as i64));
		f.insert(Field::ProcessComm, FieldValue::String(self.header.comm.clone()));

		f.insert(Field::InodeNewFilename, FieldValue::String(self.new_filename.clone()));
		f.insert(Field::InodeOldFilename, FieldValue::String(self.old_filename.clone()));
		f.insert(Field::InodeMutationType, FieldValue::Int(self.mutation as i64));

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
	fn to_fields(&self) -> HashMap<Field, FieldValue> {
		let mut f = HashMap::new();
		f.insert(Field::ProcessUid, FieldValue::Int(self.header.uid as i64));
		f.insert(Field::ProcessPid, FieldValue::Int(self.header.pid as i64));
		f.insert(Field::ProcessTgid, FieldValue::Int(self.header.tgid as i64));
		f.insert(Field::ProcessComm, FieldValue::String(self.header.comm.clone()));

		f.insert(Field::ProcessTargetPid, FieldValue::Int(self.target_pid as i64));
		f.insert(Field::ProcessTargetTgid, FieldValue::Int(self.target_tgid as i64));
		f.insert(Field::ProcessTargetUid, FieldValue::Int(self.target_uid as i64));
		f.insert(Field::ProcessTargetComm, FieldValue::String(self.target_comm.clone()));

		f.insert(Field::PtraceMode, FieldValue::Int(self.mode as i64));
		f.insert(Field::PtraceStage, FieldValue::Int(self.stage as i64));

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
	fn to_fields(&self) -> HashMap<Field, FieldValue> {
		let mut f = HashMap::new();
		f.insert(Field::ProcessUid, FieldValue::Int(self.header.uid as i64));
		f.insert(Field::ProcessPid, FieldValue::Int(self.header.pid as i64));
		f.insert(Field::ProcessTgid, FieldValue::Int(self.header.tgid as i64));
		f.insert(Field::ProcessComm, FieldValue::String(self.header.comm.clone()));

		f.insert(Field::InodeFilename, FieldValue::String(self.filename.clone()));
		f.insert(Field::InodeOp, FieldValue::Int(self.op as i64));

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
	fn to_fields(&self) -> HashMap<Field, FieldValue> {
		let mut f = HashMap::new();
		f.insert(Field::ProcessUid, FieldValue::Int(self.header.uid as i64));
		f.insert(Field::ProcessPid, FieldValue::Int(self.header.pid as i64));
		f.insert(Field::ProcessTgid, FieldValue::Int(self.header.tgid as i64));
		f.insert(Field::ProcessComm, FieldValue::String(self.header.comm.clone()));

		f.insert(Field::NetworkSport, FieldValue::Int(self.sport as i64));
		f.insert(Field::NetworkDport, FieldValue::Int(self.dport as i64));
		f.insert(Field::NetworkSaddr, FieldValue::Ip(self.saddr));
		f.insert(Field::NetworkDaddr, FieldValue::Ip(self.daddr));

		f.insert(Field::NetworkProtocol, FieldValue::String(self.protocol.clone()));
		f.insert(Field::SocketOldState, FieldValue::String(self.old_state.clone()));
		f.insert(Field::SocketNewState, FieldValue::String(self.new_state.clone()));

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
	fn to_fields(&self) -> HashMap<Field, FieldValue> {
		let mut f = HashMap::new();

		f.insert(Field::ProcessUid, FieldValue::Int(self.header.uid as i64));
		f.insert(Field::ProcessPid, FieldValue::Int(self.header.pid as i64));
		f.insert(Field::ProcessTgid, FieldValue::Int(self.header.tgid as i64));
		f.insert(Field::ProcessComm, FieldValue::String(self.header.comm.clone()));

		f.insert(Field::SocketPort, FieldValue::Int(self.port as i64));
		f.insert(Field::SocketFamily, FieldValue::Int(self.family as i64));
		f.insert(Field::SocketOp, FieldValue::Int(self.op as i64));

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
	fn to_fields(&self) -> HashMap<Field, FieldValue> {
		let mut f = HashMap::new();
		f.insert(Field::ProcessUid, FieldValue::Int(self.header.uid as i64));
		f.insert(Field::ProcessPid, FieldValue::Int(self.header.pid as i64));
		f.insert(Field::ProcessTgid, FieldValue::Int(self.header.tgid as i64));
		f.insert(Field::ProcessComm, FieldValue::String(self.header.comm.clone()));

		f.insert(Field::BpfProgType, FieldValue::Int(self.prog_type as i64));
		f.insert(Field::BpfProgFlags, FieldValue::Int(self.flags as i64));
		f.insert(Field::BpfProgAttachType, FieldValue::Int(self.attach_type as i64));

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
		}
	}

	fn to_fields(&self) -> HashMap<Field, FieldValue> {
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
		}
	}
}
