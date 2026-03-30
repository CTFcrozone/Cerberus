use std::collections::HashMap;

use crate::event::{
	BpfMapEvent, BpfProgLoadEvent, BprmSecurityEvent, CerberusEvent, Event, EventHeader, InetSockEvent, InodeEvent,
	ModuleEvent, RingBufEvent, SocketEvent,
};

impl Event for RingBufEvent {
	fn header(&self) -> &EventHeader {
		&self.header
	}
	fn header_mut(&mut self) -> &mut EventHeader {
		&mut self.header
	}

	fn to_fields(&self) -> HashMap<String, toml::Value> {
		let mut fields = HashMap::new();
		fields.insert("process.uid".into(), toml::Value::Integer(self.header.uid as i64));
		fields.insert("process.pid".into(), toml::Value::Integer(self.header.pid as i64));
		fields.insert("process.tgid".into(), toml::Value::Integer(self.header.tgid as i64));
		fields.insert("process.comm".into(), toml::Value::String(self.header.comm.to_string()));
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
	fn to_fields(&self) -> HashMap<String, toml::Value> {
		let mut f = HashMap::new();
		f.insert("process.uid".into(), toml::Value::Integer(self.header.uid as i64));
		f.insert("process.pid".into(), toml::Value::Integer(self.header.pid as i64));
		f.insert("process.tgid".into(), toml::Value::Integer(self.header.tgid as i64));
		f.insert("process.comm".into(), toml::Value::String(self.header.comm.to_string()));
		f.insert("bpf.map.id".into(), toml::Value::Integer(self.map_id as i64));
		f.insert("bpf.map.name".into(), toml::Value::String(self.map_name.to_string()));
		f.insert("bpf.map.type".into(), toml::Value::String(self.map_type.to_string()));
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
	fn to_fields(&self) -> HashMap<String, toml::Value> {
		let mut f = HashMap::new();
		f.insert("process.uid".into(), toml::Value::Integer(self.header.uid as i64));
		f.insert("process.pid".into(), toml::Value::Integer(self.header.pid as i64));
		f.insert("process.tgid".into(), toml::Value::Integer(self.header.tgid as i64));
		f.insert("process.comm".into(), toml::Value::String(self.header.comm.to_string()));
		f.insert("module.name".into(), toml::Value::String(self.module_name.to_string()));
		f.insert("module.op".into(), toml::Value::Integer(self.op as i64));
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
	fn to_fields(&self) -> HashMap<String, toml::Value> {
		let mut f = HashMap::new();
		f.insert("process.uid".into(), toml::Value::Integer(self.header.uid as i64));
		f.insert("process.pid".into(), toml::Value::Integer(self.header.pid as i64));
		f.insert("process.tgid".into(), toml::Value::Integer(self.header.tgid as i64));
		f.insert("process.comm".into(), toml::Value::String(self.header.comm.to_string()));
		f.insert(
			"process.filepath".into(),
			toml::Value::String(self.filepath.to_string()),
		);
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
	fn to_fields(&self) -> HashMap<String, toml::Value> {
		let mut f = HashMap::new();
		f.insert("process.uid".into(), toml::Value::Integer(self.header.uid as i64));
		f.insert("process.pid".into(), toml::Value::Integer(self.header.pid as i64));
		f.insert("process.tgid".into(), toml::Value::Integer(self.header.tgid as i64));
		f.insert("process.comm".into(), toml::Value::String(self.header.comm.to_string()));
		f.insert("inode.filename".into(), toml::Value::String(self.filename.to_string()));
		f.insert("inode.op".into(), toml::Value::Integer(self.op as i64));
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
	fn to_fields(&self) -> HashMap<String, toml::Value> {
		let mut f = HashMap::new();
		f.insert("process.uid".into(), toml::Value::Integer(self.header.uid as i64));
		f.insert("process.pid".into(), toml::Value::Integer(self.header.pid as i64));
		f.insert("process.tgid".into(), toml::Value::Integer(self.header.tgid as i64));
		f.insert("process.comm".into(), toml::Value::String(self.header.comm.to_string()));

		f.insert("network.sport".into(), toml::Value::Integer(self.sport as i64));
		f.insert("network.dport".into(), toml::Value::Integer(self.dport as i64));
		f.insert(
			"network.protocol".into(),
			toml::Value::String(self.protocol.to_string()),
		);
		f.insert(
			"socket.old_state".into(),
			toml::Value::String(self.old_state.to_string()),
		);
		f.insert(
			"socket.new_state".into(),
			toml::Value::String(self.new_state.to_string()),
		);
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
	fn to_fields(&self) -> HashMap<String, toml::Value> {
		let mut f = HashMap::new();
		f.insert("process.uid".into(), toml::Value::Integer(self.header.uid as i64));
		f.insert("process.pid".into(), toml::Value::Integer(self.header.pid as i64));
		f.insert("process.tgid".into(), toml::Value::Integer(self.header.tgid as i64));
		f.insert("process.comm".into(), toml::Value::String(self.header.comm.to_string()));

		f.insert("socket.port".into(), toml::Value::Integer(self.port as i64));
		f.insert("socket.family".into(), toml::Value::Integer(self.family as i64));
		f.insert("socket.op".into(), toml::Value::Integer(self.op as i64));
		f.insert("socket.addr".into(), toml::Value::Integer(self.addr as i64));
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
	fn to_fields(&self) -> HashMap<String, toml::Value> {
		let mut f = HashMap::new();
		f.insert("process.uid".into(), toml::Value::Integer(self.header.uid as i64));
		f.insert("process.pid".into(), toml::Value::Integer(self.header.pid as i64));
		f.insert("process.tgid".into(), toml::Value::Integer(self.header.tgid as i64));
		f.insert("process.comm".into(), toml::Value::String(self.header.comm.to_string()));

		f.insert("bpf.prog.type".into(), toml::Value::Integer(self.prog_type as i64));
		f.insert("bpf.prog.flags".into(), toml::Value::Integer(self.flags as i64));
		f.insert(
			"bpf.prog.attach_type".into(),
			toml::Value::Integer(self.attach_type as i64),
		);
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
		}
	}

	fn to_fields(&self) -> HashMap<String, toml::Value> {
		match self {
			CerberusEvent::Generic(e) => e.to_fields(),
			CerberusEvent::Module(e) => e.to_fields(),
			CerberusEvent::Bprm(e) => e.to_fields(),
			CerberusEvent::Inode(e) => e.to_fields(),
			CerberusEvent::InetSock(e) => e.to_fields(),
			CerberusEvent::Socket(e) => e.to_fields(),
			CerberusEvent::BpfProgLoad(e) => e.to_fields(),
			CerberusEvent::BpfMap(e) => e.to_fields(),
		}
	}
}
