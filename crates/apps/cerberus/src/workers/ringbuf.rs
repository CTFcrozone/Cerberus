use std::sync::Arc;

use crate::error::{Error, Result};

use aya::maps::{MapData, RingBuf};
use lib_common::event::{
	BpfMapEvent, BpfProgLoadEvent, BprmSecurityEvent, CerberusEvent, EventHeader, InetSockEvent, InodeEvent,
	InodeRenameEvent, ModuleEvent, RingBufEvent,
};
use lib_ebpf_common::{EbpfEvent, FILE_PATH_LEN};
use lib_event::trx::Tx;
use tokio::io::unix::AsyncFd;

use zerocopy::FromBytes;

pub struct RingBufWorker {
	pub ringbuf_fd: AsyncFd<RingBuf<MapData>>,
	pub tx: Tx<CerberusEvent>,
}

// TODO: make it shutdown aware
impl RingBufWorker {
	pub fn start(ringbuf_fd: AsyncFd<RingBuf<MapData>>, tx: Tx<CerberusEvent>) -> Result<Self> {
		Ok(RingBufWorker { ringbuf_fd, tx })
	}

	pub async fn run(mut self) -> Result<()> {
		loop {
			let mut guard = match self.ringbuf_fd.readable_mut().await {
				Ok(g) => g,
				Err(_) => break,
			};

			let ring_buf = guard.get_inner_mut();

			while let Some(item) = ring_buf.next() {
				// if self.limiter.check().is_err() {
				// 	self.dropped.fetch_add(1, Ordering::Relaxed);
				// 	continue;
				// }

				let data = item.as_ref();

				match parse_event_from_bytes(data) {
					Ok(evt) => {
						let cerberus_evt = parse_cerberus_event(evt)?;
						self.tx.send(cerberus_evt).await?;
					}
					Err(_) => continue,
				}
			}

			guard.clear_ready();
		}
		Ok(())
	}
}

fn parse_cerberus_event(evt: EbpfEvent) -> Result<CerberusEvent> {
	let cerberus_evt = match evt {
		EbpfEvent::Generic(ref e) => CerberusEvent::Generic(RingBufEvent {
			name: match e.header.event_type {
				1 => "KILL",
				2 => "IO_URING",
				3 => "SOCKET_CONNECT",
				4 => "COMMIT_CREDS",
				5 => "MODULE_INIT",
				6 => "INET_SOCK_SET_STATE",
				7 => "ENTER_PTRACE",
				8 => "BPRM_CHECK",
				_ => "UNKNOWN",
			},
			meta: e.meta,
			header: EventHeader {
				cgroup_id: e.header.cgroup_id,
				container: None,
				ts: e.header.ts,
				mnt_ns: e.header.mnt_ns,
				pid: e.header.pid,
				ppid: e.header.ppid,
				uid: e.header.uid,
				tgid: e.header.tgid,
				comm: Arc::from(String::from_utf8_lossy(&e.header.comm).trim_end_matches('\0')),
			},
		}),

		EbpfEvent::InodeRename(ref e) => CerberusEvent::InodeRename(InodeRenameEvent {
			new_filename: Arc::from(String::from_utf8_lossy(&e.new_filename).trim_end_matches('\0')),
			new_filename_len: e.new_filename_len,
			old_filename: Arc::from(String::from_utf8_lossy(&e.old_filename).trim_end_matches('\0')),
			old_filename_len: e.old_filename_len,
			header: EventHeader {
				cgroup_id: e.header.cgroup_id,
				container: None,
				ts: e.header.ts,
				mnt_ns: e.header.mnt_ns,
				pid: e.header.pid,
				ppid: e.header.ppid,

				uid: e.header.uid,
				tgid: e.header.tgid,
				comm: Arc::from(String::from_utf8_lossy(&e.header.comm).trim_end_matches('\0')),
			},
		}),
		EbpfEvent::Module(ref e) => CerberusEvent::Module(ModuleEvent {
			module_name: Arc::from(String::from_utf8_lossy(&e.module_name).trim_end_matches('\0')),
			op: e.op,
			header: EventHeader {
				cgroup_id: e.header.cgroup_id,
				container: None,
				ts: e.header.ts,
				mnt_ns: e.header.mnt_ns,
				pid: e.header.pid,
				ppid: e.header.ppid,

				uid: e.header.uid,
				tgid: e.header.tgid,
				comm: Arc::from(String::from_utf8_lossy(&e.header.comm).trim_end_matches('\0')),
			},
		}),

		EbpfEvent::BpfMap(ref e) => CerberusEvent::BpfMap(BpfMapEvent {
			map_id: e.map_id,
			map_type: Arc::from(bpf_map_type_to_str(e.map_type)),
			map_name: Arc::from(String::from_utf8_lossy(&e.map_name).trim_end_matches('\0')),
			header: EventHeader {
				cgroup_id: e.header.cgroup_id,
				container: None,
				ts: e.header.ts,
				mnt_ns: e.header.mnt_ns,
				pid: e.header.pid,
				ppid: e.header.ppid,

				uid: e.header.uid,
				tgid: e.header.tgid,
				comm: Arc::from(String::from_utf8_lossy(&e.header.comm).trim_end_matches('\0')),
			},
		}),
		EbpfEvent::Inode(ref e) => CerberusEvent::Inode(InodeEvent {
			filename: Arc::from(String::from_utf8_lossy(&e.filename).trim_end_matches('\0')),
			filename_len: e.filename_len,
			op: e.op,
			header: EventHeader {
				cgroup_id: e.header.cgroup_id,
				container: None,
				ts: e.header.ts,
				mnt_ns: e.header.mnt_ns,
				pid: e.header.pid,
				ppid: e.header.ppid,

				uid: e.header.uid,
				tgid: e.header.tgid,
				comm: Arc::from(String::from_utf8_lossy(&e.header.comm).trim_end_matches('\0')),
			},
		}),

		EbpfEvent::BprmSecurityCheck(ref e) => {
			let comm_cow = String::from_utf8_lossy(&e.header.comm);
			let comm_str = comm_cow.trim_end_matches('\0');

			let path_len = e.path_len as usize;
			let start = FILE_PATH_LEN.saturating_sub(path_len);
			let path_cow = String::from_utf8_lossy(&e.filepath[start..FILE_PATH_LEN]);
			let filepath_str = path_cow.trim_end_matches('\0');

			CerberusEvent::Bprm(BprmSecurityEvent {
				filepath: Arc::from(filepath_str),
				header: EventHeader {
					cgroup_id: e.header.cgroup_id,
					container: None,
					ts: e.header.ts,
					mnt_ns: e.header.mnt_ns,
					pid: e.header.pid,
					ppid: e.header.ppid,

					uid: e.header.uid,
					tgid: e.header.tgid,
					comm: Arc::from(comm_str),
				},
				path_len: e.path_len,
			})
		}

		EbpfEvent::BpfProgLoad(ref e) => CerberusEvent::BpfProgLoad(BpfProgLoadEvent {
			flags: e.flags,
			attach_type: e.attach_type,
			prog_type: e.prog_type,
			tag: Arc::from(String::from_utf8_lossy(&e.tag).trim_end_matches('\0')),
			header: EventHeader {
				cgroup_id: e.header.cgroup_id,
				container: None,
				ts: e.header.ts,
				mnt_ns: e.header.mnt_ns,
				pid: e.header.pid,
				ppid: e.header.ppid,

				uid: e.header.uid,
				tgid: e.header.tgid,
				comm: Arc::from(String::from_utf8_lossy(&e.header.comm).trim_end_matches('\0')),
			},
		}),

		EbpfEvent::InetSock(ref e) => CerberusEvent::InetSock(InetSockEvent {
			old_state: Arc::from(state_to_str(e.oldstate)),
			new_state: Arc::from(state_to_str(e.newstate)),
			sport: e.sport,
			dport: e.dport,
			protocol: Arc::from(protocol_to_str(e.protocol)),
			saddr: e.saddr,
			daddr: e.daddr,
			header: EventHeader {
				cgroup_id: e.header.cgroup_id,
				container: None,
				ts: e.header.ts,
				mnt_ns: e.header.mnt_ns,
				pid: e.header.pid,
				ppid: e.header.ppid,

				uid: e.header.uid,
				tgid: e.header.tgid,
				comm: Arc::from(String::from_utf8_lossy(&e.header.comm).trim_end_matches('\0')),
			},
		}),
		EbpfEvent::Socket(ref e) => CerberusEvent::Socket(lib_common::event::SocketEvent {
			addr: e.addr,
			port: e.port,
			family: e.family,
			op: e.op,
			header: EventHeader {
				cgroup_id: e.header.cgroup_id,
				container: None,
				ts: e.header.ts,
				mnt_ns: e.header.mnt_ns,
				pid: e.header.pid,
				ppid: e.header.ppid,

				uid: e.header.uid,
				tgid: e.header.tgid,
				comm: Arc::from(String::from_utf8_lossy(&e.header.comm).trim_end_matches('\0')),
			},
		}),
	};

	Ok(cerberus_evt)
}

fn parse_event_from_bytes(data: &[u8]) -> Result<EbpfEvent> {
	let header = lib_ebpf_common::EventHeader::ref_from_prefix(data)
		.map_err(|_| Error::InvalidEventSize)?
		.0;

	match header.event_type {
		1 | 4 => {
			let evt = lib_ebpf_common::GenericEvent::ref_from_prefix(data)
				.map_err(|_| Error::InvalidEventSize)?
				.0;
			Ok(EbpfEvent::Generic(*evt))
		}

		3 => {
			let evt = lib_ebpf_common::SocketEvent::ref_from_prefix(data)
				.map_err(|_| Error::InvalidEventSize)?
				.0;
			Ok(EbpfEvent::Socket(*evt))
		}

		5 => {
			let evt = lib_ebpf_common::ModuleEvent::ref_from_prefix(data)
				.map_err(|_| Error::InvalidEventSize)?
				.0;
			Ok(EbpfEvent::Module(*evt))
		}
		6 => {
			let evt = lib_ebpf_common::InetSockSetStateEvent::ref_from_prefix(data)
				.map_err(|_| Error::InvalidEventSize)?
				.0;
			Ok(EbpfEvent::InetSock(*evt))
		}
		8 => {
			let evt = lib_ebpf_common::BprmSecurityCheckEvent::ref_from_prefix(data)
				.map_err(|_| Error::InvalidEventSize)?
				.0;
			Ok(EbpfEvent::BprmSecurityCheck(*evt))
		}
		9 => {
			let evt = lib_ebpf_common::BpfProgLoadEvent::ref_from_prefix(data)
				.map_err(|_| Error::InvalidEventSize)?
				.0;
			Ok(EbpfEvent::BpfProgLoad(*evt))
		}
		10 => {
			let evt = lib_ebpf_common::InodeEvent::ref_from_prefix(data)
				.map_err(|_| Error::InvalidEventSize)?
				.0;
			Ok(EbpfEvent::Inode(*evt))
		}
		11 => {
			let evt = lib_ebpf_common::BpfMapEvent::ref_from_prefix(data)
				.map_err(|_| Error::InvalidEventSize)?
				.0;
			Ok(EbpfEvent::BpfMap(*evt))
		}
		12 => {
			let evt = lib_ebpf_common::InodeRenameEvent::ref_from_prefix(data)
				.map_err(|_| Error::InvalidEventSize)?
				.0;
			Ok(EbpfEvent::InodeRename(*evt))
		}
		_ => Err(Error::UnknownEventType(header.event_type)),
	}
}

fn state_to_str(state: i32) -> &'static str {
	match state {
		1 => "TCP_ESTABLISHED",
		2 => "TCP_SYN_SENT",
		3 => "TCP_SYN_RECV",
		4 => "TCP_FIN_WAIT1",
		5 => "TCP_FIN_WAIT2",
		6 => "TCP_TIME_WAIT",
		7 => "TCP_CLOSE",
		8 => "TCP_CLOSE_WAIT",
		9 => "TCP_LAST_ACK",
		10 => "TCP_LISTEN",
		11 => "TCP_CLOSING",
		_ => "UNKNOWN",
	}
}

fn protocol_to_str(proto: u16) -> &'static str {
	match proto {
		6 => "TCP",
		17 => "UDP",
		_ => "UNKNOWN",
	}
}

fn bpf_map_type_to_str(map_type: u32) -> &'static str {
	match map_type {
		0 => "UNSPEC",
		1 => "HASH",
		2 => "ARRAY",
		3 => "PROG_ARRAY",
		4 => "PERF_EVENT_ARRAY",
		5 => "PERCPU_HASH",
		6 => "PERCPU_ARRAY",
		7 => "STACK_TRACE",
		8 => "CGROUP_ARRAY",
		9 => "LRU_HASH",
		10 => "LRU_PERCPU_HASH",
		11 => "LPM_TRIE",
		12 => "ARRAY_OF_MAPS",
		13 => "HASH_OF_MAPS",
		14 => "DEVMAP",
		15 => "SOCKMAP",
		16 => "CPUMAP",
		17 => "XSKMAP",
		18 => "SOCKHASH",
		19 => "CGROUP_STORAGE",
		20 => "REUSEPORT_SOCKARRAY",
		21 => "PERCPU_CGROUP_STORAGE",
		22 => "QUEUE",
		23 => "STACK",
		24 => "SK_STORAGE",
		25 => "DEVMAP_HASH",
		26 => "STRUCT_OPS",
		27 => "RINGBUF",
		28 => "INODE_STORAGE",
		29 => "TASK_STORAGE",
		30 => "BLOOM_FILTER",
		31 => "USER_RINGBUF",
		32 => "CGRP_STORAGE",
		33 => "ARENA",
		_ => "UNKNOWN",
	}
}
