use std::sync::Arc;

use crate::{
	core::AppTx,
	error::{Error, Result},
	event::AppEvent,
};

use aya::maps::{MapData, RingBuf};
use lib_common::event::{BprmSecurityEvent, CerberusEvent, InetSockEvent, ModuleEvent, RingBufEvent};
use lib_ebpf_common::{
	BprmSecurityCheckEvent, EbpfEvent, EventHeader, GenericEvent, InetSockSetStateEvent, ModuleInitEvent,
	SocketConnectEvent,
};
use lib_rules::RuleEngine;
use tokio::io::unix::AsyncFd;
use tokio_util::sync::CancellationToken;
use tracing::info;
use zerocopy::FromBytes;

pub struct RingBufWorker {
	pub ringbuf_fd: AsyncFd<RingBuf<MapData>>,
	pub tx: AppTx,
	pub rule_engine: Arc<RuleEngine>,
}

impl RingBufWorker {
	pub fn start(ringbuf_fd: AsyncFd<RingBuf<MapData>>, rule_engine: Arc<RuleEngine>, tx: AppTx) -> Self {
		RingBufWorker {
			ringbuf_fd,
			tx,
			rule_engine,
		}
	}

	// pub async fn _run(mut self) -> Result<()> {
	// 	loop {
	// 		tokio::select! {
	// 			_ = self.shutdown.cancelled() => {
	// 				break;
	// 			}

	// 			ready = self.ringbuf_fd.readable_mut() => {
	// 				let mut guard = ready?;
	// 				let ring_buf = guard.get_inner_mut();

	// 				while let Some(item) = ring_buf.next() {

	// 					let data = item.as_ref();

	// 					if let Ok(evt) = parse_event_from_bytes(data) {
	// 						let cerb = parse_cerberus_event(evt)?;
	// 						for e in self.rule_engine.process_event(&cerb)? {
	// 							self.tx.send(AppEvent::Engine(e)).await?;
	// 						}
	// 						self.tx.send(AppEvent::Cerberus(cerb)).await?;
	// 					}
	// 				}

	// 				guard.clear_ready();
	// 			}
	// 		}
	// 	}

	// 	Ok(())
	// }

	pub async fn run(mut self) -> Result<()> {
		loop {
			let mut guard = match self.ringbuf_fd.readable_mut().await {
				Ok(g) => g,
				Err(_) => break,
			};

			let ring_buf = guard.get_inner_mut();

			while let Some(item) = ring_buf.next() {
				let data = item.as_ref();

				match parse_event_from_bytes(data) {
					Ok(evt) => {
						let cerberus_evt = parse_cerberus_event(evt)?;

						for evt in self.rule_engine.process_event(&cerberus_evt)? {
							self.tx.send(AppEvent::Engine(evt)).await?;
						}

						self.tx.send(AppEvent::Cerberus(cerberus_evt)).await?;
					}
					Err(e) => info!("Failed to parse event: {:?}", e),
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
			pid: e.pid,
			uid: e.uid,
			tgid: e.tgid,
			comm: Arc::from(String::from_utf8_lossy(&e.comm).trim_end_matches('\0')),
			meta: e.meta,
		}),

		EbpfEvent::ModuleInit(ref e) => CerberusEvent::Module(ModuleEvent {
			pid: e.pid,
			uid: e.uid,
			tgid: e.tgid,
			comm: Arc::from(String::from_utf8_lossy(&e.comm).trim_end_matches('\0')),
			module_name: Arc::from(String::from_utf8_lossy(&e.module_name).trim_end_matches('\0')),
		}),

		EbpfEvent::BprmSecurityCheck(ref e) => CerberusEvent::Bprm(BprmSecurityEvent {
			pid: e.pid,
			uid: e.uid,
			tgid: e.tgid,
			comm: Arc::from(String::from_utf8_lossy(&e.comm).trim_end_matches('\0')),
			filepath: Arc::from(String::from_utf8_lossy(&e.filepath).trim_end_matches('\0')),
		}),

		EbpfEvent::InetSock(ref e) => CerberusEvent::InetSock(InetSockEvent {
			old_state: Arc::from(state_to_str(e.oldstate)),
			new_state: Arc::from(state_to_str(e.newstate)),
			sport: e.sport,
			dport: e.dport,
			protocol: Arc::from(protocol_to_str(e.protocol)),
			saddr: e.saddr,
			daddr: e.daddr,
		}),
		EbpfEvent::SocketConnect(ref e) => CerberusEvent::SocketConnect(lib_common::event::SocketConnectEvent {
			addr: e.addr,
			port: e.port,
			family: e.family,
		}),
	};

	Ok(cerberus_evt)
}

fn parse_event_from_bytes(data: &[u8]) -> Result<EbpfEvent> {
	let header = EventHeader::ref_from_prefix(data).map_err(|_| Error::InvalidEventSize)?.0;

	match header.event_type {
		1 | 4 => {
			let evt = GenericEvent::ref_from_prefix(data).map_err(|_| Error::InvalidEventSize)?.0;
			Ok(EbpfEvent::Generic(*evt))
		}

		3 => {
			let evt = SocketConnectEvent::ref_from_prefix(data)
				.map_err(|_| Error::InvalidEventSize)?
				.0;
			Ok(EbpfEvent::SocketConnect(*evt))
		}

		5 => {
			let evt = ModuleInitEvent::ref_from_prefix(data).map_err(|_| Error::InvalidEventSize)?.0;
			Ok(EbpfEvent::ModuleInit(*evt))
		}
		6 => {
			let evt = InetSockSetStateEvent::ref_from_prefix(data)
				.map_err(|_| Error::InvalidEventSize)?
				.0;
			Ok(EbpfEvent::InetSock(*evt))
		}
		8 => {
			let evt = BprmSecurityCheckEvent::ref_from_prefix(data)
				.map_err(|_| Error::InvalidEventSize)?
				.0;
			Ok(EbpfEvent::BprmSecurityCheck(*evt))
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
