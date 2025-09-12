use std::sync::Arc;

use crate::{
	core::AppTx,
	error::{Error, Result},
};

use aya::maps::{MapData, RingBuf};
use lib_common::{EbpfEvent, EventHeader, GenericEvent, InetSockSetStateEvent};
use lib_event::app_evt_types::{AppEvent, CerberusEvent, InetSockEvent, RingBufEvent};
use tokio::io::unix::AsyncFd;
use tracing::info;
use zerocopy::FromBytes;

// pub struct ReceiverWorker {
// 	pub rx: EventRx,
// 	pub app_tx: AppTx,
// }

// impl ReceiverWorker {
// 	pub async fn start(rx: EventRx, app_tx: AppTx) -> Result<()> {
// 		let worker = ReceiverWorker { rx, app_tx };
// 		tokio::spawn(async move {
// 			let res = worker.start_worker().await;
// 			res
// 		});
// 		Ok(())
// 	}

// 	pub async fn start_worker(&self) -> Result<()> {
// 		while let Ok(evt) = self.rx.recv().await {
// 			let comm = Arc::from(String::from_utf8_lossy(&evt.comm).trim_end_matches('\0').as_ref());

// 			let name: &'static str = match evt.header.event_type {
// 				1 => "KILL",
// 				2 => "IO_URING",
// 				3 => "SOCKET_CONNECT",
// 				4 => "COMMIT_CREDS",
// 				5 => "MODULE_INIT",
// 				6 => "INET_SOCK_SET_STATE",
// 				_ => "UNKNOWN",
// 			};

// 			let app_evt = AppEvent::Cerberus(CerberusEvent::Generic(RingBufEvent {
// 				name,
// 				pid: evt.pid,
// 				uid: evt.uid,
// 				tgid: evt.tgid,
// 				comm,
// 				meta: evt.meta,
// 			}));

// 			self.app_tx.send(app_evt).await?;
// 		}
// 		Ok(())
// 	}
// }

pub struct RingBufWorker {
	pub ringbuf_fd: AsyncFd<RingBuf<MapData>>,
	pub tx: AppTx,
}

impl RingBufWorker {
	pub async fn start(ringbuf_fd: AsyncFd<RingBuf<MapData>>, tx: AppTx) -> Result<()> {
		let mut worker = RingBufWorker { ringbuf_fd, tx };
		tokio::spawn(async move {
			let res = worker.start_worker().await;
			res
		});
		Ok(())
	}

	async fn start_worker(&mut self) -> Result<()> {
		loop {
			let mut guard = self.ringbuf_fd.readable_mut().await?;
			let ring_buf = guard.get_inner_mut();

			while let Some(item) = ring_buf.next() {
				let data = item.as_ref();

				match parse_event_from_bytes(data) {
					Ok(evt) => match evt {
						EbpfEvent::Generic(evt) => {
							let comm = Arc::from(String::from_utf8_lossy(&evt.comm).trim_end_matches('\0').as_ref());

							let name: &'static str = match evt.header.event_type {
								1 => "KILL",
								2 => "IO_URING",
								3 => "SOCKET_CONNECT",
								4 => "COMMIT_CREDS",
								5 => "MODULE_INIT",
								6 => "INET_SOCK_SET_STATE",
								7 => "ENTER_PTRACE",
								_ => "UNKNOWN",
							};

							let app_evt = AppEvent::Cerberus(CerberusEvent::Generic(RingBufEvent {
								name,
								pid: evt.pid,
								uid: evt.uid,
								tgid: evt.tgid,
								comm,
								meta: evt.meta,
							}));

							self.tx.send(app_evt).await?;
						}
						EbpfEvent::InetSock(evt) => {
							let old_state = Arc::from(state_to_str(evt.oldstate));
							let new_state = Arc::from(state_to_str(evt.newstate));
							let protocol = Arc::from(protocol_to_str(evt.protocol));

							let app_evt = AppEvent::Cerberus(CerberusEvent::InetSock(InetSockEvent {
								old_state,
								new_state,
								sport: evt.sport,
								dport: evt.dport,
								protocol,
								saddr: evt.saddr,
								daddr: evt.daddr,
							}));

							self.tx.send(app_evt).await?;
						}
					},
					Err(e) => info!("Failed to parse event: {:?}", e),
				}
			}

			guard.clear_ready();
		}
	}
}

fn parse_event_from_bytes(data: &[u8]) -> Result<EbpfEvent> {
	let header = EventHeader::ref_from_prefix(data).map_err(|_| Error::InvalidEventSize)?.0;

	match header.event_type {
		1 | 3 | 4 | 5 => {
			let evt = GenericEvent::ref_from_prefix(data).map_err(|_| Error::InvalidEventSize)?.0;
			Ok(EbpfEvent::Generic(*evt))
		}
		6 => {
			let evt = InetSockSetStateEvent::ref_from_prefix(data)
				.map_err(|_| Error::InvalidEventSize)?
				.0;
			Ok(EbpfEvent::InetSock(*evt))
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
