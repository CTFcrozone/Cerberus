use crate::{
	error::{Error, Result},
	trx::EventRx,
};
use aya::maps::{MapData, RingBuf};
use lib_common::GenericEvent;
use tokio::io::unix::AsyncFd;
use tracing::info;
use zerocopy::FromBytes;

use crate::trx::EventTx;

use lib_common::{EbpfEvent, InetSockSetStateEvent};

pub struct ReceiverWorker {
	pub rx: EventRx,
}

impl ReceiverWorker {
	pub async fn start(rx: EventRx) -> Result<()> {
		let worker = ReceiverWorker { rx };
		tokio::spawn(async move {
			let res = worker.start_worker().await;
			res
		});
		Ok(())
	}

	pub async fn start_worker(&self) -> Result<()> {
		while let Ok(evt) = self.rx.recv().await {
			match evt {
				EbpfEvent::Generic(g) => {
					let comm_lossy = String::from_utf8_lossy(&g.comm);
					let comm = comm_lossy.trim_end_matches('\0');

					info!(
						"[{}] UID:{} | PID:{} | TGID:{} | CMD:{} | META:{}",
						match_evt_type(g.header.event_type),
						g.uid,
						g.pid,
						g.tgid,
						comm,
						g.meta
					);
				}
				EbpfEvent::InetSock(n) => {
					info!(
						"[INET_SOCK] {}:{} → {}:{} | Proto: {} | {} → {}",
						ip_to_string(n.saddr),
						n.sport,
						ip_to_string(n.daddr),
						n.dport,
						protocol_to_str(n.protocol),
						state_to_str(n.oldstate),
						state_to_str(n.newstate)
					);
				}
			}
		}
		Ok(())
	}
}

pub struct RingBufWorker {
	pub ringbuf_fd: AsyncFd<RingBuf<MapData>>,
	pub tx: EventTx,
}

impl RingBufWorker {
	pub async fn start(ringbuf_fd: AsyncFd<RingBuf<MapData>>, tx: EventTx) -> Result<()> {
		let mut worker = RingBufWorker { ringbuf_fd, tx };
		tokio::spawn(async move {
			let res = worker.start_worker().await;
			res
		});
		Ok(())
	}

	async fn start_worker(&mut self) -> Result<()> {
		let tx = self.tx.clone();
		loop {
			let mut guard = self.ringbuf_fd.readable_mut().await?;
			let ring_buf = guard.get_inner_mut();

			while let Some(item) = ring_buf.next() {
				let data = item.as_ref();

				match parse_event_from_bytes(data) {
					Ok(event) => {
						tx.send(event).await?;
					}
					Err(e) => info!("Failed to parse event: {:?}", e),
				}
			}

			guard.clear_ready();
		}
	}
}

fn parse_event_from_bytes(data: &[u8]) -> Result<EbpfEvent> {
	let header = lib_common::EventHeader::ref_from_prefix(data)
		.map_err(|_| Error::InvalidEventSize)?
		.0;

	match header.event_type {
		1 | 2 | 3 | 4 | 5 => {
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
fn ip_to_string(ip: u32) -> String {
	let octets = ip.to_be_bytes();
	format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])
}

fn protocol_to_str(proto: u16) -> &'static str {
	match proto {
		6 => "TCP",
		17 => "UDP",
		_ => "UNKNOWN",
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

fn match_evt_type(event_type: u8) -> &'static str {
	match event_type {
		1 => "KILL",
		2 => "IO_URING",
		3 => "SOCKET_CONNECT",
		4 => "COMMIT_CREDS",
		5 => "MODULE_INIT",
		6 => "INET_SOCK_SET_STATE",
		_ => "UNKNOWN",
	}
}
