use std::net::{IpAddr, Ipv4Addr};

use crate::{
	error::{Error, Result},
	trx::EventRx,
};
use aya::maps::{MapData, RingBuf};
use dns_lookup::lookup_addr;
use libc::getnameinfo;
use rust_xp_aya_ebpf_common::Event;
use tokio::io::unix::AsyncFd;
use tracing::info;
use zerocopy::FromBytes;

use crate::trx::EventTx;

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
			let comm = String::from_utf8_lossy(&evt.comm);
			let comm = comm.trim_end_matches('\0');

			let (event_name, detail) = match evt.event_type {
				1 => ("KILL", format!("Signal: {}", evt.meta)),
				2 => ("IO_URING", format!("Opcode: {}", evt.meta)),
				3 => {
					let ip_bytes = evt.meta.to_be_bytes();
					let ipaddr = Ipv4Addr::from(ip_bytes);
					let ipaddr = IpAddr::V4(ipaddr);
					let host = lookup_addr(&ipaddr)?;
					let ip_str = format!("{}.{}.{}.{}", ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
					(
						"SOCKET_CONNECT",
						format!("Destination IP: {} | HOSTNAME: {}", ip_str, host),
					)
				}
				4 => ("COMMIT_CREDS", format!("Meta: {}", evt.meta)),
				_ => ("UNKNOWN", format!("meta: {}", evt.meta)),
			};

			info!(
				"EVT RECEIVED ->> {} | PID: {} | UID: {} | CMD: {} | {}",
				event_name, evt.pid, evt.uid, comm, detail
			);
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

fn parse_event_from_bytes(data: &[u8]) -> Result<Event> {
	let evt = Event::ref_from_prefix(data).map_err(|_| Error::InvalidEventSize)?.0;
	Ok(*evt)
}
