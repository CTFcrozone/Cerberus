use std::{
	env::consts::ARCH,
	net::{IpAddr, Ipv4Addr},
	sync::Arc,
};

use crate::{
	core::AppTx,
	error::{Error, Result},
	event::{AppEvent, RingBufEvent},
	trx::EventRx,
};
use aya::maps::{MapData, RingBuf};
use cerberus_common::Event;
use tokio::io::unix::AsyncFd;
use tracing::info;
use zerocopy::FromBytes;

pub struct ReceiverWorker {
	pub rx: EventRx,
	pub app_tx: AppTx,
}

impl ReceiverWorker {
	pub async fn start(rx: EventRx, app_tx: AppTx) -> Result<()> {
		let worker = ReceiverWorker { rx, app_tx };
		tokio::spawn(async move {
			let res = worker.start_worker().await;
			res
		});
		Ok(())
	}

	pub async fn start_worker(&self) -> Result<()> {
		while let Ok(evt) = self.rx.recv().await {
			let comm = Arc::from(String::from_utf8_lossy(&evt.comm).trim_end_matches('\0').as_ref());

			let name: &'static str = match evt.event_type {
				1 => "KILL",
				2 => "IO_URING",
				3 => "SOCKET_CONNECT",
				4 => "COMMIT_CREDS",
				_ => "UNKNOWN",
			};

			let app_evt = AppEvent::Cerberus(RingBufEvent {
				name,
				pid: evt.pid,
				uid: evt.uid,
				tgid: evt.tgid,
				comm,
				meta: evt.meta,
			});

			self.app_tx.send(app_evt).await?;
		}
		Ok(())
	}
}

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
					Ok(evt) => {
						let comm = Arc::from(String::from_utf8_lossy(&evt.comm).trim_end_matches('\0').as_ref());

						let name: &'static str = match evt.event_type {
							1 => "KILL",
							2 => "IO_URING",
							3 => "SOCKET_CONNECT",
							4 => "COMMIT_CREDS",
							_ => "UNKNOWN",
						};

						let app_evt = AppEvent::Cerberus(RingBufEvent {
							name,
							pid: evt.pid,
							uid: evt.uid,
							tgid: evt.tgid,
							comm,
							meta: evt.meta,
						});

						self.tx.send(app_evt).await?;
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
