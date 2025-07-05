use crate::{
	error::{Error, Result},
	trx::EventRx,
};
use aya::maps::{MapData, RingBuf};
use rust_xp_aya_ebpf_common::Event;
use tokio::io::unix::AsyncFd;
use tracing::{debug, info};
use zerocopy::FromBytes;

use crate::trx::{new_trx_pair, EventTx};

pub struct ReceiverWorker {
	pub rx: EventRx,
}

impl ReceiverWorker {
	pub async fn start(rx: EventRx) -> Result<()> {
		tokio::spawn(async move {
			while let Ok(evt) = rx.recv().await {
				// let comm = String::from_utf8_lossy(&evt.comm);
				// let comm = comm.trim_end_matches('\0');
				info!("EVT RECEIVED ->> {evt:?}");
			}
		});
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

	// async fn send_to_channel(&self, evt: Event) -> Result<()> {
	// 	self.tx.send(evt).await
	// }
}

fn parse_event_from_bytes(data: &[u8]) -> Result<Event> {
	let evt = Event::ref_from_prefix(data).map_err(|_| Error::InvalidEventSize)?.0;
	Ok(*evt)
}

// fn parse_event_from_bytes(data: &[u8]) -> Result<Event> {
// 	if data.len() < std::mem::size_of::<Event>() {
// 		return Err(Error::InvalidEventSize);
// 	}

// 	let evt = Event::ref_from_prefix(data).map_err(|_| Error::InvalidEventSize)?.0;
// 	// let event = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const Event) };
// 	Ok(*evt)
// }
