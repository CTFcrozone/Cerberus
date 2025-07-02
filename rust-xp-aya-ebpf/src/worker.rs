use crate::error::{Error, Result};
use aya::maps::RingBuf;
use rust_xp_aya_ebpf_common::Event;
use tokio::io::unix::AsyncFd;

use crate::trx::{new_trx_pair, EventTx};

pub struct RingBufWorker {
	pub ring_buf: RingBuf<Event>,
	pub tx: EventTx,
}

// From aya source code
struct PollFd<T>(T);
fn poll_fd<T>(t: T) -> PollFd<T> {
	PollFd(t)
}
impl<T> PollFd<T> {
	fn readable(&mut self) -> Guard<'_, T> {
		Guard(self)
	}
}
struct Guard<'a, T>(&'a mut PollFd<T>);
impl<T> Guard<'_, T> {
	fn inner_mut(&mut self) -> &mut T {
		let Guard(PollFd(t)) = self;
		t
	}
	fn clear_ready(&mut self) {}
}

impl RingBufWorker {
	pub async fn start(mut ring_buf: RingBuf<Event>, tx: EventTx) -> Result<()> {
		let worker = RingBufWorker { ring_buf, tx };
		todo!()
		// tokio::spawn(async move {
		// 	let res = worker.start_worker().await;
		// 	res
		// });
		// Ok(())
	}

	async fn start_worker(&mut self) -> Result<()> {
		let mut fd = poll_fd(&mut self.ring_buf);
		loop {
			let mut guard = fd.readable();
			let ring_buf = guard.inner_mut();

			while let Some(event) = ring_buf.next() {
				todo!()
			}
		}
	}

	async fn send_to_channel(&self, evt: Event) -> Result<()> {
		self.tx.send(evt).await
	}
}

fn parse_event_from_bytes(data: &[u8]) -> Result<Event> {
	if data.len() < std::mem::size_of::<Event>() {
		return Err(Error::InvalidEventSize);
	}
	let event = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const Event) };
	Ok(event)
}
