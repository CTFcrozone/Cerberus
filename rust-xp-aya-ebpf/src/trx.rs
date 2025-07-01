use crate::Result;
use flume::{Receiver, Sender};
use rust_xp_aya_ebpf_common::Event;

pub struct EventTx {
	tx: Sender<Event>,
}

impl EventTx {
	pub async fn send(&self, item: Event) -> Result<()> {
		match self.tx.send_async(item.into()).await {
			Ok(_) => Ok(()),
			Err(ex) => Err(ex.into()),
		}
	}
}

pub struct EventRx {
	rx: Receiver<Event>,
}

impl EventRx {
	pub async fn recv(&self) -> Result<Event> {
		let res = self.rx.recv_async().await?;
		Ok(res)
	}
}

pub fn new_trx_pair() -> (EventTx, EventRx) {
	let (tx, rx) = flume::unbounded::<Event>();

	let evt_tx = EventTx { tx };

	let evt_rx = EventRx { rx };

	(evt_tx, evt_rx)
}
