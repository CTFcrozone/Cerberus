// use crate::Result;
// use cerberus_common::GenericEvent;
// use flume::{Receiver, Sender};

// #[derive(Clone)]
// pub struct EventTx {
// 	tx: Sender<GenericEvent>,
// }

// impl EventTx {
// 	pub async fn send(&self, item: GenericEvent) -> Result<()> {
// 		match self.tx.send_async(item.into()).await {
// 			Ok(_) => Ok(()),
// 			Err(ex) => Err(ex.into()),
// 		}
// 	}
// }

// pub struct EventRx {
// 	rx: Receiver<GenericEvent>,
// }

// impl EventRx {
// 	pub async fn recv(&self) -> Result<GenericEvent> {
// 		let res = self.rx.recv_async().await?;
// 		Ok(res)
// 	}
// }

// pub fn new_trx_pair() -> (EventTx, EventRx) {
// 	let (tx, rx) = flume::unbounded::<GenericEvent>();

// 	let evt_tx = EventTx { tx };

// 	let evt_rx = EventRx { rx };

// 	(evt_tx, evt_rx)
// }
