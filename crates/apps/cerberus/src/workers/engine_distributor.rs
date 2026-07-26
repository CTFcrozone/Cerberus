use crate::error::Result;
use aya::maps::HashMap as AyaHashMap;
use aya::maps::MapData;

use lib_event::unbound::Rx;
use lib_event::unbound::Tx;
use lib_rules::EngineEvent;
use lib_rules::{Response, ResponseRequest};

pub struct EngineDistributor {
	evt_rx: Rx<EngineEvent>,
	executor_tx: Tx<ResponseRequest>,
}

// TODO: make it shutdown aware
impl EngineDistributor {
	pub fn start(evt_rx: Rx<EngineEvent>, executor_tx: Tx<ResponseRequest>) -> Result<Self> {
		Ok(Self { evt_rx, executor_tx })
	}
	pub async fn run(mut self) -> Result<()> {
		while let Ok(evt) = self.evt_rx.recv().await {
			self.handle_event(evt)?;
		}
		Ok(())
	}

	fn handle_event(&self, evt: EngineEvent) -> Result<()> {
		match evt {
			EngineEvent::Response(resp) => {
				self.executor_tx.send(resp)?;
			}
			_ => {}
		}
		Ok(())
	}
}
