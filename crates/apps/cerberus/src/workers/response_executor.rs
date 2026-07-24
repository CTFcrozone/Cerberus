use crate::error::Result;
use aya::maps::HashMap as AyaHashMap;
use aya::maps::MapData;

use lib_event::unbound::Rx;
use lib_rules::{Response, ResponseRequest};

pub struct ResponseExecutor {
	req_rx: Rx<ResponseRequest>,
	ip_blocklist: AyaHashMap<MapData, u32, u32>,
}

// TODO: make it shutdown aware
impl ResponseExecutor {
	pub fn start(req_rx: Rx<ResponseRequest>, ip_blocklist: AyaHashMap<MapData, u32, u32>) -> Result<Self> {
		Ok(Self { req_rx, ip_blocklist })
	}
	pub async fn run(mut self) -> Result<()> {
		while let Ok(request) = self.req_rx.recv().await {
			self.handle_request(request)?;
		}
		Ok(())
	}

	fn handle_request(&mut self, req: ResponseRequest) -> Result<()> {
		match req.response {
			Response::BlockIp { ip, _duration_secs } => {
				self.ip_blocklist.insert(ip, 1, 0)?;
			}
			_ => {}
		}
		Ok(())
	}
	fn is_blocked(&self, ip: u32) -> Result<bool> {
		match self.ip_blocklist.get(&ip, 0) {
			Ok(value) => Ok(value == 1),
			Err(aya::maps::MapError::KeyNotFound) => Ok(false),
			Err(e) => Err(e.into()),
		}
	}
}
