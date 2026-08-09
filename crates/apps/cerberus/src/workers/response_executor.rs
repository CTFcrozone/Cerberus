use crate::error::Result;
use aya::maps::HashMap as AyaHashMap;
use aya::maps::MapData;

use lib_event::unbound::Rx;
use lib_rules::ResolvedAction;
use lib_rules::ResponseRequest;
use lib_rules::resolve_action;

pub struct ResponseExecutor {
	req_rx: Rx<ResponseRequest>,
	ip_blocklist: AyaHashMap<MapData, u32, u32>,
	lsm_exec_deny: AyaHashMap<MapData, [u8; 128], u8>,
}

impl ResponseExecutor {
	pub fn start(
		req_rx: Rx<ResponseRequest>,
		ip_blocklist: AyaHashMap<MapData, u32, u32>,
		lsm_exec_deny: AyaHashMap<MapData, [u8; 128], u8>,
	) -> Result<Self> {
		Ok(Self {
			req_rx,
			ip_blocklist,
			lsm_exec_deny,
		})
	}
	pub async fn run(mut self) -> Result<()> {
		while let Ok(request) = self.req_rx.recv().await {
			self.handle_request(request)?;
		}
		Ok(())
	}

	fn handle_request(&mut self, req: ResponseRequest) -> Result<()> {
		for action in &req.response_chain.actions {
			let action = resolve_action(action, &req.fields)?;
			match action {
				ResolvedAction::BlockIp { ip } => {
					self.ip_blocklist.insert(ip.to_bits(), 1, 0)?;
				}

				ResolvedAction::KillProcess { pid } => {
					Self::kill_process(pid)?;
				}
				ResolvedAction::DenyExec { path_key } => {
					self.lsm_exec_deny.insert(path_key, 1, 0)?;
				}
			}
		}
		Ok(())
	}

	fn kill_process(pid: u32) -> Result<()> {
		let ret = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };

		if ret == 0 {
			Ok(())
		} else {
			Err(std::io::Error::last_os_error().into())
		}
	}

	#[allow(unused)]
	fn is_blocked(&self, ip: u32) -> Result<bool> {
		match self.ip_blocklist.get(&ip, 0) {
			Ok(value) => Ok(value == 1),
			Err(aya::maps::MapError::KeyNotFound) => Ok(false),
			Err(e) => Err(e.into()),
		}
	}
}
