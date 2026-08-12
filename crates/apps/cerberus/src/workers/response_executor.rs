use std::sync::Arc;

use crate::error::Result;
use crate::event::AppEvent;
use aya::maps::HashMap as AyaHashMap;
use aya::maps::MapData;

use lib_event::unbound::Rx;
use lib_event::unbound::Tx;
use lib_rules::ResolvedAction;
use lib_rules::ResponseRequest;
use lib_rules::resolve_action;
use time::OffsetDateTime;

pub struct ResponseExecutor {
	req_rx: Rx<ResponseRequest>,
	ip_blocklist: AyaHashMap<MapData, u32, u32>,
	lsm_exec_deny: AyaHashMap<MapData, [u8; 128], u8>,
	app_tx: Tx<AppEvent>,
}

impl ResponseExecutor {
	pub fn start(
		req_rx: Rx<ResponseRequest>,
		ip_blocklist: AyaHashMap<MapData, u32, u32>,
		lsm_exec_deny: AyaHashMap<MapData, [u8; 128], u8>,
		app_tx: Tx<AppEvent>,
	) -> Result<Self> {
		Ok(Self {
			req_rx,
			app_tx,
			ip_blocklist,
			lsm_exec_deny,
		})
	}
	pub async fn run(mut self) -> Result<()> {
		while let Ok(request) = self.req_rx.recv().await {
			let resolved: Result<Vec<ResolvedAction>> = request
				.response_chain
				.actions
				.iter()
				.map(|a| resolve_action(a, &request.fields).map_err(Into::into))
				.collect();

			let (actions, success) = match resolved {
				Ok(actions) => {
					let ok = self.execute_actions(&actions).is_ok();
					(Arc::from(actions), ok)
				}
				Err(_) => (Arc::from([]), false),
			};

			let _ = self.app_tx.send(AppEvent::ResponseExecuted {
				rule_id: request.rule_id,
				actions,
				time: OffsetDateTime::now_local().unwrap_or_else(|_| OffsetDateTime::now_utc()),
				success,
			});
		}

		Ok(())
	}

	fn execute_actions(&mut self, actions: &[ResolvedAction]) -> Result<()> {
		actions.iter().try_for_each(|action| self.execute_action(action))
	}

	fn execute_action(&mut self, action: &ResolvedAction) -> Result<()> {
		match action {
			ResolvedAction::BlockIp { ip } => {
				self.ip_blocklist.insert(ip.to_bits(), 1, 0)?;
			}

			ResolvedAction::KillProcess { pid } => {
				Self::kill_process(*pid)?;
			}

			ResolvedAction::DenyExec { path_key } => {
				self.lsm_exec_deny.insert(path_key, 1, 0)?;
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
