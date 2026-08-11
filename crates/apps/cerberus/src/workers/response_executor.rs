use crate::error::Result;
use crate::event::AppEvent;
use aya::maps::HashMap as AyaHashMap;
use aya::maps::MapData;

use lib_event::unbound::Rx;
use lib_event::unbound::Tx;
use lib_rules::ResolvedAction;
use lib_rules::ResponseRequest;
use lib_rules::resolve_action;

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
			let actions = match Self::resolve_actions(&request) {
				Ok(actions) => actions,
				Err(_) => {
					let _ = self.app_tx.send(AppEvent::ResponseExecuted {
						id: request.id,
						rule_id: request.rule_id,
						actions: Vec::new(),
						success: false,
					});
					continue;
				}
			};

			let result = self.execute_actions(&actions);

			let _ = self.app_tx.send(AppEvent::ResponseExecuted {
				id: request.id,
				rule_id: request.rule_id,
				actions,
				success: result.is_ok(),
			});
		}

		Ok(())
	}

	fn execute_actions(&mut self, actions: &[ResolvedAction]) -> Result<()> {
		actions.iter().try_for_each(|action| self.execute_action(action))
	}

	fn resolve_actions(req: &ResponseRequest) -> Result<Vec<ResolvedAction>> {
		req.response_chain
			.actions
			.iter()
			.map(|action| resolve_action(action, &req.fields).map_err(crate::error::Error::from))
			.collect()
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

	fn handle_request(&mut self, req: &ResponseRequest) -> Result<()> {
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
