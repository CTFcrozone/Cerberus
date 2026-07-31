use std::{net::Ipv4Addr, sync::Arc, time::Duration};

use crate::{
	error::Result,
	rule::{Action, Response, Trigger},
};

#[cfg_attr(test, derive(PartialEq))]
#[derive(Debug, Clone)]
pub enum CompiledAction {
	KillProcess,
	BlockIp { ip: Ipv4Addr },
	EmitSignal { signal: i32 },
	Notify { message: Arc<str> },
	KvmAction { timeout: Duration, exit_budget: u64 },
}

#[cfg_attr(test, derive(PartialEq))]
#[derive(Debug, Clone)]
pub struct CompiledResponse {
	pub action: CompiledAction,
	pub trigger: Trigger,
}

impl From<Action> for CompiledAction {
	fn from(action: Action) -> Self {
		match action {
			Action::KillProcess => CompiledAction::KillProcess,
			Action::BlockIp { ip } => CompiledAction::BlockIp { ip: Ipv4Addr::from(ip) },
			Action::EmitSignal { signal } => CompiledAction::EmitSignal { signal },
			Action::Notify { message } => CompiledAction::Notify {
				message: message.into(),
			},
			Action::KvmAction {
				timeout_ms,
				exit_budget,
			} => CompiledAction::KvmAction {
				timeout: Duration::from_millis(timeout_ms),
				exit_budget,
			},
		}
	}
}

impl From<Response> for CompiledResponse {
	fn from(response: Response) -> Self {
		CompiledResponse {
			action: response.action.into(),
			trigger: response.trigger,
		}
	}
}

pub fn compile_response(raw: Response) -> Result<CompiledResponse> {
	Ok(raw.into())
}
