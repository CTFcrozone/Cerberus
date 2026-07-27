use std::{net::Ipv4Addr, sync::Arc, time::Duration};

use crate::{error::Result, rule::Response};

#[cfg_attr(test, derive(PartialEq))]
#[derive(Debug, Clone)]
pub enum CompiledResponse {
	KillProcess,
	BlockIp { ip: Ipv4Addr, duration: Duration },
	EmitSignal { signal: i32 },
	Notify { message: Arc<str> },
	KvmAction { timeout: Duration, exit_budget: u64 },
}

pub fn compile_response(raw: Response) -> Result<CompiledResponse> {
	Ok(match raw {
		Response::KillProcess => CompiledResponse::KillProcess,

		Response::BlockIp { ip, _duration_secs } => CompiledResponse::BlockIp {
			ip: Ipv4Addr::from(ip),
			duration: Duration::from_secs(_duration_secs),
		},

		Response::EmitSignal { signal } => CompiledResponse::EmitSignal { signal },

		Response::Notify { message } => CompiledResponse::Notify {
			message: message.into(),
		},

		Response::KvmAction {
			timeout_ms,
			exit_budget,
		} => CompiledResponse::KvmAction {
			timeout: Duration::from_millis(timeout_ms),
			exit_budget,
		},
	})
}
