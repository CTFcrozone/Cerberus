use std::net::Ipv4Addr;

use crate::{
	error::Result,
	rule::{Action, ResponseChain, Trigger},
};

#[cfg_attr(test, derive(PartialEq))]
#[derive(Debug, Clone)]
pub enum CompiledAction {
	KillProcess,
	BlockIp { ip: Ipv4Addr },
}

#[cfg_attr(test, derive(PartialEq))]
#[derive(Debug, Clone)]
pub struct CompiledResponseChain {
	pub trigger: Trigger,
	pub actions: Vec<CompiledAction>,
}

impl From<ResponseChain> for CompiledResponseChain {
	fn from(chain: ResponseChain) -> Self {
		Self {
			trigger: chain.trigger,
			actions: chain.actions.into_iter().map(CompiledAction::from).collect(),
		}
	}
}

impl From<Action> for CompiledAction {
	fn from(action: Action) -> Self {
		match action {
			Action::KillProcess => CompiledAction::KillProcess,
			Action::BlockIp { ip } => CompiledAction::BlockIp { ip: Ipv4Addr::from(ip) },
		}
	}
}

pub fn compile_response_chain(raw: ResponseChain) -> Result<CompiledResponseChain> {
	Ok(raw.into())
}
