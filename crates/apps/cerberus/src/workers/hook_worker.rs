use crate::{
	error::Result,
	event::AppEvent,
	hook_registry::{event::HookCommand, registry::HookRegistry},
};

use aya::Ebpf;
use lib_common::event::{CerberusEvent, Event};
use lib_container::container_manager::ContainerManager;

use lib_event::unbound::{Rx, Tx};
use tracing::{debug, error};

pub struct HookWorker {
	pub tx: Tx<AppEvent>,
	pub rx: Rx<HookCommand>,
	registry: HookRegistry,
	ebpf: Ebpf,
}

// TODO: make it shutdown aware
impl HookWorker {
	pub fn start(ebpf: Ebpf, tx: Tx<AppEvent>, rx: Rx<HookCommand>, registry: HookRegistry) -> Result<Self> {
		Ok(HookWorker { ebpf, tx, rx, registry })
	}

	pub async fn run(mut self) -> Result<()> {
		while let Ok(evt) = self.rx.recv().await {
			match evt {
				HookCommand::Enable(hook) => match self.registry.enable(&hook, &mut self.ebpf) {
					Ok(_) => {
						let _ = self.tx.send(AppEvent::HookEnabled { hook });
					}
					Err(e) => {
						let _ = self.tx.send(AppEvent::HookFailed {
							hook,
							error: e.to_string(),
						});
					}
				},
				HookCommand::Disable(hook) => match self.registry.disable(&hook, &mut self.ebpf) {
					Ok(_) => {
						let _ = self.tx.send(AppEvent::HookDisabled { hook });
					}
					Err(e) => {
						let _ = self.tx.send(AppEvent::HookFailed {
							hook,
							error: e.to_string(),
						});
					}
				},
			};
		}
		Ok(())
	}
}
