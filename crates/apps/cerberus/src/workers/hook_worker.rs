use crate::{
	error::Result,
	event::AppEvent,
	hook_registry::{
		event::{HookAction, HookRegistryEvent},
		registry::HookRegistry,
	},
};

use aya::Ebpf;
use lib_common::event::{CerberusEvent, Event};
use lib_container::container_manager::ContainerManager;

use lib_event::unbound::{Rx, Tx};
use tracing::{debug, error};

pub struct HookWorker {
	pub tx: Tx<AppEvent>,
	pub rx: Rx<HookRegistryEvent>,
	registry: HookRegistry,
}

// TODO: make it shutdown aware
impl HookWorker {
	pub fn start(tx: Tx<AppEvent>, rx: Rx<HookRegistryEvent>, registry: HookRegistry) -> Result<Self> {
		Ok(HookWorker { tx, rx, registry })
	}

	pub async fn run(mut self, ebpf: &mut Ebpf) -> Result<()> {
		while let Ok(evt) = self.rx.recv().await {
			match &evt {
				HookRegistryEvent::HookAction { hook, action } => match action {
					HookAction::Disable => {
						if let Err(e) = self.registry.disable(hook, ebpf) {
							error!("HOOK_WORKER --- ERROR: {e}");
						}
					}
					HookAction::Enable => {
						if let Err(e) = self.registry.enable(hook, ebpf) {
							error!("HOOK_WORKER --- ERROR: {e}");
						}
					}
				},
			};
			self.tx.send(evt)?;
		}

		Ok(())
	}
}
