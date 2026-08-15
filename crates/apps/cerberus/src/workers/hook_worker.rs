use crate::{
	error::Result,
	event::AppEvent,
	hook_registry::{event::HookCommand, registry::HookRegistry},
};

use aya::Ebpf;

use lib_event::unbound::{Rx, Tx};
use tokio_util::sync::CancellationToken;

pub struct HookWorker {
	tx: Tx<AppEvent>,
	rx: Rx<HookCommand>,
	registry: HookRegistry,
	ebpf: Ebpf,
	token: CancellationToken,
}

impl HookWorker {
	pub fn start(
		ebpf: Ebpf,
		tx: Tx<AppEvent>,
		rx: Rx<HookCommand>,
		registry: HookRegistry,
		token: CancellationToken,
	) -> Result<Self> {
		Ok(HookWorker {
			ebpf,
			tx,
			rx,
			registry,
			token,
		})
	}

	pub async fn run(mut self) -> Result<()> {
		loop {
			tokio::select! {
				biased;

				_ = self.token.cancelled() => {
					tracing::info!("[HookWorker]: shutting down");
					break;
				}

				res = self.rx.recv() => {
					match res {
						Ok(evt) => {
							match evt {
								HookCommand::Enable(hook) => match self.registry.enable(&hook, &mut self.ebpf) {
									Ok(_) => {
										if let Err(e) = self.tx.send(AppEvent::HookEnabled { hook }) {
											tracing::error!("HookWorker send failed: {e}");
										}
									}
									Err(e) => {
										if let Err(e) = self.tx.send(AppEvent::HookFailed {	hook, error: e.to_string() }) {
											tracing::error!("HookWorker send failed: {e}");
										}
									}
								},
								HookCommand::Disable(hook) => match self.registry.disable(&hook, &mut self.ebpf) {
									Ok(_) => {
										if let Err(e) = self.tx.send(AppEvent::HookDisabled { hook }) {
											tracing::error!("HookWorker send failed: {e}");
										}
									}
									Err(e) => {
										if let Err(e) = self.tx.send(AppEvent::HookFailed {	hook,	error: e.to_string(),}) {
											tracing::error!("HookWorker send failed: {e}");
										}
									}
								},
							};
						}
						Err(_) => {
							tracing::info!("[HookWorker]: channel closed");
							break;
						}
					}
				}
			}
		}
		Ok(())
	}
}
