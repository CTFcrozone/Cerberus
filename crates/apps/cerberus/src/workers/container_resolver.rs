use crate::error::Result;

use lib_common::event::{CerberusEvent, Event};
use lib_container::container_manager::ContainerManager;

use lib_event::unbound::{Rx, Tx};
use tokio_util::sync::CancellationToken;

pub struct ContainerResolver {
	tx: Tx<CerberusEvent>,
	rx: Rx<CerberusEvent>,
	container_mgr: ContainerManager,
	token: CancellationToken,
}

impl ContainerResolver {
	pub fn start(
		tx: Tx<CerberusEvent>,
		rx: Rx<CerberusEvent>,
		container_mgr: ContainerManager,
		token: CancellationToken,
	) -> Result<Self> {
		Ok(ContainerResolver {
			tx,
			rx,
			container_mgr,
			token,
		})
	}

	pub async fn run(mut self) -> Result<()> {
		loop {
			tokio::select! {
				biased;

				_ = self.token.cancelled() => {
					tracing::info!("[ContainerResolver]: shutting down");
					break;
				}

				res = self.rx.recv() => {
					match res {
						Ok(mut evt) => {
							let meta = evt.header_mut();
							if let Some(info) = self.container_mgr.resolve(meta.cgroup_id).await {
								meta.container = Some(info);
							}
							if let Err(e) = self.tx.send(evt) {
								tracing::error!("ContainerResolver send failed: {e}");
							}
						}
						Err(_) => {
							tracing::info!("[ContainerResolver]: channel closed");
							break;
						}
					}
				}
			}
		}
		Ok(())
	}
}
