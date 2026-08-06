use crate::error::Result;

use lib_common::event::{CerberusEvent, Event};
use lib_container::container_manager::ContainerManager;

use lib_event::unbound::{Rx, Tx};
use tracing::debug;

pub struct ContainerResolver {
	pub tx: Tx<CerberusEvent>,
	pub rx: Rx<CerberusEvent>,
	container_mgr: ContainerManager,
}

impl ContainerResolver {
	pub fn start(tx: Tx<CerberusEvent>, rx: Rx<CerberusEvent>, container_mgr: ContainerManager) -> Result<Self> {
		Ok(ContainerResolver { tx, rx, container_mgr })
	}

	pub async fn run(mut self) -> Result<()> {
		while let Ok(mut evt) = self.rx.recv().await {
			let meta = evt.header_mut();

			if let Some(info) = self.container_mgr.resolve(meta.cgroup_id).await {
				debug!("{info:?}");
				meta.container = Some(info);
			}

			self.tx.send(evt)?;
		}

		Ok(())
	}
}
