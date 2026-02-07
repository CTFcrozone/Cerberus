use std::sync::Arc;

use crate::error::{Error, Result};

use aya::maps::{MapData, RingBuf};
use lib_common::event::{BprmSecurityEvent, CerberusEvent, InetSockEvent, ModuleEvent, RingBufEvent};
use lib_container::{container::ContainerInfo, container_manager::ContainerManager};
use lib_ebpf_common::{
	BprmSecurityCheckEvent, EbpfEvent, EventHeader, GenericEvent, InetSockSetStateEvent, ModuleInitEvent,
	SocketConnectEvent,
};
use lib_event::trx::{Rx, Tx};
use tokio::io::unix::AsyncFd;

use zerocopy::FromBytes;

pub struct ContainerResolver {
	pub tx: Tx<CerberusEvent>,
	pub rx: Rx<CerberusEvent>,
	container_mgr: ContainerManager,
}

// TODO: make it shutdown aware
impl ContainerResolver {
	pub fn start(tx: Tx<CerberusEvent>, rx: Rx<CerberusEvent>, container_mgr: ContainerManager) -> Result<Self> {
		Ok(ContainerResolver { tx, rx, container_mgr })
	}

	pub async fn run(mut self) -> Result<()> {
		while let Ok(mut evt) = self.rx.recv().await {
			let meta = evt.meta_mut();

			if let Some(info) = self.container_mgr.resolve(meta.cgroup_id).await {
				meta.container = Some(info.clone());
			}

			self.tx.send(evt).await?;
		}

		Ok(())
	}
}
