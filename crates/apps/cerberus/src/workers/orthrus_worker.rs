use std::{
	sync::{
		Arc,
		atomic::{AtomicUsize, Ordering},
	},
	time::Duration,
};

use lib_common::event::{CerberusEvent, TamperEvent};
use lib_event::unbound::Tx;
use lib_orthrus::{consts::*, enums::TamperKind};
use lib_rules::Severity;
use neli::{
	consts::{nl::NlmF, socket::NlFamily},
	genl::{AttrTypeBuilder, Genlmsghdr, GenlmsghdrBuilder, NlattrBuilder, NoUserHeader},
	nl::NlPayload,
	router::asynchronous::{NlRouter, NlRouterReceiverHandle},
	types::{Buffer, GenlBuffer},
	utils::Groups,
};
use tokio_util::sync::CancellationToken;

use crate::{Error, Result};

pub type ProgCount = Arc<AtomicUsize>;
type OrthrusGenl = Genlmsghdr<u8, u16, NoUserHeader>;

pub struct OrthrusWorker {
	router: Arc<NlRouter>,
	multicast: NlRouterReceiverHandle<u16, OrthrusGenl>,
	family_id: u16,
	prog_count: ProgCount,
	tx: Tx<CerberusEvent>,
	token: CancellationToken,
}

impl OrthrusWorker {
	pub async fn start(tx: Tx<CerberusEvent>, prog_count: ProgCount, token: CancellationToken) -> Result<Self> {
		let (router, multicast) = NlRouter::connect(NlFamily::Generic, None, Groups::empty())
			.await
			.map_err(|e| Error::NeliRouter(e.to_string()))?;
		let router = Arc::new(router);

		let family_id = router
			.resolve_genl_family(ORTHRUS_GENL_NAME)
			.await
			.map_err(|e| Error::NeliRouter(e.to_string()))?;
		let grp = router
			.resolve_nl_mcast_group(ORTHRUS_GENL_NAME, ORTHRUS_MCGRP_TAMPER)
			.await
			.map_err(|e| Error::NeliRouter(e.to_string()))?;
		router
			.add_mcast_membership(Groups::new_groups(&[grp]))
			.map_err(|e| Error::NeliRouter(e.to_string()))?;

		Ok(Self {
			router,
			multicast,
			family_id,
			prog_count,
			tx,
			token,
		})
	}
	pub fn into_tasks(
		self,
	) -> (
		impl Future<Output = Result<()>> + Send + 'static,
		impl Future<Output = Result<()>> + Send + 'static,
	) {
		let Self {
			router,
			multicast,
			family_id,
			prog_count,
			tx,
			token,
		} = self;

		let hb_token = token.clone();
		let heartbeat = async move {
			Self::heartbeat_loop(router, family_id, prog_count, Duration::from_secs(3), hb_token).await;
			Ok(())
		};

		let listener = async move { Self::event_listener(multicast, tx, token).await };

		(heartbeat, listener)
	}

	fn parse_event(nlmsg: &neli::nl::Nlmsghdr<u16, OrthrusGenl>) -> Option<OrthrusEvent> {
		let genl = match nlmsg.nl_payload() {
			neli::nl::NlPayload::Payload(g) => g,
			_ => return None,
		};
		if *genl.cmd() != ORTHRUS_CMD_EVENT {
			return None;
		}

		let handle = genl.attrs().get_attr_handle();
		let sev_raw = handle.get_attr_payload_as::<u8>(ORTHRUS_ATTR_SEVERITY).ok()?;
		let kind_raw = handle.get_attr_payload_as::<u8>(ORTHRUS_ATTR_KIND).unwrap_or(0);
		let severity = match severity_from_wire(sev_raw) {
			Some(s) => s,
			None => {
				return None;
			}
		};
		let kind = match kind_from_wire(kind_raw) {
			Some(k) => k,
			None => {
				return None;
			}
		};
		let age_ms = handle.get_attr_payload_as::<u64>(ORTHRUS_ATTR_AGE_MS).unwrap_or(0);
		let reason = handle
			.get_attr_payload_as_with_len::<String>(ORTHRUS_ATTR_REASON)
			.unwrap_or_default();

		Some(OrthrusEvent {
			severity,
			kind,
			reason,
			age_ms,
		})
	}
	async fn send_heartbeat(router: &NlRouter, family_id: u16, pid: u32, n_progs: u32) -> Result<()> {
		let mut attrs: GenlBuffer<u16, Buffer> = GenlBuffer::new();
		attrs.push(
			NlattrBuilder::default()
				.nla_type(
					AttrTypeBuilder::default()
						.nla_type(ORTHRUS_ATTR_PID)
						.build()
						.map_err(|e| Error::NeliAttrTypeBuilder(e.to_string()))?,
				)
				.nla_payload(pid)
				.build()
				.map_err(|e| Error::NeliAttrTypeBuilder(e.to_string()))?,
		);
		attrs.push(
			NlattrBuilder::default()
				.nla_type(
					AttrTypeBuilder::default()
						.nla_type(ORTHRUS_ATTR_N_PROGS)
						.build()
						.map_err(|e| Error::NeliAttrTypeBuilder(e.to_string()))?,
				)
				.nla_payload(n_progs)
				.build()
				.map_err(|e| Error::NeliAttrTypeBuilder(e.to_string()))?,
		);
		let genl = GenlmsghdrBuilder::<u8, u16, NoUserHeader>::default()
			.cmd(ORTHRUS_CMD_HEARTBEAT)
			.version(ORTHRUS_GENL_VERSION)
			.attrs(attrs)
			.build()
			.map_err(|e| Error::NeliMsgHdrBuilder(e.to_string()))?;

		let _recv: NlRouterReceiverHandle<u16, OrthrusGenl> = router
			.send(family_id, NlmF::REQUEST, NlPayload::Payload(genl))
			.await
			.map_err(|e| Error::NeliRouter(e.to_string()))?;

		Ok(())
	}
	fn to_cerberus(ev: &OrthrusEvent) -> CerberusEvent {
		CerberusEvent::Tamper(TamperEvent::new(
			"orthrus",
			ev.severity as u8,
			ev.kind as u8,
			Arc::from(ev.reason.as_str()),
			ev.age_ms,
			std::process::id(),
		))
	}

	async fn heartbeat_loop(
		router: Arc<NlRouter>,
		family_id: u16,
		prog_count: ProgCount,
		interval: Duration,
		token: CancellationToken,
	) {
		let mut ticker = tokio::time::interval(interval);
		let pid = std::process::id();

		loop {
			tokio::select! {
				biased;
				_ = token.cancelled() => {
					tracing::info!("[orthrus]: heartbeat task shutting down");
					break;
				}
				_ = ticker.tick() => {
					let n = prog_count.load(Ordering::Relaxed) as u32;
					if let Err(e) = Self::send_heartbeat(&router, family_id, pid, n).await {
						tracing::warn!(error = %e, "[orthrus]: heartbeat send failed");
					}
				}
			}
		}
	}

	async fn event_listener(
		mut multicast: NlRouterReceiverHandle<u16, OrthrusGenl>,
		tx: Tx<CerberusEvent>,
		token: CancellationToken,
	) -> Result<()> {
		loop {
			tokio::select! {
				biased;
				_ = token.cancelled() => {
					tracing::info!("[orthrus]: event listener shutting down");
					break;
				}
				msg = multicast.next::<u16, OrthrusGenl>() => {
					match msg {
						Some(Ok(nlmsg)) => {
							if let Some(ev) = Self::parse_event(&nlmsg) {
								if let Err(e) = tx.send(Self::to_cerberus(&ev)) {
									tracing::error!(error = %e,
										"[orthrus]: failed to inject tamper event");
								}
							}
						}
						Some(Err(e)) => {
							tracing::error!(error = %e, "[orthrus]: recv error");
							tokio::time::sleep(Duration::from_millis(500)).await;
						}
						None => {
							tracing::info!("[orthrus]: multicast stream closed");
							break;
						}
					}
				}

			}
		}
		Ok(())
	}
}

struct OrthrusEvent {
	severity: Severity,
	kind: TamperKind,
	reason: String,
	age_ms: u64,
}

fn severity_from_wire(v: u8) -> Option<Severity> {
	match v {
		0 => Some(Severity::Info),
		1 => Some(Severity::VeryLow),
		2 => Some(Severity::Low),
		3 => Some(Severity::Medium),
		4 => Some(Severity::High),
		5 => Some(Severity::Critical),
		_ => None,
	}
}

fn kind_from_wire(v: u8) -> Option<TamperKind> {
	match v {
		0 => Some(TamperKind::HeartbeatStale),
		1 => Some(TamperKind::ProgsDropped),
		2 => Some(TamperKind::ProgsZero),
		3 => Some(TamperKind::WatchdogUnloading),
		_ => None,
	}
}
