use std::time::Duration;

use crate::{error::Result, event::AppEvent};

use lib_common::event::CerberusEvent;
use lib_event::trx::Rx;
use lib_rules::EngineEvent;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

pub async fn _run_agent_sink(rx: Rx<AppEvent>, shutdown: CancellationToken) -> Result<()> {
	loop {
		tokio::select! {
			_ = shutdown.cancelled() => {
				break;
			}

			evt = rx.recv() => {
				match evt {
					Ok(evt) => {
						match evt {
							AppEvent::Engine(e) => {
								print_alert(&e);
							}
							AppEvent::Cerberus(e) => {
								print_event(&e);
							}
							_ => {}
						}
					}
					Err(e) => {
						info!("Event channel closed: {:?}", e);
						break;
					}
				}
			}
		}
	}

	Ok(())
}

pub async fn start_agent(app_rx: Rx<AppEvent>, shutdown: CancellationToken, run_time: Duration) -> Result<()> {
	let sink_shutdown = shutdown.clone();
	let sink_handle = tokio::spawn(async move {
		let _ = _run_agent_sink(app_rx, sink_shutdown).await;
	});

	tokio::time::sleep(run_time).await;
	shutdown.cancel();
	let _ = sink_handle.await;

	Ok(())
}

fn print_alert(e: &EngineEvent) {
	match e {
		EngineEvent::Matched(ev) => {
			warn!(
				"[{}] {} (PID: {}, UID: {})",
				ev.rule_type, ev.rule_id, ev.event_meta.pid, ev.event_meta.uid
			);
		}
		EngineEvent::Correlated(ev) => {
			warn!(
				"[{} -> {}] {} (PID: {}, UID: {})",
				ev.base_rule_id, ev.seq_rule_id, ev.base_rule_hash, ev.event_meta.pid, ev.event_meta.uid
			);
		}
		_ => {}
	}
}

fn print_event(e: &CerberusEvent) {
	match e {
		CerberusEvent::Generic(g) => {
			info!("{}: {} (PID: {}, UID: {})", g.name, g.comm, g.pid, g.uid);
		}
		CerberusEvent::InetSock(i) => {
			info!(
				"{} → {} ({}:{} → {}:{})",
				i.old_state,
				i.new_state,
				ip_to_string(i.saddr),
				i.sport,
				ip_to_string(i.daddr),
				i.dport
			);
		}
		CerberusEvent::Module(m) => {
			info!("{} loaded by {} (PID: {})", m.module_name, m.comm, m.pid);
		}
		CerberusEvent::Bprm(b) => {
			info!("{} executed {} (PID: {})", b.comm, b.filepath, b.pid);
		}
		CerberusEvent::SocketConnect(s) => {
			info!(
				"{}:{} | Family: {}",
				ip_to_string(s.addr),
				s.port,
				family_to_string(s.family),
			);
		}
		_ => {}
	}
}

// TODO: create lib-utils to make the code less redundant

fn ip_to_string(ip: u32) -> String {
	let octets = ip.to_le_bytes();
	format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])
}

fn family_to_string<T: Into<i32>>(family: T) -> &'static str {
	let family = family.into();
	match family {
		libc::AF_UNSPEC => "AF_UNSPEC",         // 0
		libc::AF_UNIX => "AF_UNIX",             // 1 - Unix domain sockets
		libc::AF_INET => "AF_INET",             // 2 - IPv4
		libc::AF_AX25 => "AF_AX25",             // 3 - Amateur Radio AX.25
		libc::AF_IPX => "AF_IPX",               // 4 - IPX - Novell protocols
		libc::AF_APPLETALK => "AF_APPLETALK",   // 5 - Appletalk DDP
		libc::AF_NETROM => "AF_NETROM",         // 6 - From KA9Q: NET/ROM pseudo
		libc::AF_BRIDGE => "AF_BRIDGE",         // 7 - Multiprotocol bridge
		libc::AF_ATMPVC => "AF_ATMPVC",         // 8 - ATM PVCs
		libc::AF_X25 => "AF_X25",               // 9 - Reserved for X.25 project
		libc::AF_INET6 => "AF_INET6",           // 10 - IPv6
		libc::AF_ROSE => "AF_ROSE",             // 11 - Amateur Radio X.25 PLP
		libc::AF_DECnet => "AF_DECnet",         // 12 - Reserved for DECnet project
		libc::AF_NETBEUI => "AF_NETBEUI",       // 13 - Reserved for 802.2LLC project
		libc::AF_SECURITY => "AF_SECURITY",     // 14 - Security callback pseudo AF
		libc::AF_KEY => "AF_KEY",               // 15 - PF_KEY key management API
		libc::AF_NETLINK => "AF_NETLINK",       // 16 - Netlink
		libc::AF_PACKET => "AF_PACKET",         // 17 - Packet family
		libc::AF_ASH => "AF_ASH",               // 18 - Ash
		libc::AF_ECONET => "AF_ECONET",         // 19 - Acorn Econet
		libc::AF_ATMSVC => "AF_ATMSVC",         // 20 - ATM SVCs
		libc::AF_RDS => "AF_RDS",               // 21 - RDS sockets
		libc::AF_SNA => "AF_SNA",               // 22 - Linux SNA Project
		libc::AF_IRDA => "AF_IRDA",             // 23 - IRDA sockets
		libc::AF_PPPOX => "AF_PPPOX",           // 24 - PPPoX sockets
		libc::AF_WANPIPE => "AF_WANPIPE",       // 25 - Wanpipe API sockets
		libc::AF_LLC => "AF_LLC",               // 26 - Linux LLC
		libc::AF_IB => "AF_IB",                 // 27 - Native InfiniBand address
		libc::AF_MPLS => "AF_MPLS",             // 28 - MPLS
		libc::AF_CAN => "AF_CAN",               // 29 - Controller Area Network
		libc::AF_TIPC => "AF_TIPC",             // 30 - TIPC sockets
		libc::AF_BLUETOOTH => "AF_BLUETOOTH",   // 31 - Bluetooth sockets
		libc::AF_IUCV => "AF_IUCV",             // 32 - IUCV sockets
		libc::AF_RXRPC => "AF_RXRPC",           // 33 - RxRPC sockets
		libc::AF_ISDN => "AF_ISDN",             // 34 - mISDN sockets
		libc::AF_PHONET => "AF_PHONET",         // 35 - Phonet sockets
		libc::AF_IEEE802154 => "AF_IEEE802154", // 36 - IEEE 802.15.4 sockets
		libc::AF_CAIF => "AF_CAIF",             // 37 - CAIF sockets
		libc::AF_ALG => "AF_ALG",               // 38 - Algorithm sockets
		libc::AF_NFC => "AF_NFC",               // 39 - NFC sockets
		libc::AF_XDP => "AF_XDP",               // 40 - XDP sockets
		_ => "UNKNOWN_FAMILY",
	}
}
