use aya_ebpf::{
	bindings::xdp_action,
	helpers::{
		bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
		generated::{bpf_get_current_cgroup_id, bpf_ktime_get_ns},
	},
	programs::{LsmContext, TracePointContext, XdpContext},
};
use lib_ebpf_common::{
	EVT_INET_SOCK_SET_STATE, EVT_SOCKET, EventHeader, InetSockSetStateEvent, SOCKET_OP_BIND, SOCKET_OP_CONNECT,
	SocketEvent,
};
use network_types::{
	eth::{EthHdr, EtherType},
	ip::Ipv4Hdr,
};

use crate::{
	BLOCKLIST, EVT_MAP,
	utils::{get_mnt_ns, get_ppid, ptr_at},
	vmlinux::{sockaddr, sockaddr_in},
};

const AF_INET: u16 = 2;

fn block_ip(addr: u32) -> bool {
	unsafe { BLOCKLIST.get(&addr).is_some() }
}

pub fn try_socket_connect(ctx: LsmContext) -> Result<i32, i32> {
	let addr: *const sockaddr = ctx.arg(1);
	let ret: i32 = ctx.arg(3);

	if addr.is_null() {
		return Ok(0);
	}

	if ret != 0 {
		return Ok(ret);
	}

	let sa_family = unsafe { (*addr).sa_family };
	if sa_family != AF_INET {
		return Ok(0);
	}

	let addr_in = addr as *const sockaddr_in;

	if addr_in.is_null() {
		return Ok(0);
	}

	let addr = unsafe { (*addr_in).sin_addr.s_addr };
	let port = unsafe { (*addr_in).sin_port };
	let family = unsafe { (*addr_in).sin_family };
	let ts = unsafe { bpf_ktime_get_ns() };
	let uid = bpf_get_current_uid_gid() as u32;
	let pid = bpf_get_current_pid_tgid() as u32;
	let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
	let comm_raw = bpf_get_current_comm().unwrap_or([0u8; 16]);
	let ppid = unsafe { get_ppid() };

	let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
	let mnt_ns = unsafe { get_mnt_ns() };

	let event = SocketEvent {
		header: EventHeader {
			ts,
			event_type: EVT_SOCKET,
			cgroup_id,
			mnt_ns,
			pid,
			ppid: ppid as u32,
			uid,
			tgid,
			comm: comm_raw,
			_pad0: [0u8; 3],
		},
		addr,
		port,
		family,
		op: SOCKET_OP_CONNECT,
		_pad0: [0u8; 7],
	};

	// if let Err(e) = EVT_MAP.output::<SocketEvent>(&event, 0) {
	// 	error!(&ctx, "ringbuf write failed: {}", e);
	// }
	let _ = EVT_MAP.output::<SocketEvent>(&event, 0);
	Ok(0)
}

pub fn try_socket_bind(ctx: LsmContext) -> Result<i32, i32> {
	let addr: *const sockaddr = ctx.arg(1);
	let ret: i32 = ctx.arg(3);

	if addr.is_null() {
		return Ok(0);
	}

	if ret != 0 {
		return Ok(ret);
	}

	let sa_family = unsafe { (*addr).sa_family };
	if sa_family != AF_INET {
		return Ok(0);
	}

	let addr_in = addr as *const sockaddr_in;

	if addr_in.is_null() {
		return Ok(0);
	}

	let addr = unsafe { (*addr_in).sin_addr.s_addr };
	let port = unsafe { (*addr_in).sin_port };
	let family = unsafe { (*addr_in).sin_family };
	let ts = unsafe { bpf_ktime_get_ns() };
	let uid = bpf_get_current_uid_gid() as u32;
	let pid = bpf_get_current_pid_tgid() as u32;
	let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
	let comm_raw = bpf_get_current_comm().unwrap_or([0u8; 16]);
	let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
	let mnt_ns = unsafe { get_mnt_ns() };
	let ppid = unsafe { get_ppid() };

	let event = SocketEvent {
		header: EventHeader {
			ts,
			event_type: EVT_SOCKET,
			cgroup_id,
			mnt_ns,
			pid,
			ppid: ppid as u32,
			uid,
			tgid,
			comm: comm_raw,
			_pad0: [0u8; 3],
		},
		addr,
		port,
		family,
		op: SOCKET_OP_BIND,
		_pad0: [0u8; 7],
	};

	let _ = EVT_MAP.output::<SocketEvent>(&event, 0);

	Ok(0)
}

pub fn try_inet_sock_set_state(ctx: TracePointContext) -> Result<u32, u32> {
	let oldstate: i32 = unsafe { tp_try_read!(ctx, 16) };
	let newstate: i32 = unsafe { tp_try_read!(ctx, 20) };
	let sport: u16 = unsafe { tp_try_read!(ctx, 24) };
	let dport: u16 = unsafe { tp_try_read!(ctx, 26) };
	let protocol: u16 = unsafe { tp_try_read!(ctx, 30) };
	let saddr: u32 = unsafe { tp_try_read!(ctx, 32) };
	let daddr: u32 = unsafe { tp_try_read!(ctx, 36) };
	let ts = unsafe { bpf_ktime_get_ns() };
	let uid = bpf_get_current_uid_gid() as u32;
	let pid = bpf_get_current_pid_tgid() as u32;
	let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
	let comm_raw = bpf_get_current_comm().unwrap_or([0u8; 16]);
	let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
	let mnt_ns = unsafe { get_mnt_ns() };
	let ppid = unsafe { get_ppid() };

	if protocol != 6 {
		return Ok(0);
	}

	let event = InetSockSetStateEvent {
		header: EventHeader {
			ts,
			event_type: EVT_INET_SOCK_SET_STATE,
			cgroup_id,
			mnt_ns,
			pid,
			ppid: ppid as u32,
			uid,
			tgid,
			comm: comm_raw,
			_pad0: [0u8; 3],
		},
		oldstate,
		newstate,
		sport,
		dport,
		protocol,
		_pad0: [0u8; 2],
		saddr,
		daddr,
	};

	let _ = EVT_MAP.output::<InetSockSetStateEvent>(&event, 0);

	Ok(0)
}

pub fn try_xdp(ctx: XdpContext) -> Result<u32, ()> {
	let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
	match unsafe { (*ethhdr).ether_type() } {
		Ok(EtherType::Ipv4) => {}
		_ => return Ok(xdp_action::XDP_PASS),
	}
	let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
	let src = u32::from_be_bytes(unsafe { (*ipv4hdr).src_addr });
	let action = if block_ip(src) {
		xdp_action::XDP_DROP
	} else {
		xdp_action::XDP_PASS
	};
	Ok(action)
}
