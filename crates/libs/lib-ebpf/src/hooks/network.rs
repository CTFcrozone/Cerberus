use aya_ebpf::{
	helpers::{
		bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, r#gen::bpf_get_current_cgroup_id,
	},
	programs::{LsmContext, TracePointContext},
};
use aya_log_ebpf::error;
use lib_ebpf_common::{EventHeader, InetSockSetStateEvent, SocketConnectEvent};

use crate::{
	utils::get_mnt_ns,
	vmlinux::{sockaddr, sockaddr_in},
	EVT_MAP,
};

const AF_INET: u16 = 2;

macro_rules! try_read {
	($ctx:expr, $offset:expr) => {
		match $ctx.read_at($offset) {
			Ok(val) => val,
			Err(_) => return Err(1),
		}
	};
}

pub fn try_socket_connect(ctx: LsmContext) -> Result<i32, i32> {
	let addr: *const sockaddr = unsafe { ctx.arg(1) };
	let ret: i32 = unsafe { ctx.arg(3) };

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

	let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
	let mnt_ns = unsafe { get_mnt_ns() };

	let event = SocketConnectEvent {
		header: EventHeader {
			event_type: 3,
			cgroup_id,
			mnt_ns,
			_pad0: [0u8; 3],
		},
		addr,
		port,
		family,
	};

	match EVT_MAP.output(&event, 0) {
		Ok(_) => (),
		Err(e) => error!(&ctx, "Couldn't write to the ring buffer ->> ERROR: {}", e),
	}
	Ok(0)
}

pub fn try_inet_sock_set_state(ctx: TracePointContext) -> Result<u32, u32> {
	let oldstate: i32 = unsafe { try_read!(ctx, 16) };
	let newstate: i32 = unsafe { try_read!(ctx, 20) };
	let sport: u16 = unsafe { try_read!(ctx, 24) };
	let dport: u16 = unsafe { try_read!(ctx, 26) };
	let protocol: u16 = unsafe { try_read!(ctx, 30) };
	let saddr: u32 = unsafe { try_read!(ctx, 32) };
	let daddr: u32 = unsafe { try_read!(ctx, 36) };
	let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
	let mnt_ns = unsafe { get_mnt_ns() };

	if protocol != 6 {
		return Ok(0);
	}

	let event = InetSockSetStateEvent {
		header: EventHeader {
			event_type: 6,
			cgroup_id,
			mnt_ns,
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

	match EVT_MAP.output(&event, 0) {
		Ok(_) => (),
		Err(e) => error!(&ctx, "Couldn't write to the ring buffer ->> ERROR: {}", e),
	}

	Ok(0)
}
