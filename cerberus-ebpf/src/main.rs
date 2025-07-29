#![no_std]
#![no_main]

use aya_ebpf::{
	helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_probe_read_kernel},
	macros::{kprobe, lsm, map, tracepoint},
	maps::RingBuf,
	programs::{LsmContext, ProbeContext, TracePointContext},
};
use aya_log_ebpf::{error, warn};
use cerberus_common::{EventHeader, GenericEvent, InetSockSetStateEvent};
mod vmlinux;
use vmlinux::{module, sockaddr, sockaddr_in, task_struct};

#[map]
static EVT_MAP: RingBuf = RingBuf::with_byte_size(32 * 1024, 0);
const SYSTEMD_RESOLVE: &[u8; 16] = b"systemd-resolve\0";
const TOKIO_RUNTIME: &[u8; 16] = b"tokio-runtime-w\0";

const AF_INET: u16 = 2;

macro_rules! match_comm {
    ($comm:expr, [$( $name:expr ),*]) => {
        false $(|| &$comm[..] == $name )*
    };
}

macro_rules! try_read {
	($ctx:expr, $offset:expr) => {
		match $ctx.read_at($offset) {
			Ok(val) => val,
			Err(_) => return Err(1),
		}
	};
}

// #[lsm(hook = "socket_connect")]
// pub fn socket_connect(ctx: LsmContext) -> i32 {
// 	match try_socket_connect(ctx) {
// 		Ok(ret) => ret,
// 		Err(ret) => ret,
// 	}
// }

#[tracepoint]
pub fn inet_sock_set_state(ctx: TracePointContext) -> u32 {
	match try_inet_sock_set_state(ctx) {
		Ok(ret) => ret,
		Err(ret) => ret,
	}
}

#[lsm(hook = "task_kill")]
pub fn sys_enter_kill(ctx: LsmContext) -> i32 {
	match try_sys_enter_kill(ctx) {
		Ok(ret) => ret,
		Err(ret) => ret,
	}
}

#[kprobe]
pub fn commit_creds(ctx: ProbeContext) -> u32 {
	match try_commit_creds(ctx) {
		Ok(ret) => ret,
		Err(ret) => ret,
	}
}

#[kprobe]
pub fn do_init_module(ctx: ProbeContext) -> u32 {
	match try_do_init_module(ctx) {
		Ok(ret) => ret,
		Err(ret) => ret,
	}
}

fn try_commit_creds(ctx: ProbeContext) -> Result<u32, u32> {
	let old_uid = bpf_get_current_uid_gid() as u32;
	let pid = bpf_get_current_pid_tgid() as u32;
	let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
	let comm_raw = bpf_get_current_comm().unwrap_or([0u8; 16]);

	let new_uid = ctx.arg(1).unwrap_or(0) as u32;

	if old_uid != 0 && new_uid == 0 {
		let event = GenericEvent {
			header: EventHeader {
				event_type: 4,
				_padding: [0u8; 3],
			},
			pid,
			uid: old_uid,
			tgid,
			comm: comm_raw,
			meta: 0x00,
		};

		match EVT_MAP.output(&event, 0) {
			Ok(_) => (),
			Err(e) => return Err(e as u32),
		}
	}

	Ok(0)
}

fn try_do_init_module(ctx: ProbeContext) -> Result<u32, u32> {
	let uid = bpf_get_current_uid_gid() as u32;
	let pid = bpf_get_current_pid_tgid() as u32;
	let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
	let comm_raw = bpf_get_current_comm().unwrap_or([0u8; 16]);
	let module: *const module = ctx.arg(0).ok_or(1u32)?;

	let name_i8 = unsafe { bpf_probe_read_kernel(&(*module).name).map_err(|_| 2u32)? };

	let name: [u8; 56] = unsafe { core::mem::transmute(name_i8) };

	let len = name.iter().position(|&b| b == 0).unwrap_or(56);

	let name_str = unsafe { core::str::from_utf8_unchecked(&name[..len]) };

	warn!(&ctx, "LKM name: {}", name_str);

	let event = GenericEvent {
		header: EventHeader {
			event_type: 5,
			_padding: [0u8; 3],
		},
		pid,
		uid,
		tgid,
		comm: comm_raw,
		meta: 0,
	};

	match EVT_MAP.output(&event, 0) {
		Ok(_) => (),
		Err(e) => return Err(e as u32),
	}

	Ok(0)
}

fn try_socket_connect(ctx: LsmContext) -> Result<i32, i32> {
	let addr: *const sockaddr = unsafe { ctx.arg(1) };
	let ret: i32 = unsafe { ctx.arg(3) };

	if ret != 0 {
		return Ok(ret);
	}

	let sa_family = unsafe { (*addr).sa_family };
	if sa_family != AF_INET {
		return Ok(0);
	}

	let addr_in = addr as *const sockaddr_in;
	let dest_ip = unsafe { (*addr_in).sin_addr.s_addr };

	let uid = bpf_get_current_uid_gid() as u32;
	let pid = bpf_get_current_pid_tgid() as u32;
	let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
	let comm_raw = bpf_get_current_comm().unwrap_or([0u8; 16]);

	if match_comm!(comm_raw, [TOKIO_RUNTIME, SYSTEMD_RESOLVE]) {
		return Ok(0);
	}

	let event = GenericEvent {
		header: EventHeader {
			event_type: 3,
			_padding: [0u8; 3],
		},
		pid,
		uid,
		tgid,
		comm: comm_raw,
		meta: dest_ip,
	};

	match EVT_MAP.output(&event, 0) {
		Ok(_) => (),
		Err(e) => error!(&ctx, "Couldn't write to the ring buffer ->> ERROR: {}", e),
	}
	Ok(0)
}

fn try_inet_sock_set_state(ctx: TracePointContext) -> Result<u32, u32> {
	let oldstate: i32 = unsafe { try_read!(ctx, 16) };
	let newstate: i32 = unsafe { try_read!(ctx, 20) };
	let sport: u16 = unsafe { try_read!(ctx, 24) };
	let dport: u16 = unsafe { try_read!(ctx, 26) };
	let protocol: u16 = unsafe { try_read!(ctx, 30) };
	let saddr: u32 = unsafe { try_read!(ctx, 32) };
	let daddr: u32 = unsafe { try_read!(ctx, 36) };

	if protocol != 6 {
		return Ok(0);
	}

	let event = InetSockSetStateEvent {
		header: EventHeader {
			event_type: 6,
			_padding: [0u8; 3],
		},
		oldstate,
		newstate,
		sport,
		dport,
		protocol,
		saddr,
		daddr,
	};

	match EVT_MAP.output(&event, 0) {
		Ok(_) => (),
		Err(e) => error!(&ctx, "Couldn't write to the ring buffer ->> ERROR: {}", e),
	}

	Ok(0)
}

fn try_sys_enter_kill(ctx: LsmContext) -> Result<i32, i32> {
	let task: *const task_struct = unsafe { ctx.arg(0) };
	let sig: u32 = unsafe { ctx.arg(2) };
	let pid = unsafe { (*task).pid };

	let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
	let comm_raw = bpf_get_current_comm().unwrap_or([0u8; 16]);
	let uid = bpf_get_current_uid_gid() as u32;

	let event = GenericEvent {
		header: EventHeader {
			event_type: 1,
			_padding: [0u8; 3],
		},
		pid: pid as u32,
		uid,
		tgid,
		comm: comm_raw,
		meta: sig,
	};

	match EVT_MAP.output(&event, 0) {
		Ok(_) => (),
		Err(e) => error!(&ctx, "Couldn't write to the ring buffer ->> ERROR: {}", e), //  prints the error instead of returning, so the syscall is not blocked
	}

	Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
	loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
