#![no_std]
#![no_main]

use aya_ebpf::{
	helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid},
	macros::{kprobe, lsm, map, tracepoint},
	maps::RingBuf,
	programs::{LsmContext, ProbeContext, TracePointContext},
};
use aya_log_ebpf::error;
use cerberus_common::Event;
mod vmlinux;
use vmlinux::{sockaddr, sockaddr_in, task_struct};

#[repr(C)]
struct IoUringSubmitReq {
	common_type: u16,
	common_flags: u8,
	common_preempt_count: u8,
	common_pid: i32,

	ctx: u64,
	req: u64,
	user_data: u64,
	opcode: u8,
	_pad1: [u8; 7],
	flags: u64,
	sq_thread: u8,
	_pad2: [u8; 3],
	op_str: u32,
}

#[map]
static EVT_MAP: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

const AF_INET: u16 = 2;

#[lsm(hook = "socket_connect")]
pub fn trace_socket_connect(ctx: LsmContext) -> i32 {
	match try_socket_connect(ctx) {
		Ok(ret) => ret,
		Err(ret) => ret,
	}
}

#[lsm(hook = "task_kill")]
pub fn trace_sys_enter_kill(ctx: LsmContext) -> i32 {
	match try_sys_enter_kill(ctx) {
		Ok(ret) => ret,
		Err(ret) => ret,
	}
}

#[tracepoint]
pub fn trace_io_uring_submit(ctx: TracePointContext) -> u32 {
	match try_io_uring_submit(ctx) {
		Ok(ret) => ret,
		Err(ret) => ret,
	}
}

// #[kprobe]
// pub fn trace_mprotect(ctx: ProbeContext) -> u32 {
// 	match try_mprotect(ctx) {
// 		Ok(ret) => ret,
// 		Err(ret) => ret,
// 	}
// }

#[kprobe]
pub fn trace_commit_creds(ctx: ProbeContext) -> u32 {
	match try_commit_creds(ctx) {
		Ok(ret) => ret,
		Err(ret) => ret,
	}
}

fn try_io_uring_submit(ctx: TracePointContext) -> Result<u32, u32> {
	let uid = bpf_get_current_uid_gid() as u32;
	let pid = bpf_get_current_pid_tgid() as u32;
	let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
	let comm_raw = bpf_get_current_comm().unwrap_or([0u8; 16]);

	let req = match unsafe { ctx.read_at::<IoUringSubmitReq>(0) } {
		Ok(r) => r,
		Err(_) => return Err(1),
	};

	let event = Event {
		pid,
		uid,
		tgid,
		comm: comm_raw,
		event_type: 2,
		meta: req.opcode as u32,
	};

	match EVT_MAP.output(&event, 0) {
		Ok(_) => (),
		Err(e) => return Err(e as u32),
	}

	Ok(0)
}

// fn try_mprotect(ctx: ProbeContext) -> Result<u32, u32> {
// 	let uid = bpf_get_current_uid_gid() as u32;
// 	let pid = bpf_get_current_pid_tgid() as u32;
// 	let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
// 	let comm_raw = bpf_get_current_comm().unwrap_or([0u8; 16]);

// 	// mprotect_fixup(struct vm_area_struct *vma, struct vm_area_struct **pprev,
// 	//               unsigned long start, unsigned long end, unsigned long newflags)
// 	let newflags = match ctx.arg::<u64>(4) {
// 		Some(val) => val,
// 		None => 0,
// 	};

// 	let is_rwx = (newflags & 0x7) == 0x7;
// 	let is_wx = (newflags & 0x6) == 0x6;

// 	let event = Event {
// 		pid,
// 		uid,
// 		tgid,
// 		comm: comm_raw,
// 		event_type: 3,
// 		meta: if is_rwx {
// 			0x01
// 		} else if is_wx {
// 			0x02
// 		} else {
// 			0x00
// 		},
// 	};

// 	match EVT_MAP.output(&event, 0) {
// 		Ok(_) => (),
// 		Err(e) => return Err(e as u32),
// 	}

// 	Ok(0)
// }

fn try_commit_creds(ctx: ProbeContext) -> Result<u32, u32> {
	let old_uid = bpf_get_current_uid_gid() as u32;
	let pid = bpf_get_current_pid_tgid() as u32;
	let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
	let comm_raw = bpf_get_current_comm().unwrap_or([0u8; 16]);

	let new_uid = ctx.arg(1).unwrap_or(0) as u32;

	if old_uid != 0 && new_uid == 0 {
		let event = Event {
			pid,
			uid: old_uid,
			tgid,
			comm: comm_raw,
			event_type: 4,
			meta: 0x00,
		};

		match EVT_MAP.output(&event, 0) {
			Ok(_) => (),
			Err(e) => return Err(e as u32),
		}
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
	// Filter out tokio-runtime-w → 127.0.0.53 and systemd-resolve → 192.168.0.1
	if dest_ip == 0x3500007f || dest_ip == 0x0100a8c0 {
		return Ok(0);
	}

	let uid = bpf_get_current_uid_gid() as u32;
	let pid = bpf_get_current_pid_tgid() as u32;
	let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
	let comm_raw = bpf_get_current_comm().unwrap_or([0u8; 16]);

	let event = Event {
		pid,
		uid,
		tgid,
		comm: comm_raw,
		event_type: 3,
		meta: dest_ip,
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

	let event = Event {
		pid: pid as u32,
		uid,
		tgid,
		comm: comm_raw,
		event_type: 1,
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
