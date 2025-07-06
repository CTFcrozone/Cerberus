#![no_std]
#![no_main]

use aya_ebpf::{
	helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid},
	macros::{kprobe, map, tracepoint},
	maps::RingBuf,
	programs::{ProbeContext, TracePointContext},
};
use rust_xp_aya_ebpf_common::Event;

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

#[repr(C)]
struct SysEnterKillCtx {
	__syscall_nr: i32,
	_padding: [u8; 4],
	pid: u64,
	sig: u64,
}

#[tracepoint]
pub fn trace_sys_enter_kill(ctx: TracePointContext) -> u32 {
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

fn try_commit_creds(_ctx: ProbeContext) -> Result<u32, u32> {
	let old_uid = bpf_get_current_uid_gid() as u32;
	let pid = bpf_get_current_pid_tgid() as u32;
	let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
	let comm_raw = bpf_get_current_comm().unwrap_or([0u8; 16]);

	let new_uid = _ctx.arg(1).unwrap_or(0) as u32;

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

fn try_sys_enter_kill(ctx: TracePointContext) -> Result<u32, u32> {
	let tp_ctx = match unsafe { ctx.read_at::<SysEnterKillCtx>(8) } {
		Ok(val) => val,
		Err(_) => return Err(1),
	};

	let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
	let comm_raw = bpf_get_current_comm().unwrap_or([0u8; 16]);
	let uid = bpf_get_current_uid_gid() as u32;

	let event = Event {
		pid: tp_ctx.pid as u32,
		uid,
		tgid,
		comm: comm_raw,
		event_type: 1,
		meta: tp_ctx.sig as u32,
	};

	match EVT_MAP.output(&event, 0) {
		Ok(_) => (),
		Err(e) => return Err(e as u32),
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
