#![no_std]
#![no_main]

use aya_ebpf::{
	helpers::{
		bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
		gen::{
			bpf_get_current_cgroup_id, bpf_get_current_task, bpf_get_current_task_btf, bpf_get_ns_current_pid_tgid,
			bpf_ktime_get_ns,
		},
	},
	macros::{kprobe, map, tracepoint},
	maps::RingBuf,
	programs::{ProbeContext, TracePointContext},
};
use aya_log_ebpf::{debug, info, warn};
use rust_xp_aya_ebpf_common::Event;

// name: sys_enter_kill
// ID: 183
// format:
// 	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
// 	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
// 	field:unsigned char common_preempt_count;	offset:3;	size:1;signed:0;
// 	field:int common_pid;	offset:4;	size:4;	signed:1;

// 	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
// 	field:pid_t pid;	offset:16;	size:8;	signed:0;
// 	field:int sig;	offset:24;	size:8;	signed:0;

// print fmt: "pid: 0x%08lx, sig: 0x%08lx", ((unsigned long)(REC->pid)), ((unsigned long)(REC->sig))

#[map]
static EVT_MAP: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

#[repr(C)]
struct SysEnterKillCtx {
	__syscall_nr: i32, // 4 bytes
	_padding: [u8; 4], // to align next field (8 bytes)
	pid: u64,          // 8 bytes
	sig: u64,          // 8 bytes
}

#[tracepoint]
pub fn rust_xp_aya_ebpf(ctx: TracePointContext) -> u32 {
	match try_rust_xp_aya_ebpf(ctx) {
		Ok(ret) => ret,
		Err(ret) => ret,
	}
}

#[kprobe]
pub fn trace_openat(ctx: ProbeContext) -> u32 {
	match try_openat(ctx) {
		Ok(ret) => ret,
		Err(ret) => ret,
	}
}

fn try_openat(ctx: ProbeContext) -> Result<u32, u32> {
	let uid = bpf_get_current_uid_gid() as u32;
	let comm_raw = bpf_get_current_comm().unwrap_or([0u8; 16]);
	let len = comm_raw.iter().position(|&b| b == 0).unwrap_or(comm_raw.len());
	let comm = unsafe { core::str::from_utf8_unchecked(&comm_raw[..len]) };

	let pid = bpf_get_current_pid_tgid() as u32;

	// if comm == "gedit" {
	// 	info!(&ctx, "[OPENAT] pid={} uid={} comm={}", pid, uid, comm);
	// }

	Ok(0)
}

fn try_rust_xp_aya_ebpf(ctx: TracePointContext) -> Result<u32, u32> {
	let tp_ctx = match unsafe { ctx.read_at::<SysEnterKillCtx>(8) } {
		Ok(val) => val,
		Err(_) => return Err(1),
	};

	let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
	let comm_raw = bpf_get_current_comm().unwrap_or([0u8; 16]);
	let uid = bpf_get_current_uid_gid() as u32;

	match (tp_ctx.sig, uid) {
		(9, 0) => debug!(
			&ctx,
			"->> ROOT USER Attempted __x64_sys_kill: pid={}, sig={}, uid={}", tp_ctx.pid, tp_ctx.sig, uid
		),
		(9, _) => {
			debug!(
				&ctx,
				"->> NON-ROOT USER Attempted __x64_sys_kill: pid={}, sig={}, uid={}", tp_ctx.pid, tp_ctx.sig, uid
			);
			let event = Event {
				pid: tp_ctx.pid as u32,
				uid,
				tgid,
				sig: tp_ctx.sig,
				comm: comm_raw,
				event_type: 1,
				syscall_nr: tp_ctx.__syscall_nr as u8,
			};

			match EVT_MAP.output(&event, 0) {
				Ok(_) => (),
				Err(e) => return Err(e as u32),
			}
		}
		_ => (),
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
