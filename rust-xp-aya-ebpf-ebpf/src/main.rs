#![no_std]
#![no_main]

use aya_ebpf::{macros::tracepoint, programs::TracePointContext};
use aya_log_ebpf::info;

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

fn try_rust_xp_aya_ebpf(ctx: TracePointContext) -> Result<u32, u32> {
	let tp_ctx = match unsafe { ctx.read_at::<SysEnterKillCtx>(8) } {
		Ok(val) => val,
		Err(_) => return Err(1),
	};

	if tp_ctx.sig == 9 {
		info!(&ctx, "__x64_sys_kill: pid={}, sig={}", tp_ctx.pid, tp_ctx.sig);
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
