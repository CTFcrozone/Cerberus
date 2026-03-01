#![no_std]
#![no_main]

use aya_ebpf::{
	macros::{kprobe, lsm, map, tracepoint},
	maps::RingBuf,
	programs::{LsmContext, ProbeContext, TracePointContext},
};

mod utils;

mod hooks;
mod vmlinux;

#[map]
static EVT_MAP: RingBuf = RingBuf::with_byte_size(32 * 1024, 0);

#[lsm(hook = "bpf_prog_load")]
pub fn bpf_prog_load(ctx: LsmContext) -> i32 {
	match hooks::try_bpf_prog_load(ctx) {
		Ok(ret) => ret,
		Err(ret) => ret,
	}
}

#[lsm(hook = "socket_connect")]
pub fn socket_connect(ctx: LsmContext) -> i32 {
	match hooks::try_socket_connect(ctx) {
		Ok(ret) => ret,
		Err(ret) => ret,
	}
}

#[lsm(hook = "inode_unlink")]
pub fn inode_unlink(ctx: LsmContext) -> i32 {
	match hooks::try_inode_unlink(ctx) {
		Ok(ret) => ret,
		Err(ret) => ret,
	}
}

#[lsm(hook = "socket_bind")]
pub fn socket_bind(ctx: LsmContext) -> i32 {
	match hooks::try_socket_bind(ctx) {
		Ok(ret) => ret,
		Err(ret) => ret,
	}
}

#[tracepoint]
pub fn inet_sock_set_state(ctx: TracePointContext) -> u32 {
	match hooks::try_inet_sock_set_state(ctx) {
		Ok(ret) => ret,
		Err(ret) => ret,
	}
}

#[tracepoint]
pub fn sys_enter_ptrace(ctx: TracePointContext) -> u32 {
	match hooks::try_sys_enter_ptrace(ctx) {
		Ok(ret) => ret,
		Err(ret) => ret,
	}
}

#[lsm(hook = "task_kill")]
pub fn sys_enter_kill(ctx: LsmContext) -> i32 {
	match hooks::try_sys_enter_kill(ctx) {
		Ok(ret) => ret,
		Err(ret) => ret,
	}
}

#[lsm(hook = "bprm_check_security")]
pub fn bprm_check_security(ctx: LsmContext) -> i32 {
	match hooks::try_bprm_check_security(ctx) {
		Ok(ret) => ret,
		Err(ret) => ret,
	}
}

#[kprobe]
pub fn commit_creds(ctx: ProbeContext) -> u32 {
	match hooks::try_commit_creds(ctx) {
		Ok(ret) => ret,
		Err(ret) => ret.try_into().unwrap_or(1),
	}
}

#[kprobe]
pub fn do_init_module(ctx: ProbeContext) -> u32 {
	match hooks::try_do_init_module(ctx) {
		Ok(ret) => ret,
		Err(ret) => ret.try_into().unwrap_or(1),
	}
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
	loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
