#![no_std]
#![no_main]

use aya_ebpf::{
	bindings::path,
	helpers::{
		bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_probe_read_kernel,
		r#gen::{bpf_d_path, bpf_get_current_cgroup_id, bpf_get_current_task, bpf_send_signal},
	},
	macros::{kprobe, lsm, map, tracepoint},
	maps::{PerCpuArray, RingBuf},
	programs::{LsmContext, ProbeContext, TracePointContext},
};
use aya_log_ebpf::error;
use lib_common::{BprmSecurityCheckEvent, EventHeader, GenericEvent, InetSockSetStateEvent, ModuleInitEvent};
mod vmlinux;
use vmlinux::{linux_binprm, module, sockaddr, sockaddr_in, task_struct};

use crate::vmlinux::{cgroup_namespace, mnt_namespace, nsproxy};

#[map]
static EVT_MAP: RingBuf = RingBuf::with_byte_size(32 * 1024, 0);
#[map(name = "FPATH")]
static mut FPATH: PerCpuArray<[u8; 132]> = PerCpuArray::with_max_entries(1, 0);

const SYSTEMD_RESOLVE: &[u8; 16] = b"systemd-resolve\0";
const TOKIO_RUNTIME: &[u8; 16] = b"tokio-runtime-w\0";
const PATH_LEN: u32 = 128;
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

#[lsm(hook = "socket_connect")]
pub fn socket_connect(ctx: LsmContext) -> i32 {
	match try_socket_connect(ctx) {
		Ok(ret) => ret,
		Err(ret) => ret,
	}
}

#[tracepoint]
pub fn inet_sock_set_state(ctx: TracePointContext) -> u32 {
	match try_inet_sock_set_state(ctx) {
		Ok(ret) => ret,
		Err(ret) => ret,
	}
}

#[tracepoint]
pub fn sys_enter_ptrace(ctx: TracePointContext) -> u32 {
	match try_sys_enter_ptrace(ctx) {
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

#[lsm(hook = "bprm_check_security")]
pub fn bprm_check_security(ctx: LsmContext) -> i32 {
	match try_bprm_check_security(ctx) {
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

unsafe fn get_mnt_ns() -> u32 {
	let task = bpf_get_current_task() as *const task_struct;
	if task.is_null() {
		return 0;
	}

	let nsproxy: *const nsproxy = match bpf_probe_read_kernel(&(*task).nsproxy) {
		Ok(p) => p,
		Err(_) => return 0,
	};
	if nsproxy.is_null() {
		return 0;
	}

	let mnt_ns: *const mnt_namespace = match bpf_probe_read_kernel(&(*nsproxy).mnt_ns) {
		Ok(p) => p,
		Err(_) => return 0,
	};
	if mnt_ns.is_null() {
		return 0;
	}

	match bpf_probe_read_kernel(&(*mnt_ns).ns.inum) {
		Ok(inum) => inum,
		Err(_) => 0,
	}
}

fn try_commit_creds(ctx: ProbeContext) -> Result<u32, u32> {
	let old_uid = bpf_get_current_uid_gid() as u32;
	let pid = bpf_get_current_pid_tgid() as u32;
	let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
	let comm_raw = bpf_get_current_comm().unwrap_or([0u8; 16]);
	let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
	let mnt_ns = unsafe { get_mnt_ns() };

	let new_uid = ctx.arg(1).unwrap_or(0) as u32;

	if old_uid != 0 && new_uid == 0 {
		let event = GenericEvent {
			header: EventHeader {
				event_type: 4,
				cgroup_id,
				mnt_ns,
				_pad0: [0u8; 3],
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

fn try_sys_enter_ptrace(ctx: TracePointContext) -> Result<u32, u32> {
	let uid = bpf_get_current_uid_gid() as u32;
	let pid = bpf_get_current_pid_tgid() as u32;
	let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
	let comm_raw = bpf_get_current_comm().unwrap_or([0u8; 16]);
	let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
	let mnt_ns = unsafe { get_mnt_ns() };

	let ret = unsafe { bpf_send_signal(9) };

	let event = GenericEvent {
		header: EventHeader {
			event_type: 7,
			cgroup_id,
			mnt_ns,
			_pad0: [0u8; 3],
		},
		pid,
		uid,
		tgid,
		comm: comm_raw,
		meta: if ret == 0 { 1 } else { 0 }, // success flag
	};

	match EVT_MAP.output(&event, 0) {
		Ok(_) => (),
		Err(e) => error!(&ctx, "Failed to log ptrace event: {}", e),
	}

	Ok(0)
}

fn try_do_init_module(ctx: ProbeContext) -> Result<u32, u32> {
	let module: *const module = ctx.arg(0).ok_or(1u32)?;

	if module.is_null() {
		return Err(1u32);
	}

	let uid = bpf_get_current_uid_gid() as u32;
	let pid = bpf_get_current_pid_tgid() as u32;
	let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
	let comm_raw = bpf_get_current_comm().unwrap_or([0u8; 16]);

	let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
	let mnt_ns = unsafe { get_mnt_ns() };
	let name_i8 = unsafe { bpf_probe_read_kernel(&(*module).name).map_err(|_| 2u32)? };

	let module_name: [u8; 56] = unsafe { core::mem::transmute(name_i8) };

	let event = ModuleInitEvent {
		header: EventHeader {
			event_type: 5,
			cgroup_id,
			mnt_ns,
			_pad0: [0u8; 3],
		},
		pid,
		uid,
		tgid,
		comm: comm_raw,
		module_name,
		_pad0: [0u8; 4],
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

	let dest_ip = unsafe { (*addr_in).sin_addr.s_addr };

	let uid = bpf_get_current_uid_gid() as u32;
	let pid = bpf_get_current_pid_tgid() as u32;
	let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
	let comm_raw = bpf_get_current_comm().unwrap_or([0u8; 16]);

	let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
	let mnt_ns = unsafe { get_mnt_ns() };

	// let event = GenericEvent {
	// 	header: EventHeader {
	// 		event_type: 3,
	// 		_padding: [0u8; 7],
	// 		cgroup_id,
	// 		mnt_ns,
	// 		_pad: [0u8; 4],
	// 	},
	// 	pid,
	// 	uid,
	// 	tgid,
	// 	comm: comm_raw,
	// 	meta: dest_ip,
	// };

	// match EVT_MAP.output(&event, 0) {
	// 	Ok(_) => (),
	// 	Err(e) => error!(&ctx, "Couldn't write to the ring buffer ->> ERROR: {}", e),
	// }
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

fn try_bprm_check_security(ctx: LsmContext) -> Result<i32, i32> {
	let uid = bpf_get_current_uid_gid() as u32;
	let pid = bpf_get_current_pid_tgid() as u32;
	let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
	let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
	let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
	let mnt_ns = unsafe { get_mnt_ns() };
	let bprm: *const linux_binprm = unsafe { ctx.arg(0) };

	if bprm.is_null() {
		return Ok(0);
	}

	let buf = unsafe { FPATH.get_ptr_mut(0).ok_or(0)? };

	unsafe {
		let file = (*bprm).file;

		if file.is_null() {
			return Ok(0);
		}

		let f_path = &(*file).__bindgen_anon_1.f_path as *const _ as *mut path;
		let ret = bpf_d_path(f_path, buf as *mut i8, PATH_LEN);

		if ret < 0 {
			return Err(0);
		}
	}

	let event = BprmSecurityCheckEvent {
		header: EventHeader {
			event_type: 8,
			cgroup_id,
			mnt_ns,
			_pad0: [0u8; 3],
		},
		pid,
		uid,
		tgid,
		comm,
		filepath: unsafe { *buf },
	};

	match EVT_MAP.output(&event, 0) {
		Ok(_) => (),
		Err(e) => error!(&ctx, "Couldn't write to the ring buffer ->> ERROR: {}", e),
	}
	Ok(0)
}

fn try_sys_enter_kill(ctx: LsmContext) -> Result<i32, i32> {
	let task: *const task_struct = unsafe { ctx.arg(0) };

	if task.is_null() {
		return Ok(0);
	}

	let sig: u32 = unsafe { ctx.arg(2) };
	let pid = unsafe { (*task).pid };

	let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
	let comm_raw = bpf_get_current_comm().unwrap_or([0u8; 16]);
	let uid = bpf_get_current_uid_gid() as u32;
	let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
	let mnt_ns = unsafe { get_mnt_ns() };

	let event = GenericEvent {
		header: EventHeader {
			event_type: 1,
			cgroup_id,
			mnt_ns,
			_pad0: [0u8; 3],
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
