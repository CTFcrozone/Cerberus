use aya_ebpf::{
	helpers::{
		bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_probe_read_kernel,
		bpf_probe_read_user_str, bpf_probe_read_user_str_bytes,
		r#gen::{bpf_get_current_cgroup_id, bpf_ktime_get_ns},
	},
	programs::{ProbeContext, TracePointContext},
};
use aya_log_ebpf::error;
use lib_ebpf_common::{EventHeader, ModuleEvent};

use crate::{
	utils::{get_mnt_ns, get_ppid},
	vmlinux::module,
	EVT_MAP,
};

macro_rules! try_read {
	($ctx:expr, $offset:expr) => {
		match $ctx.read_at($offset) {
			Ok(val) => val,
			Err(_) => return Err(1),
		}
	};
}

pub fn try_sys_enter_delete_module(ctx: TracePointContext) -> Result<u32, u32> {
	let uid = bpf_get_current_uid_gid() as u32;
	let pid = bpf_get_current_pid_tgid() as u32;
	let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
	let comm_raw = bpf_get_current_comm().unwrap_or([0u8; 16]);
	let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
	let mnt_ns = unsafe { get_mnt_ns() };
	let ts = unsafe { bpf_ktime_get_ns() };
	let ppid = unsafe { get_ppid() };

	let mut module_name = [0u8; 56];
	let name_ptr: *const u8 = unsafe { try_read!(ctx, 8) };

	let _name_bytes = unsafe { bpf_probe_read_user_str_bytes(name_ptr, &mut module_name) }.map_err(|_| 1u32)?;

	let event = ModuleEvent {
		header: EventHeader {
			ts,
			event_type: 5,
			cgroup_id,
			mnt_ns,
			pid,
			ppid: ppid as u32,
			uid,
			tgid,
			comm: comm_raw,
			_pad0: [0u8; 3],
		},
		module_name,
		op: 1,
		_pad0: [0u8; 7],
	};

	if let Err(e) = EVT_MAP.output(&event, 0) {
		error!(&ctx, "ringbuf write failed: {}", e);
	}

	Ok(0)
}

pub fn try_do_init_module(ctx: ProbeContext) -> Result<u32, i64> {
	let module: *const module = ctx.arg(0).ok_or(1)?;

	if module.is_null() {
		return Err(1);
	}

	let uid = bpf_get_current_uid_gid() as u32;
	let pid = bpf_get_current_pid_tgid() as u32;
	let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
	let comm_raw = bpf_get_current_comm().unwrap_or([0u8; 16]);
	let ts = unsafe { bpf_ktime_get_ns() };
	let ppid = unsafe { get_ppid() };

	let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
	let mnt_ns = unsafe { get_mnt_ns() };
	let name_i8 = unsafe { bpf_probe_read_kernel(&(*module).name)? };

	let module_name: [u8; 56] = unsafe { core::mem::transmute(name_i8) };

	let event = ModuleEvent {
		header: EventHeader {
			ts,
			event_type: 5,
			cgroup_id,
			mnt_ns,
			pid,
			ppid: ppid as u32,
			uid,
			tgid,
			comm: comm_raw,
			_pad0: [0u8; 3],
		},
		module_name,
		op: 0,
		_pad0: [0u8; 7],
	};

	EVT_MAP.output(&event, 0)?;

	Ok(0)
}

// pub fn try_do_delete_module(ctx: ProbeContext) -> Result<u32, i64> {
// 	let name_ptr: *const u8 = ctx.arg(0).ok_or(1)?;

// 	if name_ptr.is_null() {
// 		return Err(1);
// 	}

// 	let uid = bpf_get_current_uid_gid() as u32;
// 	let pid = bpf_get_current_pid_tgid() as u32;
// 	let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
// 	let comm_raw = bpf_get_current_comm().unwrap_or([0u8; 16]);
// 	let ts = unsafe { bpf_ktime_get_ns() };
// 	let ppid = unsafe { get_ppid() };

// 	let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
// 	let mnt_ns = unsafe { get_mnt_ns() };

// 	let mut module_name = [0u8; 56];

// 	let _name_bytes = unsafe { bpf_probe_read_user_str_bytes(name_ptr, &mut module_name)? };

// 	let event = ModuleEvent {
// 		header: EventHeader {
// 			ts,
// 			event_type: 5,
// 			cgroup_id,
// 			mnt_ns,
// 			pid,
// 			ppid: ppid as u32,
// 			uid,
// 			tgid,
// 			comm: comm_raw,
// 			_pad0: [0u8; 3],
// 		},
// 		module_name,
// 		op: 1,
// 		_pad0: [0u8; 7],
// 	};

// 	EVT_MAP.output(&event, 0)?;

// 	Ok(0)
// }
