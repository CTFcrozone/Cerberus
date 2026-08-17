use aya_ebpf::{
	helpers::{
		bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_probe_read_kernel,
		generated::{bpf_get_current_cgroup_id, bpf_ktime_get_ns},
	},
	programs::{LsmContext, TracePointContext},
};
// use aya_log_ebpf::error;
use lib_ebpf_common::{
	EVT_ENTER_PTRACE, EVT_KILL, EVT_PTRACE_ACCESS_CHECK, EventHeader, GenericEvent, META_KILL_SIG, META_PTRACE_SUCCESS,
	PTRACE_STAGE_REQUEST, PtraceAccessCheckEvent,
};

use crate::{
	EVT_MAP,
	utils::{get_mnt_ns, get_parent_comm, get_ppid},
	vmlinux::task_struct,
};

pub fn try_sys_enter_ptrace(_ctx: TracePointContext) -> Result<u32, u32> {
	let uid = bpf_get_current_uid_gid() as u32;
	let pid = bpf_get_current_pid_tgid() as u32;
	let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
	let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
	let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
	let mnt_ns = unsafe { get_mnt_ns() };
	let ts = unsafe { bpf_ktime_get_ns() };
	let ppid = unsafe { get_ppid() };
	let parent_comm = unsafe { get_parent_comm() };

	let event = GenericEvent {
		header: EventHeader {
			ts,
			event_type: EVT_ENTER_PTRACE,
			cgroup_id,
			mnt_ns,
			pid,
			ppid: ppid as u32,
			uid,
			tgid,
			comm,
			parent_comm,
			_pad0: [0u8; 3],
		},
		meta: 0, // success flag
		meta_type: META_PTRACE_SUCCESS,
		_pad0: [0u8; 2],
	};

	// if let Err(e) = EVT_MAP.output::<GenericEvent>(&event, 0) {
	// 	error!(&ctx, "ringbuf write failed: {}", e);
	// }
	let _ = EVT_MAP.output::<GenericEvent>(&event, 0);

	Ok(0)
}

pub fn try_sys_enter_kill(ctx: LsmContext) -> Result<i32, i32> {
	let task: *const task_struct = { ctx.arg(0) };

	if task.is_null() {
		return Ok(0);
	}

	let sig: u32 = ctx.arg(2);
	let pid = unsafe { (*task).pid as u32 };
	let ts = unsafe { bpf_ktime_get_ns() };
	let ppid = unsafe { get_ppid() };
	let parent_comm = unsafe { get_parent_comm() };

	let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
	let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
	let uid = bpf_get_current_uid_gid() as u32;
	let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
	let mnt_ns = unsafe { get_mnt_ns() };

	let event = GenericEvent {
		header: EventHeader {
			ts,
			event_type: EVT_KILL,
			cgroup_id,
			mnt_ns,
			pid,
			ppid: ppid as u32,
			uid,
			tgid,
			comm,
			parent_comm,
			_pad0: [0u8; 3],
		},
		meta: sig,
		meta_type: META_KILL_SIG,
		_pad0: [0u8; 2],
	};

	let _ = EVT_MAP.output::<GenericEvent>(&event, 0);

	Ok(0)
}

pub fn try_ptrace_access_check(ctx: LsmContext) -> Result<i32, i32> {
	let uid = bpf_get_current_uid_gid() as u32;
	let pid = bpf_get_current_pid_tgid() as u32;
	let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
	let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
	let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
	let mnt_ns = unsafe { get_mnt_ns() };
	let ts = unsafe { bpf_ktime_get_ns() };
	let ppid = unsafe { get_ppid() };
	let parent_comm = unsafe { get_parent_comm() };

	let child: *const task_struct = ctx.arg(0);

	if child.is_null() {
		return Ok(0);
	}

	let mode: u32 = ctx.arg(1);

	let target_pid = unsafe {
		match bpf_probe_read_kernel(&(*child).pid) {
			Ok(pid) => pid as u32,
			Err(_) => return Ok(0),
		}
	};

	let target_tgid = unsafe {
		match bpf_probe_read_kernel(&(*child).tgid) {
			Ok(v) => v as u32,
			Err(_) => return Ok(0),
		}
	};

	let target_uid = unsafe {
		let cred = match bpf_probe_read_kernel(&(*child).cred) {
			Ok(v) => v,
			Err(_) => return Ok(0),
		};
		if cred.is_null() {
			return Ok(0);
		} else {
			match bpf_probe_read_kernel(&(*cred).uid.val) {
				Ok(v) => v,
				Err(_) => return Ok(0),
			}
		}
	};

	let target_comm_i8 = match unsafe { bpf_probe_read_kernel(&(*child).comm) } {
		Ok(v) => v,
		Err(_) => return Ok(0),
	};
	let target_comm: [u8; 16] = unsafe { core::mem::transmute(target_comm_i8) };

	let event = PtraceAccessCheckEvent {
		header: EventHeader {
			ts,
			event_type: EVT_PTRACE_ACCESS_CHECK,
			cgroup_id,
			mnt_ns,
			pid,
			ppid: ppid as u32,
			uid,
			tgid,
			comm,
			parent_comm,
			_pad0: [0u8; 3],
		},
		target_pid,
		target_tgid,
		target_uid,
		mode,
		stage: PTRACE_STAGE_REQUEST,
		target_comm,
		_pad0: [0; 7],
	};

	let _ = EVT_MAP.output::<PtraceAccessCheckEvent>(&event, 0);
	Ok(0)
}
