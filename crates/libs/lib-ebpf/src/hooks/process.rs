use aya_ebpf::{
	helpers::{
		bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
		r#gen::{bpf_get_current_cgroup_id, bpf_send_signal},
	},
	programs::{LsmContext, ProbeContext, TracePointContext},
};
use aya_log_ebpf::error;
use lib_ebpf_common::{EventHeader, GenericEvent};

use crate::{utils::get_mnt_ns, vmlinux::task_struct, EVT_MAP};

pub fn try_commit_creds(ctx: ProbeContext) -> Result<u32, i64> {
	let old_uid = bpf_get_current_uid_gid() as u32;
	let pid = bpf_get_current_pid_tgid() as u32;
	let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
	let comm_raw = bpf_get_current_comm().unwrap_or([0u8; 16]);
	let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
	let mnt_ns = unsafe { get_mnt_ns() };

	let new_uid = ctx.arg(1).unwrap_or(0u32);

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
			Err(e) => return Err(e),
		}
	}

	Ok(0)
}

pub fn try_sys_enter_ptrace(ctx: TracePointContext) -> Result<u32, u32> {
	let uid = bpf_get_current_uid_gid() as u32;
	let pid = bpf_get_current_pid_tgid() as u32;
	let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
	let comm_raw = bpf_get_current_comm().unwrap_or([0u8; 16]);
	let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
	let mnt_ns = unsafe { get_mnt_ns() };

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
		meta: 0, // success flag
	};

	match EVT_MAP.output(&event, 0) {
		Ok(_) => (),
		Err(e) => error!(&ctx, "Failed to log ptrace event: {}", e),
	}

	Ok(0)
}

pub fn try_sys_enter_kill(ctx: LsmContext) -> Result<i32, i32> {
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
