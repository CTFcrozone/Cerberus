use aya_ebpf::{
	helpers::{
		bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
		r#gen::{bpf_get_current_cgroup_id, bpf_ktime_get_ns},
	},
	programs::LsmContext,
};
use aya_log_ebpf::error;
use lib_ebpf_common::{
	BpfMapEvent, BpfProgLoadEvent, EventHeader, FLAG_GPL, FLAG_JITED, FLAG_KPROBE_OVR, FLAG_SLEEPABLE,
};

use crate::{
	utils::{get_mnt_ns, get_ppid},
	vmlinux::{bpf_map, bpf_prog},
	EVT_MAP,
};

// LSM_HOOK(int, 0, bpf_prog_load, struct bpf_prog *prog, union bpf_attr *attr, struct bpf_token *token, bool kernel)
pub fn try_bpf_prog_load(ctx: LsmContext) -> Result<i32, i32> {
	let uid = bpf_get_current_uid_gid() as u32;
	let pid = bpf_get_current_pid_tgid() as u32;
	let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
	let ts = unsafe { bpf_ktime_get_ns() };
	// let task = unsafe { bpf_get_current_task() as *const task_struct };
	// let parent = unsafe { bpf_probe_read_kernel(&(*task).real_parent).map_err(|e| e as i32)? };
	// let raw_ppid: i32 = unsafe { bpf_probe_read_kernel(&(*parent).pid).map_err(|e| e as i32)? };

	let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
	let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
	let mnt_ns = unsafe { get_mnt_ns() };
	let ppid = unsafe { get_ppid() };
	let prog: *const bpf_prog = unsafe { ctx.arg(0) };

	if prog.is_null() {
		return Ok(0);
	}

	let attach_type = unsafe { (*prog).expected_attach_type };
	let prog_type = unsafe { (*prog).type_ };
	let tag: [u8; 8] = unsafe { (*prog).__bindgen_anon_1.tag };

	let mut flags: u32 = 0;

	unsafe {
		if (*prog).jited() != 0 {
			flags |= FLAG_JITED;
		}
		if (*prog).sleepable() != 0 {
			flags |= FLAG_SLEEPABLE;
		}
		if (*prog).gpl_compatible() != 0 {
			flags |= FLAG_GPL;
		}
		if (*prog).kprobe_override() != 0 {
			flags |= FLAG_KPROBE_OVR;
		}
	}

	let event = BpfProgLoadEvent {
		header: EventHeader {
			ts,
			event_type: 9,
			cgroup_id,
			mnt_ns,
			pid,
			ppid: ppid as u32,
			uid,
			tgid,
			comm,
			_pad0: [0u8; 3],
		},
		attach_type,
		prog_type,
		tag,
		flags,
		_pad0: [0u8; 4],
	};

	if let Err(e) = EVT_MAP.output(&event, 0) {
		error!(&ctx, "ringbuf write failed: {}", e);
	}

	Ok(0)
}

pub fn try_bpf_map(ctx: LsmContext) -> Result<i32, i32> {
	let uid = bpf_get_current_uid_gid() as u32;
	let pid = bpf_get_current_pid_tgid() as u32;
	let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
	let ts = unsafe { bpf_ktime_get_ns() };
	// let task = unsafe { bpf_get_current_task() as *const task_struct };
	// let parent = unsafe { bpf_probe_read_kernel(&(*task).real_parent).map_err(|e| e as i32)? };
	// let raw_ppid: i32 = unsafe { bpf_probe_read_kernel(&(*parent).pid).map_err(|e| e as i32)? };

	let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
	let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
	let mnt_ns = unsafe { get_mnt_ns() };
	let ppid = unsafe { get_ppid() };
	let map: *const bpf_map = unsafe { ctx.arg(0) };

	if map.is_null() {
		return Ok(0);
	}

	let map_id: u32 = unsafe { (*map).id };
	let map_type: u32 = unsafe { (*map).map_type };
	let mut map_name = [0u8; 64];

	unsafe {
		let name_ptr = (*map).name.as_ptr() as *const u8;
		core::ptr::copy_nonoverlapping(name_ptr, map_name.as_mut_ptr(), 16);
	}

	let event = BpfMapEvent {
		header: EventHeader {
			ts,
			event_type: 11,
			cgroup_id,
			mnt_ns,
			pid,
			ppid: ppid as u32,
			uid,
			tgid,
			comm,
			_pad0: [0u8; 3],
		},
		map_id,
		map_type,
		map_name,
	};

	if let Err(e) = EVT_MAP.output(&event, 0) {
		error!(&ctx, "ringbuf write failed: {}", e);
	}

	Ok(0)
}
