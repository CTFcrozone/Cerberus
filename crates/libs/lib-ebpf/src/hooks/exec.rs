use aya_ebpf::{
	helpers::{
		bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
		generated::{bpf_get_current_cgroup_id, bpf_ktime_get_ns},
	},
	macros::map,
	maps::PerCpuArray,
	programs::LsmContext,
};
// use aya_log_ebpf::error;
use lib_ebpf_common::{BprmSecurityCheckEvent, EVT_BPRM_CHECK_SEC, EventHeader, FILE_PATH_LEN};

use crate::{
	EVT_MAP, LSM_EXEC_DENY,
	utils::{get_mnt_ns, get_parent_comm, get_ppid, resolve_file_path},
	vmlinux::linux_binprm,
};

#[map(name = "FPATH")]
static FPATH: PerCpuArray<[u8; FILE_PATH_LEN]> = PerCpuArray::with_max_entries(1, 0);

pub fn try_bprm_check_security(ctx: LsmContext) -> Result<i32, i32> {
	let uid = bpf_get_current_uid_gid() as u32;
	let pid = bpf_get_current_pid_tgid() as u32;
	let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
	let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
	let parent_comm = unsafe { get_parent_comm() };

	let ts = unsafe { bpf_ktime_get_ns() };
	let ppid = unsafe { get_ppid() };
	let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
	let mnt_ns = unsafe { get_mnt_ns() };
	let bprm: *const linux_binprm = ctx.arg(0);

	if bprm.is_null() {
		return Ok(0);
	}

	let buf = FPATH.get_ptr_mut(0).ok_or(0)?;
	let ret = unsafe { resolve_file_path((*bprm).file, buf) };
	if ret == 0 {
		return Ok(0);
	}

	let event = BprmSecurityCheckEvent {
		header: EventHeader {
			ts,
			event_type: EVT_BPRM_CHECK_SEC,
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
		filepath: unsafe { *buf },
		path_len: ret,
		_pad0: [0u8; 4],
	};

	// if let Err(e) = EVT_MAP.output::<BprmSecurityCheckEvent>(&event, 0) {
	// 	error!(&ctx, "ringbuf write failed: {}", e);
	// }
	let _ = EVT_MAP.output::<BprmSecurityCheckEvent>(&event, 0);

	if unsafe { LSM_EXEC_DENY.get(&event.filepath) }.is_some() {
		return Err(-1);
	}

	Ok(0)
}
