use aya_ebpf::{
	bindings::path,
	helpers::{
		bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
		r#gen::{bpf_d_path, bpf_get_current_cgroup_id},
	},
	macros::map,
	maps::PerCpuArray,
	programs::LsmContext,
};
use aya_log_ebpf::{error, info};
use lib_ebpf_common::{BprmSecurityCheckEvent, EventHeader};

use crate::{utils::get_mnt_ns, vmlinux::linux_binprm, EVT_MAP};

const PATH_LEN: usize = 128;

#[map(name = "FPATH")]
static mut FPATH: PerCpuArray<[u8; PATH_LEN]> = PerCpuArray::with_max_entries(1, 0);

pub fn try_bprm_check_security(ctx: LsmContext) -> Result<i32, i32> {
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
		let ret = bpf_d_path(f_path, buf as *mut i8, PATH_LEN as u32);

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
		_pad0: [0u8; 4],
	};

	match EVT_MAP.output(&event, 0) {
		Ok(_) => (),
		Err(e) => error!(&ctx, "Couldn't write to the ring buffer ->> ERROR: {}", e),
	}
	Ok(0)
}
