use aya_ebpf::{
	bindings::path,
	cty::c_char,
	helpers::{
		bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
		r#gen::{bpf_d_path, bpf_get_current_cgroup_id},
	},
	macros::map,
	maps::PerCpuArray,
	programs::LsmContext,
};
use aya_log_ebpf::{error, info};
use lib_ebpf_common::{BprmSecurityCheckEvent, EventHeader, FILE_PATH_LEN};

use crate::{utils::get_mnt_ns, vmlinux::linux_binprm, EVT_MAP};

#[map(name = "FPATH")]
static mut FPATH: PerCpuArray<[u8; FILE_PATH_LEN]> = PerCpuArray::with_max_entries(1, 0);

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

	let ret = unsafe { resolve_file_path((*bprm).file, buf) };
	if ret == 0 {
		return Ok(0);
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
		path_len: ret,
	};

	if let Err(e) = EVT_MAP.output(&event, 0) {
		error!(&ctx, "ringbuf write failed: {}", e);
	}
	Ok(0)
}

#[inline(always)]
pub unsafe fn resolve_file_path(file: *mut crate::vmlinux::file, buf: *mut [u8; FILE_PATH_LEN]) -> u32 {
	if file.is_null() || buf.is_null() {
		return 0;
	}

	let f_path = &(*file).__bindgen_anon_1.f_path as *const _ as *mut path;

	let ret = bpf_d_path(f_path, (*buf).as_mut_ptr() as *mut c_char, FILE_PATH_LEN as u32);

	if ret <= 0 || ret as usize > FILE_PATH_LEN {
		return 0;
	}

	ret as u32
}
