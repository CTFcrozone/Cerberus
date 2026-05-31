use aya_ebpf::{
	bindings::path,
	cty::c_char,
	helpers::{
		bpf_probe_read_kernel,
		r#gen::{bpf_d_path, bpf_get_current_task},
	},
};
use lib_ebpf_common::{FILE_NAME_LEN, FILE_PATH_LEN};

use crate::vmlinux::{dentry, mnt_namespace, nsproxy};

pub unsafe fn get_ppid() -> i32 {
	let task = bpf_get_current_task() as *const crate::vmlinux::task_struct;
	if task.is_null() {
		return -1;
	}

	let parent: *const crate::vmlinux::task_struct = match bpf_probe_read_kernel(&(*task).real_parent) {
		Ok(p) => p,
		Err(_) => return -1,
	};

	match bpf_probe_read_kernel(&(*parent).pid) {
		Ok(ppid) => ppid,
		Err(_) => -1,
	}
}

macro_rules! tp_try_read {
	($ctx:expr, $offset:expr) => {
		match $ctx.read_at($offset) {
			Ok(val) => val,
			Err(_) => return Err(1),
		}
	};
}

pub unsafe fn get_mnt_ns() -> u32 {
	let task = bpf_get_current_task() as *const crate::vmlinux::task_struct;
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

pub fn read_dentry_name(dentry: *const dentry, buf: &mut [u8; FILE_NAME_LEN]) -> Option<u32> {
	if dentry.is_null() {
		return None;
	}

	unsafe {
		let d = &*dentry;

		let name_ptr = d.__bindgen_anon_1.d_name.name;
		if name_ptr.is_null() {
			return None;
		}

		let len = d.__bindgen_anon_1.d_name.__bindgen_anon_1.__bindgen_anon_1.len as usize;
		let copy_len = core::cmp::min(len, FILE_NAME_LEN);

		let name = match bpf_probe_read_kernel::<[u8; FILE_NAME_LEN]>(name_ptr as *const _) {
			Ok(v) => v,
			Err(_) => return None,
		};

		buf[..copy_len].copy_from_slice(&name[..copy_len]);

		Some(copy_len as u32)
	}
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
