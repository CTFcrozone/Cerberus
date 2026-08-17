use core::mem;

use aya_ebpf::{
	bindings::path,
	cty::c_char,
	helpers::{
		bpf_probe_read_kernel,
		generated::{bpf_d_path, bpf_get_current_task},
	},
	programs::XdpContext,
};
use lib_ebpf_common::{FILE_NAME_LEN, FILE_PATH_LEN};

use crate::vmlinux::{dentry, mnt_namespace, nsproxy};

pub unsafe fn get_ppid() -> i32 {
	let task = unsafe { bpf_get_current_task() } as *const crate::vmlinux::task_struct;
	if task.is_null() {
		return -1;
	}

	let parent: *const crate::vmlinux::task_struct = match unsafe { bpf_probe_read_kernel(&(*task).real_parent) } {
		Ok(p) => p,
		Err(_) => return -1,
	};

	match unsafe { bpf_probe_read_kernel(&(*parent).pid) } {
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

pub unsafe fn get_parent_comm() -> [u8; 16] {
	let mut comm = [0u8; 16];

	let task = unsafe { bpf_get_current_task() } as *const crate::vmlinux::task_struct;
	if task.is_null() {
		return comm;
	}

	let parent: *const crate::vmlinux::task_struct = match unsafe { bpf_probe_read_kernel(&(*task).real_parent) } {
		Ok(p) => p,
		Err(_) => return comm,
	};
	if parent.is_null() {
		return comm;
	}

	if let Ok(c) = unsafe { bpf_probe_read_kernel::<[u8; 16]>(&(*parent).comm as *const _ as *const [u8; 16]) } {
		comm = c;
	}

	comm
}
#[inline(always)]
pub unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
	let start = ctx.data();
	let end = ctx.data_end();
	let len = mem::size_of::<T>();

	if start + offset + len > end {
		return Err(());
	}

	let ptr = (start + offset) as *const T;
	Ok(unsafe { &*ptr })
}

pub unsafe fn get_mnt_ns() -> u32 {
	let task = unsafe { bpf_get_current_task() } as *const crate::vmlinux::task_struct;
	if task.is_null() {
		return 0;
	}

	let nsproxy: *const nsproxy = match unsafe { bpf_probe_read_kernel(&(*task).nsproxy) } {
		Ok(p) => p,
		Err(_) => return 0,
	};
	if nsproxy.is_null() {
		return 0;
	}

	let mnt_ns: *const mnt_namespace = match unsafe { bpf_probe_read_kernel(&(*nsproxy).mnt_ns) } {
		Ok(p) => p,
		Err(_) => return 0,
	};
	if mnt_ns.is_null() {
		return 0;
	}

	match unsafe { bpf_probe_read_kernel(&(*mnt_ns).ns.inum) } {
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

	let f_path = unsafe { &(*file).__bindgen_anon_1.f_path } as *const _ as *mut path;

	let ret = unsafe { bpf_d_path(f_path, (*buf).as_mut_ptr() as *mut c_char, FILE_PATH_LEN as u32) };
	let ret_usize = ret as usize;

	if ret <= 0 || ret_usize as usize > FILE_PATH_LEN {
		return 0;
	}

	for i in ret_usize..FILE_PATH_LEN {
		if i >= ret_usize {
			unsafe { (*buf)[i] = 0 };
		}
	}

	ret as u32
}
