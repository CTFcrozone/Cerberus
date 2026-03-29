use aya_ebpf::helpers::{bpf_probe_read_kernel, r#gen::bpf_get_current_task};

use crate::vmlinux::{mnt_namespace, nsproxy, pid_type::PIDTYPE_SID, signal_struct};

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
