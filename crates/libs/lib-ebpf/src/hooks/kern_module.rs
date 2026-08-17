use aya_ebpf::{
	helpers::{
		bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_probe_read_kernel,
		generated::{bpf_get_current_cgroup_id, bpf_ktime_get_ns},
	},
	programs::ProbeContext,
};
use lib_ebpf_common::{EVT_MODULE, EventHeader, MODULE_OP_INIT, ModuleEvent};

use crate::{
	EVT_MAP,
	utils::{get_mnt_ns, get_parent_comm, get_ppid},
	vmlinux::module,
};

pub fn try_do_init_module(ctx: ProbeContext) -> Result<u32, i64> {
	let module: *const module = ctx.arg(0).ok_or(1)?;

	if module.is_null() {
		return Err(1);
	}

	let uid = bpf_get_current_uid_gid() as u32;
	let pid = bpf_get_current_pid_tgid() as u32;
	let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
	let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
	let ts = unsafe { bpf_ktime_get_ns() };
	let ppid = unsafe { get_ppid() };
	let parent_comm = unsafe { get_parent_comm() };

	let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
	let mnt_ns = unsafe { get_mnt_ns() };
	let name_i8 = unsafe { bpf_probe_read_kernel(&(*module).name)? };

	let module_name: [u8; 56] = unsafe { core::mem::transmute(name_i8) };

	let event = ModuleEvent {
		header: EventHeader {
			ts,
			event_type: EVT_MODULE,
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
		module_name,
		op: MODULE_OP_INIT,
		_pad0: [0u8; 7],
	};

	EVT_MAP.output::<ModuleEvent>(&event, 0)?;

	Ok(0)
}
