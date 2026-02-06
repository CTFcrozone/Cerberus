use aya_ebpf::{
	helpers::{
		bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_probe_read_kernel,
		r#gen::bpf_get_current_cgroup_id,
	},
	programs::ProbeContext,
};
use lib_ebpf_common::{EventHeader, ModuleInitEvent};

use crate::{utils::get_mnt_ns, vmlinux::module, EVT_MAP};

pub fn try_do_init_module(ctx: ProbeContext) -> Result<u32, i64> {
	let module: *const module = ctx.arg(0).ok_or(1i64)?;

	if module.is_null() {
		return Err(1i64);
	}

	let uid = bpf_get_current_uid_gid() as u32;
	let pid = bpf_get_current_pid_tgid() as u32;
	let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
	let comm_raw = bpf_get_current_comm().unwrap_or([0u8; 16]);

	let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
	let mnt_ns = unsafe { get_mnt_ns() };
	let name_i8 = unsafe { bpf_probe_read_kernel(&(*module).name).map_err(|_| 1i64)? };

	let module_name: [u8; 56] = unsafe { core::mem::transmute(name_i8) };

	let event = ModuleInitEvent {
		header: EventHeader {
			event_type: 5,
			cgroup_id,
			mnt_ns,
			_pad0: [0u8; 3],
		},
		pid,
		uid,
		tgid,
		comm: comm_raw,
		module_name,
		_pad0: [0u8; 4],
	};

	match EVT_MAP.output(&event, 0) {
		Ok(_) => (),
		Err(e) => return Err(e),
	}

	Ok(0)
}
