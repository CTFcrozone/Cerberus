use aya_ebpf::{
	helpers::{
		bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, r#gen::bpf_get_current_cgroup_id,
	},
	programs::LsmContext,
};
use aya_log_ebpf::error;
use lib_ebpf_common::{BpfProgLoadEvent, EventHeader, FLAG_GPL, FLAG_JITED, FLAG_KPROBE_OVR, FLAG_SLEEPABLE};

use crate::{utils::get_mnt_ns, vmlinux::bpf_prog, EVT_MAP};

// LSM_HOOK(int, 0, bpf_prog_load, struct bpf_prog *prog, union bpf_attr *attr, struct bpf_token *token, bool kernel)
pub fn try_bpf_prog_load(ctx: LsmContext) -> Result<i32, i32> {
	let uid = bpf_get_current_uid_gid() as u32;
	let pid = bpf_get_current_pid_tgid() as u32;
	let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
	let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
	let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
	let mnt_ns = unsafe { get_mnt_ns() };

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
			event_type: 9,
			cgroup_id,
			mnt_ns,
			_pad0: [0u8; 3],
		},
		pid,
		uid,
		tgid,
		comm,
		attach_type,
		prog_type,
		tag,
		flags,
	};

	if let Err(e) = EVT_MAP.output(&event, 0) {
		error!(&ctx, "ringbuf write failed: {}", e);
	}

	Ok(0)
}
