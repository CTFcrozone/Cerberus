use aya_ebpf::{
	helpers::{
		bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
		r#gen::{bpf_get_current_cgroup_id, bpf_ktime_get_ns},
	},
	programs::LsmContext,
};
use aya_log_ebpf::error;
use lib_ebpf_common::{EventHeader, InodeEvent};

use crate::{
	utils::{get_mnt_ns, get_ppid},
	vmlinux::dentry,
	EVT_MAP,
};

// LSM_HOOK(int, 0, inode_unlink, struct inode *dir, struct dentry *dentry)
pub fn try_inode_unlink(ctx: LsmContext) -> Result<i32, i32> {
	let uid = bpf_get_current_uid_gid() as u32;
	let pid = bpf_get_current_pid_tgid() as u32;
	let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
	let comm_raw = bpf_get_current_comm().unwrap_or([0u8; 16]);
	let ts = unsafe { bpf_ktime_get_ns() };
	let ppid = unsafe { get_ppid() };

	let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
	let mnt_ns = unsafe { get_mnt_ns() };
	let mut filename = [0u8; 64];

	let dentry: *const dentry = unsafe { ctx.arg(1) };

	if dentry.is_null() {
		return Ok(0);
	}

	let name = unsafe { (*dentry).__bindgen_anon_1.d_name.name };
	let len = unsafe { (*dentry).__bindgen_anon_1.d_name.__bindgen_anon_1.__bindgen_anon_1.len };

	let slice = unsafe { core::slice::from_raw_parts(name, len as usize) };
	let copy_len = core::cmp::min(slice.len(), filename.len());
	filename[..copy_len].copy_from_slice(&slice[..copy_len]);

	let event = InodeEvent {
		header: EventHeader {
			ts,
			event_type: 10,
			cgroup_id,
			mnt_ns,
			pid,
			ppid: ppid as u32,
			uid,
			tgid,
			comm: comm_raw,
			_pad0: [0u8; 3],
		},
		filename,
		filename_len: len,
		op: 0,
		_pad0: [0u8; 3],
	};

	if let Err(e) = EVT_MAP.output(&event, 0) {
		error!(&ctx, "ringbuf write failed: {}", e);
	}

	Ok(0)
}

pub fn try_inode_mkdir(ctx: LsmContext) -> Result<i32, i32> {
	let uid = bpf_get_current_uid_gid() as u32;
	let pid = bpf_get_current_pid_tgid() as u32;
	let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
	let comm_raw = bpf_get_current_comm().unwrap_or([0u8; 16]);
	let ts = unsafe { bpf_ktime_get_ns() };
	let ppid = unsafe { get_ppid() };

	let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
	let mnt_ns = unsafe { get_mnt_ns() };
	let mut filename = [0u8; 64];

	let dentry: *const dentry = unsafe { ctx.arg(1) };

	if dentry.is_null() {
		return Ok(0);
	}

	let name = unsafe { (*dentry).__bindgen_anon_1.d_name.name };
	let len = unsafe { (*dentry).__bindgen_anon_1.d_name.__bindgen_anon_1.__bindgen_anon_1.len };

	let slice = unsafe { core::slice::from_raw_parts(name, len as usize) };
	let copy_len = core::cmp::min(slice.len(), filename.len());
	filename[..copy_len].copy_from_slice(&slice[..copy_len]);

	let event = InodeEvent {
		header: EventHeader {
			ts,
			event_type: 10,
			cgroup_id,
			mnt_ns,
			pid,
			ppid: ppid as u32,
			uid,
			tgid,
			comm: comm_raw,
			_pad0: [0u8; 3],
		},
		filename,
		filename_len: len,
		op: 1,
		_pad0: [0u8; 3],
	};

	if let Err(e) = EVT_MAP.output(&event, 0) {
		error!(&ctx, "ringbuf write failed: {}", e);
	}

	Ok(0)
}

pub fn try_inode_rmdir(ctx: LsmContext) -> Result<i32, i32> {
	let uid = bpf_get_current_uid_gid() as u32;
	let pid = bpf_get_current_pid_tgid() as u32;
	let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
	let comm_raw = bpf_get_current_comm().unwrap_or([0u8; 16]);
	let ts = unsafe { bpf_ktime_get_ns() };
	let ppid = unsafe { get_ppid() };

	let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
	let mnt_ns = unsafe { get_mnt_ns() };
	let mut filename = [0u8; 64];

	let dentry: *const dentry = unsafe { ctx.arg(1) };

	if dentry.is_null() {
		return Ok(0);
	}

	let name = unsafe { (*dentry).__bindgen_anon_1.d_name.name };
	let len = unsafe { (*dentry).__bindgen_anon_1.d_name.__bindgen_anon_1.__bindgen_anon_1.len };

	let slice = unsafe { core::slice::from_raw_parts(name, len as usize) };
	let copy_len = core::cmp::min(slice.len(), filename.len());
	filename[..copy_len].copy_from_slice(&slice[..copy_len]);

	let event = InodeEvent {
		header: EventHeader {
			ts,
			event_type: 10,
			cgroup_id,
			mnt_ns,
			pid,
			ppid: ppid as u32,
			uid,
			tgid,
			comm: comm_raw,
			_pad0: [0u8; 3],
		},
		filename,
		filename_len: len,
		op: 2,
		_pad0: [0u8; 3],
	};

	if let Err(e) = EVT_MAP.output(&event, 0) {
		error!(&ctx, "ringbuf write failed: {}", e);
	}

	Ok(0)
}
