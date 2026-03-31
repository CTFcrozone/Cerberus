use aya_ebpf::{
	helpers::{
		bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
		r#gen::{bpf_get_current_cgroup_id, bpf_ktime_get_ns},
	},
	programs::LsmContext,
};
use aya_log_ebpf::error;
use lib_ebpf_common::{EventHeader, InodeEvent, InodeRenameEvent, FILE_NAME_LEN};

use crate::{
	utils::{get_mnt_ns, get_ppid, read_dentry_name},
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
	let mut filename = [0u8; FILE_NAME_LEN];

	let dentry: *const dentry = unsafe { ctx.arg(1) };

	let len = match read_dentry_name(dentry, &mut filename) {
		Some(l) => l,
		None => return Ok(0),
	};

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

pub fn try_inode_rename(ctx: LsmContext) -> Result<i32, i32> {
	let uid = bpf_get_current_uid_gid() as u32;
	let pid = bpf_get_current_pid_tgid() as u32;
	let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
	let comm_raw = bpf_get_current_comm().unwrap_or([0u8; 16]);
	let ts = unsafe { bpf_ktime_get_ns() };
	let ppid = unsafe { get_ppid() };

	let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
	let mnt_ns = unsafe { get_mnt_ns() };
	let mut old_filename = [0u8; FILE_NAME_LEN];
	let mut new_filename = [0u8; FILE_NAME_LEN];

	let old_dentry: *const dentry = unsafe { ctx.arg(1) };
	let new_dentry: *const dentry = unsafe { ctx.arg(3) };

	let old_filename_len = match read_dentry_name(old_dentry, &mut old_filename) {
		Some(l) => l,
		None => return Ok(0),
	};

	let new_filename_len = match read_dentry_name(new_dentry, &mut new_filename) {
		Some(l) => l,
		None => return Ok(0),
	};

	let event = InodeRenameEvent {
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
		new_filename,
		old_filename,
		new_filename_len,
		old_filename_len,
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
	let mut filename = [0u8; FILE_NAME_LEN];

	let dentry: *const dentry = unsafe { ctx.arg(1) };
	let len = match read_dentry_name(dentry, &mut filename) {
		Some(l) => l,
		None => return Ok(0),
	};

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
	let mut filename = [0u8; FILE_NAME_LEN];

	let dentry: *const dentry = unsafe { ctx.arg(1) };
	let len = match read_dentry_name(dentry, &mut filename) {
		Some(l) => l,
		None => return Ok(0),
	};

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
