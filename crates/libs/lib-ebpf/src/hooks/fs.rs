use core::ffi::c_char;

use aya_ebpf::{
	helpers::{
		bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_probe_read_kernel_str_bytes,
		r#gen::{bpf_get_current_cgroup_id, bpf_ktime_get_ns},
	},
	programs::LsmContext,
};
use aya_log_ebpf::error;
use lib_ebpf_common::{
	EventHeader, InodeEvent, InodeMutationEvent, EVT_INODE, EVT_INODE_MUTATE, FILE_NAME_LEN, INODE_MUTATION_LINK,
	INODE_MUTATION_RENAME, INODE_MUTATION_SYMLINK, INODE_OP_MKDIR, INODE_OP_RMDIR, INODE_OP_UNLINK,
};

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
			event_type: EVT_INODE,
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
		op: INODE_OP_UNLINK,
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

	let event = InodeMutationEvent {
		header: EventHeader {
			ts,
			event_type: EVT_INODE_MUTATE,
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
		mutation: INODE_MUTATION_RENAME,
		_pad0: [0u8; 7],
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
			event_type: EVT_INODE,
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
		op: INODE_OP_MKDIR,
		_pad0: [0u8; 3],
	};

	if let Err(e) = EVT_MAP.output(&event, 0) {
		error!(&ctx, "ringbuf write failed: {}", e);
	}

	Ok(0)
}

pub fn try_inode_link(ctx: LsmContext) -> Result<i32, i32> {
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

	let old_dentry: *const dentry = unsafe { ctx.arg(0) };
	let new_dentry: *const dentry = unsafe { ctx.arg(2) };

	let old_filename_len = match read_dentry_name(old_dentry, &mut old_filename) {
		Some(l) => l,
		None => return Ok(0),
	};

	let new_filename_len = match read_dentry_name(new_dentry, &mut new_filename) {
		Some(l) => l,
		None => return Ok(0),
	};

	let event = InodeMutationEvent {
		header: EventHeader {
			ts,
			event_type: EVT_INODE_MUTATE,
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
		mutation: INODE_MUTATION_LINK,
		_pad0: [0u8; 7],
	};

	if let Err(e) = EVT_MAP.output(&event, 0) {
		error!(&ctx, "ringbuf write failed: {}", e);
	}

	Ok(0)
}

pub fn try_inode_symlink(ctx: LsmContext) -> Result<i32, i32> {
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

	let new_dentry: *const dentry = unsafe { ctx.arg(1) };
	let old_name: *const c_char = unsafe { ctx.arg(2) };

	let new_filename_len = match read_dentry_name(new_dentry, &mut new_filename) {
		Some(l) => l,
		None => return Ok(0),
	};

	let old_filename_len = unsafe {
		match bpf_probe_read_kernel_str_bytes(old_name as *const u8, &mut old_filename) {
			Ok(s) => s.len() as u32,
			Err(_) => return Ok(0),
		}
	};

	let event = InodeMutationEvent {
		header: EventHeader {
			ts,
			event_type: EVT_INODE_MUTATE,
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
		mutation: INODE_MUTATION_SYMLINK,
		_pad0: [0u8; 7],
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
			event_type: EVT_INODE,
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
		op: INODE_OP_RMDIR,
		_pad0: [0u8; 3],
	};

	if let Err(e) = EVT_MAP.output(&event, 0) {
		error!(&ctx, "ringbuf write failed: {}", e);
	}

	Ok(0)
}
