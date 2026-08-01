use lib_common::event::{InodeEvent, InodeMutationEvent};

use crate::log_line::utils::{inode_mutation_to_string, inode_op_to_string};

pub fn render_inode(i: &InodeEvent) -> String {
	let h = &i.header;

	format!(
		"[INODE_{}] UID:{} | PID:{} | TGID:{} | CMD:{} | FILE:{}",
		inode_op_to_string(i.op),
		h.uid,
		h.pid,
		h.tgid,
		h.comm,
		i.filename
	)
}

pub fn render_inode_mutation(m: &InodeMutationEvent) -> String {
	let h = &m.header;

	format!(
		"[INODE_{}] UID:{} | PID:{} | TGID:{} | CMD:{} | OLD:{} | NEW:{}",
		inode_mutation_to_string(m.mutation),
		h.uid,
		h.pid,
		h.tgid,
		h.comm,
		m.old_filename,
		m.new_filename
	)
}
