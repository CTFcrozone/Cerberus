use lib_common::event::{InodeEvent, InodeMutationEvent};
use ratatui::text::Line;

use crate::views::support::render::{inode_mutation_to_string, inode_op_to_string};

pub fn render_inode(i: &InodeEvent) -> Line<'static> {
	let h = &i.header;

	Line::raw(format!(
		"[INODE_{}] UID:{} | PID:{} | TGID:{} | CMD:{} | FILE:{}",
		inode_op_to_string(i.op),
		h.uid,
		h.pid,
		h.tgid,
		h.comm,
		i.filename
	))
}

pub fn render_inode_mutation(m: &InodeMutationEvent) -> Line<'static> {
	let h = &m.header;

	Line::raw(format!(
		"[INODE_{}] UID:{} | PID:{} | TGID:{} | CMD:{} | OLD:{} | NEW:{}",
		inode_mutation_to_string(m.mutation),
		h.uid,
		h.pid,
		h.tgid,
		h.comm,
		m.old_filename,
		m.new_filename
	))
}
