use lib_common::event::{BprmSecurityEvent, ModuleEvent, PtraceAccessCheckEvent, RingBufEvent};
use ratatui::text::Line;

use crate::views::support::render::{module_op_to_string, ptrace_stage_to_string};

pub fn render_generic(g: &RingBufEvent) -> Line<'static> {
	let h = &g.header;

	Line::raw(format!(
		"[{}] UID:{} | PID:{} | TGID:{} | CMD:{} | META:{}",
		g.name, h.uid, h.pid, h.tgid, h.comm, g.meta
	))
}

pub fn render_module(m: &ModuleEvent) -> Line<'static> {
	let h = &m.header;

	Line::raw(format!(
		"[MODULE_{}] UID:{} | PID:{} | TGID:{} | CMD:{} | MODULE:{}",
		module_op_to_string(m.op),
		h.uid,
		h.pid,
		h.tgid,
		h.comm,
		m.module_name
	))
}

pub fn render_bprm(b: &BprmSecurityEvent) -> Line<'static> {
	let h = &b.header;

	Line::raw(format!(
		"[EXEC] UID:{} | PID:{} | TGID:{} | CMD:{} | FILE:{}",
		h.uid, h.pid, h.tgid, h.comm, b.filepath
	))
}

pub fn render_ptrace(p: &PtraceAccessCheckEvent) -> Line<'static> {
	let h = &p.header;

	Line::raw(format!(
		"[PTRACE_{}] UID:{} | PID:{} | TGID:{} | CMD:{} \
		 -> TARGET_PID:{} | TARGET_TGID:{} | TARGET_UID:{} \
		 | TARGET_COMM:{} | MODE:{:#x}",
		ptrace_stage_to_string(p.stage),
		h.uid,
		h.pid,
		h.tgid,
		h.comm,
		p.target_pid,
		p.target_tgid,
		p.target_uid,
		p.target_comm,
		p.mode
	))
}
