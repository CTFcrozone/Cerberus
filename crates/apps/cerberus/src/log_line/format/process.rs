use lib_common::event::{BprmSecurityEvent, ModuleEvent, PtraceAccessCheckEvent, RingBufEvent};

use crate::log_line::utils::{module_op_to_string, ptrace_stage_to_string};

pub fn render_generic(g: &RingBufEvent) -> String {
	let h = &g.header;

	format!(
		"[{}] UID:{} | PID:{} | TGID:{} | CMD:{} | META:{}",
		g.name, h.uid, h.pid, h.tgid, h.comm, g.meta
	)
}

pub fn render_module(m: &ModuleEvent) -> String {
	let h = &m.header;

	format!(
		"[MODULE_{}] UID:{} | PID:{} | TGID:{} | CMD:{} | MODULE:{}",
		module_op_to_string(m.op),
		h.uid,
		h.pid,
		h.tgid,
		h.comm,
		m.module_name
	)
}

pub fn render_bprm(b: &BprmSecurityEvent) -> String {
	let h = &b.header;

	format!(
		"[EXEC] UID:{} | PID:{} | TGID:{} | CMD:{} | FILE:{}",
		h.uid, h.pid, h.tgid, h.comm, b.filepath
	)
}

pub fn render_ptrace(p: &PtraceAccessCheckEvent) -> String {
	let h = &p.header;

	format!(
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
	)
}
