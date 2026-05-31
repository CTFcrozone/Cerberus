use lib_common::event::{BpfMapEvent, BpfProgLoadEvent};
use ratatui::text::Line;

use crate::views::support::render::{attach_type_to_string, flags_to_string, prog_type_to_string};

pub fn render_bpf_prog(b: &BpfProgLoadEvent) -> Line<'static> {
	let h = &b.header;

	Line::raw(format!(
		"[BPF_PROG_LOAD] UID:{} | PID:{} | CMD:{} \
		 | TYPE:{} | ATTACH:{} | FLAGS:{}",
		h.uid,
		h.pid,
		h.comm,
		prog_type_to_string(b.prog_type),
		attach_type_to_string(b.attach_type),
		flags_to_string(b.flags),
	))
}

pub fn render_bpf_map(b: &BpfMapEvent) -> Line<'static> {
	let h = &b.header;

	Line::raw(format!(
		"[BPF_MAP] UID:{} | PID:{} | CMD:{} \
		 | NAME:{} | TYPE:{} | ID:{}",
		h.uid, h.pid, h.comm, b.map_name, b.map_type, b.map_id,
	))
}
