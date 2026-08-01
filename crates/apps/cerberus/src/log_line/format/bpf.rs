use crate::log_line::utils::{attach_type_to_string, flags_to_string, prog_type_to_string};
use lib_common::event::{BpfMapEvent, BpfProgLoadEvent};

pub fn render_bpf_prog(b: &BpfProgLoadEvent) -> String {
	let h = &b.header;

	format!(
		"[BPF_PROG_LOAD] UID:{} | PID:{} | CMD:{} \
		 | TYPE:{} | ATTACH:{} | FLAGS:{}",
		h.uid,
		h.pid,
		h.comm,
		prog_type_to_string(b.prog_type),
		attach_type_to_string(b.attach_type),
		flags_to_string(b.flags),
	)
}

pub fn render_bpf_map(b: &BpfMapEvent) -> String {
	let h = &b.header;

	format!(
		"[BPF_MAP] UID:{} | PID:{} | CMD:{} \
		 | NAME:{} | TYPE:{} | ID:{}",
		h.uid, h.pid, h.comm, b.map_name, b.map_type, b.map_id,
	)
}
