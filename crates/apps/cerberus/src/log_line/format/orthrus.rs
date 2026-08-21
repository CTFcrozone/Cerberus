use lib_common::event::TamperEvent;

pub fn render_tamper(t: &TamperEvent) -> String {
	let h = &t.header;
	let sev = match t.severity {
		0 => "INFO",
		1 => "VERY_LOW",
		2 => "LOW",
		3 => "MEDIUM",
		4 => "HIGH",
		5 => "CRITICAL",
		_ => "?",
	};
	if t.age_ms > 0 {
		format!(
			"[TAMPER] SRC:{} | SEV:{} | REASON:{} | AGE_MS:{} | PID:{}",
			t.source, sev, t.reason, t.age_ms, h.pid,
		)
	} else {
		format!(
			"[TAMPER] SRC:{} | SEV:{} | REASON:{} | PID:{}",
			t.source, sev, t.reason, h.pid,
		)
	}
}
