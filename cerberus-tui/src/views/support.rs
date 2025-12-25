use lib_event::app_evt_types::CerberusEvent;
use ratatui::text::Line;

pub fn line_from_event(evt: &CerberusEvent) -> Line<'static> {
	match evt {
		CerberusEvent::Generic(g) => Line::raw(format!(
			"[{}] UID:{} | PID:{} | TGID:{} | CMD:{} | META:{}",
			g.name, g.uid, g.pid, g.tgid, g.comm, g.meta
		)),
		CerberusEvent::Module(m) => Line::raw(format!(
			"[MODULE_INIT] UID:{} | PID:{} | TGID:{} | CMD:{} | MODULE_NAME:{}",
			m.uid, m.pid, m.tgid, m.comm, m.module_name
		)),
		CerberusEvent::Bprm(b) => Line::raw(format!(
			"[BRPM_SEC_CHECK] UID:{} | PID:{} | TGID:{} | CMD:{} | FILEPATH:{}",
			b.uid, b.pid, b.tgid, b.comm, b.filepath
		)),
		CerberusEvent::InetSock(n) => Line::raw(format!(
			"[INET_SOCK] {}:{} → {}:{} | Proto: {} | {} → {}",
			ip_to_string(n.saddr),
			n.sport,
			ip_to_string(n.daddr),
			n.dport,
			n.protocol,
			n.old_state,
			n.new_state
		)),
	}
}

pub fn ip_to_string(ip: u32) -> String {
	let octets = ip.to_le_bytes();
	format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])
}
