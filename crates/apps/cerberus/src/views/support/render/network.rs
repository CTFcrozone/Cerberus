use lib_common::event::{InetSockEvent, SocketEvent};
use ratatui::text::Line;

use crate::views::support::render::{family_to_string, ip_to_string, socket_op_to_string};

pub fn render_socket(s: &SocketEvent) -> Line<'static> {
	Line::raw(format!(
		"[SOCKET_{}] {}:{} | FAMILY:{}",
		socket_op_to_string(s.op),
		ip_to_string(s.addr),
		s.port,
		family_to_string(s.family)
	))
}

pub fn render_inet_sock(n: &InetSockEvent) -> Line<'static> {
	Line::raw(format!(
		"[INET_SOCK] {}:{} -> {}:{} | PROTO:{} | {} -> {}",
		ip_to_string(n.saddr),
		n.sport,
		ip_to_string(n.daddr),
		n.dport,
		n.protocol,
		n.old_state,
		n.new_state
	))
}
