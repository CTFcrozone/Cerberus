use lib_common::event::CerberusEvent;
use ratatui::text::Line;

mod bpf;
mod fs;
mod network;
mod process;
mod utils;

pub use utils::*;

pub fn line_from_event(evt: &CerberusEvent) -> Line<'static> {
	match evt {
		CerberusEvent::Generic(e) => process::render_generic(e),
		CerberusEvent::Module(e) => process::render_module(e),
		CerberusEvent::Bprm(e) => process::render_bprm(e),
		CerberusEvent::PtraceAccessCheck(e) => process::render_ptrace(e),

		CerberusEvent::Inode(e) => fs::render_inode(e),
		CerberusEvent::InodeMutation(e) => fs::render_inode_mutation(e),

		CerberusEvent::Socket(e) => network::render_socket(e),
		CerberusEvent::InetSock(e) => network::render_inet_sock(e),

		CerberusEvent::BpfProgLoad(e) => bpf::render_bpf_prog(e),
		CerberusEvent::BpfMap(e) => bpf::render_bpf_map(e),
	}
}
