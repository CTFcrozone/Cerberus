use lib_common::event::CerberusEvent;
use lib_rules::Severity;

mod bpf;
mod fs;
mod network;
mod orthrus;
mod process;

pub fn string_from_event(evt: &CerberusEvent) -> String {
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
		CerberusEvent::Tamper(e) => orthrus::render_tamper(e),
	}
}

pub fn severity_to_level(sev: Severity) -> tracing::Level {
	match sev {
		Severity::Critical => tracing::Level::ERROR,
		Severity::High => tracing::Level::WARN,
		Severity::Medium => tracing::Level::WARN,
		Severity::Low => tracing::Level::INFO,
		Severity::VeryLow => tracing::Level::DEBUG,
		Severity::Info => tracing::Level::DEBUG,
	}
}
