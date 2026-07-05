mod utils;

use lib_common::event::*;
use lib_rules::EngineEvent;
use tracing::{info, warn};

use crate::log_line::utils::{
	attach_type_to_string, family_to_string, flags_to_string, inode_mutation_to_string, inode_op_to_string,
	ip_to_string, module_op_to_string, prog_type_to_string, ptrace_stage_to_string, socket_op_to_string,
};

pub fn log_cerberus_event(evt: &CerberusEvent) {
	match evt {
		CerberusEvent::Generic(e) => {
			let h = &e.header;

			info!(
				event.kind = "generic",

				process.uid = h.uid,
				process.pid = h.pid,
				process.tgid = h.tgid,
				process.comm = %h.comm,

				generic.name = %e.name,
				generic.meta = %e.meta,
			);
		}

		CerberusEvent::Module(e) => {
			let h = &e.header;

			warn!(
				event.kind = "module",

				process.uid = h.uid,
				process.pid = h.pid,
				process.tgid = h.tgid,
				process.comm = %h.comm,

				module.op = %module_op_to_string(e.op),
				module.name = %e.module_name,
			);
		}

		CerberusEvent::Bprm(e) => {
			let h = &e.header;

			info!(
				event.kind = "exec",

				process.uid = h.uid,
				process.pid = h.pid,
				process.tgid = h.tgid,
				process.comm = %h.comm,

				process.filepath = %e.filepath,
			);
		}

		CerberusEvent::PtraceAccessCheck(e) => {
			let h = &e.header;

			warn!(
				event.kind = "ptrace",

				process.uid = h.uid,
				process.pid = h.pid,
				process.tgid = h.tgid,
				process.comm = %h.comm,

				process.target.pid = e.target_pid,
				process.target.tgid = e.target_tgid,
				process.target.uid = e.target_uid,
				process.target.comm = %e.target_comm,

				ptrace.mode = format_args!("{:#x}", e.mode),
				ptrace.stage = %ptrace_stage_to_string(e.stage),
			);
		}

		CerberusEvent::Inode(e) => {
			let h = &e.header;

			info!(
				event.kind = "inode",

				process.uid = h.uid,
				process.pid = h.pid,
				process.tgid = h.tgid,
				process.comm = %h.comm,

				inode.filename = %e.filename,
				inode.op = %inode_op_to_string(e.op),
			);
		}

		CerberusEvent::InodeMutation(e) => {
			let h = &e.header;

			info!(
				event.kind = "inode_mutation",

				process.uid = h.uid,
				process.pid = h.pid,
				process.tgid = h.tgid,
				process.comm = %h.comm,

				inode.old_filename = %e.old_filename,
				inode.new_filename = %e.new_filename,
				inode.mutation.type = %inode_mutation_to_string(e.mutation),
			);
		}

		CerberusEvent::Socket(e) => {
			info!(
				event.kind = "socket",

				socket.op = %socket_op_to_string(e.op),
				socket.port = e.port,
				socket.family = %family_to_string(e.family),

				network.address = %ip_to_string(e.addr),
			);
		}

		CerberusEvent::InetSock(e) => {
			info!(
				event.kind = "inet_sock",

				network.saddr = %ip_to_string(e.saddr),
				network.daddr = %ip_to_string(e.daddr),

				network.sport = e.sport,
				network.dport = e.dport,

				network.protocol = e.protocol.as_ref(),

				socket.old_state = e.old_state.as_ref(),
				socket.new_state = e.new_state.as_ref(),
			);
		}

		CerberusEvent::BpfProgLoad(e) => {
			let h = &e.header;

			warn!(
				event.kind = "bpf_prog_load",

				process.uid = h.uid,
				process.pid = h.pid,
				process.tgid = h.tgid,
				process.comm = %h.comm,

				bpf.prog.type = %prog_type_to_string(e.prog_type),
				bpf.prog.attach_type = %attach_type_to_string(e.attach_type),
				bpf.prog.flags = %flags_to_string(e.flags),
				bpf.prog.tag = %e.tag,
			);
		}

		CerberusEvent::BpfMap(e) => {
			let h = &e.header;

			warn!(
				event.kind = "bpf_map",

				process.uid = h.uid,
				process.pid = h.pid,
				process.tgid = h.tgid,
				process.comm = %h.comm,

				bpf.map.name = %e.map_name,
				bpf.map.type = e.map_type.as_ref(),
				bpf.map.id = e.map_id,
			);
		}
	}
}
pub fn log_engine_event(evt: &EngineEvent) {
	match evt {
		EngineEvent::Matched(e) => {
			info!(
				event.kind = "rule_match",

				rule.id = %e.rule_id,
				rule.severity = %e.severity.as_str(),

				process.uid = e.event_meta.uid,
				process.pid = e.event_meta.pid,
				process.comm = %e.event_meta.comm,
			);
		}

		EngineEvent::Correlation(c) => match c {
			lib_rules::CorrelationEvent::Step { .. } => {
				tracing::debug!(event = "correlation_step",);
			}

			lib_rules::CorrelationEvent::Completed {
				root_rule_id,
				seq_id,
				seq_instance_id,
				path,
				steps,
				event_meta,
			} => {
				warn!(
					event.kind = "correlation",

					correlation.root_rule_id = %root_rule_id,
					correlation.seq_id = %seq_id,
					correlation.instance_id = %seq_instance_id,
					correlation.path = %path.join("->"),
					correlation.steps = steps,

					process.uid = event_meta.uid,
					process.pid = event_meta.pid,
					process.comm = %event_meta.comm,
				);
			}
		},

		EngineEvent::Response(r) => {
			warn!(
				event.kind = "response",

				rule.id = %r.rule_id,
				response.action = %format!("{:?}", r.response),
			);
		}
	}
}
