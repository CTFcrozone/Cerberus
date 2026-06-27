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
				event = "generic",
				uid = h.uid,
				pid = h.pid,
				tgid = h.tgid,
				cmd = %h.comm,
				name = %e.name,
				meta = %e.meta,
			);
		}

		CerberusEvent::Module(e) => {
			let h = &e.header;

			warn!(
				event = "module",
				operation = %module_op_to_string(e.op),

				uid = h.uid,
				pid = h.pid,
				tgid = h.tgid,
				cmd = %h.comm,

				module = %e.module_name,
			);
		}

		CerberusEvent::Bprm(e) => {
			let h = &e.header;

			info!(
				event = "exec",

				uid = h.uid,
				pid = h.pid,
				tgid = h.tgid,
				cmd = %h.comm,

				file = %e.filepath,
			);
		}

		CerberusEvent::PtraceAccessCheck(e) => {
			let h = &e.header;

			warn!(
				event = "ptrace",
				stage = %ptrace_stage_to_string(e.stage),

				uid = h.uid,
				pid = h.pid,
				tgid = h.tgid,
				cmd = %h.comm,

				target_pid = e.target_pid,
				target_tgid = e.target_tgid,
				target_uid = e.target_uid,
				target_comm = %e.target_comm,

				mode = format_args!("{:#x}", e.mode),
			);
		}

		CerberusEvent::Inode(e) => {
			let h = &e.header;

			info!(
				event = "inode",
				operation = %inode_op_to_string(e.op),

				uid = h.uid,
				pid = h.pid,
				tgid = h.tgid,
				cmd = %h.comm,

				file = %e.filename,
			);
		}

		CerberusEvent::InodeMutation(e) => {
			let h = &e.header;

			info!(
				event = "inode_mutation",
				mutation = %inode_mutation_to_string(e.mutation),

				uid = h.uid,
				pid = h.pid,
				tgid = h.tgid,
				cmd = %h.comm,

				old = %e.old_filename,
				new = %e.new_filename,
			);
		}

		CerberusEvent::Socket(e) => {
			info!(
				event = "socket",
				operation = %socket_op_to_string(e.op),

				addr = %ip_to_string(e.addr),
				port = e.port,

				family = %family_to_string(e.family),
			);
		}

		CerberusEvent::InetSock(e) => {
			info!(
				event = "inet_sock",

				src = %format!("{}:{}", ip_to_string(e.saddr), e.sport),

				dst = %format!("{}:{}", ip_to_string(e.daddr), e.dport),

				protocol = e.protocol.as_ref(),

				old_state = e.old_state.as_ref(),
				new_state = e.new_state.as_ref(),
			);
		}

		CerberusEvent::BpfProgLoad(e) => {
			let h = &e.header;

			warn!(
				event = "bpf_prog_load",

				uid = h.uid,
				pid = h.pid,
				cmd = %h.comm,

				prog_type = %prog_type_to_string(e.prog_type),

				attach_type = %attach_type_to_string(e.attach_type),

				flags = %flags_to_string(e.flags),
			);
		}

		CerberusEvent::BpfMap(e) => {
			let h = &e.header;

			warn!(
				event = "bpf_map",

				uid = h.uid,
				pid = h.pid,
				cmd = %h.comm.as_ref(),

				map_name = %e.map_name.as_ref(),
				map_type = e.map_type.as_ref(),
				map_id = e.map_id,
			);
		}
	}
}
pub fn log_engine_event(evt: &EngineEvent) {
	match evt {
		EngineEvent::Matched(e) => {
			tracing::info!(
				event = "rule_matched",
				rule_id = %e.rule_id,
				severity = %e.severity.as_str(),
				uid = e.event_meta.uid,
				pid = e.event_meta.pid,
				comm = %e.event_meta.comm,
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
				tracing::warn!(
					event = "correlation_completed",
					root_rule_id = %root_rule_id,
					seq_id = %seq_id,
					seq_instance_id = %seq_instance_id,

					steps = steps,
					path = %path.join("->"),

					uid = event_meta.uid,
					pid = event_meta.pid,
					comm = %event_meta.comm,
				);
			}
		},

		EngineEvent::Response(r) => {
			tracing::warn!(
				event = "response",
				rule_id = %r.rule_id,
				response = %format!("{:?}", r.response),
			);
		}
	}
}
