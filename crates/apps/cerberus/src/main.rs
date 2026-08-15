// region:    --- Modules
mod agent;
mod cli;
mod core;
mod error;
mod event;
mod hook_registry;
mod log_line;
mod styles;
mod supervisor;
mod views;
mod workers;
// endregion: --- Modules

use crate::{
	cli::args::{Cli, RunMode},
	core::start_tui,
	event::AppEvent,
	hook_registry::{
		HookView,
		event::HookCommand,
		helper_fns::{register_kprobe, register_lsm, register_tracepoint, register_xdp},
		registry::HookRegistry,
	},
	supervisor::Supervisor,
	workers::{ContainerResolver, HookWorker, ResponseExecutor, RingBufWorker, RuleEngineWorker, RuleWatchWorker},
};

pub use self::error::{Error, Result};
use agent::*;
use aya::{
	Btf, Ebpf,
	maps::{MapData, RingBuf},
};
use clap::Parser;

use lib_common::event::CerberusEvent;
use lib_container::{container_manager::ContainerManager, runtime::k8s_connect};
use lib_event::unbound::new_channel_unbounded_async;
use lib_rules::{ResponseRequest, RuleEngine, RuleSet};
use std::{path::Path, sync::Arc};
use tracing_subscriber::{EnvFilter, fmt::time::ChronoLocal, layer::SubscriberExt, util::SubscriberInitExt};
#[rustfmt::skip]
use tracing::{debug};
use tokio::io::unix::AsyncFd;

#[tokio::main]
async fn main() -> Result<()> {
	let args = Cli::parse();

	let console_layer = tracing_subscriber::fmt::layer()
		.with_target(false)
		.with_timer(ChronoLocal::new("[%H:%M:%S]".to_string()));
	let filter = EnvFilter::from_default_env();

	let (_guard, logging_enabled) = if let Some(path) = &args.log {
		let dir = path.parent().unwrap_or(Path::new("."));
		std::fs::create_dir_all(dir)?;

		let file = path.file_name().and_then(|f| f.to_str()).unwrap_or("cerberus.log");

		let appender = tracing_appender::rolling::hourly(dir, file);
		let (writer, guard) = tracing_appender::non_blocking(appender);

		let json_layer = tracing_subscriber::fmt::layer()
			.json()
			.with_current_span(false)
			.with_span_list(false)
			.with_target(false)
			.with_writer(writer);

		tracing_subscriber::registry()
			.with(filter)
			.with(console_layer)
			.with(json_layer)
			.init();

		(Some(guard), true)
	} else {
		tracing_subscriber::registry().with(filter).with(console_layer).init();

		(None, false)
	};

	if args.time.is_some() && args.mode != RunMode::Agent {
		return Err(Error::InvalidTimeMode);
	}

	// Bump the memlock rlimit. This is needed for older kernels that don't use the
	// new memcg based accounting, see https://lwn.net/Articles/837122/
	let rlim = libc::rlimit {
		rlim_cur: libc::RLIM_INFINITY,
		rlim_max: libc::RLIM_INFINITY,
	};
	let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
	if ret != 0 {
		debug!("remove limit on locked memory failed, ret is: {ret}");
	}

	let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/cerberus")))?;
	// match aya_log::EbpfLogger::init(&mut ebpf) {
	// 	Err(e) => {
	// 		// This can happen if you remove all log statements from your eBPF program.
	// 		warn!("failed to initialize eBPF logger: {e}");
	// 	}
	// 	Ok(logger) => {
	// 		let mut logger = tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
	// 		tokio::task::spawn(async move {
	// 			loop {
	// 				let mut guard = logger.readable_mut().await.unwrap();
	// 				guard.get_inner_mut().flush();
	// 				guard.clear_ready();
	// 			}
	// 		});
	// 	}
	// }
	let rule_dir = match args.rules {
		Some(path) => path,
		None => dirs::home_dir().ok_or(Error::HomeDirNotFound)?.join(".cerberus").join("rules"),
	};
	std::fs::create_dir_all(&rule_dir)?;
	let ruleset = RuleSet::load_from_dir(&rule_dir)?;
	let rules: Arc<[Arc<str>]> = ruleset
		.rules()
		.iter()
		.map(|r| Arc::<str>::from(r.inner.id.as_str()))
		.collect::<Vec<_>>()
		.into();

	if ruleset.rule_count() == 0 {
		return Err(Error::NoRulesInDir(rule_dir.display().to_string()));
	}
	let rule_engine = Arc::new(RuleEngine::new_from_ruleset(ruleset)?);

	let mut registry = HookRegistry::default();

	let ringbuf_fd = load_hooks(&mut ebpf, &mut registry, &args.iface)?;

	let hooks = registry
		.hooks()
		.map(|(name, hook)| HookView {
			name: (name.clone()),
			state: if hook.link.is_some() {
				hook_registry::HookState::Enabled
			} else {
				hook_registry::HookState::Disabled
			},
		})
		.collect();

	let (app_tx, app_rx) = new_channel_unbounded_async::<AppEvent>("app_event");

	let (ringbuf_tx, ringbuf_rx) = new_channel_unbounded_async::<CerberusEvent>("ringbuf");

	let (hook_tx, hook_rx) = new_channel_unbounded_async::<HookCommand>("hook");
	let (response_tx, response_rx) = new_channel_unbounded_async::<ResponseRequest>("executor");
	let mut supervisor = Supervisor::new();
	let blocklist: aya::maps::HashMap<_, u32, u32> =
		aya::maps::HashMap::try_from(ebpf.take_map("BLOCKLIST").ok_or(Error::EbpfMapNotFound {
			map: "BLOCKLIST".into(),
		})?)?;
	let lsm_exec_deny: aya::maps::HashMap<_, [u8; 128], u8> =
		aya::maps::HashMap::try_from(ebpf.take_map("LSM_EXEC_DENY").ok_or(Error::EbpfMapNotFound {
			map: "LSM_EXEC_DENY".into(),
		})?)?;
	let token = supervisor.token();
	let response_worker =
		ResponseExecutor::start(response_rx, blocklist, lsm_exec_deny, app_tx.clone(), token.clone())?;
	let ringbuf_worker = RingBufWorker::start(ringbuf_fd, ringbuf_tx.clone(), token.clone())?;
	let hook_worker = HookWorker::start(ebpf, app_tx.clone(), hook_rx, registry, token.clone())?;

	let rule_input_rx = if args.container_resolver {
		let k8s_client = k8s_connect().await?;
		let container_mgr = ContainerManager::new(k8s_client)?;
		let (container_resolver_tx, container_resolver_rx) =
			new_channel_unbounded_async::<CerberusEvent>("container_resolver");
		let container_resolver_worker =
			ContainerResolver::start(container_resolver_tx, ringbuf_rx, container_mgr, token.clone())?;
		supervisor.spawn(container_resolver_worker.run());
		container_resolver_rx
	} else {
		ringbuf_rx
	};
	let rule_worker = RuleEngineWorker::start(
		rule_engine.clone(),
		app_tx.clone(),
		response_tx,
		rule_input_rx,
		token.clone(),
	)?;
	let rule_watch_worker =
		RuleWatchWorker::start(app_tx.clone(), rule_engine.clone(), rule_dir.clone(), token.clone())?;
	supervisor.spawn(ringbuf_worker.run());
	supervisor.spawn(hook_worker.run());
	supervisor.spawn(rule_worker.run(logging_enabled));
	supervisor.spawn(response_worker.run());
	supervisor.spawn(rule_watch_worker.run());

	match args.mode {
		RunMode::Tui => {
			start_tui(hooks, rules, app_tx, app_rx, hook_tx, supervisor.token()).await?;
		}

		RunMode::Agent => {
			start_agent(app_rx, supervisor.token(), args.time).await?;
		}
	}

	supervisor.token().cancelled().await;
	supervisor.shutdown().await?;

	Ok(())
}

pub fn load_hooks(ebpf: &mut Ebpf, registry: &mut HookRegistry, iface: &str) -> Result<AsyncFd<RingBuf<MapData>>> {
	let btf = Btf::from_sys_fs()?;
	register_lsm(ebpf, registry, "sys_enter_kill", "task_kill", &btf)?;
	register_lsm(ebpf, registry, "socket_connect", "socket_connect", &btf)?;
	register_lsm(ebpf, registry, "socket_bind", "socket_bind", &btf)?;
	register_lsm(ebpf, registry, "inode_unlink", "inode_unlink", &btf)?;
	register_lsm(ebpf, registry, "inode_mkdir", "inode_mkdir", &btf)?;
	register_lsm(ebpf, registry, "inode_rmdir", "inode_rmdir", &btf)?;
	register_lsm(ebpf, registry, "inode_link", "inode_link", &btf)?;
	register_lsm(ebpf, registry, "inode_symlink", "inode_symlink", &btf)?;
	register_lsm(ebpf, registry, "inode_rename", "inode_rename", &btf)?;
	register_lsm(ebpf, registry, "bpf_prog_load", "bpf_prog_load", &btf)?;
	register_lsm(ebpf, registry, "bpf_map", "bpf_map", &btf)?;
	register_lsm(ebpf, registry, "ptrace_access_check", "ptrace_access_check", &btf)?;
	register_lsm(ebpf, registry, "bprm_check_security", "bprm_check_security", &btf)?;
	register_tracepoint(ebpf, registry, "inet_sock_set_state", "sock", "inet_sock_set_state")?;
	register_tracepoint(ebpf, registry, "sys_enter_ptrace", "syscalls", "sys_enter_ptrace")?;
	register_kprobe(ebpf, registry, "do_init_module", "do_init_module", 0)?;
	register_xdp(ebpf, registry, "xdp_hook", iface)?;

	let ring_buf = RingBuf::try_from(
		ebpf.take_map("EVT_MAP")
			.ok_or(Error::EbpfMapNotFound { map: "EVT_MAP".into() })?,
	)?;
	let fd = AsyncFd::new(ring_buf)?;
	Ok(fd)
}
