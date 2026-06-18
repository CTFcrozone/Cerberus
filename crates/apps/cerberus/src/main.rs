// region:    --- Modules
mod agent;
mod cli;
mod core;
mod error;
mod event;
mod hook_registry;
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
		event::HookRegistryEvent,
		helper_fns::{register_kprobe, register_lsm, register_tracepoint},
		registry::HookRegistry,
	},
	supervisor::Supervisor,
	workers::{ContainerResolver, HookWorker, RingBufWorker, RuleEngineWorker, RuleWatchWorker},
};

pub use self::error::{Error, Result};
use agent::*;
use aya::{
	maps::{MapData, RingBuf},
	Btf, Ebpf,
};
use clap::Parser;

use lib_common::event::CerberusEvent;
use lib_container::{container_manager::ContainerManager, runtime::k8s_connect};
use lib_event::unbound::new_channel_unbounded_async;
use lib_rules::{RuleEngine, RuleSet};
use std::sync::Arc;
use tracing_subscriber::EnvFilter;
#[rustfmt::skip]
use tracing::{debug, warn};
use tokio::io::unix::AsyncFd;

#[tokio::main]
async fn main() -> Result<()> {
	let args = Cli::parse();
	tracing_subscriber::fmt()
		.with_target(false)
		.without_time()
		.with_env_filter(EnvFilter::from_default_env())
		.init();

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
	if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
		// This can happen if you remove all log statements from your eBPF program.
		warn!("failed to initialize eBPF logger: {e}");
	}

	let rule_dir = args.rules;

	let ruleset = RuleSet::load_from_dir(&rule_dir)?;
	let rules: Arc<[String]> = ruleset.rules().iter().map(|r| r.inner.id.clone()).collect();

	if ruleset.rule_count() == 0 {
		return Err(Error::NoRulesInDir(rule_dir.display().to_string()));
	}

	let rule_engine = Arc::new(RuleEngine::new_from_ruleset(ruleset)?);

	let mut registry = HookRegistry::default();
	let hooks = registry.hooks();
	let ringbuf_fd = load_hooks(&mut ebpf, &mut registry)?;

	let (app_tx, app_rx) = new_channel_unbounded_async::<AppEvent>("app_event");

	let (ringbuf_tx, ringbuf_rx) = new_channel_unbounded_async::<CerberusEvent>("ringbuf");

	// let (hook_tx, hook_rx) = new_channel_unbounded_async::<HookRegistryEvent>("hook");

	let mut supervisor = Supervisor::new();

	let ringbuf_worker = RingBufWorker::start(ringbuf_fd, ringbuf_tx.clone())?;
	// let hook_worker = HookWorker::start(app_tx.clone(), hook_rx, registry)?;

	let rule_input_rx = if args.container_resolver {
		let k8s_client = k8s_connect().await?;
		let container_mgr = ContainerManager::new(k8s_client)?;
		let (container_resolver_tx, container_resolver_rx) =
			new_channel_unbounded_async::<CerberusEvent>("container_resolver");
		let container_resolver_worker = ContainerResolver::start(container_resolver_tx, ringbuf_rx, container_mgr)?;
		supervisor.spawn(container_resolver_worker.run());
		container_resolver_rx
	} else {
		ringbuf_rx
	};
	let rule_worker = RuleEngineWorker::start(rule_engine.clone(), app_tx.clone(), rule_input_rx)?;
	let rule_watch_worker = RuleWatchWorker::start(app_tx.clone(), rule_engine.clone(), rule_dir.clone())?;
	supervisor.spawn(ringbuf_worker.run());
	supervisor.spawn(rule_worker.run());
	supervisor.spawn(rule_watch_worker.run());

	match args.mode {
		RunMode::Tui => {
			start_tui(hooks, rules, app_tx, app_rx, supervisor.token()).await?;
		}

		RunMode::Agent => {
			start_agent(app_rx, supervisor.token(), args.time).await?;
		}
	}

	supervisor.token().cancelled().await;
	supervisor.shutdown().await?;

	Ok(())
}

pub fn load_hooks(ebpf: &mut Ebpf, registry: &mut HookRegistry) -> Result<AsyncFd<RingBuf<MapData>>> {
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

	let ring_buf = RingBuf::try_from(
		ebpf.take_map("EVT_MAP")
			.ok_or(Error::EbpfMapNotFound { map: "EVT_MAP".into() })?,
	)?;
	let fd = AsyncFd::new(ring_buf)?;
	Ok(fd)
}
