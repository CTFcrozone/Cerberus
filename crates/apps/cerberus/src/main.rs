// region:    --- Modules
mod agent;
mod cli;
mod core;
mod error;
mod event;
mod styles;
mod supervisor;
mod views;
mod workers;
// endregion: --- Modules

use crate::{
	cli::args::{Cli, RunMode},
	core::start_tui,
	event::AppEvent,
	supervisor::Supervisor,
	workers::{RingBufWorker, RuleEngineWorker},
};

pub use self::error::{Error, Result};
use agent::*;
use aya::{
	maps::{MapData, RingBuf},
	programs::{KProbe, Lsm, TracePoint},
	Btf, Ebpf,
};
use clap::Parser;
use core::AppTx;
use lib_common::event::CerberusEvent;
use lib_event::trx::new_channel;
use lib_rules::RuleEngine;
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
	let rule_engine = Arc::new(RuleEngine::new(&rule_dir)?);

	let (app_tx, app_rx) = new_channel::<AppEvent>("app_event");
	let app_tx = AppTx::from(app_tx);

	let (ringbuf_tx, ringbuf_rx) = new_channel::<CerberusEvent>("ringbuf");

	// let (exit_tx, _exit_rx) = new_channel::<()>("exit");
	// let exit_tx = ExitTx::from(exit_tx);

	let ringbuf_fd = load_hooks(&mut ebpf)?;

	let mut supervisor = Supervisor::new();
	// install_signal_handlers(supervisor.token()).await?;

	let ringbuf_worker = RingBufWorker::start(ringbuf_fd, ringbuf_tx.clone())?;
	let rule_worker = RuleEngineWorker::start(rule_engine.clone(), app_tx.clone(), ringbuf_rx)?;
	supervisor.spawn(ringbuf_worker.run());
	supervisor.spawn(rule_worker.run());

	match args.mode {
		RunMode::Tui => {
			start_tui(ebpf, rule_engine, app_tx, app_rx, supervisor.token(), rule_dir).await?;
		}

		RunMode::Agent => {
			let duration = args.time.ok_or(Error::NoTimeSpecified)?;
			start_agent(app_rx, supervisor.token(), duration.into()).await?;
		}
	}

	supervisor.token().cancelled().await;

	supervisor.shutdown().await?;

	Ok(())
}

pub fn load_hooks(ebpf: &mut Ebpf) -> Result<AsyncFd<RingBuf<MapData>>> {
	let btf = Btf::from_sys_fs()?;
	let program: &mut Lsm = ebpf.program_mut("sys_enter_kill").ok_or(Error::EbpfProgNotFound)?.try_into()?;
	program.load("task_kill", &btf)?;
	program.attach()?;

	let lsm_socket_connect: &mut Lsm = ebpf.program_mut("socket_connect").ok_or(Error::EbpfProgNotFound)?.try_into()?;
	lsm_socket_connect.load("socket_connect", &btf)?;
	lsm_socket_connect.attach()?;
	//
	let kp_module_init: &mut KProbe = ebpf.program_mut("do_init_module").ok_or(Error::EbpfProgNotFound)?.try_into()?;
	kp_module_init.load()?;
	kp_module_init.attach("do_init_module", 0)?;

	let bprm: &mut Lsm = ebpf
		.program_mut("bprm_check_security")
		.ok_or(Error::EbpfProgNotFound)?
		.try_into()?;
	bprm.load("bprm_check_security", &btf)?;
	bprm.attach()?;

	let kp_commit_creds: &mut KProbe = ebpf.program_mut("commit_creds").ok_or(Error::EbpfProgNotFound)?.try_into()?;
	kp_commit_creds.load()?;
	kp_commit_creds.attach("commit_creds", 0)?;

	let tp_inet_sock_set_state: &mut TracePoint = ebpf
		.program_mut("inet_sock_set_state")
		.ok_or(Error::EbpfProgNotFound)?
		.try_into()?;
	tp_inet_sock_set_state.load()?;
	tp_inet_sock_set_state.attach("sock", "inet_sock_set_state")?;

	let sys_enter_ptrace: &mut TracePoint = ebpf
		.program_mut("sys_enter_ptrace")
		.ok_or(Error::EbpfProgNotFound)?
		.try_into()?;
	sys_enter_ptrace.load()?;
	sys_enter_ptrace.attach("syscalls", "sys_enter_ptrace")?;

	let ring_buf = RingBuf::try_from(ebpf.take_map("EVT_MAP").ok_or(Error::EbpfProgNotFound)?)?;
	let fd = AsyncFd::new(ring_buf)?;
	Ok(fd)
}
