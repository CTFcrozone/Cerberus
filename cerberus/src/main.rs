// region:    --- Modules
mod cli;
mod core;
mod daemon;
mod error;
mod event;
mod styles;
mod supervisor;
mod views;
mod worker;
// endregion: --- Modules

use crate::{
	cli::args::{Cli, RunMode},
	worker::RingBufWorker,
};

pub use self::error::{Error, Result};
use aya::{
	maps::{MapData, RingBuf},
	programs::{KProbe, Lsm, TracePoint},
	Btf, Ebpf,
};
use clap::Parser;
use core::{start_tui, AppTx, ExitTx};
use daemon::*;
use lib_event::{app_evt_types::AppEvent, trx::new_channel};
use lib_rules::engine::RuleEngine;
use std::sync::Arc;
#[rustfmt::skip]
use tracing::{debug, warn};
use tokio::io::unix::AsyncFd;

#[tokio::main]
async fn main() -> Result<()> {
	let args = Cli::parse();

	if args.time.is_some() && args.mode != RunMode::Daemon {
		return Err(Error::InvalidTimeMode);
	}

	let _tracing_guard = init_tracing(&args.log_file);

	if let RunMode::Daemon = args.mode {
		daemonize_process(&args.log_file)?;
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

	let home_dir = std::env::home_dir().ok_or(Error::HomeDirNotFound)?;
	let rule_dir = home_dir.join(".cerberus/rules/");
	let rule_engine = Arc::new(RuleEngine::new(rule_dir)?);

	let (app_tx, app_rx) = new_channel::<AppEvent>("app_event");
	let app_tx = AppTx::from(app_tx);

	let (exit_tx, exit_rx) = new_channel::<()>("exit");
	let exit_tx = ExitTx::from(exit_tx);

	match args.mode {
		RunMode::Tui => {
			let ringbuf_fd = load_hooks(&mut ebpf)?;
			RingBufWorker::start(ringbuf_fd, rule_engine.clone(), app_tx.clone()).await?;
			start_tui(ebpf, rule_engine, app_tx, app_rx, exit_tx).await?;
		}

		RunMode::Daemon => {
			let Some(duration) = args.time else {
				return Err(Error::NoTimeSpecified);
			};
			start_daemon(ebpf, rule_engine, app_tx, app_rx, exit_tx, duration.into()).await?;
		}
	}

	let _ = exit_rx.recv().await;

	// if let Err(err) = tui_handle.await {
	// 	eprintln!("TUI task panicked or failed: {err}");
	// }

	Ok(())
}

pub fn load_hooks(ebpf: &mut Ebpf) -> Result<AsyncFd<RingBuf<MapData>>> {
	let btf = Btf::from_sys_fs()?;
	let program: &mut Lsm = ebpf.program_mut("sys_enter_kill").ok_or(Error::EbpfProgNotFound)?.try_into()?;
	program.load("task_kill", &btf)?;
	program.attach()?;

	// let lsm_socket_connect: &mut Lsm = ebpf.program_mut("socket_connect").ok_or(Error::EbpfProgNotFound)?.try_into()?;
	// lsm_socket_connect.load("socket_connect", &btf)?;
	// lsm_socket_connect.attach()?;
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
