mod error;
mod trx;
mod worker;
pub use self::error::{Error, Result};
use aya::{
	maps::RingBuf,
	programs::{KProbe, Lsm, TracePoint},
	Btf,
};
#[rustfmt::skip]
use tracing::{info, debug, warn};
use tokio::{io::unix::AsyncFd, signal};
use tracing_subscriber::EnvFilter;
use trx::new_trx_pair;
use worker::{ReceiverWorker, RingBufWorker};

#[tokio::main]
async fn main() -> Result<()> {
	tracing_subscriber::fmt()
		.with_target(false)
		.with_env_filter(EnvFilter::from_default_env())
		.init();

	info!("->> STARTING eBPF PROG");
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

	// This will include your eBPF object file as raw bytes at compile-time and load it at
	// runtime. This approach is recommended for most real-world use cases. If you would
	// like to specify the eBPF program at runtime rather than at compile-time, you can
	// reach for `Bpf::load_file` instead.
	let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/cerberus")))?;
	if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
		// This can happen if you remove all log statements from your eBPF program.
		warn!("failed to initialize eBPF logger: {e}");
	}

	// Now do all program_mut calls BEFORE wrapping in AsyncFd
	let btf = Btf::from_sys_fs()?;
	let program: &mut Lsm = ebpf.program_mut("sys_enter_kill").ok_or(Error::EbpfProgNotFound)?.try_into()?;
	program.load("task_kill", &btf)?;
	program.attach()?;

	// let lsm_socket_connect: &mut Lsm = ebpf.program_mut("socket_connect").ok_or(Error::EbpfProgNotFound)?.try_into()?;
	// lsm_socket_connect.load("socket_connect", &btf)?;
	// lsm_socket_connect.attach()?;

	let kp_commit_creds: &mut KProbe = ebpf.program_mut("commit_creds").ok_or(Error::EbpfProgNotFound)?.try_into()?;
	kp_commit_creds.load()?;
	kp_commit_creds.attach("commit_creds", 0)?;

	let tp_inet_sock_set_state: &mut TracePoint = ebpf
		.program_mut("inet_sock_set_state")
		.ok_or(Error::EbpfProgNotFound)?
		.try_into()?;
	tp_inet_sock_set_state.load()?;
	tp_inet_sock_set_state.attach("sock", "inet_sock_set_state")?;

	let kp_module_init: &mut KProbe = ebpf.program_mut("do_init_module").ok_or(Error::EbpfProgNotFound)?.try_into()?;
	kp_module_init.load()?;
	kp_module_init.attach("do_init_module", 0)?;

	let ring_buf = RingBuf::try_from(ebpf.take_map("EVT_MAP").ok_or(Error::EbpfProgNotFound)?)?;
	let trx = new_trx_pair();
	let fd = AsyncFd::new(ring_buf)?;
	RingBufWorker::start(fd, trx.0).await?;
	ReceiverWorker::start(trx.1).await?;

	let ctrl_c = signal::ctrl_c();
	ctrl_c.await?;
	info!("Exiting...");

	Ok(())
}
