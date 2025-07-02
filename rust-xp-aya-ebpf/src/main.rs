mod error;
mod trx;
mod worker;
pub use self::error::{Error, Result};
use aya::{
	maps::RingBuf,
	programs::{KProbe, TracePoint},
};
#[rustfmt::skip]
use tracing::{info, debug, warn};
use tokio::{io::unix::AsyncFd, signal};
use tracing_subscriber::EnvFilter;

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
	let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
		env!("OUT_DIR"),
		"/rust-xp-aya-ebpf"
	)))?;
	if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
		// This can happen if you remove all log statements from your eBPF program.
		warn!("failed to initialize eBPF logger: {e}");
	}

	// Now do all program_mut calls BEFORE wrapping in AsyncFd
	let program: &mut TracePoint = ebpf
		.program_mut("rust_xp_aya_ebpf")
		.ok_or(Error::EbpfProgNotFound)?
		.try_into()?;
	program.load()?;
	program.attach("syscalls", "sys_enter_kill")?;

	let kp_openat: &mut KProbe = ebpf.program_mut("trace_openat").ok_or(Error::EbpfProgNotFound)?.try_into()?;
	kp_openat.load()?;
	kp_openat.attach("do_sys_openat2", 0)?;

	// let ring_buf = RingBuf::try_from(ebpf.map_mut("EVTS").ok_or(Error::EbpfProgNotFound)?)?;
	// let mut evt_fd = AsyncFd::new(ring_buf)?;

	// tokio::spawn(async move {
	// 	loop {
	// 		match evt_fd.readable_mut().await {
	// 			Ok(mut guard) => {
	// 				let evts = guard.get_inner_mut();

	// 				while let Some(evt) = evts.next() {}

	// 				guard.clear_ready();
	// 			}
	// 			Err(e) => {
	// 				eprintln!("Error waiting for evt_fd readiness: {}", e);
	// 				break;
	// 			}
	// 		}
	// 	}
	// });

	let ctrl_c = signal::ctrl_c();
	ctrl_c.await?;
	info!("Exiting...");

	Ok(())
}
