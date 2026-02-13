use std::{
	sync::{
		atomic::{AtomicBool, Ordering},
		Arc, Mutex,
	},
	thread,
	time::{Duration, Instant},
};

use flume::RecvTimeoutError;
use kvm_bindings::kvm_userspace_memory_region;
use kvm_ioctls::{Kvm, VcpuExit, VcpuFd};
use lib_event::trx::{new_channel, Rx, Tx};
use vm_memory::{Address, Bytes, GuestAddress, GuestMemoryBackend, GuestMemoryMmap};

use crate::{
	error::Result,
	support::{CODE_START, MEM_SIZE},
	Error,
};

#[derive(Debug)]
pub enum ExitKind {
	CleanHlt,
	Io,
	Mmio,
	FailEntry,
	InternalError,
	Crash,
	Unknown,
}

#[derive(Debug)]
pub struct ProbeResult {
	pub exit_kind: ExitKind,
	pub rax: u64,
	pub rip: u64,
	pub timed_out: bool,
	pub exit_budget_hit: bool,
	pub total_exits: u64,
	pub execution_time: Duration,
}

pub struct RuntimeProbe {
	pub vcpu: VcpuFd,
	pub mem: GuestMemoryMmap,
}

impl RuntimeProbe {
	pub fn new() -> Result<Self> {
		let kvm = Kvm::new()?;
		let vm = kvm.create_vm()?;

		let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), MEM_SIZE as usize)])?;

		let host_addr = mem.get_host_address(GuestAddress(0))? as u64;

		let region = kvm_userspace_memory_region {
			slot: 0,
			guest_phys_addr: 0,
			memory_size: MEM_SIZE,
			userspace_addr: host_addr,
			flags: 0,
		};

		unsafe {
			vm.set_user_memory_region(region)?;
		}

		let vcpu = vm.create_vcpu(0)?;

		#[cfg(target_arch = "x86_64")]
		{
			crate::support::configure_cpuid(&kvm, &vcpu)?;
		}

		let mut probe = Self { vcpu, mem };
		crate::support::reset_state(&mut probe.vcpu, &mut probe.mem)?;

		Ok(probe)
	}

	pub fn execute(&mut self, code: &[u8], timeout: Duration, exit_budget: u64) -> Result<ProbeResult> {
		let size = MEM_SIZE as usize - CODE_START as usize;
		if code.len() > size {
			return Err(Error::CodeTooLarge {
				size: code.len(),
				max: size,
			});
		}
		crate::support::wipe_memory(&mut self.mem)?;
		crate::support::reset_state(&mut self.vcpu, &mut self.mem)?;
		self._execute(code, timeout, exit_budget)
	}

	fn _execute(&mut self, code: &[u8], timeout: Duration, exit_budget: u64) -> Result<ProbeResult> {
		self.mem.write(code, GuestAddress(CODE_START))?;

		let start = Instant::now();
		let mut budget = exit_budget;
		let mut exit_count = 0u64;
		let mut timed_out = false;
		let mut budget_hit = false;
		let mut exit_kind = ExitKind::Unknown;

		'run_loop: loop {
			if start.elapsed() >= timeout {
				timed_out = true;
				break 'run_loop;
			}

			if budget == 0 {
				budget_hit = true;
				break 'run_loop;
			}

			let exit = match self.vcpu.run() {
				Ok(e) => e,
				Err(e) => {
					if e.errno() == libc::EINTR {
						continue 'run_loop;
					}
					exit_kind = ExitKind::InternalError;
					break 'run_loop;
				}
			};

			exit_count += 1;

			budget = budget.saturating_sub(1);

			match exit {
				VcpuExit::Hlt => {
					exit_kind = ExitKind::CleanHlt;
					break 'run_loop;
				}
				VcpuExit::IoOut(_, _) | VcpuExit::IoIn(_, _) => {
					exit_kind = ExitKind::Io;
					break 'run_loop;
				}
				VcpuExit::MmioRead(_, _) | VcpuExit::MmioWrite(_, _) => {
					exit_kind = ExitKind::Mmio;
					break 'run_loop;
				}
				VcpuExit::FailEntry(_, _) => {
					exit_kind = ExitKind::FailEntry;
					break 'run_loop;
				}
				VcpuExit::InternalError => {
					exit_kind = ExitKind::InternalError;
					break 'run_loop;
				}
				VcpuExit::Hypercall(_) => {
					exit_kind = ExitKind::Unknown;
					break 'run_loop;
				}
				VcpuExit::IrqWindowOpen => {
					continue 'run_loop;
				}
				VcpuExit::Shutdown | VcpuExit::Exception => {
					exit_kind = ExitKind::Crash;
					break 'run_loop;
				}
				VcpuExit::Debug(_) => {
					continue 'run_loop;
				}
				_ => continue 'run_loop,
			}
		}

		let regs = self.vcpu.get_regs()?;
		let execution_time = start.elapsed();

		Ok(ProbeResult {
			exit_kind,
			rax: regs.rax,
			rip: regs.rip,
			timed_out,
			exit_budget_hit: budget_hit,
			execution_time,
			total_exits: exit_count,
		})
	}
}
// region:    --- Tests

#[cfg(test)]
mod tests {
	type Result<T> = core::result::Result<T, Box<dyn std::error::Error>>; // For tests.

	use super::*;
	use std::time::Duration;

	#[test]
	fn runtime_probe_executes_hlt_cleanly() -> Result<()> {
		let fx_code = b"\xF4"; // hlt
		let mut probe = RuntimeProbe::new()?;
		let result = probe.execute(fx_code, Duration::from_millis(100), 10)?;
		assert!(matches!(result.exit_kind, ExitKind::CleanHlt));
		assert!(!result.timed_out);
		assert!(!result.exit_budget_hit);
		Ok(())
	}

	#[test]
	fn runtime_probe_detects_io_instruction() -> Result<()> {
		let fx_code = b"\xE4\x01"; // in al, 0x1
		let mut probe = RuntimeProbe::new()?;
		let result = probe.execute(fx_code, Duration::from_millis(100), 10)?;
		assert!(matches!(result.exit_kind, ExitKind::Io));
		Ok(())
	}

	#[test]
	fn runtime_probe_hits_exit_budget() -> Result<()> {
		let fx_code = b"\xEB\xFE"; // infinite loop
		let mut probe = RuntimeProbe::new()?;
		let result = probe.execute(fx_code, Duration::from_millis(500), 5)?; // very small budget
		assert!(result.exit_budget_hit);
		assert!(!result.timed_out);
		Ok(())
	}
	#[test]
	fn runtime_probe_times_out() -> Result<()> {
		let fx_code = b"\xEB\xFE"; // infinite loop
		let mut probe = RuntimeProbe::new()?;
		// Use a massive budget so it won't be hit first
		let result = probe.execute(fx_code, Duration::from_millis(10), u64::MAX)?;
		assert!(result.timed_out);
		assert!(!result.exit_budget_hit);
		Ok(())
	}
	#[test]
	fn runtime_probe_returns_rax_value() -> Result<()> {
		let fx_code = b"\xB8\x42\x69\x00\x00\xF4"; // mov eax, 0x6942; hlt
		let mut probe = RuntimeProbe::new()?;
		let result = probe.execute(fx_code, Duration::from_millis(100), 10)?;
		assert_eq!(result.rax, 0x6942);
		assert!(matches!(result.exit_kind, ExitKind::CleanHlt));
		Ok(())
	}

	#[test]
	fn runtime_probe_resets_state_between_executions() -> Result<()> {
		let mut probe = RuntimeProbe::new()?;
		let fx_code1 = b"\xB8\x42\x69\x00\x00\xF4"; // mov eax, 0x6942; hlt
		let result1 = probe.execute(fx_code1, Duration::from_millis(100), 10)?;
		assert_eq!(result1.rax, 0x6942);

		let fx_code2 = b"\xF4"; // hlt only
		let result2 = probe.execute(fx_code2, Duration::from_millis(100), 10)?;
		assert_eq!(result2.rax, 0);
		Ok(())
	}

	#[test]
	fn runtime_probe_handles_crashing_code() -> Result<()> {
		let fx_code = b"\x6A\x00\x0F\x01\xF8"; // privileged instruction
		let mut probe = RuntimeProbe::new()?;
		let result = probe.execute(fx_code, Duration::from_millis(100), 10)?;
		assert!(matches!(result.exit_kind, ExitKind::Crash));
		Ok(())
	}

	#[test]
	fn runtime_probe_wipe_memory_prevents_leaks() -> Result<()> {
		let mut probe = RuntimeProbe::new()?;
		let secret = b"SECRET_PASSWORD";
		probe.mem.write(secret, GuestAddress(0x2000))?;
		let fx_code = b"\xA1\x00\x20\x00\x00\xF4"; // mov eax, [0x2000]; hlt
		let result = probe.execute(fx_code, Duration::from_millis(100), 10)?;
		assert_eq!(result.rax, 0);
		Ok(())
	}
}
// endregion: --- Tests
