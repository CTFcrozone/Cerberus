use std::time::{Duration, Instant};

use kvm_bindings::kvm_userspace_memory_region;
use kvm_ioctls::{Kvm, VcpuExit, VcpuFd};
use vm_memory::{Address, Bytes, GuestAddress, GuestMemoryBackend, GuestMemoryMmap};

use crate::error::Result;

const MEM_SIZE: u64 = 0x200000; // 2MB
const CODE_START: u64 = 0x1000;
const STACK_START: u64 = 0x1ff000;

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

		let mut probe = Self { vcpu, mem };
		probe.reset_state()?;

		Ok(probe)
	}

	pub fn reset_state(&mut self) -> Result<()> {
		let gdt_addr = GuestAddress(0x500);
		let gdt: [u64; 3] = [
			0,
			Self::gdt_entry(0, 0xFFFFF, 0x9A | (1 << 7)), // code
			Self::gdt_entry(0, 0xFFFFF, 0x92 | (1 << 7)), // data
		];

		for (i, entry) in gdt.iter().enumerate() {
			self.mem.write_obj(*entry, gdt_addr.unchecked_add((i * 8) as u64))?;
		}

		let mut sregs = self.vcpu.get_sregs()?;
		sregs.cr0 = 0x1; //  protected mode
		sregs.cr2 = 0;
		sregs.cr3 = 0;
		sregs.cr4 = 0;
		sregs.efer = 0;

		sregs.gdt.base = 0x500;
		sregs.gdt.limit = (3 * 8 - 1) as u16;

		// CS
		sregs.cs.selector = 0x08;
		sregs.cs.base = 0;
		sregs.cs.limit = 0xFFFFF;
		sregs.cs.g = 1;
		sregs.cs.db = 1;
		sregs.cs.present = 1;
		sregs.cs.s = 1;
		sregs.cs.type_ = 0b1010;

		// DS, SS
		for seg in [&mut sregs.ds, &mut sregs.ss] {
			seg.selector = 0x10;
			seg.base = 0;
			seg.limit = 0xFFFFF;
			seg.g = 1;
			seg.db = 1;
			seg.present = 1;
			seg.s = 1;
			seg.type_ = 0b0010;
		}

		self.vcpu.set_sregs(&sregs)?;

		let mut regs = self.vcpu.get_regs()?;
		regs.rax = 0;
		regs.rip = CODE_START;
		regs.rsp = STACK_START;
		regs.rflags = 0x2;
		self.vcpu.set_regs(&regs)?;

		Ok(())
	}

	pub fn wipe_memory(&mut self) -> Result<()> {
		let zeros = vec![0u8; MEM_SIZE as usize];
		self.mem.write(&zeros, GuestAddress(0))?;
		Ok(())
	}

	pub fn execute(&mut self, code: &[u8], timeout: Duration, exit_budget: u64) -> Result<ProbeResult> {
		self.wipe_memory()?;
		self.reset_state()?;
		self._execute(code, timeout, exit_budget)
	}

	fn gdt_entry(base: u32, limit: u32, flags: u16) -> u64 {
		(limit as u64 & 0xFFFF)
			| ((base as u64 & 0xFFFFFF) << 16)
			| ((flags as u64) << 40)
			| (((limit as u64 >> 16) & 0xF) << 48)
			| (((base as u64 >> 24) & 0xFF) << 56)
	}

	fn _execute(&mut self, code: &[u8], timeout: Duration, exit_budget: u64) -> Result<ProbeResult> {
		self.mem.write(code, GuestAddress(CODE_START))?;

		let start = Instant::now();
		let mut exit_kind = ExitKind::Unknown;
		let mut budget = exit_budget;
		let mut timed_out = false;
		let mut budget_hit = false;

		loop {
			if start.elapsed() >= timeout {
				timed_out = true;
				break;
			}

			if budget == 0 {
				budget_hit = true;
				break;
			}

			let exit = match self.vcpu.run() {
				Ok(e) => e,
				Err(_) => {
					exit_kind = ExitKind::InternalError;
					break;
				}
			};

			budget = budget.saturating_sub(1);

			match exit {
				VcpuExit::Hlt => {
					exit_kind = ExitKind::CleanHlt;
					break;
				}
				VcpuExit::IoOut(_, _) | VcpuExit::IoIn(_, _) => {
					exit_kind = ExitKind::Io;
					break;
				}
				VcpuExit::MmioRead(_, _) | VcpuExit::MmioWrite(_, _) => {
					exit_kind = ExitKind::Mmio;
					break;
				}
				VcpuExit::FailEntry(_, _) => {
					exit_kind = ExitKind::FailEntry;
					break;
				}
				VcpuExit::InternalError => {
					exit_kind = ExitKind::InternalError;
					break;
				}
				VcpuExit::Shutdown | VcpuExit::Exception => {
					exit_kind = ExitKind::Crash;
					break;
				}
				VcpuExit::Debug(_) => {
					continue;
				}
				_ => {
					exit_kind = ExitKind::Unknown;
					break;
				}
			}
		}

		let regs = self.vcpu.get_regs()?;
		Ok(ProbeResult {
			exit_kind,
			rax: regs.rax,
			rip: regs.rip,
			timed_out,
			exit_budget_hit: budget_hit,
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

	// ?? FIXME
	#[test]
	fn runtime_probe_hits_exit_budget() -> Result<()> {
		let fx_code = b"\xE4\x01\xEB\xFC"; // in al, 0x1; jmp $-4

		let fx_timeout = Duration::from_millis(100);
		let fx_budget = 5;

		let mut probe = RuntimeProbe::new()?;
		let result = probe.execute(fx_code, fx_timeout, fx_budget)?;

		assert!(result.exit_budget_hit);
		assert!(!result.timed_out);
		Ok(())
	}

	// ???????????????????????????
	#[test]
	fn runtime_probe_times_out() -> Result<()> {
		let fx_code = b"\xEB\xFE"; // JMP -2
		let mut probe = RuntimeProbe::new()?;
		let result = probe.execute(fx_code, Duration::from_millis(10), 10000)?;
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
