use std::time::{Duration, Instant};

use kvm_bindings::kvm_userspace_memory_region;
use kvm_ioctls::{Kvm, VcpuExit, VcpuFd, VmFd};
use vm_memory::{Bytes, GuestAddress, GuestMemoryBackend, GuestMemoryMmap};

use crate::{
	error::Result,
	support::{CODE_START, MEM_SIZE},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitReason {
	/// Guest executed HLT instruction
	Hlt,
	/// Guest performed I/O that requires emulation
	Io,
	/// Guest accessed MMIO that requires emulation
	Mmio,
	/// Guest crashed (triple fault, exception)
	Crash,
	/// VM entry failed
	FailEntry,
	/// Internal KVM error
	InternalError,
	/// Hypercall from guest
	Hypercall,
	/// Unknown/unhandled exit
	Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
	/// Guest voluntarily stopped (HLT)
	GuestHalted,
	/// Guest crashed
	GuestCrashed,
	/// Execution time limit exceeded
	Timeout,
	/// VM exit budget exhausted
	ExitBudgetExhausted,
	/// Unhandled VM exit type
	UnhandledExit(ExitReason),
	/// KVM internal error
	InternalError,
}

#[derive(Debug)]
pub struct ExecutionResult {
	pub stop_reason: StopReason,
	pub total_exits: u64,
	pub exit_counts: ExitCounts,
	pub rax: u64,
	pub rip: u64,
	pub execution_time: Duration,
}

#[derive(Debug, Default)]
pub struct ExitCounts {
	pub io: u64,
	pub mmio: u64,
	pub hlt: u64,
	pub irq_window: u64,
	pub debug: u64,
	pub other: u64,
}

pub struct Execution {
	_kvm: Kvm,
	_vm: VmFd,
	vcpu: VcpuFd,
	mem: GuestMemoryMmap,
}

impl Execution {
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
			flags: if crate::support::supports_readonly_mem(&kvm) {
				1 << 1 // KVM_MEM_READONLY per API Section 4.35
			} else {
				0
			},
		};

		unsafe {
			vm.set_user_memory_region(region)?;
		}

		let vcpu = vm.create_vcpu(0)?;

		#[cfg(target_arch = "x86_64")]
		{
			crate::support::configure_cpuid(&kvm, &vcpu)?;
			let _ = vcpu.set_tsc_khz(2_000_000);
		}

		let mut execution = Self {
			_kvm: kvm,
			_vm: vm,
			vcpu,
			mem,
		};
		crate::support::reset_state(&mut execution.vcpu, &mut execution.mem)?;

		Ok(execution)
	}

	pub fn run(&mut self, code: &[u8], timeout: Duration, exit_budget: u64) -> Result<ExecutionResult> {
		self.mem.write(code, GuestAddress(CODE_START))?;

		let start = Instant::now();
		let mut remaining_budget = exit_budget;
		let mut counts = ExitCounts::default();
		let mut total_exits = 0u64;

		let stop_reason = 'run_loop: loop {
			if start.elapsed() >= timeout {
				break 'run_loop StopReason::Timeout;
			}

			if remaining_budget == 0 {
				break 'run_loop StopReason::ExitBudgetExhausted;
			}

			let exit_result = match self.vcpu.run() {
				Ok(exit) => exit,
				Err(e) => {
					if e.errno() == libc::EINTR {
						continue 'run_loop;
					}
					break 'run_loop StopReason::InternalError;
				}
			};

			total_exits += 1;
			remaining_budget = remaining_budget.saturating_sub(1);

			match exit_result {
				VcpuExit::Hlt => {
					counts.hlt += 1;
					break 'run_loop StopReason::GuestHalted;
				}

				VcpuExit::Shutdown | VcpuExit::Exception => {
					break 'run_loop StopReason::GuestCrashed;
				}

				VcpuExit::FailEntry(_, _) => {
					break 'run_loop StopReason::InternalError;
				}

				VcpuExit::InternalError => {
					break 'run_loop StopReason::InternalError;
				}

				VcpuExit::IoOut(_, _) | VcpuExit::IoIn(_, _) => {
					counts.io += 1;

					continue 'run_loop;
				}

				VcpuExit::MmioRead(_, _) | VcpuExit::MmioWrite(_, _) => {
					counts.mmio += 1;

					continue 'run_loop;
				}

				VcpuExit::Hypercall(_) => {
					break 'run_loop StopReason::UnhandledExit(ExitReason::Hypercall);
				}

				VcpuExit::IrqWindowOpen => {
					counts.irq_window += 1;
					continue 'run_loop;
				}

				VcpuExit::Debug(_) => {
					counts.debug += 1;
					continue 'run_loop;
				}
				_ => {
					counts.other += 1;
					break 'run_loop StopReason::UnhandledExit(ExitReason::Unknown);
				}
			}
		};

		let regs = self.vcpu.get_regs()?;

		Ok(ExecutionResult {
			stop_reason,
			total_exits,
			exit_counts: counts,
			rax: regs.rax,
			rip: regs.rip,
			execution_time: start.elapsed(),
		})
	}
}
