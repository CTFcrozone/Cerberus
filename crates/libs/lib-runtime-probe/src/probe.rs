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
use kvm_ioctls::{Kvm, VcpuExit, VcpuFd, VmFd};
use lib_event::trx::{new_channel, Rx, Tx};
use vm_memory::{Address, Bytes, GuestAddress, GuestMemoryBackend, GuestMemoryMmap};

use crate::{
	error::Result,
	execution::{Execution, ExecutionResult},
	support::{CODE_START, MEM_SIZE},
	Error,
};

pub struct RuntimeProbe;

impl RuntimeProbe {
	/// Execute untrusted code in an isolated VM.
	///
	/// # Arguments
	/// * `code` - Raw x86-64 machine code to execute
	/// * `timeout` - Maximum execution time
	/// * `exit_budget` - Maximum number of VM exits allowed
	///
	/// # Security
	/// Each call creates a fresh VM, ensuring no state leakage between executions.
	/// The VM is automatically destroyed when this function returns.
	///
	/// # Example
	/// ```no_run
	/// use std::time::Duration;
	///
	/// let code = b"\xB8\x42\x00\x00\x00\xF4"; // mov eax, 0x42; hlt
	/// let result = RuntimeProbe::execute(code, Duration::from_secs(1), 1000)?;
	///
	/// assert_eq!(result.stop_reason, StopReason::GuestHalted);
	/// assert_eq!(result.rax, 0x42);
	/// ```
	pub fn execute(code: &[u8], timeout: Duration, exit_budget: u64) -> Result<ExecutionResult> {
		let size = MEM_SIZE as usize - CODE_START as usize;
		if code.len() > size {
			return Err(Error::CodeTooLarge {
				size: code.len(),
				max: size,
			});
		}

		let mut execution = Execution::new()?;

		execution.run(code, timeout, exit_budget)
	}
}

// region:    --- Tests

#[cfg(test)]
mod tests {
	type Result<T> = core::result::Result<T, Box<dyn std::error::Error>>; // For tests.

	use crate::execution::StopReason;

	use super::*;
	use std::time::Duration;

	#[test]
	fn runtime_probe_executes_hlt_cleanly() -> Result<()> {
		let fx_code = b"\xF4"; // hlt
		let result = RuntimeProbe::execute(fx_code, Duration::from_millis(100), 10)?;

		assert_eq!(result.stop_reason, StopReason::GuestHalted);
		assert_eq!(result.exit_counts.hlt, 1);
		assert_eq!(result.total_exits, 1);
		Ok(())
	}

	#[test]
	fn runtime_probe_detects_io_instruction() -> Result<()> {
		let fx_code = b"\xE4\x01\xF4"; // in al, 0x1; hlt
		let result = RuntimeProbe::execute(fx_code, Duration::from_millis(100), 100)?;

		// Should halt cleanly after doing one I/O
		assert_eq!(result.stop_reason, StopReason::GuestHalted);
		assert_eq!(result.exit_counts.io, 1);
		assert_eq!(result.exit_counts.hlt, 1);
		assert_eq!(result.total_exits, 2); // 1 I/O + 1 HLT
		Ok(())
	}

	#[test]
	fn runtime_probe_hits_exit_budget() -> Result<()> {
		// Code that exits frequently - test budget limit
		let fx_code = b"\xE4\x01\xEB\xFC"; // in al, 1; jmp $-2
		let result = RuntimeProbe::execute(fx_code, Duration::from_secs(10), 100)?;

		assert_eq!(result.stop_reason, StopReason::ExitBudgetExhausted);
		assert_eq!(result.total_exits, 100);
		assert!(result.exit_counts.io > 0, "Should have I/O exits");
		Ok(())
	}

	#[test]
	fn runtime_probe_times_out() -> Result<()> {
		// Code that exits less frequently - test timeout
		let fx_code = b"\x90\x90\x90\x90\xE4\x01\xEB\xF9"; // nop×4; in al,1; jmp $-5
		let result = RuntimeProbe::execute(fx_code, Duration::from_millis(50), u64::MAX)?;

		assert_eq!(result.stop_reason, StopReason::Timeout);
		assert!(result.total_exits > 0, "Should have some exits");
		assert!(result.exit_counts.io > 0, "Should have I/O exits");
		Ok(())
	}

	#[test]
	fn runtime_probe_returns_rax_value() -> Result<()> {
		let fx_code = b"\xB8\x42\x69\x00\x00\xF4"; // mov eax, 0x6942; hlt
		let result = RuntimeProbe::execute(fx_code, Duration::from_millis(100), 10)?;

		assert_eq!(result.stop_reason, StopReason::GuestHalted);
		assert_eq!(result.rax, 0x6942);
		assert_eq!(result.exit_counts.hlt, 1);
		Ok(())
	}

	#[test]
	fn runtime_probe_resets_state_between_executions() -> Result<()> {
		// First execution sets rax to 0x6942
		let fx_code1 = b"\xB8\x42\x69\x00\x00\xF4"; // mov eax, 0x6942; hlt
		let result1 = RuntimeProbe::execute(fx_code1, Duration::from_millis(100), 10)?;
		assert_eq!(result1.rax, 0x6942);
		assert_eq!(result1.stop_reason, StopReason::GuestHalted);

		// Second execution should have rax reset to 0 (fresh VM!)
		let fx_code2 = b"\xF4"; // hlt only
		let result2 = RuntimeProbe::execute(fx_code2, Duration::from_millis(100), 10)?;
		assert_eq!(result2.rax, 0);
		assert_eq!(result2.stop_reason, StopReason::GuestHalted);
		Ok(())
	}

	#[test]
	fn runtime_probe_handles_crashing_code() -> Result<()> {
		// Privileged instruction that should cause a fault
		let fx_code = b"\x0F\x01\xF8"; // swapgs (privileged)
		let result = RuntimeProbe::execute(fx_code, Duration::from_millis(100), 10)?;

		assert_eq!(result.stop_reason, StopReason::GuestCrashed);
		Ok(())
	}

	#[test]
	fn runtime_probe_wipe_memory_prevents_leaks() -> Result<()> {
		// First execution: write secret to memory
		let fx_code1 = b"\xC7\x05\x00\x20\x00\x00\x42\x42\x42\x42\xF4";
		// mov DWORD PTR [0x2000], 0x42424242; hlt
		let result1 = RuntimeProbe::execute(fx_code1, Duration::from_millis(100), 10)?;
		assert_eq!(result1.stop_reason, StopReason::GuestHalted);

		// Second execution: try to read from 0x2000
		// Should get 0 because it's a FRESH VM with zeroed memory
		let fx_code2 = b"\xA1\x00\x20\x00\x00\xF4"; // mov eax, [0x2000]; hlt
		let result2 = RuntimeProbe::execute(fx_code2, Duration::from_millis(100), 10)?;

		assert_eq!(result2.stop_reason, StopReason::GuestHalted);
		assert_eq!(result2.rax, 0, "Memory should be zeroed in fresh VM");
		Ok(())
	}

	#[test]
	fn runtime_probe_tracks_exit_counts() -> Result<()> {
		// Code that does multiple I/O operations then halts
		let fx_code = b"\xE4\x01\xE4\x02\xE4\x03\xF4"; // in al,1; in al,2; in al,3; hlt
		let result = RuntimeProbe::execute(fx_code, Duration::from_millis(100), 100)?;

		assert_eq!(result.stop_reason, StopReason::GuestHalted);
		assert_eq!(result.exit_counts.io, 3, "Should have 3 I/O exits");
		assert_eq!(result.exit_counts.hlt, 1, "Should have 1 HLT exit");
		assert_eq!(result.total_exits, 4, "Should have 4 total exits");
		Ok(())
	}

	#[test]
	fn runtime_probe_execution_time_reasonable() -> Result<()> {
		let fx_code = b"\xF4"; // hlt
		let result = RuntimeProbe::execute(fx_code, Duration::from_millis(100), 10)?;

		assert_eq!(result.stop_reason, StopReason::GuestHalted);
		// Execution should be very fast (< 50ms for a simple HLT, including VM setup)
		assert!(
			result.execution_time < Duration::from_millis(50),
			"Execution took too long: {:?}",
			result.execution_time
		);
		Ok(())
	}

	#[test]
	fn runtime_probe_isolation_between_executions() -> Result<()> {
		// Malicious code tries to set up interrupt handlers
		let malicious = b"\xFA\xF4"; // cli; hlt (disable interrupts)
		let result1 = RuntimeProbe::execute(malicious, Duration::from_millis(100), 10)?;
		assert_eq!(result1.stop_reason, StopReason::GuestHalted);

		// Second execution should not be affected (fresh VM)
		let normal = b"\xF4"; // hlt
		let result2 = RuntimeProbe::execute(normal, Duration::from_millis(100), 10)?;
		assert_eq!(result2.stop_reason, StopReason::GuestHalted);
		// If state leaked, this might crash instead
		Ok(())
	}

	#[test]
	fn runtime_probe_concurrent_executions() -> Result<()> {
		use std::thread;

		// Spawn multiple threads executing different code simultaneously
		let handles: Vec<_> = (0..4)
			.map(|i| {
				thread::spawn(move || {
					let code = match i {
						0 => b"\xB8\x01\x00\x00\x00\xF4".to_vec(), // mov eax, 1; hlt
						1 => b"\xB8\x02\x00\x00\x00\xF4".to_vec(), // mov eax, 2; hlt
						2 => b"\xB8\x03\x00\x00\x00\xF4".to_vec(), // mov eax, 3; hlt
						_ => b"\xB8\x04\x00\x00\x00\xF4".to_vec(), // mov eax, 4; hlt
					};

					RuntimeProbe::execute(&code, Duration::from_millis(100), 10)
				})
			})
			.collect();

		// All should complete successfully
		for (i, handle) in handles.into_iter().enumerate() {
			let result = handle.join().unwrap()?;
			assert_eq!(result.stop_reason, StopReason::GuestHalted);
			assert_eq!(result.rax as usize, i + 1);
		}

		Ok(())
	}
}
// endregion: --- Tests
