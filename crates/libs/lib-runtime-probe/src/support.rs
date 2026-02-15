#[cfg(target_arch = "x86_64")]
use kvm_ioctls::Kvm;
use kvm_ioctls::{Cap, VcpuFd};
use vm_memory::{Address, Bytes, GuestAddress, GuestMemoryMmap};

use crate::error::Result;

#[allow(unused)]
pub static ZERO_PAGE: [u8; MEM_SIZE as usize] = [0u8; MEM_SIZE as usize];
pub(crate) const MEM_SIZE: u64 = 0x200000; // 2MB
#[allow(unused)]
pub(crate) const CODE_SIZE: u64 = 0x10000; // 64KB
pub(crate) const CODE_START: u64 = 0x1000;
pub(crate) const STACK_START: u64 = 0x1ff000;

pub(crate) fn gdt_entry(base: u32, limit: u32, flags: u16) -> u64 {
	(limit as u64 & 0xFFFF)
		| ((base as u64 & 0xFFFFFF) << 16)
		| ((flags as u64) << 40)
		| (((limit as u64 >> 16) & 0xF) << 48)
		| (((base as u64 >> 24) & 0xFF) << 56)
}

#[allow(unused)]
pub(crate) fn wipe_memory(mem: &mut GuestMemoryMmap) -> Result<()> {
	mem.write(&ZERO_PAGE, GuestAddress(0))?;
	Ok(())
}

pub(crate) fn reset_state(vcpu: &mut VcpuFd, mem: &mut GuestMemoryMmap) -> Result<()> {
	let gdt_addr = GuestAddress(0x500);
	let gdt: [u64; 3] = [
		0,
		gdt_entry(0, 0xFFFFF, 0x9A | (1 << 7)), // code
		gdt_entry(0, 0xFFFFF, 0x92 | (1 << 7)), // data
	];

	for (i, entry) in gdt.iter().enumerate() {
		mem.write_obj(*entry, gdt_addr.unchecked_add((i * 8) as u64))?;
	}

	let mut sregs = vcpu.get_sregs()?;
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

	vcpu.set_sregs(&sregs)?;

	let mut regs = vcpu.get_regs()?;
	regs.rax = 0;
	regs.rip = CODE_START;
	regs.rsp = STACK_START;
	regs.rflags = 0x2;
	vcpu.set_regs(&regs)?;

	Ok(())
}

pub(crate) fn supports_readonly_mem(kvm: &Kvm) -> bool {
	kvm.check_extension(Cap::ReadonlyMem)
}

#[cfg(target_arch = "x86_64")]
pub(crate) fn configure_cpuid(kvm: &Kvm, vcpu: &VcpuFd) -> Result<()> {
	use kvm_bindings::*;

	let mut cpuid = kvm.get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)?;

	for entry in cpuid.as_mut_slice().iter_mut() {
		match entry.function {
			// CPUID.01H: Feature Information
			1 => {
				entry.ecx &= !(1 << 24); // Disable TSC-Deadline (timing attacks)
				entry.ecx &= !(1 << 31); // Disable Hypervisor bit (VM detection)

				entry.edx &= !(1 << 4); // Disable RDTSC (timing attacks)
				entry.edx &= !(1 << 21); // Disable Debug Store
			}

			// CPUID.07H: Extended Features
			7 => {
				if entry.index == 0 {
					entry.ebx &= !(1 << 2); // Disable SGX (side-channels)
					entry.ebx &= !(1 << 10); // Disable INVPCID
					entry.ebx &= !(1 << 26); // Disable IBRS/IBPB (let KVM handle speculation)

					entry.edx &= !(1 << 26); // Disable IBRS (Spectre mitigation - KVM handles this)
					entry.edx &= !(1 << 27); // Disable STIBP
					entry.edx &= !(1 << 29); // Disable IA32_ARCH_CAPABILITIES
				}
			}

			// CPUID.0DH: Extended State (XSAVE)
			0xD => {
				// Allow basic x87/SSE but not AVX-512 (complexity)
				if entry.index >= 2 {
					entry.eax = 0;
					entry.ebx = 0;
					entry.ecx = 0;
					entry.edx = 0;
				}
			}

			// CPUID.80000001H: Extended Processor Info
			0x80000001 => {
				entry.ecx &= !(1 << 2); // Disable SVM (nested virtualization)
				entry.ecx &= !(1 << 3); // Disable Extended APIC
			}

			_ => {}
		}
	}

	vcpu.set_cpuid2(&cpuid)?;
	Ok(())
}
