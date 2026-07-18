use aya::{
	Btf, Ebpf,
	programs::{KProbe, Lsm, TracePoint, Xdp, XdpMode},
};

use crate::{
	Error, Result,
	hook_registry::{
		hook::{Hook, HookKind},
		registry::HookRegistry,
	},
};

pub fn register_lsm(
	ebpf: &mut Ebpf,
	registry: &mut HookRegistry,
	program_name: &str,
	hook_name: &str,
	btf: &Btf,
) -> Result<()> {
	let prog: &mut Lsm = ebpf
		.program_mut(program_name)
		.ok_or(Error::EbpfProgNotFound {
			program: program_name.into(),
		})?
		.try_into()?;

	prog.load(hook_name, btf)?;

	let link = prog.attach()?;

	registry.add(Hook::new(program_name, HookKind::Lsm, link.into()))?;

	Ok(())
}

pub fn register_tracepoint(
	ebpf: &mut Ebpf,
	registry: &mut HookRegistry,
	program_name: &str,
	category: &str,
	event: &str,
) -> Result<()> {
	let prog: &mut TracePoint = ebpf
		.program_mut(program_name)
		.ok_or(Error::EbpfProgNotFound {
			program: program_name.into(),
		})?
		.try_into()?;

	prog.load()?;

	let link = prog.attach(category, event)?;

	registry.add(Hook::new(
		program_name,
		HookKind::Tracepoint {
			category: category.into(),
			event: event.into(),
		},
		link.into(),
	))?;

	Ok(())
}

pub fn register_kprobe(
	ebpf: &mut Ebpf,
	registry: &mut HookRegistry,
	program_name: &str,
	function: &str,
	offset: u64,
) -> Result<()> {
	let prog: &mut KProbe = ebpf
		.program_mut(program_name)
		.ok_or(Error::EbpfProgNotFound {
			program: program_name.into(),
		})?
		.try_into()?;

	prog.load()?;

	let link = prog.attach(function, offset)?;

	registry.add(Hook::new(
		program_name,
		HookKind::Kprobe {
			function: function.into(),
			offset,
		},
		link.into(),
	))?;

	Ok(())
}

pub fn register_xdp(ebpf: &mut Ebpf, registry: &mut HookRegistry, program_name: &str, iface: &str) -> Result<()> {
	let prog: &mut Xdp = ebpf
		.program_mut(program_name)
		.ok_or(Error::EbpfProgNotFound {
			program: program_name.into(),
		})?
		.try_into()?;

	prog.load()?;

	let link = prog.attach(iface, XdpMode::default())?;

	registry.add(Hook::new(
		program_name,
		HookKind::Xdp { iface: iface.into() },
		link.into(),
	))?;

	Ok(())
}
