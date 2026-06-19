use std::sync::Arc;

use aya::{
	programs::{kprobe::KProbeLinkId, lsm::LsmLinkId, trace_point::TracePointLinkId, KProbe, Lsm, TracePoint},
	Ebpf,
};
use derive_more::From;

use crate::{Error, Result};

#[derive(From)]
pub enum HookLink {
	#[from]
	Lsm(LsmLinkId),
	#[from]
	Tracepoint(TracePointLinkId),
	#[from]
	Kprobe(KProbeLinkId),
}

pub enum HookKind {
	Lsm,
	Tracepoint { category: Arc<str>, event: Arc<str> },
	Kprobe { function: Arc<str>, offset: u64 },
}

pub enum HookState {
	Enabled,
	Disabled,
}

pub struct HookView {
	pub name: Arc<str>,
	pub state: HookState,
}

pub struct Hook {
	pub program_name: Arc<str>,
	pub kind: HookKind,
	pub link: Option<HookLink>,
}

impl Hook {
	pub fn new(program_name: &str, kind: HookKind, link: HookLink) -> Self {
		Self {
			program_name: program_name.into(),
			kind,
			link: Some(link),
		}
	}

	pub fn unload(&mut self, ebpf: &mut Ebpf) -> Result<()> {
		match &self.kind {
			HookKind::Lsm => {
				let prog: &mut Lsm = ebpf
					.program_mut(&self.program_name)
					.ok_or(Error::EbpfProgNotFound {
						program: self.program_name.clone(),
					})?
					.try_into()?;

				prog.unload()?;
			}

			HookKind::Tracepoint { .. } => {
				let prog: &mut TracePoint = ebpf
					.program_mut(&self.program_name)
					.ok_or(Error::EbpfProgNotFound {
						program: self.program_name.clone(),
					})?
					.try_into()?;

				prog.unload()?;
			}

			HookKind::Kprobe { .. } => {
				let prog: &mut KProbe = ebpf
					.program_mut(&self.program_name)
					.ok_or(Error::EbpfProgNotFound {
						program: self.program_name.clone(),
					})?
					.try_into()?;

				prog.unload()?;
			}
		}
		self.link = None;

		Ok(())
	}

	pub fn enable(&mut self, ebpf: &mut Ebpf) -> Result<()> {
		if self.link.is_some() {
			return Ok(());
		}

		match &self.kind {
			HookKind::Lsm => {
				let prog: &mut Lsm = ebpf
					.program_mut(&self.program_name)
					.ok_or(Error::EbpfProgNotFound {
						program: self.program_name.clone(),
					})?
					.try_into()?;
				self.link = Some(prog.attach()?.into());
			}

			HookKind::Tracepoint { category, event } => {
				let prog: &mut TracePoint = ebpf
					.program_mut(&self.program_name)
					.ok_or(Error::EbpfProgNotFound {
						program: self.program_name.clone(),
					})?
					.try_into()?;

				self.link = Some(prog.attach(category, event)?.into());
			}

			HookKind::Kprobe { function, offset } => {
				let prog: &mut KProbe = ebpf
					.program_mut(&self.program_name)
					.ok_or(Error::EbpfProgNotFound {
						program: self.program_name.clone(),
					})?
					.try_into()?;

				self.link = Some(prog.attach(function.as_ref(), *offset)?.into());
			}
		}

		Ok(())
	}

	pub fn disable(&mut self, ebpf: &mut Ebpf) -> Result<()> {
		let link = self.link.take().ok_or(Error::HookAlreadyDisabled {
			program: self.program_name.to_string(),
		})?;

		match link {
			HookLink::Lsm(id) => {
				let prog: &mut Lsm = ebpf
					.program_mut(&self.program_name)
					.ok_or(Error::EbpfProgNotFound {
						program: self.program_name.clone(),
					})?
					.try_into()?;

				prog.detach(id)?;
			}

			HookLink::Tracepoint(id) => {
				let prog: &mut TracePoint = ebpf
					.program_mut(&self.program_name)
					.ok_or(Error::EbpfProgNotFound {
						program: self.program_name.clone(),
					})?
					.try_into()?;

				prog.detach(id)?;
			}

			HookLink::Kprobe(id) => {
				let prog: &mut KProbe = ebpf
					.program_mut(&self.program_name)
					.ok_or(Error::EbpfProgNotFound {
						program: self.program_name.clone(),
					})?
					.try_into()?;

				prog.detach(id)?;
			}
		}

		Ok(())
	}
}
