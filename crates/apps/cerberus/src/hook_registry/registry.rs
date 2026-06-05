use std::collections::{HashMap, HashSet};

use aya::Ebpf;

use crate::{hook_registry::hook::Hook, Error, Result};

pub struct HookRegistry {
	hooks: HashMap<String, Hook>,
}

impl HookRegistry {
	pub fn disable(&mut self, name: &str, ebpf: &mut Ebpf) -> Result<()> {
		self.hooks
			.get_mut(name)
			.ok_or(Error::HookNotFound { hook: name.into() })?
			.disable(ebpf)
	}

	pub fn enable(&mut self, name: &str, ebpf: &mut Ebpf) -> Result<()> {
		self.hooks
			.get_mut(name)
			.ok_or(Error::HookNotFound { hook: name.into() })?
			.enable(ebpf)
	}

	pub fn unload_all(&mut self, ebpf: &mut Ebpf) -> Result<()> {
		for hook in self.hooks.values_mut() {
			let _ = hook.disable(ebpf);
			let _ = hook.unload(ebpf);
		}
		Ok(())
	}

	pub fn enable_all(&mut self, ebpf: &mut Ebpf) -> Result<()> {
		for hook in self.hooks.values_mut() {
			let _ = hook.enable(ebpf);
		}
		Ok(())
	}

	pub fn disable_all(&mut self, ebpf: &mut Ebpf) -> Result<()> {
		for hook in self.hooks.values_mut() {
			let _ = hook.disable(ebpf);
		}
		Ok(())
	}
}
