use std::{
	collections::{hash_map::Entry, HashMap},
	sync::Arc,
};

use aya::Ebpf;

use crate::{hook_registry::hook::Hook, Error, Result};

#[derive(Default)]
pub struct HookRegistry {
	hooks: HashMap<Arc<str>, Hook>,
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

	pub fn hooks(&self) -> impl Iterator<Item = (&Arc<str>, &Hook)> {
		self.hooks.iter()
	}

	pub fn add(&mut self, hook: Hook) -> Result<()> {
		match self.hooks.entry(hook.program_name.clone()) {
			Entry::Occupied(_) => Err(Error::HookAlreadyExists {
				hook: hook.program_name,
			}),
			Entry::Vacant(v) => {
				v.insert(hook);
				Ok(())
			}
		}
	}

	pub fn remove(&mut self, name: &str) -> Option<Hook> {
		self.hooks.remove(name)
	}

	pub fn get(&self, name: &str) -> Option<&Hook> {
		self.hooks.get(name)
	}

	pub fn get_mut(&mut self, name: &str) -> Option<&mut Hook> {
		self.hooks.get_mut(name)
	}

	pub fn disable_all(&mut self, ebpf: &mut Ebpf) -> Result<()> {
		for hook in self.hooks.values_mut() {
			let _ = hook.disable(ebpf);
		}
		Ok(())
	}
}
