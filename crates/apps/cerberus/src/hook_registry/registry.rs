use std::{
	collections::{HashMap, hash_map::Entry},
	sync::{
		Arc,
		atomic::{AtomicUsize, Ordering},
	},
};

use aya::Ebpf;

use crate::{Error, Result, hook_registry::hook::Hook};

#[derive(Default)]
pub struct HookRegistry {
	hooks: HashMap<Arc<str>, Hook>,
	prog_count: Option<Arc<AtomicUsize>>,
}

impl HookRegistry {
	pub fn set_prog_count(&mut self, c: Arc<AtomicUsize>) {
		self.prog_count = Some(c);
		self.refresh_count();
	}

	fn refresh_count(&self) {
		if let Some(c) = &self.prog_count {
			let n = self.hooks.values().filter(|h| h.is_enabled()).count();
			c.store(n, Ordering::Relaxed);
		}
	}

	pub fn disable(&mut self, name: &str, ebpf: &mut Ebpf) -> Result<()> {
		self.hooks
			.get_mut(name)
			.ok_or(Error::HookNotFound { hook: name.into() })?
			.disable(ebpf)?;
		self.refresh_count();
		Ok(())
	}

	pub fn enable(&mut self, name: &str, ebpf: &mut Ebpf) -> Result<()> {
		self.hooks
			.get_mut(name)
			.ok_or(Error::HookNotFound { hook: name.into() })?
			.enable(ebpf)?;
		self.refresh_count();
		Ok(())
	}

	pub fn unload_all(&mut self, ebpf: &mut Ebpf) -> Result<()> {
		for hook in self.hooks.values_mut() {
			let _ = hook.disable(ebpf);
			let _ = hook.unload(ebpf);
		}
		self.refresh_count();
		Ok(())
	}

	pub fn enable_all(&mut self, ebpf: &mut Ebpf) -> Result<()> {
		for hook in self.hooks.values_mut() {
			let _ = hook.enable(ebpf);
		}
		self.refresh_count();
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
		self.refresh_count();
		Ok(())
	}
}
