use std::sync::Arc;

use derive_more::From;
use lib_common::event::CerberusEvent;
use lib_rules::EngineEvent;

use crate::hook_registry::event::HookRegistryEvent;

#[derive(From, Clone)]
pub enum AppEvent {
	#[from]
	Term(crossterm::event::Event),
	#[from]
	Cerberus(CerberusEvent),
	#[from]
	Engine(EngineEvent),
	#[from]
	LoadedHooks,
	#[from]
	Watcher(RuleWatchEvent),
	RuleReload {
		rules: Arc<[String]>,
	},
	#[from]
	HookRegistry(HookRegistryEvent),
}

#[derive(Debug, Clone)]
pub enum RuleWatchEvent {
	Reload,
}
