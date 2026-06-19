use std::sync::Arc;

use derive_more::From;
use lib_common::event::CerberusEvent;
use lib_rules::EngineEvent;

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
	HookEnabled {
		hook: Arc<str>,
	},
	HookDisabled {
		hook: Arc<str>,
	},
	HookFailed {
		hook: Arc<str>,
		error: String,
	},
}

#[derive(Debug, Clone)]
pub enum RuleWatchEvent {
	Reload,
}
