use std::sync::Arc;

use derive_more::From;
use lib_common::event::CerberusEvent;
use lib_rules::{EngineEvent, ResolvedAction};
use time::OffsetDateTime;

#[derive(From, Clone)]
pub enum AppEvent {
	#[from]
	Term(crossterm::event::Event),
	#[from]
	Cerberus(CerberusEvent),
	#[from]
	Engine(EngineEvent),
	#[from]
	Watcher(RuleWatchEvent),
	RuleReload {
		rules: Arc<[Arc<str>]>,
	},
	HookEnabled {
		hook: Arc<str>,
	},
	HookDisabled {
		hook: Arc<str>,
	},
	ResponseExecuted {
		rule_id: Arc<str>,
		actions: Arc<[ResolvedAction]>,
		time: OffsetDateTime,
		success: bool,
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
