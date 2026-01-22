use derive_more::From;

use crate::event::{CerberusEvent, EngineEvent, EvaluatedEvent};

#[derive(From)]
pub enum AppEvent {
	#[from]
	Term(crossterm::event::Event),
	#[from]
	Cerberus(CerberusEvent),
	#[from]
	CerberusEvaluated(EvaluatedEvent),
	#[from]
	Engine(EngineEvent),
	#[from]
	LoadedHooks,
	#[from]
	Action(ActionEvent),
	#[from]
	Watcher(RuleWatchEvent),
}

#[derive(Debug, Clone)]
pub enum RuleWatchEvent {
	Reload,
}

#[derive(Debug)]
pub enum ActionEvent {
	Quit,
}
