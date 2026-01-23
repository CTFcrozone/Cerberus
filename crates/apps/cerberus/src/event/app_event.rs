use derive_more::From;
use lib_common::event::CerberusEvent;
use lib_rules::EngineEvent;

#[derive(From)]
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
