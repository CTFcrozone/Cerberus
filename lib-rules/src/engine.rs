use std::{
	collections::HashMap,
	path::Path,
	sync::{Arc, RwLock},
};

use lib_event::app_evt_types::CerberusEvent;

use crate::ruleset::RuleSet;
use crate::{
	ctx::EvalCtx,
	error::{Error, Result},
};

pub struct RuleEngine {
	ruleset: Arc<RwLock<RuleSet>>,
}

impl RuleEngine {
	pub fn new(dir: impl AsRef<Path>) -> Result<Self> {
		let ruleset = Arc::new(RwLock::new(RuleSet::load_from_dir(dir)?));

		Ok(Self { ruleset })
	}

	pub async fn process_event() -> Result<()> {
		todo!()
	}

	fn event_to_ctx(event: &CerberusEvent) -> EvalCtx {
		let mut fields = HashMap::new();
		match event {
			CerberusEvent::Generic(e) => {
				fields.insert("name".into(), toml::Value::String(e.name.into()));
				fields.insert("uid".into(), toml::Value::Integer(e.uid as i64));
				fields.insert("pid".into(), toml::Value::Integer(e.pid as i64));
				fields.insert("tgid".into(), toml::Value::Integer(e.tgid as i64));
				fields.insert("comm".into(), toml::Value::String(e.comm.to_string()));
			}
			CerberusEvent::InetSock(e) => {
				fields.insert("old_state".into(), toml::Value::String(e.old_state.to_string()));
				fields.insert("new_state".into(), toml::Value::String(e.new_state.to_string()));
				fields.insert("sport".into(), toml::Value::Integer(e.sport as i64));
				fields.insert("dport".into(), toml::Value::Integer(e.dport as i64));
				fields.insert("protocol".into(), toml::Value::String(e.protocol.to_string()));
			}
		}
		EvalCtx::new(fields)
	}
}
