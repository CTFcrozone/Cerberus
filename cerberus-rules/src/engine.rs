use std::{
	path::Path,
	sync::{Arc, RwLock},
};

use crate::error::{Error, Result};
use crate::ruleset::RuleSet;

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
}
