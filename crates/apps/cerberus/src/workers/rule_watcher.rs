use std::{path::PathBuf, sync::Arc, time::Duration};

use crate::{error::Result, event::RuleWatchEvent};

use lib_event::trx::{new_channel, Rx};
use lib_rules::RuleEngine;
use notify::{INotifyWatcher, RecursiveMode};
use notify_debouncer_full::{new_debouncer, DebounceEventResult, Debouncer, NoCache};
use tokio_util::sync::CancellationToken;

pub struct RuleWatchWorker {
	rx: Rx<RuleWatchEvent>,
	rule_engine: Arc<RuleEngine>,
	_debouncer: Debouncer<INotifyWatcher, NoCache>,
	rule_dir: PathBuf,
	token: CancellationToken,
}

impl RuleWatchWorker {
	pub fn start(rule_engine: Arc<RuleEngine>, rule_dir: PathBuf, token: CancellationToken) -> Result<Self> {
		let (tx, rx) = new_channel::<RuleWatchEvent>("rules");

		let mut debouncer = new_debouncer(Duration::from_secs(1), None, move |res: DebounceEventResult| {
			if res.is_ok() {
				let _ = tx.send_sync(RuleWatchEvent::Reload);
			}
		})?;

		debouncer.watch(&rule_dir, RecursiveMode::Recursive)?;

		Ok(RuleWatchWorker {
			rx,
			rule_engine,
			rule_dir,
			_debouncer: debouncer,
			token,
		})
	}
	pub async fn run(self) -> Result<()> {
		while !self.token.is_cancelled() {
			match self.rx.recv().await {
				Ok(RuleWatchEvent::Reload) => {
					self.rule_engine.reload_ruleset(&self.rule_dir)?;
				}
				Err(_) => break,
			}
		}
		Ok(())
	}
}
