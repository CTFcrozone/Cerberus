use std::{path::PathBuf, sync::Arc, time::Duration};

use crate::{
	error::Result,
	event::{AppEvent, RuleWatchEvent},
};

use lib_event::unbound::{Rx, Tx, new_channel_unbounded_async};
use lib_rules::RuleEngine;
use notify::{INotifyWatcher, RecursiveMode};
use notify_debouncer_full::{DebounceEventResult, Debouncer, NoCache, new_debouncer};
use tokio_util::sync::CancellationToken;

pub struct RuleWatchWorker {
	tx: Tx<AppEvent>,
	rx: Rx<RuleWatchEvent>,
	rule_engine: Arc<RuleEngine>,
	_debouncer: Debouncer<INotifyWatcher, NoCache>,
	rule_dir: PathBuf,
	token: CancellationToken,
}

impl RuleWatchWorker {
	pub fn start(
		app_tx: Tx<AppEvent>,
		rule_engine: Arc<RuleEngine>,
		rule_dir: PathBuf,
		token: CancellationToken,
	) -> Result<Self> {
		let (tx, rx) = new_channel_unbounded_async::<RuleWatchEvent>("rules");

		let mut debouncer = new_debouncer(Duration::from_secs(1), None, move |res: DebounceEventResult| {
			if res.is_ok() {
				let _ = tx.send(RuleWatchEvent::Reload);
			}
		})?;

		debouncer.watch(&rule_dir, RecursiveMode::Recursive)?;

		Ok(RuleWatchWorker {
			tx: app_tx,
			rx,
			rule_engine,
			rule_dir,
			_debouncer: debouncer,
			token,
		})
	}
	pub async fn run(mut self) -> Result<()> {
		loop {
			tokio::select! {
				biased;

				_ = self.token.cancelled() => {
					tracing::info!("[RuleWatchWorker]: shutting down");
					break;
				}

				res = self.rx.recv() => {
					match res {
						Ok(_) => {
							if let Err(e) = self.rule_engine.reload_ruleset_async(&self.rule_dir).await {
								tracing::error!("Rule reload failed: {e}");
								continue;
							}
							let rules: Arc<[Arc<str>]> = self
								.rule_engine
								.snapshot()
								.ruleset()
								.rules()
								.iter()
								.map(|r| Arc::clone(&r.inner.id))
								.collect::<Vec<_>>()
								.into();
							if let Err(e) = self.tx.send(AppEvent::RuleReload { rules }) {
								tracing::error!("Failed to send rule reload event: {e}");
							}
						}
						Err(_) => {
							tracing::info!("[RuleWatchWorker]: channel closed");
							break;
						}
					}
				}
			}
		}
		Ok(())
	}
}
