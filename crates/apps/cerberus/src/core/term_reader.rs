use std::time::Duration;

use crate::Result;
use crossterm::event::EventStream;
use futures::StreamExt;
use tokio::{select, task::JoinHandle};

use super::AppTx;

pub fn run_term_read(app_tx: AppTx) -> Result<JoinHandle<()>> {
	let handle = tokio::spawn(async move {
		let mut reader = EventStream::new();

		loop {
			select! {
				_ = tokio::time::sleep(Duration::from_millis(200)) => {  },
				maybe_event = reader.next() => {
					match maybe_event {
						Some(Ok(event)) => {
							if let Err(err) = app_tx.send(event).await {
								println!("run_term_read - Cannot send app_txt.send. Cause: {err}");
								break;
							}
						}
						Some(Err(e)) => println!("Error: {e:?}\r"),
						None => break,
					}
				}
			};
		}
	});
	Ok(handle)
}
