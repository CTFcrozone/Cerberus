use crate::{Result, event::AppEvent};
use crossterm::event::EventStream;
use futures::StreamExt;
use lib_event::unbound::Tx;
use tokio::task::JoinHandle;

pub fn run_term_read(app_tx: Tx<AppEvent>) -> Result<JoinHandle<()>> {
	let handle = tokio::spawn(async move {
		let mut reader = EventStream::new();

		while let Some(event) = reader.next().await {
			match event {
				Ok(event) => {
					if let Err(err) = app_tx.send(event) {
						println!("Cannot send terminal event: {err}");
						break;
					}
				}
				Err(e) => println!("Terminal error: {e:?}"),
			}
		}
	});

	Ok(handle)
}
