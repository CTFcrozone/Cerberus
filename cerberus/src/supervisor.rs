use std::future::Future;

use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::Result;

pub struct Supervisor {
	pub shutdown: CancellationToken,
	pub tasks: JoinSet<Result<()>>,
}

impl Supervisor {
	pub fn new() -> Self {
		Self {
			shutdown: CancellationToken::new(),
			tasks: JoinSet::new(),
		}
	}

	pub fn token(&self) -> CancellationToken {
		self.shutdown.clone()
	}

	pub fn token_ref(&self) -> &CancellationToken {
		&self.shutdown
	}

	pub fn spawn<F>(&mut self, fut: F)
	where
		F: Future<Output = Result<()>> + Send + 'static,
	{
		self.tasks.spawn(fut);
	}

	pub async fn shutdown(mut self) -> Result<()> {
		info!("Supervisor shutdown starting");
		self.shutdown.cancel();

		while let Some(res) = self.tasks.join_next().await {
			res??;
		}
		info!("Supervisor shutdown complete");

		Ok(())
	}
}
