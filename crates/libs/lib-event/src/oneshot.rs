use crate::{error::Result, Error};

pub struct OneShotTx<T>(crossfire::oneshot::TxOneshot<T>, &'static str);
pub struct OneShotRx<T>(crossfire::oneshot::RxOneshot<T>, &'static str);

impl<T> OneShotTx<T> {
	pub fn send(self, value: T) {
		self.0.send(value)
	}

	pub fn name(&self) -> &'static str {
		self.1
	}
}

impl<T> OneShotRx<T> {
	pub async fn recv(self) -> Result<T> {
		self.0.recv_async().await.map_err(|err| Error::ChannelRx {
			name: self.1,
			cause: err.to_string(),
		})
	}
	pub fn recv_blocking(self) -> Result<T> {
		self.0.recv().map_err(|err| Error::ChannelRx {
			name: self.1,
			cause: err.to_string(),
		})
	}
}

pub fn new_oneshot<T>(name: &'static str) -> (OneShotTx<T>, OneShotRx<T>) {
	let (tx, rx) = crossfire::oneshot::oneshot();
	(OneShotTx(tx, name), OneShotRx(rx, name))
}
