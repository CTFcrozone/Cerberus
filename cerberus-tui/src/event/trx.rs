use crate::Result;

pub fn new_channel<T>(name: &'static str) -> (Tx<T>, Rx<T>) {
	let (tx, rx) = flume::unbounded();

	(Tx(tx, name), Rx(rx, name))
}

pub struct Tx<T>(flume::Sender<T>, &'static str);

impl<T> Tx<T> {
	pub fn send_sync(&self, value: impl Into<T>) -> Result<()> {
		self.0.send(value.into())?;
		Ok(())
	}

	pub async fn send(&self, value: impl Into<T>) -> Result<()> {
		let _ = self.0.send_async(value.into()).await?;
		Ok(())
	}
}

impl<T> Clone for Tx<T> {
	fn clone(&self) -> Self {
		Self(self.0.clone(), self.1)
	}
}

pub struct Rx<T>(flume::Receiver<T>, &'static str);

impl<T> Rx<T> {
	pub async fn recv(&self) -> Result<T> {
		let res = self.0.recv_async().await?;
		Ok(res)
	}
}

impl<T> Clone for Rx<T> {
	fn clone(&self) -> Self {
		Self(self.0.clone(), self.1)
	}
}
