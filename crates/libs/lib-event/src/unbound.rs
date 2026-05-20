use std::time::Duration;

use crossfire::{flavor::Flavor, mpsc::List, AsyncRx, AsyncRxTrait, TryRecvError};

use crate::{error::Result, Error};

// crossfire::mpsc::unbounded_async()

pub struct Rx<T>
where
	T: Send + 'static,
{
	pub inner: AsyncRx<List<T>>,
	pub name: &'static str,
}

#[derive(Clone)]
pub struct Tx<T>
where
	T: Send + 'static,
{
	pub inner: crossfire::MTx<List<T>>,
	pub name: &'static str,
}

impl<T> Tx<T>
where
	T: Send + 'static,
{
	pub fn send(&self, value: impl Into<T>) -> Result<()> {
		self.inner.send(value.into()).map_err(|err| Error::ChannelTx {
			name: self.name,
			cause: err.to_string(),
		})
	}
}

impl<T: Send + 'static> Rx<T> {
	pub async fn recv(&mut self) -> Result<T> {
		self.inner.recv().await.map_err(|err| Error::ChannelRx {
			name: self.name,
			cause: err.to_string(),
		})
	}

	pub fn try_recv(&self) -> Result<Option<T>> {
		match self.inner.try_recv() {
			Ok(v) => Ok(Some(v)),
			Err(crossfire::TryRecvError::Empty) => Ok(None),
			Err(err @ crossfire::TryRecvError::Disconnected) => Err(Error::ChannelRx {
				name: self.name,
				cause: err.to_string(),
			}),
		}
	}
}

pub fn new_channel_unbounded_async<T: Send + 'static>(name: &'static str) -> (Tx<T>, Rx<T>) {
	let (tx, rx) = crossfire::mpsc::unbounded_async::<T>();

	(Tx { inner: tx, name }, Rx { inner: rx, name })
}
