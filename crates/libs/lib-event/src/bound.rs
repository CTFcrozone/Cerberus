use crossfire::{mpsc::Array, AsyncRx};

use crate::{error::Result, Error};

// crossfire::mpsc::bounded_async(size)

pub struct BoundedAsyncRx<T>
where
	T: Send + 'static,
{
	pub inner: AsyncRx<Array<T>>,
	pub name: &'static str,
}

#[derive(Clone)]
pub struct BoundedAsyncTx<T>
where
	T: Send + 'static + Unpin,
{
	pub inner: crossfire::MAsyncTx<Array<T>>,
	pub name: &'static str,
}

impl<T> BoundedAsyncTx<T>
where
	T: Send + 'static + Unpin,
{
	pub async fn send(&self, value: impl Into<T>) -> Result<()> {
		self.inner.send(value.into()).await.map_err(|err| Error::ChannelTx {
			name: self.name,
			cause: err.to_string(),
		})
	}
}

impl<T: Send + 'static> BoundedAsyncRx<T> {
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

pub fn new_channel_bounded_async<T: Send + 'static + Unpin>(
	name: &'static str,
	size: usize,
) -> (BoundedAsyncTx<T>, BoundedAsyncRx<T>) {
	let (tx, rx) = crossfire::mpsc::bounded_async::<T>(size);

	(BoundedAsyncTx { inner: tx, name }, BoundedAsyncRx { inner: rx, name })
}
