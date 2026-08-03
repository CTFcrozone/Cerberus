use derive_more::{Display, From};

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Display, From)]
#[display("{self:?}")]
pub enum Error {
	#[from(String, &String, &str)]
	#[display("{_0}")]
	Custom(String),
	#[from]
	#[display("KVM ioctl error: {_0}")]
	KvmBindings(kvm_ioctls::Error),
	#[display("Virtual machine memory error: {err}")]
	VmMemory { err: String },
	#[display("Guest crashed: {reason} (RIP: {rip:#x})")]
	GuestCrash { reason: String, rip: u64 },
	#[display("Code size {size} bytes exceeds maximum allowed size of {max} bytes")]
	CodeTooLarge { size: usize, max: usize },
	#[display("Lock poisoned")]
	LockPoison,
	#[from]
	#[display("ELF parsing error: {_0}")]
	Goblin(goblin::error::Error),
}

impl<T> From<std::sync::PoisonError<T>> for Error {
	fn from(_val: std::sync::PoisonError<T>) -> Self {
		Self::LockPoison
	}
}

impl From<vm_memory::mmap::FromRangesError> for Error {
	fn from(value: vm_memory::mmap::FromRangesError) -> Self {
		Error::VmMemory { err: value.to_string() }
	}
}
impl From<vm_memory::GuestMemoryError> for Error {
	fn from(value: vm_memory::GuestMemoryError) -> Self {
		Error::VmMemory { err: value.to_string() }
	}
}

impl Error {
	pub fn custom_from_err(err: impl std::error::Error) -> Self {
		Self::Custom(err.to_string())
	}

	pub fn custom(val: impl Into<String>) -> Self {
		Self::Custom(val.into())
	}
}

// endregion: --- Custom

// region:    --- Error Boilerplate

impl std::error::Error for Error {}

// endregion: --- Error Boilerplate
