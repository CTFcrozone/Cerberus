use crate::error::Result;
use crate::{engine::ResponseRequest, executor::support};

pub struct ResponseExecutor;

impl ResponseExecutor {
	pub fn execute(req: ResponseRequest) -> Result<()> {
		match req.response {
			crate::Response::KillProcess => {
				support::kill_process(req.event_meta.pid as i32)?;
			}
			crate::Response::EmitSignal { signal } => unsafe {
				libc::kill(req.event_meta.pid as i32, signal);
			},
			_ => {}
		}
		Ok(())
	}
}
