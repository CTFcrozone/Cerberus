use crate::error::Result;

pub fn kill_process(pid: i32) -> Result<()> {
	let res = unsafe { libc::kill(pid, libc::SIGKILL) };
	if res != 0 {
		return Err(std::io::Error::last_os_error().into());
	}
	Ok(())
}
