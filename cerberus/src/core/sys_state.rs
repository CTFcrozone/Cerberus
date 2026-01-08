use crate::Result;
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind, get_current_pid};

pub struct SysState {
    pub pid: Pid,
    pub sys: System,
}

impl SysState {
    pub fn new() -> Result<Self> {
        let pid = get_current_pid()
            .map_err(|err| format!("Failed to get current pid: Cause: {}", err))?;
        let sys = System::new();
        Ok(SysState { pid, sys })
    }

    fn refresh(&mut self) {
        self.sys.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[self.pid]),
            true,
            ProcessRefreshKind::nothing()
                .with_memory()
                .with_disk_usage()
                .with_exe(UpdateKind::OnlyIfNotSet)
                .with_tasks(),
        );
    }
}

impl SysState {
    pub fn memory(&mut self) -> u64 {
        self.refresh();
        if let Some(proc) = self.sys.process(self.pid) {
            proc.memory()
        } else {
            0
        }
    }
}
