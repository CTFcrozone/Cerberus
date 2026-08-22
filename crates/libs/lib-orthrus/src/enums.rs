#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TamperKind {
	HeartbeatStale,
	ProgsDropped,
	ProgsZero,
	WatchdogUnloading,
}
