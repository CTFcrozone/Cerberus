#[derive(Debug, Clone)]
pub enum HookRegistryEvent {
	HookAction { hook: String, action: HookAction },
}

#[derive(Debug, Clone)]
pub enum HookAction {
	Enable,
	Disable,
}
