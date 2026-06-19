use std::sync::Arc;

#[derive(Debug, Clone)]
pub enum HookCommand {
	Enable(Arc<str>),
	Disable(Arc<str>),
}
