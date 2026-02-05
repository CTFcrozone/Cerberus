use std::path::PathBuf;

use clap::{Parser, ValueEnum};
use humantime::Duration;

#[derive(Parser, Debug)]
#[command(name = "cerberus")]
pub struct Cli {
	#[arg(long, value_enum, default_value = "tui")]
	pub mode: RunMode,

	#[arg(long)]
	pub rules: PathBuf,

	#[arg(long, help = "Time duration (e.g., 20s, 5m, 1h). REQUIRED when using --mode agent")]
	pub time: Option<Duration>,
}

#[derive(Copy, Clone, Debug, ValueEnum, PartialEq, Eq)]
pub enum RunMode {
	Tui,
	Agent,
}
