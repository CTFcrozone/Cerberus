use std::path::PathBuf;

use clap::{Parser, ValueEnum};
use humantime::Duration;

#[derive(Parser, Debug)]
#[command(name = "cerberus")]
pub struct Cli {
	#[arg(long, value_enum, default_value = "tui")]
	pub mode: RunMode,

	#[arg(long, value_name = "DIR", help = "Directory containing detection rules")]
	pub rules: PathBuf,

	#[arg(long, value_name = "IFACE", help = "Network interface to attach the XDP program")]
	pub iface: String,

	#[arg(long, help = "Time duration (e.g., 20s, 5m, 1h). Optional when using --mode agent")]
	pub time: Option<Duration>,

	#[arg(long, help = "Enable container metadata resolution (Docker/K8s)")]
	pub container_resolver: bool,

	#[arg(long, value_name = "PATH", help = "Write logs to the specified file or directory")]
	pub log: Option<PathBuf>,
}

#[derive(Copy, Clone, Debug, ValueEnum, PartialEq, Eq)]
pub enum RunMode {
	Tui,
	Agent,
}
