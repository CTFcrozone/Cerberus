use clap::{Parser, ValueEnum};
use humantime::Duration;

#[derive(Parser, Debug)]
#[command(name = "cerberus")]
pub struct Cli {
	#[arg(long, value_enum, default_value = "tui")]
	pub mode: RunMode,

	#[arg(long)]
	pub time: Option<Duration>,

	#[arg(long, default_value = "/var/log/cerberus.log")]
	pub log_file: String,
}

#[derive(Copy, Clone, Debug, ValueEnum, PartialEq, Eq)]
pub enum RunMode {
	Tui,
	Agent,
}
