use clap::{Parser, ValueEnum};

#[derive(Parser)]
#[command(name = "cerberus")]
pub struct Cli {
	#[arg(long, value_enum, default_value = "tui")]
	pub mode: RunMode,

	#[arg(long, default_value = "/var/log/cerberus.log")]
	pub log_file: String,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum RunMode {
	Tui,
	Daemon,
}
