use crate::error::{Error, Result};
use modql::SqliteFromRow;
use rusqlite::types::FromSql;
use rusqlite::{Connection, OptionalExtension, Params};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
pub struct Db {
	conn: Arc<Mutex<Connection>>,
}

impl Db {
	pub fn new() -> Result<Self> {
		let db_path = db_path()?;
		let conn = Connection::open(db_path)?;

		let conn = Arc::new(Mutex::new(conn));

		Ok(Self { conn })
	}
}

fn db_path() -> Result<PathBuf> {
	let home_dir = std::env::home_dir().ok_or_else(|| Error::custom("Could not determine home directory"))?;

	let cerberus_dir = home_dir.join(".cerberus");

	if !cerberus_dir.exists() {
		std::fs::create_dir(&cerberus_dir)
			.map_err(|e| Error::custom(format!("Failed to create .cerberus directory: {}", e)))?;
	}

	Ok(cerberus_dir.join("cerberus.db"))
}
