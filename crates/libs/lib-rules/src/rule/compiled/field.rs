use std::str::FromStr;

use lib_event_schema::Field;

use crate::error::{Error, Result};

pub fn compile_field(s: &str) -> Result<Field> {
	Field::from_str(s).map_err(|_| Error::UnknownField { field: s.into() })
}
