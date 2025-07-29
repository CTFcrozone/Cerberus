pub trait DbBmc: Sized {
	const TABLE: &'static str;

	fn table_ref() -> &'static str {
		Self::TABLE
	}
}
