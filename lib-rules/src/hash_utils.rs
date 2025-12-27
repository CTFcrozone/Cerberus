pub fn hash(content: &str) -> String {
	let mut hasher = blake3::Hasher::new();
	hasher.update(content.as_bytes());
	hex::encode(hasher.finalize().as_bytes())
}
