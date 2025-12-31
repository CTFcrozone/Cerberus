pub fn blake3_hex(content: &str) -> String {
	let mut hasher = blake3::Hasher::new();
	hasher.update(content.as_bytes());
	hex::encode(hasher.finalize().as_bytes())
}

pub fn blake3(content: &str) -> [u8; 32] {
	let mut hasher = blake3::Hasher::new();
	hasher.update(content.as_bytes());
	*hasher.finalize().as_bytes()
}
