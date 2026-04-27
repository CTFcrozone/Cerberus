use std::sync::Arc;

pub fn blake3(content: &str) -> [u8; 32] {
	let mut hasher = blake3::Hasher::new();
	hasher.update(content.as_bytes());
	*hasher.finalize().as_bytes()
}

pub fn hex_encode(content: impl AsRef<[u8]>) -> Arc<str> {
	hex::encode(content).into()
}
