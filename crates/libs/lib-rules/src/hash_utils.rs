use std::{collections::HashMap, sync::Arc};

use rustc_hash::FxBuildHasher;

pub fn blake3(content: &str) -> [u8; 32] {
	let mut hasher = blake3::Hasher::new();
	hasher.update(content.as_bytes());
	*hasher.finalize().as_bytes()
}

pub fn hex_encode(content: impl AsRef<[u8]>) -> Arc<str> {
	hex::encode(content).into()
}

pub type FastMap<K, V> = HashMap<K, V, FxBuildHasher>;
pub type FastDashMap<K, V> = dashmap::DashMap<K, V, FxBuildHasher>;

#[inline]
pub fn new_fast_map<K, V>() -> FastMap<K, V> {
	HashMap::with_hasher(FxBuildHasher)
}

#[inline]
pub fn new_fast_dashmap<K, V>() -> FastDashMap<K, V>
where
	K: std::hash::Hash + Eq,
{
	dashmap::DashMap::with_hasher(FxBuildHasher)
}
