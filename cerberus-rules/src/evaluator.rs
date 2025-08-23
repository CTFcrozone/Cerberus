use toml::Value;

pub struct Evaluator;

impl Evaluator {
	fn equals(a: &Value, b: &Value) -> bool {
		if let (Some(ai), Some(bi)) = (a.as_integer(), b.as_integer()) {
			return ai == bi;
		}
		if let (Some(af), Some(bf)) = (a.as_float(), b.as_float()) {
			return (af - bf).abs() < std::f64::EPSILON;
		}
		if let (Some(ai), Some(bf)) = (a.as_integer(), b.as_float()) {
			return (ai as f64 - bf).abs() < std::f64::EPSILON;
		}
		if let (Some(af), Some(bi)) = (a.as_float(), b.as_integer()) {
			return (af - bi as f64).abs() < std::f64::EPSILON;
		}
		if let (Some(as_), Some(bs_)) = (a.as_str(), b.as_str()) {
			return as_ == bs_;
		}
		if let (Some(ab), Some(bb)) = (a.as_bool(), b.as_bool()) {
			return ab == bb;
		}
		a == b
	}

	fn in_array(val: &Value, target: &Value) -> bool {
		target
			.as_array()
			.map(|arr| arr.iter().any(|el| Self::equals(val, el)))
			.unwrap_or(false)
	}

	fn numeric_cmp<F>(a: &Value, b: &Value, cmp: F) -> bool
	where
		F: Fn(f64, f64) -> bool,
	{
		let aval = a
			.as_float()
			.or_else(|| a.as_integer().map(|i| i as f64))
			.or_else(|| a.as_str().and_then(|s| s.parse::<f64>().ok()));
		let bval = b
			.as_float()
			.or_else(|| b.as_integer().map(|i| i as f64))
			.or_else(|| b.as_str().and_then(|s| s.parse::<f64>().ok()));

		match (aval, bval) {
			(Some(x), Some(y)) => cmp(x, y),
			_ => false,
		}
	}
}
