fn main() {
	tonic_prost_build::configure()
		.build_client(true)
		.compile_protos(&["proto/api.proto"], &["proto"])
		.unwrap();
}
