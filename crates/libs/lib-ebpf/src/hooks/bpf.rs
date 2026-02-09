use aya_ebpf::programs::LsmContext;

// LSM_HOOK(int, 0, bpf_prog_load, struct bpf_prog *prog, union bpf_attr *attr, struct bpf_token *token, bool kernel)
pub fn try_bpf_prog_load(ctx: LsmContext) -> Result<i32, i32> {
	// TODO
	Ok(1)
}
