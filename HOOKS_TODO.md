# Core

- [x] kprobe::commit_creds
- [x] tracepoint::syscalls:sys_enter_ptrace
- [x] tracepoint::syscalls:sys_enter_kill
- [x] lsm::socket_connect
- [x] tracepoint::sock:inet_sock_set_state
- [x] kprobe::do_init_module
- [x] lsm::bprm_check_security
- [x] lsm::bpf_prog_load

### Process / Exec

- [ ] tracepoint::sched:sched_process_fork
- [ ] tracepoint::sched:sched_process_exit
- [ ] kprobe::prepare_creds
- [ ] kprobe::override_creds
- [ ] lsm::bprm_committing_creds
- [ ] lsm::task_alloc
- [ ] lsm::task_kill
- [ ] lsm::ptrace_access_check
- [ ] lsm::capable
- [ ] lsm::capset

### File / FS

- [ ] lsm::inode_permission
- [x] lsm::inode_mkdir
- [x] lsm::inode_rmdir
- [x] lsm::inode_unlink
- [ ] lsm::inode_symlink
- [ ] lsm::inode_rename
- [ ] lsm::inode_link
- [ ] lsm::inode_setattr
- [ ] lsm::mmap_file
- [ ] lsm::file_mprotect
- [ ] kprobe::do_mmap

### Networking

- [ ] kprobe::tcp_connect
- [ ] kprobe::inet_csk_accept
- [ ] kprobe::sock_sendmsg
- [ ] kprobe::sock_recvmsg
- [x] tracepoint::sock:inet_sock_set_state
- [x] lsm::socket_bind
- [ ] lsm::socket_recvmsg

### Modules / Kernel Tampering

- [ ] tracepoint::module:init_module
- [x] kprobe:: `__x64_sys_delete_module/__pfx___x64_sys_delete_module`
- [ ] kprobe::module_alloc
- [ ] kprobe::module_free

### BPF Security

- [ ] lsm::bpf
- [ ] lsm::bpf_map
- [ ] lsm::bpf_prog
- [ ] kprobe::bpf_prog_attach
