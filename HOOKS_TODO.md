# Hooks

- [x] commit_creds - kprobe
- [x] sys_enter_ptrace - tracepoint
- [x] sys_enter_kill - tracepoint
- [x] socket_connect - LSM
- [x] inet_sock_set_state - tracepoint
- [x] do_init_module - kprobe
- [x] bprm_check_security - LSM
- [x] bpf_prog_load - LSM

### Process / Exec

- [ ] do_fork - kprobe
- [ ] sys_enter_execve - tracepoint
- [ ] prepare_creds - kprobe
- [ ] override_creds - kprobe
- [ ] bprm_committing_creds - LSM
- [ ] task_alloc - LSM
- [ ] task_kill - LSM
- [ ] ptrace_access_check - LSM
- [ ] capable - LSM
- [ ] capset - LSM

### File / FS

- [ ] file_permission - LSM
- [ ] inode_permission - LSM
- [ ] inode_mkdir - LSM
- [ ] inode_rmdir - LSM
- [x] inode_unlink - LSM - only ebpf part atm
- [ ] inode_symlink - LSM
- [ ] inode_rename - LSM
- [ ] inode_link - LSM
- [ ] inode_setattr - LSM
- [ ] mmap_file - LSM
- [ ] file_mprotect - LSM
- [ ] do_mmap - kprobe

### Networking

- [ ] tcp_connect - kprobe
- [ ] tcp_accept - kprobe
- [ ] sock_sendmsg - kprobe
- [ ] sock_recvmsg - kprobe
- [ ] tcp_sendmsg - kprobe
- [ ] inet_csk_accept - kprobe
- [x] socket_bind - LSM
- [ ] socket_sendmsg - LSM
- [ ] socket_recvmsg - LSM

### Modules / Kernel Tampering

- [ ] init_module - tracepoint
- [ ] delete_module - kprobe
- [ ] module_alloc - kprobe
- [ ] module_free - kprobe

### BPF Security

- [ ] bpf - LSM
- [ ] bpf_map - LSM
- [ ] bpf_prog - LSM
- [ ] bpf_prog_attach - kprobe
