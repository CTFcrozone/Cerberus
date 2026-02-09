use lib_common::event::CerberusEvent;
use lib_ebpf_common::{FLAG_GPL, FLAG_JITED, FLAG_KPROBE_OVR, FLAG_SLEEPABLE};
use ratatui::text::Line;

fn flags_to_string(flags: u32) -> String {
	let mut s = Vec::new();
	if flags & FLAG_JITED != 0 {
		s.push("JIT");
	}
	if flags & FLAG_SLEEPABLE != 0 {
		s.push("SLEEPABLE");
	}
	if flags & FLAG_GPL != 0 {
		s.push("GPL");
	}
	if flags & FLAG_KPROBE_OVR != 0 {
		s.push("KPROBE_OVR");
	}
	s.join(",")
}

fn attach_type_to_string(atype: u32) -> &'static str {
	match atype {
		0 => "CGROUP_INET_INGRESS",
		1 => "CGROUP_INET_EGRESS",
		2 => "CGROUP_INET_SOCK_CREATE",
		3 => "CGROUP_SOCK_OPS",
		4 => "SK_SKB_STREAM_PARSER",
		5 => "SK_SKB_STREAM_VERDICT",
		6 => "CGROUP_DEVICE",
		7 => "SK_MSG_VERDICT",
		8 => "CGROUP_INET4_BIND",
		9 => "CGROUP_INET6_BIND",
		10 => "CGROUP_INET4_CONNECT",
		11 => "CGROUP_INET6_CONNECT",
		12 => "CGROUP_INET4_POST_BIND",
		13 => "CGROUP_INET6_POST_BIND",
		14 => "CGROUP_UDP4_SENDMSG",
		15 => "CGROUP_UDP6_SENDMSG",
		16 => "LIRC_MODE2",
		17 => "FLOW_DISSECTOR",
		18 => "CGROUP_SYSCTL",
		19 => "CGROUP_UDP4_RECVMSG",
		20 => "CGROUP_UDP6_RECVMSG",
		21 => "CGROUP_GETSOCKOPT",
		22 => "CGROUP_SETSOCKOPT",
		23 => "TRACE_RAW_TP",
		24 => "TRACE_FENTRY",
		25 => "TRACE_FEXIT",
		26 => "MODIFY_RETURN",
		27 => "LSM_MAC",
		28 => "TRACE_ITER",
		29 => "CGROUP_INET4_GETPEERNAME",
		30 => "CGROUP_INET6_GETPEERNAME",
		31 => "CGROUP_INET4_GETSOCKNAME",
		32 => "CGROUP_INET6_GETSOCKNAME",
		33 => "XDP_DEVMAP",
		34 => "CGROUP_INET_SOCK_RELEASE",
		35 => "XDP_CPUMAP",
		36 => "SK_LOOKUP",
		37 => "XDP",
		38 => "SK_SKB_VERDICT",
		39 => "SK_REUSEPORT_SELECT",
		40 => "SK_REUSEPORT_SELECT_OR_MIGRATE",
		41 => "PERF_EVENT",
		42 => "TRACE_KPROBE_MULTI",
		43 => "LSM_CGROUP",
		44 => "STRUCT_OPS",
		45 => "NETFILTER",
		46 => "TCX_INGRESS",
		47 => "TCX_EGRESS",
		48 => "TRACE_UPROBE_MULTI",
		49 => "CGROUP_UNIX_CONNECT",
		50 => "CGROUP_UNIX_SENDMSG",
		51 => "CGROUP_UNIX_RECVMSG",
		52 => "CGROUP_UNIX_GETPEERNAME",
		53 => "CGROUP_UNIX_GETSOCKNAME",
		54 => "NETKIT_PRIMARY",
		55 => "NETKIT_PEER",
		56 => "TRACE_KPROBE_SESSION",
		57 => "TRACE_UPROBE_SESSION",
		_ => "UNKNOWN",
	}
}

fn prog_type_to_string(ptype: u32) -> &'static str {
	match ptype {
		0 => "UNSPEC",
		1 => "SOCKET_FILTER",
		2 => "KPROBE",
		3 => "SCHED_CLS",
		4 => "SCHED_ACT",
		5 => "TRACEPOINT",
		6 => "XDP",
		7 => "PERF_EVENT",
		8 => "CGROUP_SKB",
		9 => "CGROUP_SOCK",
		10 => "LWT_IN",
		11 => "LWT_OUT",
		12 => "LWT_XMIT",
		13 => "SOCK_OPS",
		14 => "SK_SKB",
		15 => "CGROUP_DEVICE",
		16 => "SK_MSG",
		17 => "RAW_TRACEPOINT",
		18 => "CGROUP_SOCK_ADDR",
		19 => "LWT_SEG6LOCAL",
		20 => "LIRC_MODE2",
		21 => "SK_REUSEPORT",
		22 => "FLOW_DISSECTOR",
		23 => "CGROUP_SYSCTL",
		24 => "RAW_TRACEPOINT_WRITABLE",
		25 => "CGROUP_SOCKOPT",
		26 => "TRACING",
		27 => "STRUCT_OPS",
		28 => "EXT",
		29 => "LSM",
		30 => "SK_LOOKUP",
		31 => "SYSCALL",
		32 => "NETFILTER",
		_ => "UNKNOWN",
	}
}

pub fn line_from_event(evt: &CerberusEvent) -> Line<'static> {
	match evt {
		CerberusEvent::Generic(g) => Line::raw(format!(
			"[{}] UID:{} | PID:{} | TGID:{} | CMD:{} | META:{}",
			g.name, g.uid, g.pid, g.tgid, g.comm, g.meta
		)),
		CerberusEvent::Module(m) => Line::raw(format!(
			"[MODULE_INIT] UID:{} | PID:{} | TGID:{} | CMD:{} | MODULE_NAME:{}",
			m.uid, m.pid, m.tgid, m.comm, m.module_name
		)),
		CerberusEvent::Bprm(b) => Line::raw(format!(
			"[BRPM_SEC_CHECK] UID:{} | PID:{} | TGID:{} | CMD:{} | FILEPATH:{}",
			b.uid, b.pid, b.tgid, b.comm, b.filepath
		)),
		CerberusEvent::SocketConnect(s) => Line::raw(format!(
			"[SOCKET_CONNECT] {}:{} | Family: {}",
			ip_to_string(s.addr),
			s.port,
			family_to_string(s.family),
		)),
		CerberusEvent::InetSock(n) => Line::raw(format!(
			"[INET_SOCK] {}:{} → {}:{} | Proto: {} | {} → {}",
			ip_to_string(n.saddr),
			n.sport,
			ip_to_string(n.daddr),
			n.dport,
			n.protocol,
			n.old_state,
			n.new_state
		)),
		CerberusEvent::BpfProgLoad(b) => {
			let prog_type_str = prog_type_to_string(b.prog_type);
			let attach_type_str = attach_type_to_string(b.attach_type);
			let flags_str = flags_to_string(b.flags);

			Line::raw(format!(
				"[BPF_PROG_LOAD] UID:{} | PID:{} | CMD:{} | TYPE:{} | ATTACH:{} | FLAGS:{} | TAG:0x{}",
				b.uid,
				b.pid,
				b.comm,
				prog_type_str,
				attach_type_str,
				flags_str,
				hex::encode(b.tag.as_ref())
			))
		}
	}
}

fn ip_to_string(ip: u32) -> String {
	let octets = ip.to_le_bytes();
	format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])
}

fn family_to_string<T: Into<i32>>(family: T) -> &'static str {
	let family = family.into();
	match family {
		libc::AF_UNSPEC => "AF_UNSPEC",         // 0
		libc::AF_UNIX => "AF_UNIX",             // 1 - Unix domain sockets
		libc::AF_INET => "AF_INET",             // 2 - IPv4
		libc::AF_AX25 => "AF_AX25",             // 3 - Amateur Radio AX.25
		libc::AF_IPX => "AF_IPX",               // 4 - IPX - Novell protocols
		libc::AF_APPLETALK => "AF_APPLETALK",   // 5 - Appletalk DDP
		libc::AF_NETROM => "AF_NETROM",         // 6 - From KA9Q: NET/ROM pseudo
		libc::AF_BRIDGE => "AF_BRIDGE",         // 7 - Multiprotocol bridge
		libc::AF_ATMPVC => "AF_ATMPVC",         // 8 - ATM PVCs
		libc::AF_X25 => "AF_X25",               // 9 - Reserved for X.25 project
		libc::AF_INET6 => "AF_INET6",           // 10 - IPv6
		libc::AF_ROSE => "AF_ROSE",             // 11 - Amateur Radio X.25 PLP
		libc::AF_DECnet => "AF_DECnet",         // 12 - Reserved for DECnet project
		libc::AF_NETBEUI => "AF_NETBEUI",       // 13 - Reserved for 802.2LLC project
		libc::AF_SECURITY => "AF_SECURITY",     // 14 - Security callback pseudo AF
		libc::AF_KEY => "AF_KEY",               // 15 - PF_KEY key management API
		libc::AF_NETLINK => "AF_NETLINK",       // 16 - Netlink
		libc::AF_PACKET => "AF_PACKET",         // 17 - Packet family
		libc::AF_ASH => "AF_ASH",               // 18 - Ash
		libc::AF_ECONET => "AF_ECONET",         // 19 - Acorn Econet
		libc::AF_ATMSVC => "AF_ATMSVC",         // 20 - ATM SVCs
		libc::AF_RDS => "AF_RDS",               // 21 - RDS sockets
		libc::AF_SNA => "AF_SNA",               // 22 - Linux SNA Project
		libc::AF_IRDA => "AF_IRDA",             // 23 - IRDA sockets
		libc::AF_PPPOX => "AF_PPPOX",           // 24 - PPPoX sockets
		libc::AF_WANPIPE => "AF_WANPIPE",       // 25 - Wanpipe API sockets
		libc::AF_LLC => "AF_LLC",               // 26 - Linux LLC
		libc::AF_IB => "AF_IB",                 // 27 - Native InfiniBand address
		libc::AF_MPLS => "AF_MPLS",             // 28 - MPLS
		libc::AF_CAN => "AF_CAN",               // 29 - Controller Area Network
		libc::AF_TIPC => "AF_TIPC",             // 30 - TIPC sockets
		libc::AF_BLUETOOTH => "AF_BLUETOOTH",   // 31 - Bluetooth sockets
		libc::AF_IUCV => "AF_IUCV",             // 32 - IUCV sockets
		libc::AF_RXRPC => "AF_RXRPC",           // 33 - RxRPC sockets
		libc::AF_ISDN => "AF_ISDN",             // 34 - mISDN sockets
		libc::AF_PHONET => "AF_PHONET",         // 35 - Phonet sockets
		libc::AF_IEEE802154 => "AF_IEEE802154", // 36 - IEEE 802.15.4 sockets
		libc::AF_CAIF => "AF_CAIF",             // 37 - CAIF sockets
		libc::AF_ALG => "AF_ALG",               // 38 - Algorithm sockets
		libc::AF_NFC => "AF_NFC",               // 39 - NFC sockets
		libc::AF_XDP => "AF_XDP",               // 40 - XDP sockets
		_ => "UNKNOWN_FAMILY",
	}
}
