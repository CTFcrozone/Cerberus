use aya_ebpf::macros::map;
use aya_ebpf::maps::RingBuf;

#[map(name = "EVTS")]
static mut EVT_MAP: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);
