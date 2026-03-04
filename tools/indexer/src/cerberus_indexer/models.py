"""
Domain models for the CerberusOS indexer.

Dataclasses for code chunks, pattern evidence, pattern entries, and the
static pattern-specification table that drives pattern mining.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

# ---------------------------------------------------------------------------
# Code chunk model
# ---------------------------------------------------------------------------


@dataclass
class CodeChunk:
    """A single chunk of source code ready for embedding and upsert."""

    file: str
    chunk_index: int
    total_chunks: int
    language: str
    hash: str
    text: str
    # v0.3.0 metadata fields (all optional with defaults for backward compat)
    line_start: int = 0
    line_end: int = 0
    symbols: List[str] = field(default_factory=list)
    kind: str = "mixed"
    crate_name: str = ""
    subsystem: str = ""
    module_path: str = ""
    is_test: bool = False
    is_unsafe: bool = False
    calls: List[str] = field(default_factory=list)
    declared: List[str] = field(default_factory=list)
    doc_comment: str = ""


# ---------------------------------------------------------------------------
# Pattern mining models
# ---------------------------------------------------------------------------


@dataclass
class Evidence:
    """One regex hit inside a source file that supports a pattern."""

    file_path: str
    line_start: int
    line_end: int
    code_snippet: str
    context: str


@dataclass
class PatternEntry:
    """A fully-resolved pattern with evidence, ready for embedding."""

    pattern_id: str
    pattern_name: str
    origin_path: str
    snippet: str
    reason: str
    tags: List[str]
    scope_paths: List[str]
    evidence: List[Evidence]
    timestamp: str
    confidence: float


@dataclass
class PatternSpec:
    """
    Static specification for a pattern to mine.

    Each spec carries two regexes (one for code, one for docs), a
    human-readable reason, a tag list, and the directory scopes in
    which to search.
    """

    name: str
    code_regex: str
    doc_regex: str
    reason: str
    tags: List[str] = field(default_factory=list)
    scopes: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Built-in pattern table
# ---------------------------------------------------------------------------

PATTERNS: List[PatternSpec] = [
    PatternSpec(
        name="Determinism via BTreeMap",
        code_regex=r"\bBTreeMap\s*<",
        doc_regex=r"\bdeterminism\b|\bBTreeMap\b",
        reason="Deterministic iteration/serialization for auditability.",
        tags=["determinism", "collections"],
        scopes=["cerberus/crucibles", "cerberus/kernel", "cerberus/runtime"],
    ),
    PatternSpec(
        name="no_std imports",
        code_regex=r"\buse\s+(alloc|core)::",
        doc_regex=r"\bno_std\b|\balloc\b|\bcore\b",
        reason="no_std compatibility for kernel/runtime crates.",
        tags=["no_std"],
        scopes=["cerberus/crucibles", "cerberus/runtime", "cerberus/kernel"],
    ),
    PatternSpec(
        name="Feature gate std",
        code_regex=r"#\s*\[\s*cfg\(feature\s*=\s*\"std\"\)\s*]",
        doc_regex=r"\bfeature gate\b|\bcfg\(feature *= *\"std\"",
        reason="Conditional compilation boundary for std-only code.",
        tags=["feature-gate"],
        scopes=["cerberus/crucibles", "cerberus/runtime"],
    ),
    PatternSpec(
        name="Spin mutex",
        code_regex=r"\bspin::Mutex\b",
        doc_regex=r"\bspin::Mutex\b|\bthread safety\b",
        reason="Spinlock for no_std synchronization.",
        tags=["sync", "no_std"],
        scopes=["cerberus/crucibles", "cerberus/runtime", "cerberus/kernel"],
    ),
    PatternSpec(
        name="Schema versioning",
        code_regex=r"\bschema_version\b",
        doc_regex=r"\bschema version\b",
        reason="Forward/backward compatibility contract.",
        tags=["versioning"],
        scopes=["cerberus/crucibles", "cerberus/runtime", "cerberus/kernel"],
    ),
    PatternSpec(
        name="Domain separation",
        code_regex=r"Temper\.[A-Za-z0-9_.-]+",
        doc_regex=r"\bdomain separation\b|Temper\.",
        reason="Prevents cross-protocol key reuse.",
        tags=["crypto", "domain-separation"],
        scopes=["cerberus/runtime/temper"],
    ),
    PatternSpec(
        name="Content-addressed IDs (BLA3)",
        code_regex=r"\bBLAKE3\b|\bObjectId\b",
        doc_regex=r"\bcontent-addressed\b|\bBLAKE3\b",
        reason="Deterministic IDs for integrity/audit.",
        tags=["integrity"],
        scopes=["cerberus/kernel/ledgerfs", "cerberus/crucibles/fs-cbl"],
    ),
    PatternSpec(
        name="Setup/Exec/Check test structure",
        code_regex=r"Setup:?|Exec:?|Check:?",
        doc_regex=r"\bSetup/Exec/Check\b|\btest structure\b",
        reason="Consistent test documentation and flow.",
        tags=["testing"],
        scopes=["tests", "cerberus"],
    ),
    PatternSpec(
        name="Capability gates",
        code_regex=r"\bAUDIT_CBL_CAP\b|\bCapabilityId\b",
        doc_regex=r"\bcapability\b|\bAUDIT_CBL_CAP\b",
        reason="Least-privilege capability enforcement.",
        tags=["capability", "security"],
        scopes=["cerberus/crucibles", "cerberus/kernel/forge"],
    ),
    PatternSpec(
        name="Batch IPC op codes",
        code_regex=r"\bBatch[A-Za-z]+|IPC\b",
        doc_regex=r"\bIPC\b|\bbatch ops\b",
        reason="Deterministic IPC batching patterns.",
        tags=["ipc", "performance"],
        scopes=["cerberus/crucibles/fs-cbl"],
    ),
    PatternSpec(
        name="Boot phase breadcrumbs",
        code_regex=r'console_write\(b"(INIT:[A-Z_]+)',
        doc_regex=r"INIT:START|INIT:TLS_OK|INIT:HEAP_OK|INIT:MANIFEST|INIT:ENGINE_RUN",
        reason="Boot sequence progress markers — if missing from serial, boot halted before this point.",
        tags=["boot", "debug", "serial"],
        scopes=["cerberus/kernel/forge-init", "cerberus/kernel/forge-boot"],
    ),
    PatternSpec(
        name="LedgerFS on-disk layout",
        code_regex=r"SUPERBLOCK_MAGIC|PART_TYPE_CERBERUS_LFS|0xC0|SECTORS_PER_BLOCK|BLOCK_SIZE",
        doc_regex=r"LedgerFS|superblock|partition.*0xC0|block.*4096",
        reason="LedgerFS disk format constants — needed for partition probing and superblock verification.",
        tags=["ledgerfs", "boot", "disk"],
        scopes=[
            "cerberus/kernel/forge-boot",
            "cerberus/kernel/ledgerfs",
            "cerberus/kernel/forge-builder",
        ],
    ),
    PatternSpec(
        name="Service lifecycle states",
        code_regex=r"ServiceStatus::(Idle|Starting|Running|Failed|Crashed|Unavailable)",
        doc_regex=r"service.*lifecycle|Idle.*Starting.*Running|forge-rc.*supervisor",
        reason="Service state machine transitions — diagnose why services aren't reaching Running.",
        tags=["services", "forge-rc", "lifecycle"],
        scopes=["cerberus/kernel/forge-rc", "cerberus/kernel/forge-init"],
    ),
    PatternSpec(
        name="Kernel syscall interface",
        code_regex=r"(?:process_create|process_yield|ipc_recv|ipc_send|console_write|file_open)\s*\(",
        doc_regex=r"syscall|ProcessCreate|IpcRecv|process_create",
        reason="Userspace → kernel syscall boundary.",
        tags=["syscall", "kernel", "ipc"],
        scopes=["cerberus/kernel"],
    ),
    PatternSpec(
        name="ATA PIO disk I/O",
        code_regex=r"ata_pio_read|ata_pio_write|port::inb|port::outb.*0x1F",
        doc_regex=r"ATA.*PIO|sector.*read|disk.*I/O",
        reason="Raw disk I/O — the only way the kernel reads LedgerFS before drivers are loaded.",
        tags=["disk", "ata", "boot", "hardware"],
        scopes=["cerberus/kernel/forge-boot", "cerberus/kernel/forge-drivers"],
    ),
    PatternSpec(
        name="MBR partition table",
        code_regex=r"MBR_PARTITION_TABLE_OFFSET|0x55AA|partition.*entry|PART_TYPE",
        doc_regex=r"MBR|partition.*table|boot.*signature",
        reason="MBR parsing — if partition probing fails, boot halts.",
        tags=["boot", "mbr", "partition"],
        scopes=["cerberus/kernel/forge-boot", "cerberus/kernel/forge-builder"],
    ),
    PatternSpec(
        name="ELF loading and process creation",
        code_regex=r"process_create\(|elf.*parse|elf.*load|\.elf\b",
        doc_regex=r"ELF.*binary|process.*create|spawn.*service",
        reason="How service binaries are loaded from disk into new processes.",
        tags=["elf", "process", "spawn"],
        scopes=[
            "cerberus/kernel/forge-init",
            "cerberus/kernel/forge-rc",
            "cerberus/kernel/forge-boot",
        ],
    ),
    PatternSpec(
        name="Serial port debug output",
        code_regex=r"SerialPort::new|serial_panic|sp\.init\(\)|writeln!\(sp",
        doc_regex=r"serial.*port|0x3F8|serial.*panic|serial.*debug",
        reason="Serial output is the primary debug channel.",
        tags=["debug", "serial", "boot"],
        scopes=["cerberus/kernel/forge-boot", "cerberus/kernel/forge-init"],
    ),
    PatternSpec(
        name="Forge-rc service manifest and boot order",
        code_regex=r"boot_order|build_manifest|register_from_rcf|set_spawner|ServiceEngine",
        doc_regex=r"manifest|boot.*order|service.*engine|forge-rc",
        reason="How services are registered and ordered for boot.",
        tags=["services", "manifest", "boot-order"],
        scopes=["cerberus/kernel/forge-rc", "cerberus/kernel/forge-init"],
    ),
    PatternSpec(
        name="Cryptographic verification (ML-DSA / SLH-DSA / BLAKE3)",
        code_regex=r"mldsa|slhdsa|ML-DSA|SLH-DSA|verify_root_seal|verify_signature|blake3::hash",
        doc_regex=r"ML-DSA|SLH-DSA|root.*seal|signature.*verification|post-quantum",
        reason="Cryptographic verification in the boot chain. Failure = halt (fail-closed).",
        tags=["crypto", "verification", "boot", "pqc"],
        scopes=["cerberus/kernel/forge-boot", "cerberus/runtime/temper", "cerberus/crypto"],
    ),
]
