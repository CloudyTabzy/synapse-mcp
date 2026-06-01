"""api_unicorn — Unicorn concrete CPU emulation engine for IDA Pro MCP.

Optional module: tools are only registered when ``unicorn`` is installed.
Install with: pip install unicorn  (or: ida-pro-mcp --install-deps unicorn)

Unicorn fills the gap that Triton and angr cannot close: deterministic
*concrete* execution of arbitrary binary code, at ~70M instructions/sec, with
no symbolic state explosion. It maps IDA's segments byte-for-byte into a QEMU-
backed emulator and runs real code at real addresses — decryption stubs,
obfuscation loops, VM dispatchers, hash routines — none of which symbolic
engines handle well.

Architecture (in-process, no subprocess worker — contrast api_angr.py):
  * ``Uc()`` is IDA-safe: installs no signal handlers, never forks, spawns no
    daemon threads, holds no cffi handles that must cross a process boundary.
  * A ``@idasync`` helper gathers all IDA-derived data (segment bytes, arch,
    entry point) ONCE up front as plain Python objects. After that the
    emulation loop touches no IDA API, so it runs off the main thread without
    racing the UI.
  * Wall-clock deadline is enforced by a ``threading.Timer`` that calls
    ``emu.emu_stop()`` (documented thread-safe). Combined with a hard
    ``max_insns`` cap on every tool, emulation can never run away.
  * No session cache: ``Uc()`` creation is ~1ms and segment mapping is linear
    in binary size, so each call starts fresh (no stale register/hook state).

Tool roster (14 tools + 1 always-registered probe):

  Infrastructure
    U.0  unicorn_status                  — availability probe (always registered)

  Core emulation
    U.1  unicorn_emulate                 — general-purpose IDA-segment emulation
    U.2  unicorn_trace                   — block/insn/full trace + loop detection
    U.5  unicorn_call_function           — concrete CC-aware function call

  Decryption / unpacking
    U.3  unicorn_emulate_and_patch  ⚠️   — decrypt stub → patch IDB
    U.4  unicorn_diff_memory             — before/after memory delta (read-only)
    U.10 workflow_unicorn_decrypt_analyze ⚠️ — emulate → patch → analyze → define

  Malware / advanced RE
    U.6  unicorn_emulate_shellcode       — raw bytes + syscall interception
    U.7  unicorn_recover_stackstrings    — stack-write interception → strings
    U.8  unicorn_find_memory_accesses    — record all R/W + hot-region detection
    U.9  unicorn_resolve_api_hash        — emulate hash routine vs WinAPI names

  Hybrid cross-engine
    H.1  hybrid_unicorn_triton_analyze   — concrete prefix → Triton symbolic suffix
    H.2  hybrid_unicorn_miasm_hot_blocks — exec trace → Miasm lifts hot blocks
    H.3  hybrid_unicorn_networkx_exec_graph — multi-trace → NetworkX graph analysis

The reverse-direction hybrid ``hybrid_angr_unicorn_concrete`` (Unicorn decrypts
→ angr loads the decrypted binary) lives in api_angr.py because angr is the
consumer that holds the Project state.

Implementation pattern (mirrors api_angr.py / api_triton.py): each tool is a
thin wrapper over a private ``_xxx_impl`` helper so workflow/hybrid tools can
call the impls directly without re-entering @idasync (which raises
IDASyncError on nested execute_sync).
"""
from __future__ import annotations

import logging
import math
import os
import threading
import time
from typing import Annotated, NotRequired, TypedDict

import idaapi
import idautils
import idc

from .rpc import tool, unsafe
from .sync import idasync, tool_timeout
from .utils import (
    parse_address,
    read_bytes_bss_safe,
    tool_error,
    normalize_list_input,
)

logger = logging.getLogger(__name__)

# ============================================================================
# Optional import guard
# ============================================================================

try:
    import unicorn as _uc
    from unicorn import (
        Uc,
        UcError,
        UC_ARCH_X86,
        UC_ARCH_ARM,
        UC_ARCH_ARM64,
        UC_ARCH_MIPS,
        UC_ARCH_SPARC,
        UC_MODE_32,
        UC_MODE_64,
        UC_MODE_ARM,
        UC_MODE_THUMB,
        UC_MODE_BIG_ENDIAN,
        UC_MODE_LITTLE_ENDIAN,
        UC_PROT_NONE,
        UC_PROT_READ,
        UC_PROT_WRITE,
        UC_PROT_EXEC,
        UC_PROT_ALL,
        UC_HOOK_CODE,
        UC_HOOK_BLOCK,
        UC_HOOK_MEM_READ,
        UC_HOOK_MEM_READ_AFTER,
        UC_HOOK_MEM_WRITE,
        UC_HOOK_MEM_INVALID,
        UC_HOOK_MEM_UNMAPPED,
        UC_HOOK_INSN,
        UC_HOOK_INTR,
        UC_MEM_WRITE,
        UC_MEM_READ,
        UC_MEM_READ_UNMAPPED,
        UC_MEM_WRITE_UNMAPPED,
        UC_MEM_FETCH_UNMAPPED,
        UC_SECOND_SCALE,
    )
    UNICORN_AVAILABLE = True
    _UC_VERSION = getattr(_uc, "__version__", "") or (
        "%d.%d" % _uc.uc_version()[:2] if hasattr(_uc, "uc_version") else "unknown")
except Exception:  # ImportError, or partial/old binding missing a constant
    _uc = None  # type: ignore[assignment]
    Uc = None  # type: ignore[assignment]
    UcError = Exception  # type: ignore[assignment,misc]
    UNICORN_AVAILABLE = False
    _UC_VERSION = ""
    logger.warning(
        "unicorn not installed — unicorn_* tools unavailable. "
        "Install with: pip install unicorn"
    )

# Cross-engine availability (probed lazily inside hybrid tools so this module
# never hard-depends on the other optional engines).
try:
    from .api_triton import TRITON_AVAILABLE as _TRITON_AVAILABLE
except Exception:
    _TRITON_AVAILABLE = False
try:
    from .api_miasm import MIASM_AVAILABLE as _MIASM_AVAILABLE
except Exception:
    _MIASM_AVAILABLE = False
try:
    from .api_networkx import NETWORKX_AVAILABLE as _NETWORKX_AVAILABLE
except Exception:
    _NETWORKX_AVAILABLE = False


# ============================================================================
# Tunables
# ============================================================================

# Page size for mem_map (Unicorn requires 4KB alignment).
_PAGE = 0x1000
# Default stack size mapped for emulation.
_DEFAULT_STACK_SIZE = 0x10000
# Default stack base per bitness — chosen above typical IDA load ranges.
_STACK_BASE_32 = 0x7FFE0000
_STACK_BASE_64 = 0x00007FFFFFFE0000
# A scratch region for shellcode args / hash-input strings.
_SCRATCH_SIZE = 0x4000
# Cap a single segment map (sanity guard against a corrupt segment table).
_MAX_SEGMENT_MAP = 256 * 1024 * 1024
# Cap total recorded events (writes / accesses / trace entries) per call so a
# pathological loop cannot exhaust memory before max_insns trips.
_MAX_EVENTS = 100_000
_MAX_TRACE = 50_000

# Built-in candidate list for unicorn_resolve_api_hash — the WinAPIs most
# commonly resolved by hash in shellcode/malware loaders, by module.
_COMMON_WINAPIS: tuple[tuple[str, str], ...] = (
    # kernel32 — loader / memory / process / thread
    ("LoadLibraryA", "kernel32.dll"), ("LoadLibraryW", "kernel32.dll"),
    ("LoadLibraryExA", "kernel32.dll"), ("LoadLibraryExW", "kernel32.dll"),
    ("GetProcAddress", "kernel32.dll"), ("GetModuleHandleA", "kernel32.dll"),
    ("GetModuleHandleW", "kernel32.dll"), ("GetModuleFileNameA", "kernel32.dll"),
    ("FreeLibrary", "kernel32.dll"), ("VirtualAlloc", "kernel32.dll"),
    ("VirtualAllocEx", "kernel32.dll"), ("VirtualFree", "kernel32.dll"),
    ("VirtualProtect", "kernel32.dll"), ("VirtualProtectEx", "kernel32.dll"),
    ("VirtualQuery", "kernel32.dll"), ("HeapAlloc", "kernel32.dll"),
    ("HeapCreate", "kernel32.dll"), ("HeapFree", "kernel32.dll"),
    ("GetProcessHeap", "kernel32.dll"), ("CreateThread", "kernel32.dll"),
    ("CreateRemoteThread", "kernel32.dll"), ("ResumeThread", "kernel32.dll"),
    ("SuspendThread", "kernel32.dll"), ("OpenThread", "kernel32.dll"),
    ("GetCurrentThreadId", "kernel32.dll"), ("GetCurrentProcess", "kernel32.dll"),
    ("GetCurrentProcessId", "kernel32.dll"), ("OpenProcess", "kernel32.dll"),
    ("CreateProcessA", "kernel32.dll"), ("CreateProcessW", "kernel32.dll"),
    ("TerminateProcess", "kernel32.dll"), ("ExitProcess", "kernel32.dll"),
    ("ExitThread", "kernel32.dll"), ("WriteProcessMemory", "kernel32.dll"),
    ("ReadProcessMemory", "kernel32.dll"), ("CreateFileA", "kernel32.dll"),
    ("CreateFileW", "kernel32.dll"), ("ReadFile", "kernel32.dll"),
    ("WriteFile", "kernel32.dll"), ("CloseHandle", "kernel32.dll"),
    ("SetFilePointer", "kernel32.dll"), ("GetFileSize", "kernel32.dll"),
    ("CreateFileMappingA", "kernel32.dll"), ("MapViewOfFile", "kernel32.dll"),
    ("UnmapViewOfFile", "kernel32.dll"), ("DeleteFileA", "kernel32.dll"),
    ("GetTempPathA", "kernel32.dll"), ("GetTickCount", "kernel32.dll"),
    ("Sleep", "kernel32.dll"), ("WaitForSingleObject", "kernel32.dll"),
    ("CreateMutexA", "kernel32.dll"), ("CreateEventA", "kernel32.dll"),
    ("GetLastError", "kernel32.dll"), ("SetLastError", "kernel32.dll"),
    ("IsDebuggerPresent", "kernel32.dll"),
    ("CheckRemoteDebuggerPresent", "kernel32.dll"),
    ("GetComputerNameA", "kernel32.dll"), ("GetSystemInfo", "kernel32.dll"),
    ("GetVersionExA", "kernel32.dll"), ("GetEnvironmentVariableA", "kernel32.dll"),
    ("WinExec", "kernel32.dll"), ("GetStartupInfoA", "kernel32.dll"),
    ("CreateToolhelp32Snapshot", "kernel32.dll"), ("Process32First", "kernel32.dll"),
    ("Process32Next", "kernel32.dll"), ("Module32First", "kernel32.dll"),
    ("Module32Next", "kernel32.dll"), ("OutputDebugStringA", "kernel32.dll"),
    ("GetThreadContext", "kernel32.dll"), ("SetThreadContext", "kernel32.dll"),
    ("FlushInstructionCache", "kernel32.dll"), ("LocalAlloc", "kernel32.dll"),
    ("GlobalAlloc", "kernel32.dll"), ("lstrcmpA", "kernel32.dll"),
    ("lstrlenA", "kernel32.dll"), ("lstrcatA", "kernel32.dll"),
    # ntdll — native API often used to bypass kernel32 hooks
    ("NtAllocateVirtualMemory", "ntdll.dll"), ("NtProtectVirtualMemory", "ntdll.dll"),
    ("NtWriteVirtualMemory", "ntdll.dll"), ("NtReadVirtualMemory", "ntdll.dll"),
    ("NtCreateThreadEx", "ntdll.dll"), ("NtQueueApcThread", "ntdll.dll"),
    ("NtQueryInformationProcess", "ntdll.dll"),
    ("NtSetInformationThread", "ntdll.dll"), ("RtlMoveMemory", "ntdll.dll"),
    ("LdrLoadDll", "ntdll.dll"), ("LdrGetProcedureAddress", "ntdll.dll"),
    # user32
    ("MessageBoxA", "user32.dll"), ("MessageBoxW", "user32.dll"),
    ("GetForegroundWindow", "user32.dll"), ("FindWindowA", "user32.dll"),
    ("wsprintfA", "user32.dll"), ("GetAsyncKeyState", "user32.dll"),
    ("SetWindowsHookExA", "user32.dll"), ("GetKeyState", "user32.dll"),
    # advapi32 — registry / service / crypto / token
    ("RegOpenKeyExA", "advapi32.dll"), ("RegOpenKeyExW", "advapi32.dll"),
    ("RegSetValueExA", "advapi32.dll"), ("RegQueryValueExA", "advapi32.dll"),
    ("RegCreateKeyExA", "advapi32.dll"), ("RegCloseKey", "advapi32.dll"),
    ("RegDeleteKeyA", "advapi32.dll"), ("OpenProcessToken", "advapi32.dll"),
    ("AdjustTokenPrivileges", "advapi32.dll"), ("LookupPrivilegeValueA", "advapi32.dll"),
    ("CreateServiceA", "advapi32.dll"), ("OpenSCManagerA", "advapi32.dll"),
    ("StartServiceA", "advapi32.dll"), ("CryptAcquireContextA", "advapi32.dll"),
    ("CryptCreateHash", "advapi32.dll"), ("CryptHashData", "advapi32.dll"),
    ("CryptDeriveKey", "advapi32.dll"), ("CryptDecrypt", "advapi32.dll"),
    ("CryptEncrypt", "advapi32.dll"),
    # ws2_32 — networking
    ("WSAStartup", "ws2_32.dll"), ("WSASocketA", "ws2_32.dll"),
    ("socket", "ws2_32.dll"), ("connect", "ws2_32.dll"), ("send", "ws2_32.dll"),
    ("recv", "ws2_32.dll"), ("bind", "ws2_32.dll"), ("listen", "ws2_32.dll"),
    ("accept", "ws2_32.dll"), ("closesocket", "ws2_32.dll"),
    ("inet_addr", "ws2_32.dll"), ("gethostbyname", "ws2_32.dll"),
    ("htons", "ws2_32.dll"), ("WSACleanup", "ws2_32.dll"),
    # wininet / urlmon — staging
    ("InternetOpenA", "wininet.dll"), ("InternetOpenUrlA", "wininet.dll"),
    ("InternetConnectA", "wininet.dll"), ("HttpOpenRequestA", "wininet.dll"),
    ("HttpSendRequestA", "wininet.dll"), ("InternetReadFile", "wininet.dll"),
    ("URLDownloadToFileA", "urlmon.dll"),
)


# ============================================================================
# TypedDict result types
# ============================================================================


class UnicornStatusResult(TypedDict, total=False):
    ok: bool
    available: bool
    version: str
    archs: list[str]
    input_file: str
    detected_arch: str
    ida_segments: int
    total_mapped_bytes: int
    cross_engines: dict
    hint: str
    error: str


class UnicornMemWrite(TypedDict, total=False):
    addr: str
    size: int
    value: str
    hex: str
    repeat: int  # present when consecutive identical writes were collapsed


class UnicornEmulateResult(TypedDict, total=False):
    ok: bool
    insns_executed: int
    stop_reason: str
    regs: dict
    memory_writes: list[UnicornMemWrite]
    unmapped_accesses: list[dict]
    note: str
    error: str
    error_type: str


class UnicornTraceEntry(TypedDict, total=False):
    addr: str
    size: int
    mnemonic: str
    op_str: str
    regs: dict


class UnicornTraceResult(TypedDict, total=False):
    ok: bool
    trace: list[UnicornTraceEntry]
    insns_executed: int
    unique_addrs: int
    loops_detected: list[dict]
    stop_reason: str
    note: str
    error: str


class UnicornPatchResult(TypedDict, total=False):
    ok: bool
    bytes_patched: int
    insns_executed: int
    patch_start: str
    patch_hex_preview: str
    entropy_before: float
    entropy_after: float
    entropy_delta: float
    functions_created: int
    stop_reason: str
    note: str
    error: str


class UnicornDiffResult(TypedDict, total=False):
    ok: bool
    changed_regions: list[dict]
    unchanged_regions: list[dict]
    total_changed_bytes: int
    insns_executed: int
    note: str
    error: str


class UnicornCallResult(TypedDict, total=False):
    ok: bool
    return_value: str
    return_value_bytes: str
    regs: dict
    insns_executed: int
    stop_reason: str
    memory_writes: list[UnicornMemWrite]
    note: str
    error: str


class UnicornShellcodeResult(TypedDict, total=False):
    ok: bool
    syscalls: list[dict]
    strings_extracted: list[str]
    files_accessed: list[str]
    network_targets: list[str]
    processes_spawned: list[str]
    insns_executed: int
    stop_reason: str
    note: str
    error: str


class UnicornStackstringsResult(TypedDict, total=False):
    ok: bool
    strings: list[dict]
    stack_write_count: int
    bytes_written_to_stack: int
    insns_executed: int
    note: str
    error: str


class UnicornMemAccessResult(TypedDict, total=False):
    ok: bool
    accesses: list[dict]
    read_count: int
    write_count: int
    hot_regions: list[dict]
    insns_executed: int
    note: str
    error: str


class UnicornHashResult(TypedDict, total=False):
    ok: bool
    results: list[dict]
    tested: int
    resolved: int
    elapsed_ms: int
    unmatched_known_hashes: list[str]
    note: str
    error: str


class UnicornWorkflowResult(TypedDict, total=False):
    ok: bool
    steps: list[dict]
    total_functions_created: int
    entropy_delta: float
    elapsed_ms: int
    note: str
    error: str


class HybridUnicornTritonResult(TypedDict, total=False):
    ok: bool
    concrete_phase: dict
    symbolic_phase: dict
    engines_used: list[str]
    note: str
    error: str


class HybridUnicornMiasmResult(TypedDict, total=False):
    ok: bool
    total_blocks_executed: int
    unique_blocks_executed: int
    hot_blocks_lifted: int
    blocks: list[dict]
    deobfuscation_summary: str
    note: str
    error: str


class HybridUnicornNxResult(TypedDict, total=False):
    ok: bool
    nodes: int
    edges: int
    iterations_run: int
    bottleneck_nodes: list[dict]
    loops: list[dict]
    dispatcher_candidates: list[str]
    dead_blocks: list[str]
    note: str
    error: str


# ============================================================================
# Arch / register mapping  (IDA → Unicorn)
# ============================================================================

# (procname-prefix, uc_arch, mode32, mode64). Mode is OR-ed with endianness.
_UC_ARCH_PATTERNS: tuple = ()


def _build_uc_arch_patterns() -> tuple:
    """Built lazily so the module imports even when unicorn is absent."""
    if not UNICORN_AVAILABLE:
        return ()
    return (
        ("metapc",  UC_ARCH_X86,   UC_MODE_32,  UC_MODE_64),
        ("80",      UC_ARCH_X86,   UC_MODE_32,  UC_MODE_64),
        ("x86",     UC_ARCH_X86,   UC_MODE_32,  UC_MODE_64),
        ("i386",    UC_ARCH_X86,   UC_MODE_32,  UC_MODE_64),
        ("i486",    UC_ARCH_X86,   UC_MODE_32,  UC_MODE_64),
        ("i586",    UC_ARCH_X86,   UC_MODE_32,  UC_MODE_64),
        ("i686",    UC_ARCH_X86,   UC_MODE_32,  UC_MODE_64),
        ("ia",      UC_ARCH_X86,   UC_MODE_32,  UC_MODE_64),
        ("aarch64", UC_ARCH_ARM64, UC_MODE_ARM, UC_MODE_ARM),
        ("arm64",   UC_ARCH_ARM64, UC_MODE_ARM, UC_MODE_ARM),
        ("arm",     UC_ARCH_ARM,   UC_MODE_ARM, UC_MODE_ARM),
        ("mips",    UC_ARCH_MIPS,  UC_MODE_32,  UC_MODE_64),
        ("sparc",   UC_ARCH_SPARC, UC_MODE_32,  UC_MODE_32),
    )


def _detect_uc_arch() -> tuple[int, int, int]:
    """Return (uc_arch, uc_mode, bits) for the loaded IDB.

    Mode already incorporates endianness. Falls back to x86 of the detected
    bitness if the procname is unrecognised.
    """
    patterns = _build_uc_arch_patterns()
    try:
        procname = idaapi.inf_get_procname().lower()
    except Exception:
        try:
            procname = idaapi.get_inf_structure().procname.lower()
        except Exception:
            procname = "metapc"

    try:
        is_64 = bool(idaapi.inf_is_64bit())
    except Exception:
        try:
            is_64 = bool(idaapi.get_inf_structure().is_64bit())
        except Exception:
            is_64 = False

    try:
        is_be = bool(idaapi.inf_is_be())
    except Exception:
        is_be = False

    bits = 64 if is_64 else 32
    uc_arch, uc_mode = UC_ARCH_X86, (UC_MODE_64 if is_64 else UC_MODE_32)
    for prefix, arch, m32, m64 in patterns:
        if procname.startswith(prefix):
            uc_arch = arch
            uc_mode = m64 if is_64 else m32
            break

    # x86 is little-endian only in Unicorn; endianness flag applies to the
    # RISC families (ARM/MIPS/SPARC/PPC).
    if uc_arch != UC_ARCH_X86:
        uc_mode |= (UC_MODE_BIG_ENDIAN if is_be else UC_MODE_LITTLE_ENDIAN)
    return (uc_arch, uc_mode, bits)


# Lazily-populated per-arch register-name → UC_*_REG_* maps.
_REG_MAPS: dict = {}


def _register_map(uc_arch: int, uc_mode: int) -> dict:
    """Return {lowercase_reg_name: UC_*_REG_* constant} for the arch."""
    key = (uc_arch, uc_mode & (UC_MODE_64 if UNICORN_AVAILABLE else 0))
    cached = _REG_MAPS.get(key)
    if cached is not None:
        return cached

    m: dict = {}
    if uc_arch == UC_ARCH_X86:
        from unicorn import x86_const as c
        is64 = bool(uc_mode & UC_MODE_64)
        common32 = {
            "eax": c.UC_X86_REG_EAX, "ebx": c.UC_X86_REG_EBX,
            "ecx": c.UC_X86_REG_ECX, "edx": c.UC_X86_REG_EDX,
            "esi": c.UC_X86_REG_ESI, "edi": c.UC_X86_REG_EDI,
            "esp": c.UC_X86_REG_ESP, "ebp": c.UC_X86_REG_EBP,
            "eip": c.UC_X86_REG_EIP, "eflags": c.UC_X86_REG_EFLAGS,
        }
        m.update(common32)
        if is64:
            m.update({
                "rax": c.UC_X86_REG_RAX, "rbx": c.UC_X86_REG_RBX,
                "rcx": c.UC_X86_REG_RCX, "rdx": c.UC_X86_REG_RDX,
                "rsi": c.UC_X86_REG_RSI, "rdi": c.UC_X86_REG_RDI,
                "rsp": c.UC_X86_REG_RSP, "rbp": c.UC_X86_REG_RBP,
                "rip": c.UC_X86_REG_RIP, "rflags": c.UC_X86_REG_EFLAGS,
                "r8": c.UC_X86_REG_R8, "r9": c.UC_X86_REG_R9,
                "r10": c.UC_X86_REG_R10, "r11": c.UC_X86_REG_R11,
                "r12": c.UC_X86_REG_R12, "r13": c.UC_X86_REG_R13,
                "r14": c.UC_X86_REG_R14, "r15": c.UC_X86_REG_R15,
            })
    elif uc_arch == UC_ARCH_ARM:
        from unicorn import arm_const as c
        for i in range(13):
            m["r%d" % i] = getattr(c, "UC_ARM_REG_R%d" % i)
        m.update({
            "sp": c.UC_ARM_REG_SP, "lr": c.UC_ARM_REG_LR,
            "pc": c.UC_ARM_REG_PC, "cpsr": c.UC_ARM_REG_CPSR,
            "r13": c.UC_ARM_REG_SP, "r14": c.UC_ARM_REG_LR,
            "r15": c.UC_ARM_REG_PC,
        })
    elif uc_arch == UC_ARCH_ARM64:
        from unicorn import arm64_const as c
        for i in range(29):
            m["x%d" % i] = getattr(c, "UC_ARM64_REG_X%d" % i)
        for i in range(29):
            wname = "UC_ARM64_REG_W%d" % i
            if hasattr(c, wname):
                m["w%d" % i] = getattr(c, wname)
        m.update({
            "sp": c.UC_ARM64_REG_SP, "lr": c.UC_ARM64_REG_LR,
            "pc": c.UC_ARM64_REG_PC,
        })
    elif uc_arch == UC_ARCH_MIPS:
        from unicorn import mips_const as c
        m.update({
            "pc": c.UC_MIPS_REG_PC, "sp": c.UC_MIPS_REG_SP,
            "ra": c.UC_MIPS_REG_RA,
        })
        for i in range(32):
            rname = "UC_MIPS_REG_%d" % i
            if hasattr(c, rname):
                m["$%d" % i] = getattr(c, rname)

    _REG_MAPS[key] = m
    return m


def _pc_reg_name(uc_arch: int, uc_mode: int) -> str:
    if uc_arch == UC_ARCH_X86:
        return "rip" if (uc_mode & UC_MODE_64) else "eip"
    return "pc"


def _sp_reg_name(uc_arch: int, uc_mode: int) -> str:
    if uc_arch == UC_ARCH_X86:
        return "rsp" if (uc_mode & UC_MODE_64) else "esp"
    return "sp"


def _ret_reg_name(uc_arch: int, uc_mode: int) -> str:
    """Return-value register name for the arch."""
    if uc_arch == UC_ARCH_X86:
        return "rax" if (uc_mode & UC_MODE_64) else "eax"
    if uc_arch == UC_ARCH_ARM64:
        return "x0"
    if uc_arch == UC_ARCH_ARM:
        return "r0"
    return "pc"


def _result_reg_names(uc_arch: int, uc_mode: int) -> list[str]:
    """Registers to read back into the result dict."""
    if uc_arch == UC_ARCH_X86:
        if uc_mode & UC_MODE_64:
            return ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp",
                    "rip", "r8", "r9", "r10", "r11", "r12", "r13", "r14",
                    "r15", "rflags"]
        return ["eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp",
                "eip", "eflags"]
    if uc_arch == UC_ARCH_ARM64:
        return ["x%d" % i for i in range(8)] + ["sp", "lr", "pc"]
    if uc_arch == UC_ARCH_ARM:
        return ["r%d" % i for i in range(13)] + ["sp", "lr", "pc", "cpsr"]
    if uc_arch == UC_ARCH_MIPS:
        return ["pc", "sp", "ra"]
    return []


# ============================================================================
# IDA data gathering — the ONLY part that touches the IDA SDK.
# Runs once per tool call on the main thread; everything else is pure Python.
# ============================================================================


def _ida_seg_perm_to_uc(perm: int) -> int:
    """Map IDA SEGPERM_* flags to Unicorn UC_PROT_* flags.

    Unknown/zero permission grants UC_PROT_ALL so legitimate accesses to a
    mislabelled segment don't raise spurious protection faults.
    """
    if not perm:
        return UC_PROT_ALL
    prot = UC_PROT_NONE
    if perm & idaapi.SEGPERM_READ:
        prot |= UC_PROT_READ
    if perm & idaapi.SEGPERM_WRITE:
        prot |= UC_PROT_WRITE
    if perm & idaapi.SEGPERM_EXEC:
        prot |= UC_PROT_EXEC
    return prot or UC_PROT_ALL


def _gather_ida_segments_internal() -> list[dict]:
    """Raw segment gather — assumes it is already on the IDA main thread.

    Returns one dict per segment: {start, size, perms (uc), data: bytes, name}.
    BSS / uninitialised bytes are read as zeros via read_bytes_bss_safe.
    """
    out: list[dict] = []
    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if seg is None:
            continue
        start = int(seg.start_ea)
        size = int(seg.end_ea - seg.start_ea)
        if size <= 0 or size > _MAX_SEGMENT_MAP:
            if size > _MAX_SEGMENT_MAP:
                logger.warning("unicorn: skipping oversized segment at 0x%x (%d bytes)",
                               start, size)
            continue
        try:
            name = idaapi.get_segm_name(seg) or ""
        except Exception:
            name = ""
        data = read_bytes_bss_safe(start, size)
        out.append({
            "start": start,
            "size": size,
            "perms": _ida_seg_perm_to_uc(seg.perm),
            "data": data,
            "name": name,
        })
    return out


def _seg_for_addr(segments: list[dict], addr: int) -> dict | None:
    for s in segments:
        if s["start"] <= addr < s["start"] + s["size"]:
            return s
    return None


def _label_for_addr(segments: list[dict], addr: int) -> str:
    s = _seg_for_addr(segments, addr)
    return s["name"] if s else ""


# ============================================================================
# Entropy / string extraction (pure, no IDA)
# ============================================================================


def _shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits/byte (0.0–8.0). 0 for empty input."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return round(ent, 3)


def _extract_ascii_strings(data: bytes, min_len: int = 4) -> list[str]:
    out: list[str] = []
    cur = bytearray()
    for b in data:
        if 0x20 <= b <= 0x7E:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append(cur.decode("ascii", "replace"))
            cur = bytearray()
    if len(cur) >= min_len:
        out.append(cur.decode("ascii", "replace"))
    return out


def _extract_utf16le_strings(data: bytes, min_len: int = 4) -> list[str]:
    out: list[str] = []
    cur = bytearray()
    i = 0
    n = len(data)
    while i + 1 < n:
        lo, hi = data[i], data[i + 1]
        if hi == 0x00 and 0x20 <= lo <= 0x7E:
            cur.append(lo)
            i += 2
        else:
            if len(cur) >= min_len:
                out.append(cur.decode("ascii", "replace"))
            cur = bytearray()
            i += 1
    if len(cur) >= min_len:
        out.append(cur.decode("ascii", "replace"))
    return out


def _hex_preview(data: bytes, n: int = 32) -> str:
    return " ".join("%02x" % b for b in data[:n])


# ============================================================================
# Page alignment + segment mapping
# ============================================================================


def _align_down(addr: int) -> int:
    return addr & ~(_PAGE - 1)


def _align_up(addr: int) -> int:
    return (addr + _PAGE - 1) & ~(_PAGE - 1)


def _merge_page_regions(segments: list[dict]) -> list[dict]:
    """Coalesce segments into non-overlapping page-aligned map regions.

    Two IDA segments often share a page (e.g. .text ending mid-page where
    .rodata begins). Mapping each independently raises UC_ERR_MAP, so we merge
    them into one region, OR-ing permissions, before mem_map().
    Returns [{base, size, perms}] sorted by base.
    """
    if not segments:
        return []
    regions = []
    for s in sorted(segments, key=lambda x: x["start"]):
        lo = _align_down(s["start"])
        hi = _align_up(s["start"] + s["size"])
        perms = s["perms"]
        if regions and lo <= regions[-1]["base"] + regions[-1]["size"]:
            prev = regions[-1]
            new_hi = max(prev["base"] + prev["size"], hi)
            prev["size"] = new_hi - prev["base"]
            prev["perms"] |= perms
        else:
            regions.append({"base": lo, "size": hi - lo, "perms": perms})
    return regions


def _map_segments(emu, segments: list[dict]) -> list[dict]:
    """Map all IDA segments into the emulator. Returns the mapped regions."""
    regions = _merge_page_regions(segments)
    for r in regions:
        emu.mem_map(r["base"], r["size"], r["perms"])
    # Write the real bytes on top of the zero-filled pages.
    for s in segments:
        if s["data"]:
            emu.mem_write(s["start"], s["data"])
    return regions


def _choose_stack_base(segments: list[dict], bits: int, size: int) -> int:
    """Pick a stack base that does not collide with any mapped segment."""
    base = _STACK_BASE_64 if bits == 64 else _STACK_BASE_32
    regions = _merge_page_regions(segments)

    def collides(b: int) -> bool:
        lo, hi = b, b + size
        for r in regions:
            if not (hi <= r["base"] or lo >= r["base"] + r["size"]):
                return True
        return False

    tries = 0
    while collides(base) and tries < 64:
        base -= 0x100000
        if base < _PAGE:
            base = (_STACK_BASE_64 if bits == 64 else _STACK_BASE_32) + 0x1000000
        tries += 1
    return _align_down(base)


def _map_stack(emu, segments: list[dict], bits: int,
               size: int = _DEFAULT_STACK_SIZE) -> tuple[int, int]:
    """Map a dedicated stack region. Returns (stack_base, initial_sp)."""
    size = _align_up(max(size, _PAGE))
    base = _choose_stack_base(segments, bits, size)
    emu.mem_map(base, size, UC_PROT_READ | UC_PROT_WRITE)
    initial_sp = base + size - 0x100  # leave headroom for canary/alignment
    return base, initial_sp


# ============================================================================
# Register set / read
# ============================================================================


def _parse_reg_value(v) -> int:
    if isinstance(v, int):
        return v
    s = str(v).strip()
    if not s:
        return 0
    try:
        return int(s, 0)
    except ValueError:
        return int(s, 16)


def _set_regs(emu, reg_map: dict, regs: dict | None) -> list[str]:
    """Write a {name: value} dict into emulator registers.

    Returns the list of register names that could not be resolved (ignored).
    """
    unknown: list[str] = []
    if not regs:
        return unknown
    for name, val in regs.items():
        key = str(name).strip().lower()
        uc_reg = reg_map.get(key)
        if uc_reg is None:
            unknown.append(name)
            continue
        try:
            emu.reg_write(uc_reg, _parse_reg_value(val))
        except Exception:
            unknown.append(name)
    return unknown


def _read_regs(emu, reg_map: dict, names: list[str]) -> dict:
    out: dict = {}
    for name in names:
        uc_reg = reg_map.get(name.lower())
        if uc_reg is None:
            continue
        try:
            out[name] = hex(emu.reg_read(uc_reg))
        except Exception:
            pass
    return out


# ============================================================================
# Core emulation runner — deadline-enforced, off the IDA main thread.
# ============================================================================


class _EmuController:
    """Bundles a Uc instance with the bookkeeping shared by every tool.

    Records memory writes, unmapped accesses, and instruction count. Auto-maps
    zero pages on invalid access so a single stray read can't abort a whole
    decryption run. Owns the wall-clock deadline timer.
    """

    def __init__(self, segments: list[dict], uc_arch: int, uc_mode: int, bits: int):
        self.segments = segments
        self.uc_arch = uc_arch
        self.uc_mode = uc_mode
        self.bits = bits
        self.emu = Uc(uc_arch, uc_mode)
        self.reg_map = _register_map(uc_arch, uc_mode)
        self.regions = _map_segments(self.emu, segments)
        self.mapped_pages: set[int] = set()
        for r in self.regions:
            for p in range(r["base"], r["base"] + r["size"], _PAGE):
                self.mapped_pages.add(p)

        self.insn_count = 0
        self.memory_writes: list[dict] = []
        self.unmapped: list[dict] = []
        self.stop_reason = "running"
        self._max_insns = 0
        self._stack_base = 0
        self._stack_top = 0
        self._timer: threading.Timer | None = None

    # -- stack -----------------------------------------------------------
    def setup_stack(self, size: int = _DEFAULT_STACK_SIZE) -> int:
        self._stack_base, sp = _map_stack(self.emu, self.segments, self.bits, size)
        self._stack_top = self._stack_base + _align_up(max(size, _PAGE))
        sp_reg = self.reg_map.get(_sp_reg_name(self.uc_arch, self.uc_mode))
        if sp_reg is not None:
            self.emu.reg_write(sp_reg, sp)
        return sp

    @property
    def stack_range(self) -> tuple[int, int]:
        return (self._stack_base, self._stack_top)

    def ensure_mapped(self, addr: int, size: int = _PAGE) -> None:
        """Map zero pages covering [addr, addr+size) if not already mapped."""
        lo = _align_down(addr)
        hi = _align_up(addr + size)
        for p in range(lo, hi, _PAGE):
            if p not in self.mapped_pages:
                try:
                    self.emu.mem_map(p, _PAGE, UC_PROT_ALL)
                    self.mapped_pages.add(p)
                except UcError:
                    pass

    # -- hooks -----------------------------------------------------------
    def install_default_hooks(self, record_writes: bool = True) -> None:
        self.emu.hook_add(UC_HOOK_MEM_INVALID, self._hook_mem_invalid)
        if record_writes:
            self.emu.hook_add(UC_HOOK_MEM_WRITE, self._hook_mem_write)

    def _hook_mem_invalid(self, uc, access, address, size, value, user_data):
        # Auto-map a zero page and continue; record the fault for the agent.
        if len(self.unmapped) < _MAX_EVENTS:
            self.unmapped.append({
                "addr": hex(address),
                "access": ("write" if access in (UC_MEM_WRITE_UNMAPPED,)
                           else "fetch" if access == UC_MEM_FETCH_UNMAPPED
                           else "read"),
                "size": size,
            })
        self.ensure_mapped(address, size)
        return True  # retry the access

    def _hook_mem_write(self, uc, access, address, size, value, user_data):
        if len(self.memory_writes) < _MAX_EVENTS:
            try:
                raw = int(value).to_bytes(size, "little", signed=False)
            except (OverflowError, ValueError):
                raw = b""
            self.memory_writes.append({
                "addr": hex(address),
                "size": size,
                "value": hex(value & ((1 << (size * 8)) - 1)),
                "hex": " ".join("%02x" % b for b in raw),
            })

    def count_hook(self, uc, address, size, user_data):
        self.insn_count += 1

    # -- run -------------------------------------------------------------
    def run(self, start: int, end: int, max_insns: int, timeout_ms: int) -> str:
        """Run emu_start with a wall-clock deadline. Returns stop_reason."""
        self._max_insns = max_insns
        timed_out = {"v": False}

        def _kill():
            timed_out["v"] = True
            try:
                self.emu.emu_stop()
            except Exception:
                pass

        if timeout_ms and timeout_ms > 0:
            self._timer = threading.Timer(timeout_ms / 1000.0, _kill)
            self._timer.daemon = True
            self._timer.start()

        try:
            # count=max_insns enforces the hard instruction cap inside Unicorn;
            # timeout in us is a secondary native guard alongside our timer.
            uc_timeout_us = (timeout_ms * 1000) if timeout_ms and timeout_ms > 0 else 0
            self.emu.emu_start(start, end, timeout=uc_timeout_us,
                               count=max_insns if max_insns > 0 else 0)
            if timed_out["v"]:
                self.stop_reason = "timeout"
            elif max_insns > 0 and self.insn_count >= max_insns:
                self.stop_reason = "max_insns"
            else:
                self.stop_reason = "end_address_reached"
        except UcError as e:
            if timed_out["v"]:
                self.stop_reason = "timeout"
            else:
                self.stop_reason = "error: %s" % e
        finally:
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None
        return self.stop_reason


def _emulate_impl(
    segments: list[dict],
    uc_arch: int,
    uc_mode: int,
    bits: int,
    start: int,
    end: int,
    regs: dict | None,
    stack_size: int,
    max_insns: int,
    timeout_ms: int,
    bypass_antidebug: bool = False,
) -> dict:
    """Pure-Python emulation core. No IDA calls. Used by U.1 and reused widely."""
    ctl = _EmuController(segments, uc_arch, uc_mode, bits)
    ctl.setup_stack(stack_size)
    ctl.install_default_hooks(record_writes=True)
    ctl.emu.hook_add(UC_HOOK_CODE, ctl.count_hook)
    if bypass_antidebug:
        _install_antidebug_hooks(ctl)
    _set_regs(ctl.emu, ctl.reg_map, regs)

    stop = ctl.run(start, end, max_insns, timeout_ms)
    out_regs = _read_regs(ctl.emu, ctl.reg_map, _result_reg_names(uc_arch, uc_mode))
    return {
        "ok": True,
        "insns_executed": ctl.insn_count,
        "stop_reason": stop,
        "regs": out_regs,
        "memory_writes": ctl.memory_writes,
        "unmapped_accesses": ctl.unmapped,
        "_controller": ctl,  # internal: callers may read emulator memory
    }


def _install_antidebug_hooks(ctl: "_EmuController") -> None:
    """Best-effort anti-(debug|emulation) neutralisation for x86 targets.

    Handles RDTSC (returns a small monotonic counter) and CPUID (clears the
    hypervisor-present bit, ECX[31]). Both instructions are emulated by the
    hook and then skipped by advancing the program counter past them, so the
    deterministic values we wrote are not overwritten by native execution.
    CALL-based API checks (IsDebuggerPresent etc.) are out of scope — those
    need an import table, which raw emulation lacks.
    """
    if ctl.uc_arch != UC_ARCH_X86:
        return
    from unicorn import x86_const as c

    is64 = bool(ctl.uc_mode & UC_MODE_64)
    rax = c.UC_X86_REG_RAX if is64 else c.UC_X86_REG_EAX
    rbx = c.UC_X86_REG_RBX if is64 else c.UC_X86_REG_EBX
    rcx = c.UC_X86_REG_RCX if is64 else c.UC_X86_REG_ECX
    rdx = c.UC_X86_REG_RDX if is64 else c.UC_X86_REG_EDX
    rip = c.UC_X86_REG_RIP if is64 else c.UC_X86_REG_EIP
    state = {"tsc": 0x1000}

    def _hook_code(uc, address, size, user_data):
        try:
            opc = bytes(uc.mem_read(address, min(size, 2)))
        except Exception:
            return
        if opc[:2] == b"\x0f\x31":  # RDTSC
            state["tsc"] += 0x100
            uc.reg_write(rax, state["tsc"] & 0xFFFFFFFF)
            uc.reg_write(rdx, (state["tsc"] >> 32) & 0xFFFFFFFF)
            uc.reg_write(rip, address + size)  # skip the instruction
        elif opc[:2] == b"\x0f\xa2":  # CPUID
            leaf = uc.reg_read(rax) & 0xFFFFFFFF
            if leaf == 1:
                # Generic Intel feature bits; clear hypervisor-present (ECX[31]).
                uc.reg_write(rax, 0x000006FB)
                uc.reg_write(rbx, 0)
                uc.reg_write(rcx, 0)  # hypervisor bit cleared
                uc.reg_write(rdx, 0x078BFBFF)
            else:
                uc.reg_write(rax, 0)
                uc.reg_write(rbx, 0)
                uc.reg_write(rcx, 0)
                uc.reg_write(rdx, 0)
            uc.reg_write(rip, address + size)  # skip the instruction

    ctl.emu.hook_add(UC_HOOK_CODE, _hook_code)


# ============================================================================
# Capstone (optional) — used only to annotate "full" traces with mnemonics.
# ============================================================================

_CS_CACHE: dict = {}


def _get_capstone(uc_arch: int, uc_mode: int):
    """Return a configured Capstone disassembler, or None if unavailable."""
    key = (uc_arch, uc_mode & (UC_MODE_64 if UNICORN_AVAILABLE else 0))
    if key in _CS_CACHE:
        return _CS_CACHE[key]
    md = None
    try:
        import capstone as _cs
        if uc_arch == UC_ARCH_X86:
            mode = _cs.CS_MODE_64 if (uc_mode & UC_MODE_64) else _cs.CS_MODE_32
            md = _cs.Cs(_cs.CS_ARCH_X86, mode)
        elif uc_arch == UC_ARCH_ARM64:
            md = _cs.Cs(_cs.CS_ARCH_ARM64, _cs.CS_MODE_ARM)
        elif uc_arch == UC_ARCH_ARM:
            md = _cs.Cs(_cs.CS_ARCH_ARM, _cs.CS_MODE_ARM)
        elif uc_arch == UC_ARCH_MIPS:
            mode = _cs.CS_MODE_64 if (uc_mode & UC_MODE_64) else _cs.CS_MODE_32
            md = _cs.Cs(_cs.CS_ARCH_MIPS, mode)
        if md is not None:
            md.detail = False
    except Exception:
        md = None
    _CS_CACHE[key] = md
    return md


# ============================================================================
# U.0 — unicorn_status (always registered)
# ============================================================================


@tool
@idasync
def unicorn_status() -> UnicornStatusResult:
    """Probe Unicorn availability and the current binary's emulation readiness.

    Always registered regardless of whether unicorn is installed. Reports the
    detected architecture and how many IDA segments would be mapped, so an
    agent knows up front what an emulation call will cover.
    """
    if not UNICORN_AVAILABLE:
        return {
            "ok": True,
            "available": False,
            "version": "",
            "hint": "Install with: pip install unicorn  (or --install-deps unicorn)",
        }

    archs = ["x86", "arm", "arm64", "mips", "sparc"]
    try:
        uc_arch, uc_mode, bits = _detect_uc_arch()
        if uc_arch == UC_ARCH_X86:
            detected = "x86_64" if bits == 64 else "x86"
        elif uc_arch == UC_ARCH_ARM64:
            detected = "aarch64"
        elif uc_arch == UC_ARCH_ARM:
            detected = "arm"
        elif uc_arch == UC_ARCH_MIPS:
            detected = "mips64" if bits == 64 else "mips32"
        else:
            detected = "unknown"
    except Exception:
        detected = "unknown"

    seg_count = 0
    total = 0
    try:
        for seg_ea in idautils.Segments():
            seg = idaapi.getseg(seg_ea)
            if seg is None:
                continue
            seg_count += 1
            total += int(seg.end_ea - seg.start_ea)
    except Exception:
        pass

    try:
        input_file = idaapi.get_input_file_path() or ""
    except Exception:
        input_file = ""

    return {
        "ok": True,
        "available": True,
        "version": _UC_VERSION,
        "archs": archs,
        "input_file": input_file,
        "detected_arch": detected,
        "ida_segments": seg_count,
        "total_mapped_bytes": total,
        "cross_engines": {
            "triton": bool(_TRITON_AVAILABLE),
            "miasm": bool(_MIASM_AVAILABLE),
            "networkx": bool(_NETWORKX_AVAILABLE),
            "capstone": _get_capstone(UC_ARCH_X86, UC_MODE_64) is not None,
        },
        "hint": "Run unicorn_emulate to test concrete emulation of the current IDB",
    }


# ============================================================================
# Memory-write post-processing — pure Python, no IDA.
# ============================================================================


def _compress_mem_writes(
    writes: list[dict],
    filter_range: tuple[int, int] | None = None,
) -> list[dict]:
    """Run-length compress consecutive identical writes; optionally filter by range.

    Consecutive writes to the same addr+size+value are collapsed into one entry
    with a ``repeat`` field. This eliminates the common CRT zero-init pattern
    (hundreds of identical 1-byte 0x00 writes to 0x0) that makes raw output
    unreadable for agents.

    filter_range=(lo, hi): keep only writes where lo <= addr < hi.
    """
    if not writes:
        return writes
    if filter_range is not None:
        lo, hi = filter_range
        writes = [w for w in writes if lo <= int(w["addr"], 16) < hi]
    if not writes:
        return writes
    out: list[dict] = []
    i = 0
    while i < len(writes):
        w = writes[i]
        j = i + 1
        while (j < len(writes) and
               writes[j]["addr"] == w["addr"] and
               writes[j]["size"] == w["size"] and
               writes[j]["value"] == w["value"]):
            j += 1
        count = j - i
        entry = dict(w)
        if count > 1:
            entry["repeat"] = count
        out.append(entry)
        i = j
    return out


def _parse_filter_range(
    filter_str: str | None,
    segments: list[dict],
) -> tuple[int, int] | None:
    """Parse a write-filter string into (lo, hi), or None for no filtering.

    Formats:
      ``'0x140000000-0x140667000'``  — explicit hex range (inclusive start, exclusive end)
      ``'image'``                    — union of all IDA segments (min_start..max_end)
    """
    if not filter_str:
        return None
    s = filter_str.strip().lower()
    if s == "image":
        if not segments:
            return None
        lo = min(seg["start"] for seg in segments)
        hi = max(seg["start"] + seg["size"] for seg in segments)
        return lo, hi
    if "-" in s:
        parts = s.split("-", 1)
        try:
            return int(parts[0].strip(), 16), int(parts[1].strip(), 16)
        except ValueError:
            return None
    return None


# ============================================================================
# All other tools require unicorn. Registered only when present.
#
# Tools are @tool-only (NOT @idasync): the emulation loop must run off the IDA
# main thread so a long run never freezes the UI. IDA data (segments + arch) is
# gathered up front via _prepare(), which uses idasync to marshal exactly once
# to the main thread, returning plain Python objects the emulation core never
# needs to touch IDA for again.
# ============================================================================

if UNICORN_AVAILABLE:

    def _prepare_internal() -> tuple[list[dict], int, int, int]:
        """Gather all IDA data needed for emulation. Must run on main thread."""
        segs = _gather_ida_segments_internal()
        arch, mode, bits = _detect_uc_arch()
        return segs, arch, mode, bits

    _prepare = idasync(_prepare_internal)

    # =====================================================================
    # U.1 — unicorn_emulate
    # =====================================================================

    @tool
    def unicorn_emulate(
        start: Annotated[str, "Start address (hex). Must be in the IDB."],
        end: Annotated[str, "Stop address (exclusive, hex)."],
        regs: Annotated[
            dict | None,
            "Initial register values, e.g. {'rax': '0x1234', 'rcx': '0'}.",
        ] = None,
        stack_size: Annotated[int, "Stack bytes to allocate (default 0x10000)."] = _DEFAULT_STACK_SIZE,
        max_insns: Annotated[int, "Hard instruction cap (default 50000)."] = 50000,
        timeout_ms: Annotated[int, "Wall-clock timeout in ms (default 5000)."] = 5000,
        bypass_antidebug: Annotated[
            bool, "Neutralise RDTSC/CPUID anti-analysis checks (default False)."
        ] = False,
        filter_writes_to: Annotated[
            str | None,
            "Only report memory writes within this range: 'START-END' hex (e.g. "
            "'0x140000000-0x140667000') or 'image' (all IDA segments). "
            "Consecutive identical writes are always deduplicated. Default: report all.",
        ] = None,
    ) -> UnicornEmulateResult:
        """Concrete-emulate an IDA address range with all segments mapped.

        Maps every IDA segment byte-for-byte into a fresh Unicorn instance,
        sets up a dedicated stack, applies the requested register values, and
        runs from `start` to `end`. Records register state, all memory writes,
        and any unmapped-memory faults (auto-mapped to zero pages so a stray
        access can't abort the run).

        Consecutive identical writes (e.g. CRT zero-init loops) are collapsed
        into a single entry with a ``repeat`` count so output stays readable.
        Use filter_writes_to to scope write reporting to a region of interest.

        This is the bread-and-butter tool: use it to run a function or code
        slice and observe its concrete effects without a debugger.
        """
        try:
            segments, uc_arch, uc_mode, bits = _prepare()
            start_ea = parse_address(start)
            end_ea = parse_address(end)
            res = _emulate_impl(
                segments, uc_arch, uc_mode, bits,
                start_ea, end_ea, regs, stack_size, max_insns, timeout_ms,
                bypass_antidebug=bypass_antidebug,
            )
            res.pop("_controller", None)
            frange = _parse_filter_range(filter_writes_to, segments)
            res["memory_writes"] = _compress_mem_writes(
                res.get("memory_writes", []), frange)
            res["note"] = _emulate_note(res)
            return res
        except Exception as e:
            return tool_error(e, context="unicorn_emulate")

    def _emulate_note(res: dict) -> str:
        sr = res.get("stop_reason", "")
        n = res.get("insns_executed", 0)
        if sr == "end_address_reached":
            return f"Reached end address after {n} instructions."
        if sr == "max_insns":
            return (f"Hit the {n}-instruction cap before reaching end — raise "
                    "max_insns or check for an unintended loop.")
        if sr == "timeout":
            return f"Timed out after {n} instructions — likely an infinite loop."
        if str(sr).startswith("error"):
            return (f"Emulation faulted after {n} instructions ({sr}). Check "
                    "register setup and that all needed memory is mapped.")
        return f"Executed {n} instructions ({sr})."

    # =====================================================================
    # U.2 — unicorn_trace
    # =====================================================================

    @tool
    def unicorn_trace(
        start: Annotated[str, "Start address (hex)."],
        end: Annotated[str, "Stop address (exclusive, hex)."],
        regs: Annotated[dict | None, "Initial register values."] = None,
        trace_level: Annotated[
            str, "'blocks' (fast), 'insns', or 'full' (addr+mnemonic+regs)."
        ] = "insns",
        max_insns: Annotated[int, "Instruction cap (default 10000)."] = 10000,
        timeout_ms: Annotated[int, "Timeout in ms (default 5000)."] = 5000,
    ) -> UnicornTraceResult:
        """Execute and return a trace; flags repeated addresses as loops.

        trace_level:
          • 'blocks' — one entry per basic block (fastest; best for loop maps).
          • 'insns'  — one entry per instruction (address + size).
          • 'full'   — adds Capstone mnemonic/op_str and key register state per
                       instruction (slowest; Capstone optional).

        Any address visited >= 5 times is reported in loops_detected — a quick
        signal for decryption loops and VM fetch cycles.
        """
        try:
            segments, uc_arch, uc_mode, bits = _prepare()
            start_ea = parse_address(start)
            end_ea = parse_address(end)
            level = (trace_level or "insns").lower()
            if level not in ("blocks", "insns", "full"):
                level = "insns"

            ctl = _EmuController(segments, uc_arch, uc_mode, bits)
            ctl.setup_stack()
            ctl.install_default_hooks(record_writes=False)
            _set_regs(ctl.emu, ctl.reg_map, regs)

            trace: list[dict] = []
            visit_counts: dict[int, int] = {}
            md = _get_capstone(uc_arch, uc_mode) if level == "full" else None
            trace_regs = _result_reg_names(uc_arch, uc_mode)[:6]

            def _on_block(uc, address, size, user_data):
                visit_counts[address] = visit_counts.get(address, 0) + 1
                if level == "blocks" and len(trace) < _MAX_TRACE:
                    trace.append({"addr": hex(address), "size": size})

            def _on_insn(uc, address, size, user_data):
                ctl.insn_count += 1
                visit_counts[address] = visit_counts.get(address, 0) + 1
                if len(trace) >= _MAX_TRACE:
                    return
                entry: dict = {"addr": hex(address), "size": size}
                if level == "full":
                    if md is not None:
                        try:
                            code = bytes(uc.mem_read(address, size))
                            for insn in md.disasm(code, address):
                                entry["mnemonic"] = insn.mnemonic
                                entry["op_str"] = insn.op_str
                                break
                        except Exception:
                            pass
                    entry["regs"] = _read_regs(uc, ctl.reg_map, trace_regs)
                trace.append(entry)

            if level == "blocks":
                ctl.emu.hook_add(UC_HOOK_BLOCK, _on_block)
                ctl.emu.hook_add(UC_HOOK_CODE, ctl.count_hook)
            else:
                ctl.emu.hook_add(UC_HOOK_CODE, _on_insn)

            stop = ctl.run(start_ea, end_ea, max_insns, timeout_ms)

            loops = [
                {"addr": hex(a), "count": c,
                 "note": f"visited {c}× — probable loop body"}
                for a, c in sorted(visit_counts.items(), key=lambda kv: -kv[1])
                if c >= 5
            ][:20]

            return {
                "ok": True,
                "trace": trace,
                "insns_executed": ctl.insn_count,
                "unique_addrs": len(visit_counts),
                "loops_detected": loops,
                "stop_reason": stop,
                "note": (f"{len(trace)} trace entries, {len(loops)} loop(s) detected. "
                         + ("Trace truncated." if len(trace) >= _MAX_TRACE else "")),
            }
        except Exception as e:
            return tool_error(e, context="unicorn_trace")

    # =====================================================================
    # U.5 — unicorn_call_function
    # =====================================================================

    def _is_pe_internal() -> bool:
        try:
            return idaapi.inf_get_filetype() == getattr(idaapi, "f_PE", 11)
        except Exception:
            return False

    _ida_is_pe = idasync(_is_pe_internal)

    def _resolve_cc(cc: str, bits: int) -> str:
        cc = (cc or "auto").lower()
        if cc != "auto":
            return cc
        if bits == 64:
            try:
                return "msvc_x64" if _ida_is_pe() else "sysv_x64"
            except Exception:
                return "sysv_x64"
        return "cdecl"

    def _setup_call_cc(ctl: "_EmuController", cc: str, args: list[int],
                       initial_sp: int, ret_sentinel: int) -> None:
        """Place args per calling convention and a sentinel return address.

        The stack pointer is set so that on entry the function sees
        [sp] == ret_sentinel (its return address), matching a real CALL.
        """
        from unicorn import x86_const as c
        emu = ctl.emu
        is64 = bool(ctl.uc_mode & UC_MODE_64)
        ptr = 8 if is64 else 4

        def push(sp: int, val: int) -> int:
            sp -= ptr
            emu.mem_write(sp, val.to_bytes(ptr, "little"))
            return sp

        sp = initial_sp
        if ctl.uc_arch == UC_ARCH_X86 and is64:
            if cc == "msvc_x64":
                regs = [c.UC_X86_REG_RCX, c.UC_X86_REG_RDX,
                        c.UC_X86_REG_R8, c.UC_X86_REG_R9]
                for i, a in enumerate(args[:4]):
                    emu.reg_write(regs[i], a)
                stack_args = args[4:]
                # push extra args right-to-left, then 0x20 shadow space
                for a in reversed(stack_args):
                    sp = push(sp, a)
                sp -= 0x20
            else:  # sysv_x64
                regs = [c.UC_X86_REG_RDI, c.UC_X86_REG_RSI, c.UC_X86_REG_RDX,
                        c.UC_X86_REG_RCX, c.UC_X86_REG_R8, c.UC_X86_REG_R9]
                for i, a in enumerate(args[:6]):
                    emu.reg_write(regs[i], a)
                for a in reversed(args[6:]):
                    sp = push(sp, a)
            # 16-byte align then push return address
            sp &= ~0xF
            sp = push(sp, ret_sentinel)
            emu.reg_write(c.UC_X86_REG_RSP, sp)
        elif ctl.uc_arch == UC_ARCH_X86:  # 32-bit
            stack_args = args
            if cc == "fastcall":
                if len(args) >= 1:
                    emu.reg_write(c.UC_X86_REG_ECX, args[0])
                if len(args) >= 2:
                    emu.reg_write(c.UC_X86_REG_EDX, args[1])
                stack_args = args[2:]
            for a in reversed(stack_args):
                sp = push(sp, a)
            sp = push(sp, ret_sentinel)
            emu.reg_write(c.UC_X86_REG_ESP, sp)
        elif ctl.uc_arch == UC_ARCH_ARM64:
            from unicorn import arm64_const as a64
            for i, a in enumerate(args[:8]):
                emu.reg_write(getattr(a64, "UC_ARM64_REG_X%d" % i), a)
            emu.reg_write(a64.UC_ARM64_REG_LR, ret_sentinel)
        elif ctl.uc_arch == UC_ARCH_ARM:
            from unicorn import arm_const as a32
            for i, a in enumerate(args[:4]):
                emu.reg_write(getattr(a32, "UC_ARM_REG_R%d" % i), a)
            emu.reg_write(a32.UC_ARM_REG_LR, ret_sentinel)

    def _call_function_impl(
        segments: list[dict], uc_arch: int, uc_mode: int, bits: int,
        func_ea: int, args: list[int], cc: str,
        max_insns: int, timeout_ms: int,
        record_writes: bool = True,
    ) -> dict:
        ctl = _EmuController(segments, uc_arch, uc_mode, bits)
        sp = ctl.setup_stack()
        ctl.install_default_hooks(record_writes=record_writes)
        ctl.emu.hook_add(UC_HOOK_CODE, ctl.count_hook)

        # Sentinel return address: emu_start stops on reaching it (it is never
        # executed), giving a clean "function returned" signal.
        sb, st = ctl.stack_range
        ret_sentinel = (st + 0x1000) & ~0xF  # just above the stack, page-distinct

        cc_resolved = _resolve_cc(cc, bits)
        _setup_call_cc(ctl, cc_resolved, args, sp, ret_sentinel)

        timed_out = {"v": False}

        def _kill():
            timed_out["v"] = True
            try:
                ctl.emu.emu_stop()
            except Exception:
                pass

        timer = None
        if timeout_ms > 0:
            timer = threading.Timer(timeout_ms / 1000.0, _kill)
            timer.daemon = True
            timer.start()
        try:
            ctl.emu.emu_start(func_ea, ret_sentinel,
                              timeout=(timeout_ms * 1000) if timeout_ms > 0 else 0,
                              count=max_insns if max_insns > 0 else 0)
            if timed_out["v"]:
                stop = "timeout"
            elif max_insns > 0 and ctl.insn_count >= max_insns:
                stop = "max_insns"
            else:
                stop = "ret_executed"
        except UcError as e:
            stop = "timeout" if timed_out["v"] else ("error: %s" % e)
        finally:
            if timer is not None:
                timer.cancel()

        ret_name = _ret_reg_name(uc_arch, uc_mode)
        ret_reg = ctl.reg_map.get(ret_name)
        ret_val = 0
        if ret_reg is not None:
            try:
                ret_val = ctl.emu.reg_read(ret_reg)
            except Exception:
                ret_val = 0
        ptr = 8 if bits == 64 else 4
        return {
            "ok": True,
            "return_value": hex(ret_val),
            "return_value_bytes": " ".join(
                "%02x" % b for b in (ret_val & ((1 << (ptr * 8)) - 1)).to_bytes(ptr, "little")
            ),
            "regs": _read_regs(ctl.emu, ctl.reg_map, _result_reg_names(uc_arch, uc_mode)),
            "insns_executed": ctl.insn_count,
            "stop_reason": stop,
            "memory_writes": ctl.memory_writes,
            "cc_used": cc_resolved,
            "_controller": ctl,
        }

    @tool
    def unicorn_call_function(
        func_addr: Annotated[str, "Function address to call (hex)."],
        args: Annotated[
            list[str] | str | None,
            "Argument values (hex/dec), e.g. ['0x10', '0x20'] or '0x10,0x20'.",
        ] = None,
        cc: Annotated[
            str,
            "Calling convention: 'auto', 'sysv_x64', 'msvc_x64', 'cdecl', "
            "'stdcall', 'fastcall'.",
        ] = "auto",
        max_insns: Annotated[int, "Instruction cap (default 100000)."] = 100000,
        timeout_ms: Annotated[int, "Timeout in ms (default 5000)."] = 5000,
    ) -> UnicornCallResult:
        """Concrete-call a function with given args; return its value.

        Sets up the calling convention (auto-detected: MSVC x64 for PE, SysV
        x64 otherwise, cdecl for 32-bit), pushes a sentinel return address, and
        runs until the top-level RET. The fastest way to answer "what does this
        function return for these inputs?" — crypto round functions, hash
        routines, DRM validators, string comparisons.
        """
        try:
            segments, uc_arch, uc_mode, bits = _prepare()
            func_ea = parse_address(func_addr)
            arg_ints = [_parse_reg_value(a) for a in normalize_list_input(args or [])]
            res = _call_function_impl(
                segments, uc_arch, uc_mode, bits, func_ea, arg_ints, cc,
                max_insns, timeout_ms,
            )
            res.pop("_controller", None)
            res["memory_writes"] = _compress_mem_writes(res.get("memory_writes", []))
            rv = res.get("return_value", "0x0")
            res["note"] = f"Returned {rv} after {res.get('insns_executed', 0)} instructions ({res.get('stop_reason')})."
            return res
        except Exception as e:
            return tool_error(e, context="unicorn_call_function")

    # =====================================================================
    # IDB patch / analyze helpers (the only post-emulation IDA writes)
    # =====================================================================

    @idasync
    def _patch_idb(addr: int, data: bytes) -> int:
        import ida_bytes
        ida_bytes.patch_bytes(addr, bytes(data))
        return len(data)

    @idasync
    def _analyze_and_count(start: int, end: int) -> int:
        """plan_and_wait over a range, then report functions now defined in it."""
        import ida_auto
        import ida_funcs
        ida_auto.plan_and_wait(start, end)
        count = 0
        f = ida_funcs.get_next_func(start - 1)
        while f is not None and f.start_ea < end:
            count += 1
            f = ida_funcs.get_next_func(f.start_ea)
        return count

    def _original_bytes(segments: list[dict], addr: int, size: int) -> bytes:
        """Reconstruct the pre-emulation bytes for [addr, addr+size) from segs."""
        out = bytearray(size)
        for i in range(size):
            seg = _seg_for_addr(segments, addr + i)
            if seg is not None:
                off = (addr + i) - seg["start"]
                if 0 <= off < len(seg["data"]):
                    out[i] = seg["data"][off]
        return bytes(out)

    # =====================================================================
    # U.3 — unicorn_emulate_and_patch  ⚠️ unsafe
    # =====================================================================

    @unsafe
    @tool
    def unicorn_emulate_and_patch(
        start: Annotated[str, "Decrypt-stub start address (hex)."],
        end: Annotated[str, "Decrypt-stub end address (exclusive, hex)."],
        patch_start: Annotated[str, "Start of region to read back and patch (hex)."],
        patch_size: Annotated[int, "Bytes to read from emulator memory and patch."],
        regs: Annotated[
            dict | None,
            "Decryption args, e.g. {'ecx': '0x1493000', 'edx': '0x8000'}.",
        ] = None,
        analyze: Annotated[bool, "Auto plan_and_wait after patching (default True)."] = True,
        stack_size: Annotated[int, "Stack bytes (default 0x10000)."] = _DEFAULT_STACK_SIZE,
        max_insns: Annotated[int, "Instruction cap (default 200000)."] = 200000,
        timeout_ms: Annotated[int, "Timeout in ms (default 10000)."] = 10000,
    ) -> UnicornPatchResult:
        """Emulate a decryption stub, then patch the decrypted bytes into the IDB.

        The encrypted-section workhorse — recovers code/data that IDA can't see
        without a live debugger:
          1. Map all IDA segments, run the decrypt stub (`start`→`end`).
          2. Read `patch_size` bytes from `patch_start` in emulator memory.
          3. ida_bytes.patch_bytes() them into the database.
          4. If analyze=True, plan_and_wait over the region.

        Reports entropy before/after as a decryption sanity check — a large
        drop means the region went from encrypted/compressed to real code/data.
        """
        try:
            segments, uc_arch, uc_mode, bits = _prepare()
            start_ea = parse_address(start)
            end_ea = parse_address(end)
            patch_ea = parse_address(patch_start)
            if patch_size <= 0:
                return {"ok": False, "error": "patch_size must be positive",
                        "error_type": "value_error"}

            res = _emulate_impl(
                segments, uc_arch, uc_mode, bits,
                start_ea, end_ea, regs, stack_size, max_insns, timeout_ms,
            )
            ctl = res.pop("_controller")
            try:
                decrypted = bytes(ctl.emu.mem_read(patch_ea, patch_size))
            except UcError as e:
                return {"ok": False,
                        "error": f"could not read {patch_size} bytes at {patch_start}: {e}",
                        "error_type": "unmapped_memory",
                        "stop_reason": res.get("stop_reason")}

            before = _original_bytes(segments, patch_ea, patch_size)
            ent_before = _shannon_entropy(before)
            ent_after = _shannon_entropy(decrypted)

            patched = _patch_idb(patch_ea, decrypted)
            functions_created = 0
            if analyze:
                functions_created = _analyze_and_count(patch_ea, patch_ea + patch_size)

            delta = round(ent_after - ent_before, 3)
            if delta <= -1.0:
                note = (f"Entropy dropped {abs(delta)} pts — region likely "
                        f"decrypted. {functions_created} function(s) defined.")
            elif before == decrypted:
                note = ("Bytes unchanged by emulation — the stub may not have "
                        "written to this region, or needs different register args.")
            else:
                note = (f"Region changed (entropy delta {delta}). "
                        f"{functions_created} function(s) defined.")

            return {
                "ok": True,
                "bytes_patched": patched,
                "insns_executed": res.get("insns_executed", 0),
                "patch_start": hex(patch_ea),
                "patch_hex_preview": _hex_preview(decrypted, 32),
                "entropy_before": ent_before,
                "entropy_after": ent_after,
                "entropy_delta": delta,
                "functions_created": functions_created,
                "stop_reason": res.get("stop_reason"),
                "note": note,
            }
        except Exception as e:
            return tool_error(e, context="unicorn_emulate_and_patch")

    # =====================================================================
    # U.4 — unicorn_diff_memory
    # =====================================================================

    @tool
    def unicorn_diff_memory(
        start: Annotated[str, "Start address (hex)."],
        end: Annotated[str, "Stop address (exclusive, hex)."],
        regs: Annotated[dict | None, "Initial register values."] = None,
        watch_regions: Annotated[
            list[dict] | None,
            "Regions to diff: [{'start','size','label'}]. Default: writable segments.",
        ] = None,
        stack_size: Annotated[int, "Stack bytes (default 0x10000)."] = _DEFAULT_STACK_SIZE,
        max_insns: Annotated[int, "Instruction cap (default 200000)."] = 200000,
        timeout_ms: Annotated[int, "Timeout in ms (default 10000)."] = 10000,
    ) -> UnicornDiffResult:
        """Emulate, then report which memory regions the run changed.

        A read-only reconnaissance counterpart to unicorn_emulate_and_patch:
        runs the code, compares emulator memory to the original IDA bytes, and
        reports changed regions with entropy shift and any newly-visible ASCII/
        UTF-16 strings. Does NOT modify the IDB — use it to decide what (and
        whether) to patch.
        """
        try:
            segments, uc_arch, uc_mode, bits = _prepare()
            start_ea = parse_address(start)
            end_ea = parse_address(end)

            # Build watch list.
            watch: list[dict] = []
            if watch_regions:
                for r in watch_regions:
                    rs = parse_address(r["start"])
                    sz = int(r.get("size") or 0)
                    if sz <= 0 and r.get("end"):
                        sz = parse_address(r["end"]) - rs
                    watch.append({"start": rs, "size": sz,
                                  "label": r.get("label", "")})
            else:
                for s in segments:
                    if s["perms"] & UC_PROT_WRITE:
                        watch.append({"start": s["start"], "size": s["size"],
                                      "label": s["name"]})

            res = _emulate_impl(
                segments, uc_arch, uc_mode, bits,
                start_ea, end_ea, regs, stack_size, max_insns, timeout_ms,
            )
            ctl = res.pop("_controller")

            changed: list[dict] = []
            unchanged: list[dict] = []
            total_changed = 0
            for w in watch:
                size = w["size"]
                if size <= 0 or size > _MAX_SEGMENT_MAP:
                    continue
                before = _original_bytes(segments, w["start"], size)
                try:
                    after = bytes(ctl.emu.mem_read(w["start"], size))
                except UcError:
                    continue
                if before == after:
                    unchanged.append({"addr": hex(w["start"]), "size": size,
                                      "label": w["label"]})
                    continue
                nchg = sum(1 for a, b in zip(before, after) if a != b)
                total_changed += nchg
                eb = _shannon_entropy(before)
                ea = _shannon_entropy(after)
                strings = (_extract_ascii_strings(after, 4)
                           + _extract_utf16le_strings(after, 4))[:20]
                if eb - ea >= 1.0:
                    rnote = "high→low entropy: likely decrypted."
                elif strings:
                    rnote = "now contains readable strings."
                else:
                    rnote = "region modified during execution."
                changed.append({
                    "addr": hex(w["start"]), "size": size, "label": w["label"],
                    "bytes_changed": nchg,
                    "entropy_before": eb, "entropy_after": ea,
                    "hex_preview": _hex_preview(after, 32),
                    "ascii_strings": strings,
                    "note": rnote,
                })

            return {
                "ok": True,
                "changed_regions": changed,
                "unchanged_regions": unchanged,
                "total_changed_bytes": total_changed,
                "insns_executed": res.get("insns_executed", 0),
                "note": (f"{len(changed)} region(s) changed, {total_changed} bytes total. "
                         + ("Use unicorn_emulate_and_patch to commit a region to the IDB."
                            if changed else "No memory changed — check register args.")),
            }
        except Exception as e:
            return tool_error(e, context="unicorn_diff_memory")

    # =====================================================================
    # U.7 — unicorn_recover_stackstrings
    # =====================================================================

    @tool
    def unicorn_recover_stackstrings(
        func_addr: Annotated[str, "Function to execute (hex)."],
        min_length: Annotated[int, "Minimum string length to report (default 4)."] = 4,
        regs: Annotated[dict | None, "Initial register values (optional)."] = None,
        max_insns: Annotated[int, "Instruction cap (default 100000)."] = 100000,
        timeout_ms: Annotated[int, "Timeout in ms (default 5000)."] = 5000,
    ) -> UnicornStackstringsResult:
        """Execute a function and recover strings built on the stack.

        Stackstrings — character-by-character writes that assemble a string in
        a local buffer — are a top malware string-obfuscation technique. This
        intercepts every write into the stack region, coalesces adjacent bytes,
        and scans for ASCII and UTF-16LE strings. These strings are usually the
        arguments later passed to GetProcAddress, registry, or network APIs.
        """
        try:
            segments, uc_arch, uc_mode, bits = _prepare()
            func_ea = parse_address(func_addr)

            ctl = _EmuController(segments, uc_arch, uc_mode, bits)
            sp = ctl.setup_stack()
            ctl.install_default_hooks(record_writes=False)
            ctl.emu.hook_add(UC_HOOK_CODE, ctl.count_hook)
            _set_regs(ctl.emu, ctl.reg_map, regs)
            stack_lo, stack_hi = ctl.stack_range

            stack_writes: dict[int, int] = {}  # addr -> byte
            write_count = {"n": 0}

            def _on_write(uc, access, address, size, value, user_data):
                if not (stack_lo <= address < stack_hi):
                    return
                if write_count["n"] >= _MAX_EVENTS:
                    return
                write_count["n"] += 1
                try:
                    raw = int(value).to_bytes(size, "little", signed=False)
                except (OverflowError, ValueError):
                    return
                for i in range(size):
                    stack_writes[address + i] = raw[i]

            ctl.emu.hook_add(UC_HOOK_MEM_WRITE, _on_write)
            # Use a sentinel-return call so a normal function returns cleanly.
            ret_sentinel = (stack_hi + 0x1000) & ~0xF
            ptr = 8 if bits == 64 else 4
            sp2 = (sp - ptr)
            ctl.emu.mem_write(sp2, ret_sentinel.to_bytes(ptr, "little"))
            sp_reg = ctl.reg_map.get(_sp_reg_name(uc_arch, uc_mode))
            if sp_reg is not None:
                ctl.emu.reg_write(sp_reg, sp2)
            ctl.run(func_ea, ret_sentinel, max_insns, timeout_ms)

            # Coalesce contiguous stack writes and scan for strings.
            strings: list[dict] = []
            if stack_writes:
                addrs = sorted(stack_writes)
                run_start = addrs[0]
                buf = bytearray([stack_writes[run_start]])
                prev = run_start

                def _flush(rstart: int, data: bytes):
                    for enc, scan in (("ascii", _extract_ascii_strings),
                                      ("utf16le", _extract_utf16le_strings)):
                        for s in scan(data, min_length):
                            off = data.find(s.encode("ascii", "replace"))
                            strings.append({
                                "addr": hex(rstart + max(off, 0)),
                                "encoding": enc,
                                "value": s,
                                "stack_offset": (rstart + max(off, 0)) - (stack_hi - 0x100),
                            })

                for a in addrs[1:]:
                    if a == prev + 1:
                        buf.append(stack_writes[a])
                    else:
                        _flush(run_start, bytes(buf))
                        run_start = a
                        buf = bytearray([stack_writes[a]])
                    prev = a
                _flush(run_start, bytes(buf))

            # De-duplicate by (value, encoding).
            seen = set()
            uniq = []
            for s in strings:
                k = (s["value"], s["encoding"])
                if k not in seen:
                    seen.add(k)
                    uniq.append(s)

            return {
                "ok": True,
                "strings": uniq,
                "stack_write_count": write_count["n"],
                "bytes_written_to_stack": len(stack_writes),
                "insns_executed": ctl.insn_count,
                "note": (f"Found {len(uniq)} stackstring(s). These are often passed "
                         "to GetProcAddress, registry, or network APIs."
                         if uniq else
                         "No stackstrings found — the function may not build "
                         "strings on the stack, or needs argument setup via regs."),
            }
        except Exception as e:
            return tool_error(e, context="unicorn_recover_stackstrings")

    # =====================================================================
    # U.8 — unicorn_find_memory_accesses
    # =====================================================================

    @tool
    def unicorn_find_memory_accesses(
        start: Annotated[str, "Start address (hex)."],
        end: Annotated[str, "Stop address (exclusive, hex)."],
        regs: Annotated[dict | None, "Initial register values."] = None,
        filter_regions: Annotated[
            list[dict] | None,
            "Only report accesses in these ranges: [{'start','end','label'}].",
        ] = None,
        access_type: Annotated[str, "'all', 'reads', or 'writes'."] = "all",
        max_insns: Annotated[int, "Instruction cap (default 100000)."] = 100000,
        timeout_ms: Annotated[int, "Timeout in ms (default 5000)."] = 5000,
    ) -> UnicornMemAccessResult:
        """Record every memory read/write during emulation; flag hot regions.

        Reveals where a routine reads its keys/constants and where it writes
        its output. Addresses accessed >= 10 times are surfaced as hot_regions
        — typically key schedules, dispatch tables, or repeated constant
        lookups. Use filter_regions to focus on a suspected key/table area.
        """
        try:
            segments, uc_arch, uc_mode, bits = _prepare()
            start_ea = parse_address(start)
            end_ea = parse_address(end)
            want = (access_type or "all").lower()

            ranges = []
            if filter_regions:
                for r in filter_regions:
                    rs = parse_address(r["start"])
                    re_ = parse_address(r["end"]) if r.get("end") else rs + int(r.get("size", 0))
                    ranges.append((rs, re_, r.get("label", "")))

            def _in_filter(addr: int) -> tuple[bool, str]:
                if not ranges:
                    return True, _label_for_addr(segments, addr)
                for lo, hi, label in ranges:
                    if lo <= addr < hi:
                        return True, (label or _label_for_addr(segments, addr))
                return False, ""

            ctl = _EmuController(segments, uc_arch, uc_mode, bits)
            ctl.setup_stack()
            ctl.install_default_hooks(record_writes=False)
            ctl.emu.hook_add(UC_HOOK_CODE, ctl.count_hook)
            _set_regs(ctl.emu, ctl.reg_map, regs)

            accesses: list[dict] = []
            counts: dict[int, int] = {}
            tally = {"r": 0, "w": 0}

            def _record(kind: str, uc, address, size, value):
                ok, label = _in_filter(address)
                if not ok:
                    return
                counts[address] = counts.get(address, 0) + 1
                if kind == "read":
                    tally["r"] += 1
                else:
                    tally["w"] += 1
                if len(accesses) >= _MAX_EVENTS:
                    return
                pc_reg = ctl.reg_map.get(_pc_reg_name(uc_arch, uc_mode))
                pc = uc.reg_read(pc_reg) if pc_reg is not None else 0
                accesses.append({
                    "type": kind, "addr": hex(address), "size": size,
                    "value": hex(value) if value is not None else "",
                    "pc": hex(pc), "label": label,
                })

            if want in ("all", "reads"):
                def _on_read(uc, access, address, size, value, user_data):
                    _record("read", uc, address, size, value)
                ctl.emu.hook_add(UC_HOOK_MEM_READ_AFTER, _on_read)
            if want in ("all", "writes"):
                def _on_write(uc, access, address, size, value, user_data):
                    _record("write", uc, address, size, value)
                ctl.emu.hook_add(UC_HOOK_MEM_WRITE, _on_write)

            ctl.run(start_ea, end_ea, max_insns, timeout_ms)

            hot = [
                {"addr": hex(a), "count": c, "label": _label_for_addr(segments, a),
                 "note": f"accessed {c}× — likely key material or lookup table"}
                for a, c in sorted(counts.items(), key=lambda kv: -kv[1])
                if c >= 10
            ][:20]

            return {
                "ok": True,
                "accesses": accesses,
                "read_count": tally["r"],
                "write_count": tally["w"],
                "hot_regions": hot,
                "insns_executed": ctl.insn_count,
                "note": (f"{tally['r']} reads, {tally['w']} writes, {len(hot)} hot region(s)."
                         + (" Trace truncated." if len(accesses) >= _MAX_EVENTS else "")),
            }
        except Exception as e:
            return tool_error(e, context="unicorn_find_memory_accesses")

    # =====================================================================
    # U.9 — unicorn_resolve_api_hash
    # =====================================================================

    @tool
    def unicorn_resolve_api_hash(
        hash_func_addr: Annotated[str, "Address of the hash function (hex)."],
        api_names: Annotated[
            list[str] | str | None,
            "API names to test. Default: built-in ~200-name WinAPI list.",
        ] = None,
        known_hashes: Annotated[
            list[str] | str | None,
            "If given, only report names whose hash matches one of these.",
        ] = None,
        cc: Annotated[str, "Calling convention (default 'auto')."] = "auto",
        max_insns: Annotated[int, "Per-name instruction cap (default 20000)."] = 20000,
        timeout_ms: Annotated[int, "Per-name timeout in ms (default 2000)."] = 2000,
    ) -> UnicornHashResult:
        """Brute-map a custom API-hash function against known API names.

        Malware and shellcode resolve imports by hashing API name strings and
        comparing to a precomputed table, hiding which APIs they use. This
        emulates the hash routine once per candidate name (string pointer as
        the first argument) and records each name→hash. Supply known_hashes
        from the binary's table to filter to just the matches.

        The single best tool for de-obfuscating hash-based import resolution.
        """
        t0 = time.time()
        try:
            segments, uc_arch, uc_mode, bits = _prepare()
            func_ea = parse_address(hash_func_addr)
            names = normalize_list_input(api_names) if api_names else \
                [n for n, _m in _COMMON_WINAPIS]
            modules = dict(_COMMON_WINAPIS)
            known = set()
            for h in (normalize_list_input(known_hashes) if known_hashes else []):
                try:
                    known.add(int(str(h), 0) & 0xFFFFFFFFFFFFFFFF)
                except ValueError:
                    pass

            # Map segments + a scratch page once; reuse across all names.
            ctl = _EmuController(segments, uc_arch, uc_mode, bits)
            sp = ctl.setup_stack()
            ctl.install_default_hooks(record_writes=False)
            scratch_base = _choose_stack_base(segments, bits, _SCRATCH_SIZE)
            # Ensure scratch does not collide with the stack we just mapped.
            sb, st = ctl.stack_range
            if not (scratch_base + _SCRATCH_SIZE <= sb or scratch_base >= st):
                scratch_base = _align_down(sb - _SCRATCH_SIZE - _PAGE)
            ctl.emu.mem_map(scratch_base, _align_up(_SCRATCH_SIZE),
                            UC_PROT_READ | UC_PROT_WRITE)
            cc_resolved = _resolve_cc(cc, bits)
            ret_sentinel = (st + 0x1000) & ~0xF
            ret_reg = ctl.reg_map.get(_ret_reg_name(uc_arch, uc_mode))

            results: list[dict] = []
            resolved = 0
            for name in names:
                try:
                    enc = name.encode("ascii", "ignore") + b"\x00"
                    ctl.emu.mem_write(scratch_base, enc)
                    _setup_call_cc(ctl, cc_resolved, [scratch_base], sp, ret_sentinel)
                    timed = {"v": False}

                    def _kill():
                        timed["v"] = True
                        try:
                            ctl.emu.emu_stop()
                        except Exception:
                            pass
                    timer = threading.Timer(timeout_ms / 1000.0, _kill)
                    timer.daemon = True
                    timer.start()
                    try:
                        ctl.emu.emu_start(func_ea, ret_sentinel,
                                          timeout=timeout_ms * 1000,
                                          count=max_insns)
                    except UcError:
                        pass
                    finally:
                        timer.cancel()
                    h = ctl.emu.reg_read(ret_reg) if ret_reg is not None else 0
                    if known and h not in known:
                        continue
                    results.append({"api": name, "hash": hex(h),
                                    "module": modules.get(name, "")})
                    resolved += 1
                except Exception:
                    continue

            unmatched = [hex(h) for h in known
                         if h not in {int(r["hash"], 16) for r in results}]
            elapsed = int((time.time() - t0) * 1000)
            return {
                "ok": True,
                "results": results,
                "tested": len(names),
                "resolved": resolved,
                "elapsed_ms": elapsed,
                "unmatched_known_hashes": unmatched,
                "note": (f"{resolved}/{len(names)} name(s) reported. "
                         + ("Use set_name() to label the matched call sites/table entries."
                            if resolved else
                            "No matches — verify hash_func_addr, calling convention, "
                            "and that the hash takes a char* as its first arg.")),
            }
        except Exception as e:
            return tool_error(e, context="unicorn_resolve_api_hash")

    # =====================================================================
    # U.6 — unicorn_emulate_shellcode
    # =====================================================================

    # syscall-number → (name, [arg-register-order]) for Linux ABIs.
    _LINUX_X86_SYSCALLS = {
        1: "exit", 2: "fork", 3: "read", 4: "write", 5: "open", 6: "close",
        11: "execve", 41: "dup", 63: "dup2", 90: "mmap", 91: "munmap",
        102: "socketcall", 119: "sigreturn", 125: "mprotect", 192: "mmap2",
    }
    _LINUX_X64_SYSCALLS = {
        0: "read", 1: "write", 2: "open", 3: "close", 9: "mmap", 10: "mprotect",
        11: "munmap", 41: "socket", 42: "connect", 43: "accept", 44: "sendto",
        45: "recvfrom", 49: "bind", 50: "listen", 56: "clone", 57: "fork",
        59: "execve", 60: "exit", 101: "ptrace", 105: "setuid",
    }

    def _read_cstr(emu, addr: int, limit: int = 256) -> str:
        if not addr:
            return ""
        try:
            raw = bytes(emu.mem_read(addr, limit))
        except Exception:
            return ""
        nul = raw.find(b"\x00")
        if nul >= 0:
            raw = raw[:nul]
        return raw.decode("latin-1", "replace")

    @tool
    def unicorn_emulate_shellcode(
        hex_bytes: Annotated[str, "Raw shellcode as hex (spaces optional)."],
        os_type: Annotated[
            str, "'linux_x86', 'linux_x64', 'windows_x86', or 'windows_x64'."
        ] = "linux_x86",
        address: Annotated[str, "Base address to map code at (default 0x1000000)."] = "0x1000000",
        max_insns: Annotated[int, "Instruction cap (default 50000)."] = 50000,
        timeout_ms: Annotated[int, "Timeout in ms (default 5000)."] = 5000,
    ) -> UnicornShellcodeResult:
        """Sandbox raw shellcode bytes and log its syscalls / API behavior.

        Maps the bytes into a clean emulator (no IDB needed), runs them, and
        intercepts Linux syscalls (int 0x80 / syscall) to record file access,
        network connects, process spawns, and written data — extracting any
        readable strings along the way. Windows targets are traced with string
        extraction (full WinAPI interception needs an import table, which raw
        shellcode lacks).

        Safe: nothing touches the real OS — syscalls are emulated stubs.
        """
        try:
            os_t = (os_type or "linux_x86").lower()
            is64 = os_t.endswith("x64")
            uc_arch = UC_ARCH_X86
            uc_mode = UC_MODE_64 if is64 else UC_MODE_32
            base = parse_address(address)
            code = bytes.fromhex(hex_bytes.replace(" ", "").replace("\n", ""))
            if not code:
                return {"ok": False, "error": "empty shellcode", "error_type": "value_error"}

            emu = Uc(uc_arch, uc_mode)
            reg_map = _register_map(uc_arch, uc_mode)
            from unicorn import x86_const as c

            code_size = _align_up(len(code) + _PAGE)
            emu.mem_map(_align_down(base), code_size, UC_PROT_ALL)
            emu.mem_write(base, code)
            # 2 MB scratch (stack + heap) well clear of the code.
            scratch = _align_up(base + code_size + 0x100000)
            emu.mem_map(scratch, 0x200000, UC_PROT_READ | UC_PROT_WRITE)
            sp = scratch + 0x180000
            emu.reg_write(c.UC_X86_REG_RSP if is64 else c.UC_X86_REG_ESP, sp)

            mapped_pages = set()
            syscalls: list[dict] = []
            strings: set = set()
            files: set = set()
            net: set = set()
            procs: set = set()
            insn_count = {"n": 0}
            fake_fd = {"next": 3}
            stop_flag = {"stop": False, "reason": "end"}

            def _ensure(addr, size):
                lo, hi = _align_down(addr), _align_up(addr + size)
                for p in range(lo, hi, _PAGE):
                    if p not in mapped_pages:
                        try:
                            emu.mem_map(p, _PAGE, UC_PROT_ALL)
                            mapped_pages.add(p)
                        except UcError:
                            pass

            def _on_invalid(uc, access, addr, size, value, ud):
                _ensure(addr, size)
                return True

            def _count(uc, addr, size, ud):
                insn_count["n"] += 1

            def _handle_syscall(num, argregs):
                tbl = _LINUX_X64_SYSCALLS if is64 else _LINUX_X86_SYSCALLS
                name = tbl.get(num, "sys_%d" % num)
                a = [emu.reg_read(r) for r in argregs]
                entry = {"insn": insn_count["n"], "name": name}
                if name == "exit":
                    stop_flag["stop"] = True
                    stop_flag["reason"] = "sys_exit"
                elif name == "write":
                    fd, buf, cnt = a[0], a[1], min(a[2], 4096)
                    data = b""
                    try:
                        data = bytes(emu.mem_read(buf, cnt))
                    except Exception:
                        pass
                    entry["args"] = {"fd": fd, "count": a[2]}
                    entry["data_preview"] = data[:120].decode("latin-1", "replace")
                    for s in _extract_ascii_strings(data, 4):
                        strings.add(s)
                elif name in ("open", "execve"):
                    path = _read_cstr(emu, a[0])
                    entry["args"] = {"path": path}
                    if name == "open":
                        files.add(path)
                        ret = fake_fd["next"]; fake_fd["next"] += 1
                        # Syscall return goes in the accumulator (RAX/EAX).
                        emu.reg_write(c.UC_X86_REG_RAX if is64 else c.UC_X86_REG_EAX, ret)
                        entry["retval"] = ret
                    else:
                        procs.add(path)
                elif name in ("mmap", "mmap2", "mprotect"):
                    entry["args"] = {"addr": hex(a[0]), "len": a[1]}
                    if name != "mprotect":
                        _ensure(a[0] or scratch, a[1] or _PAGE)
                elif name in ("connect", "sendto", "bind"):
                    # sockaddr is arg1; try to decode AF_INET ip:port
                    try:
                        sa = bytes(emu.mem_read(a[1], 8))
                        fam = int.from_bytes(sa[0:2], "little")
                        if fam == 2:  # AF_INET
                            port = int.from_bytes(sa[2:4], "big")
                            ip = ".".join(str(x) for x in sa[4:8])
                            net.add("%s:%d" % (ip, port))
                            entry["args"] = {"target": "%s:%d" % (ip, port)}
                    except Exception:
                        pass
                if len(syscalls) < _MAX_EVENTS:
                    syscalls.append(entry)
                if stop_flag["stop"]:
                    try:
                        emu.emu_stop()
                    except Exception:
                        pass

            if is64:
                def _on_syscall(uc, ud):
                    num = emu.reg_read(c.UC_X86_REG_RAX)
                    _handle_syscall(num, [c.UC_X86_REG_RDI, c.UC_X86_REG_RSI,
                                          c.UC_X86_REG_RDX, c.UC_X86_REG_R10,
                                          c.UC_X86_REG_R8, c.UC_X86_REG_R9])
                from unicorn.x86_const import UC_X86_INS_SYSCALL
                emu.hook_add(UC_HOOK_INSN, _on_syscall, None, 1, 0, UC_X86_INS_SYSCALL)
            else:
                def _on_intr(uc, intno, ud):
                    if intno != 0x80:
                        return
                    num = emu.reg_read(c.UC_X86_REG_EAX)
                    _handle_syscall(num, [c.UC_X86_REG_EBX, c.UC_X86_REG_ECX,
                                          c.UC_X86_REG_EDX, c.UC_X86_REG_ESI,
                                          c.UC_X86_REG_EDI])
                emu.hook_add(UC_HOOK_INTR, _on_intr)

            emu.hook_add(UC_HOOK_MEM_INVALID, _on_invalid)
            emu.hook_add(UC_HOOK_CODE, _count)

            timed = {"v": False}

            def _kill():
                timed["v"] = True
                try:
                    emu.emu_stop()
                except Exception:
                    pass
            timer = threading.Timer(timeout_ms / 1000.0, _kill)
            timer.daemon = True
            timer.start()
            try:
                emu.emu_start(base, base + len(code),
                              timeout=timeout_ms * 1000, count=max_insns)
            except UcError:
                pass
            finally:
                timer.cancel()

            reason = stop_flag["reason"] if stop_flag["stop"] else (
                "timeout" if timed["v"] else
                "max_insns" if insn_count["n"] >= max_insns else "end_reached")

            # Also harvest strings written anywhere in the scratch region.
            try:
                blob = bytes(emu.mem_read(scratch, 0x200000))
                for s in _extract_ascii_strings(blob, 5)[:50]:
                    strings.add(s)
            except Exception:
                pass

            return {
                "ok": True,
                "syscalls": syscalls,
                "strings_extracted": sorted(strings)[:100],
                "files_accessed": sorted(files),
                "network_targets": sorted(net),
                "processes_spawned": sorted(procs),
                "insns_executed": insn_count["n"],
                "stop_reason": reason,
                "note": (f"{len(syscalls)} syscall(s), {len(net)} network target(s), "
                         f"{len(files)} file(s). "
                         + ("Windows API interception is limited without an import table; "
                            "syscalls shown are Linux-ABI." if os_t.startswith("windows")
                            else "")),
            }
        except Exception as e:
            return tool_error(e, context="unicorn_emulate_shellcode")

    # =====================================================================
    # U.10 — workflow_unicorn_decrypt_analyze  ⚠️ unsafe
    # =====================================================================

    @unsafe
    @tool
    def workflow_unicorn_decrypt_analyze(
        decrypt_stub: Annotated[str, "Decrypt-stub start address (hex)."],
        encrypted_start: Annotated[str, "Encrypted region start (hex)."],
        encrypted_size: Annotated[int, "Encrypted region size in bytes."],
        stub_end: Annotated[
            str | None, "Decrypt-stub end (hex). Default: encrypted_start."
        ] = None,
        regs: Annotated[dict | None, "Decryption args as registers."] = None,
        max_insns: Annotated[int, "Instruction cap (default 500000)."] = 500000,
        timeout_ms: Annotated[int, "Timeout in ms (default 15000)."] = 15000,
    ) -> UnicornWorkflowResult:
        """One-call encrypted-section recovery: emulate → patch → analyze → define.

        Orchestrates the full workflow:
          1. Dry-run diff to confirm the region is high-entropy (encrypted).
          2. Emulate the decrypt stub and patch the decrypted bytes into the IDB.
          3. plan_and_wait + scan_and_define_funcs over the recovered region.

        Returns a per-step summary so an agent sees exactly where the pipeline
        succeeded or stalled.
        """
        t0 = time.time()
        steps: list[dict] = []
        try:
            start_ea = parse_address(decrypt_stub)
            enc_start = parse_address(encrypted_start)
            end_ea = parse_address(stub_end) if stub_end else enc_start
            segments, uc_arch, uc_mode, bits = _prepare()

            # Step 1: entropy check (read-only).
            before = _original_bytes(segments, enc_start, encrypted_size)
            ent_before = _shannon_entropy(before)
            steps.append({
                "step": "entropy_check", "entropy_before": ent_before, "ok": True,
                "note": ("high entropy — consistent with encrypted/compressed data"
                         if ent_before >= 7.0 else
                         "entropy is moderate — region may already be plaintext"),
            })

            # Step 2: emulate + patch (reuse the dedicated tool's impl path).
            res = _emulate_impl(
                segments, uc_arch, uc_mode, bits,
                start_ea, end_ea, regs, _DEFAULT_STACK_SIZE, max_insns, timeout_ms,
            )
            ctl = res.pop("_controller")
            try:
                decrypted = bytes(ctl.emu.mem_read(enc_start, encrypted_size))
            except UcError as e:
                steps.append({"step": "emulate_and_patch", "ok": False,
                              "error": str(e)})
                return {"ok": False, "steps": steps,
                        "error": "could not read decrypted region",
                        "error_type": "unmapped_memory"}
            ent_after = _shannon_entropy(decrypted)
            patched = _patch_idb(enc_start, decrypted)
            steps.append({
                "step": "emulate_and_patch", "ok": True,
                "bytes_patched": patched, "insns": res.get("insns_executed", 0),
                "entropy_after": ent_after,
            })

            # Step 3: analyze + define functions.
            funcs = _analyze_and_count(enc_start, enc_start + encrypted_size)
            steps.append({"step": "analyze_and_define", "ok": True,
                          "functions_created": funcs})

            delta = round(ent_after - ent_before, 3)
            return {
                "ok": True,
                "steps": steps,
                "total_functions_created": funcs,
                "entropy_delta": delta,
                "elapsed_ms": int((time.time() - t0) * 1000),
                "note": (f"Recovered {patched} bytes; entropy delta {delta}; "
                         f"{funcs} function(s) defined."),
            }
        except Exception as e:
            res = tool_error(e, context="workflow_unicorn_decrypt_analyze")
            res["steps"] = steps
            return res

    # =====================================================================
    # H.1 — hybrid_unicorn_triton_analyze
    # =====================================================================

    def _entry_point_internal() -> int | None:
        try:
            for _idx, _ord, ea, _name in idautils.Entries():
                return int(ea)
        except Exception:
            pass
        try:
            ea = idc.get_inf_attr(idc.INF_START_EA)
            if ea not in (idaapi.BADADDR, 0):
                return int(ea)
        except Exception:
            pass
        return None

    _gather_entry = idasync(_entry_point_internal)

    @idasync
    def _triton_handoff(
        concrete_regs: dict, mem_writes: list[dict],
        symbolic_start: int, symbolic_end: int,
        sym_regs: list[str], max_insns: int, timeout_ms: int,
    ) -> dict:
        """Triton phase, marshalled to the main thread (it reads IDB bytes).

        Builds a Triton context seeded with Unicorn's concrete register +
        memory state, symbolizes the requested registers, processes the
        symbolic slice, and solves the resulting path predicate.
        """
        from . import api_triton as T
        if not getattr(T, "TRITON_AVAILABLE", False):
            return {"ok": False, "error": "triton not installed"}
        arch = T._detect_arch_from_ida()
        ctx = T._build_ctx(arch, pc_tracking_symbolic=True)

        # Seed concrete register state from Unicorn.
        seeded = 0
        for name, valhex in (concrete_regs or {}).items():
            try:
                reg = ctx.getRegister(name.lower())
                ctx.setConcreteRegisterValue(reg, int(str(valhex), 16))
                seeded += 1
            except Exception:
                pass
        # Apply Unicorn's memory writes so Triton sees the same heap/stack.
        for w in (mem_writes or []):
            try:
                raw = bytes.fromhex(w.get("hex", "").replace(" ", ""))
                if raw:
                    ctx.setConcreteMemoryAreaValue(int(w["addr"], 16), raw)
            except Exception:
                pass
        # Mark the unknowns symbolic.
        sym_info = T._symbolize_registers_internal(ctx, sym_regs or [])
        # Symbolically process the interesting slice.
        processed, truncated, calls = T._process_function_instructions_linear(
            ctx, symbolic_start, symbolic_end, max_insns)
        pcs = ctx.getPathConstraints()
        solution: dict = {}
        sat = False
        try:
            predicate = ctx.getPathPredicate()
            model = ctx.getModel(predicate, timeout=timeout_ms)
            if model:
                sat = True
                for _vid, sm in model.items():
                    sv = sm.getVariable()
                    alias = sv.getAlias() or sv.getName()
                    solution[alias] = hex(sm.getValue())
        except Exception as e:
            return {"ok": False, "error": f"triton solve failed: {e}",
                    "regs_seeded": seeded, "symbolic_insns": len(processed)}
        return {
            "ok": True,
            "regs_seeded": seeded,
            "symbolized": [s.get("register") for s in sym_info if s.get("ok")],
            "symbolic_insns": len(processed),
            "path_constraints": len(pcs),
            "sat": sat,
            "solution": solution,
            "truncated": truncated,
        }

    @tool
    def hybrid_unicorn_triton_analyze(
        concrete_end: Annotated[str, "Unicorn stops here; Triton begins here (hex)."],
        symbolic_start: Annotated[str, "Triton starts symbolic processing here (hex)."],
        symbolic_end: Annotated[str, "Triton symbolic slice end (exclusive, hex)."],
        sym_regs: Annotated[
            list[str] | str,
            "Registers to make symbolic after the concrete prefix, e.g. ['rdi'].",
        ],
        start: Annotated[
            str | None, "Concrete start (hex). Default: program entry point."
        ] = None,
        regs: Annotated[dict | None, "Initial registers for the concrete pass."] = None,
        max_insns: Annotated[int, "Concrete-phase instruction cap (default 200000)."] = 200000,
        sym_max_insns: Annotated[int, "Symbolic-phase instruction cap (default 4000)."] = 4000,
        timeout_ms: Annotated[int, "Concrete-phase timeout in ms (default 8000)."] = 8000,
        solve_timeout_ms: Annotated[int, "SMT solve timeout in ms (default 10000)."] = 10000,
    ) -> HybridUnicornTritonResult:
        """Concrete prefix (Unicorn) → symbolic suffix (Triton). Warm-start symbex.

        Triton explodes on long concrete preambles (key setup, anti-debug,
        crypto init). This runs that prefix concretely at Unicorn speed, hands
        the resulting register + memory state to Triton, marks the chosen
        registers symbolic, and solves only the interesting slice. Ideal for
        serial checks where the input is mangled deterministically before the
        comparison.
        """
        try:
            if not _TRITON_AVAILABLE:
                return {"ok": False, "error": "triton not installed",
                        "error_type": "missing_dependency",
                        "note": "Install with: pip install triton-library"}
            segments, uc_arch, uc_mode, bits = _prepare()
            conc_end = parse_address(concrete_end)
            sym_start = parse_address(symbolic_start)
            sym_end = parse_address(symbolic_end)
            start_ea = parse_address(start) if start else (
                _gather_entry() or conc_end)
            sregs = normalize_list_input(sym_regs)

            t0 = time.time()
            conc = _emulate_impl(
                segments, uc_arch, uc_mode, bits,
                start_ea, conc_end, regs, _DEFAULT_STACK_SIZE, max_insns, timeout_ms,
            )
            conc.pop("_controller", None)
            conc_ms = int((time.time() - t0) * 1000)

            t1 = time.time()
            sym = _triton_handoff(
                conc.get("regs", {}), conc.get("memory_writes", []),
                sym_start, sym_end, sregs, sym_max_insns, solve_timeout_ms)
            sym_ms = int((time.time() - t1) * 1000)

            return {
                "ok": bool(sym.get("ok", False)),
                "concrete_phase": {
                    "insns_executed": conc.get("insns_executed", 0),
                    "stop_reason": conc.get("stop_reason"),
                    "regs_handed_off": conc.get("regs", {}),
                    "time_ms": conc_ms,
                },
                "symbolic_phase": {**sym, "time_ms": sym_ms},
                "engines_used": ["unicorn", "triton"],
                "note": (
                    "Solved the symbolic slice — see symbolic_phase.solution."
                    if sym.get("sat") else
                    "Concrete prefix ran; Triton produced no satisfying model "
                    "(slice may be unconstrained or UNSAT — widen sym_regs or the slice)."),
            }
        except Exception as e:
            return tool_error(e, context="hybrid_unicorn_triton_analyze")

    # =====================================================================
    # H.2 — hybrid_unicorn_miasm_hot_blocks
    # =====================================================================

    @idasync
    def _miasm_lift_blocks(block_addrs: list[int]) -> dict:
        """Lift + symbolically simplify a set of blocks (main-thread phase)."""
        from . import api_miasm as M
        if not getattr(M, "MIASM_AVAILABLE", False):
            return {"ok": False, "error": "miasm not installed", "blocks": []}
        from miasm.ir.symbexec import SymbolicExecutionEngine
        from miasm.expr.simplifications import expr_simp

        out: list[dict] = []
        for ea in block_addrs:
            entry = {"addr": hex(ea)}
            try:
                data = M._manager.get_bytes(ea, ea + 256)
                if not data:
                    entry["error"] = "no bytes"
                    out.append(entry)
                    continue
                mdis, loc_db = M._manager.get_mdis(data, ea)
                asm_block = mdis.dis_block(ea)
                lifter = M._manager.machine.lifter_model_call(loc_db)
                ircfg = lifter.new_ircfg()
                lifter.add_asmblock_to_ircfg(asm_block, ircfg)
                sb = SymbolicExecutionEngine(lifter)
                for _, irblock in M._iter_ircfg_blocks(ircfg):
                    sb.eval_updt_irblock(irblock)
                regs: dict[str, str] = {}
                for dest, expr in sb.symbols.items():
                    try:
                        simp = expr_simp(expr)
                    except Exception:
                        simp = expr
                    if str(dest) != str(simp):
                        regs[str(dest)] = str(simp)
                entry["simplified_effects"] = regs
            except Exception as e:
                entry["error"] = str(e)
            out.append(entry)
        return {"ok": True, "blocks": out}

    @tool
    def hybrid_unicorn_miasm_hot_blocks(
        start: Annotated[str, "Start address (hex)."],
        end: Annotated[str, "Stop address (exclusive, hex)."],
        regs: Annotated[dict | None, "Initial register values."] = None,
        min_executions: Annotated[int, "Min executions for a block to be 'hot' (default 1)."] = 1,
        max_blocks: Annotated[int, "Max hot blocks to lift (default 40)."] = 40,
        max_insns: Annotated[int, "Instruction cap (default 200000)."] = 200000,
        timeout_ms: Annotated[int, "Timeout in ms (default 8000)."] = 8000,
    ) -> HybridUnicornMiasmResult:
        """Trace concretely (Unicorn) → lift only the executed blocks (Miasm).

        Static Miasm lifting wastes effort on dead obfuscation blocks (and may
        choke on intentionally-broken handlers). This records which basic
        blocks actually execute for the given input, then lifts and simplifies
        only those — fast and reliable on VM-protected code where most handlers
        are dormant for any one program.
        """
        try:
            if not _MIASM_AVAILABLE:
                return {"ok": False, "error": "miasm not installed",
                        "error_type": "missing_dependency",
                        "note": "Install with: pip install miasm future"}
            segments, uc_arch, uc_mode, bits = _prepare()
            start_ea = parse_address(start)
            end_ea = parse_address(end)

            ctl = _EmuController(segments, uc_arch, uc_mode, bits)
            ctl.setup_stack()
            ctl.install_default_hooks(record_writes=False)
            ctl.emu.hook_add(UC_HOOK_CODE, ctl.count_hook)
            _set_regs(ctl.emu, ctl.reg_map, regs)

            block_counts: dict[int, int] = {}
            total_blocks = {"n": 0}

            def _on_block(uc, address, size, user_data):
                total_blocks["n"] += 1
                block_counts[address] = block_counts.get(address, 0) + 1

            ctl.emu.hook_add(UC_HOOK_BLOCK, _on_block)
            ctl.run(start_ea, end_ea, max_insns, timeout_ms)

            hot = sorted(
                (a for a, c in block_counts.items() if c >= min_executions),
                key=lambda a: -block_counts[a],
            )[:max_blocks]

            lifted = _miasm_lift_blocks(hot)
            blocks_out = []
            for b in lifted.get("blocks", []):
                ea = int(b["addr"], 16)
                blocks_out.append({**b, "execution_count": block_counts.get(ea, 0)})
            blocks_out.sort(key=lambda b: -b.get("execution_count", 0))

            dead = len([1 for a, c in block_counts.items() if c < min_executions])
            return {
                "ok": True,
                "total_blocks_executed": total_blocks["n"],
                "unique_blocks_executed": len(block_counts),
                "hot_blocks_lifted": len([b for b in blocks_out if "error" not in b]),
                "blocks": blocks_out,
                "deobfuscation_summary": (
                    f"{len(hot)} hot block(s) lifted; "
                    f"{dead} block(s) below the execution threshold skipped."),
                "note": "simplified_effects shows each block's net register/memory effect.",
            }
        except Exception as e:
            return tool_error(e, context="hybrid_unicorn_miasm_hot_blocks")

    # =====================================================================
    # H.3 — hybrid_unicorn_networkx_exec_graph
    # =====================================================================

    @tool
    def hybrid_unicorn_networkx_exec_graph(
        start: Annotated[str, "Start address (hex)."],
        end: Annotated[str, "Stop address (exclusive, hex)."],
        reg_sets: Annotated[
            list[dict] | None,
            "Per-iteration register states: [{'rdi':'0x1'}, {...}]. Default: one empty run.",
        ] = None,
        max_insns: Annotated[int, "Per-iteration instruction cap (default 100000)."] = 100000,
        timeout_ms: Annotated[int, "Per-iteration timeout in ms (default 5000)."] = 5000,
    ) -> HybridUnicornNxResult:
        """Multi-trace execution (Unicorn) → execution-graph analysis (NetworkX).

        Runs the code once per register set, building a weighted block-
        transition graph, then applies NetworkX: betweenness centrality
        surfaces VM dispatchers (high fan-in + fan-out), strongly-connected
        components surface loops (the tightest = crypto rounds), and high-fan-
        out nodes flag handler dispatch tables. Reveals dynamic structure that
        static CFG analysis misses.
        """
        try:
            if not _NETWORKX_AVAILABLE:
                return {"ok": False, "error": "networkx not installed",
                        "error_type": "missing_dependency",
                        "note": "Install with: pip install networkx>=3.0"}
            import networkx as nx
            segments, uc_arch, uc_mode, bits = _prepare()
            start_ea = parse_address(start)
            end_ea = parse_address(end)
            iters = reg_sets if reg_sets else [None]

            G = nx.DiGraph()
            exec_counts: dict[int, int] = {}

            for regs in iters:
                ctl = _EmuController(segments, uc_arch, uc_mode, bits)
                ctl.setup_stack()
                ctl.install_default_hooks(record_writes=False)
                _set_regs(ctl.emu, ctl.reg_map, regs)
                prev = {"addr": None}

                def _on_block(uc, address, size, user_data):
                    exec_counts[address] = exec_counts.get(address, 0) + 1
                    if not G.has_node(address):
                        G.add_node(address, size=size, exec_count=0)
                    G.nodes[address]["exec_count"] = exec_counts[address]
                    p = prev["addr"]
                    if p is not None and p != address:
                        if G.has_edge(p, address):
                            G[p][address]["count"] += 1
                        else:
                            G.add_edge(p, address, count=1)
                    prev["addr"] = address

                ctl.emu.hook_add(UC_HOOK_BLOCK, _on_block)
                ctl.emu.hook_add(UC_HOOK_CODE, ctl.count_hook)
                ctl.run(start_ea, end_ea, max_insns, timeout_ms)

            if G.number_of_nodes() == 0:
                return {"ok": True, "nodes": 0, "edges": 0,
                        "iterations_run": len(iters),
                        "bottleneck_nodes": [], "loops": [],
                        "dispatcher_candidates": [], "dead_blocks": [],
                        "note": "No blocks executed — check start/end and register setup."}

            # Betweenness centrality → bottleneck / dispatcher candidates.
            try:
                bc = nx.betweenness_centrality(G, weight=None)
            except Exception:
                bc = {n: 0.0 for n in G.nodes}

            bottlenecks = []
            for n in sorted(G.nodes, key=lambda x: -bc.get(x, 0.0))[:5]:
                bottlenecks.append({
                    "addr": hex(n),
                    "in_degree": G.in_degree(n),
                    "out_degree": G.out_degree(n),
                    "exec_count": G.nodes[n].get("exec_count", 0),
                    "betweenness": round(bc.get(n, 0.0), 4),
                    "note": ("high fan-in/fan-out — likely VM dispatcher"
                             if G.out_degree(n) >= 4 and G.in_degree(n) >= 4
                             else "central node"),
                })

            dispatchers = [hex(n) for n in G.nodes if G.out_degree(n) >= 4]

            loops = []
            for scc in nx.strongly_connected_components(G):
                if len(scc) >= 2:
                    nodes = sorted(scc)
                    min_iter = min(G.nodes[n].get("exec_count", 0) for n in nodes)
                    loops.append({
                        "type": "scc",
                        "nodes": [hex(n) for n in nodes[:20]],
                        "size": len(scc),
                        "min_iterations": min_iter,
                        "note": ("tight loop — probable crypto round"
                                 if len(scc) <= 4 else "loop region"),
                    })
            # self-loops too
            for n in nx.nodes_with_selfloops(G):
                loops.append({
                    "type": "self_loop", "nodes": [hex(n)],
                    "size": 1,
                    "min_iterations": G.nodes[n].get("exec_count", 0),
                    "note": "single-block loop (e.g. rep/string op or tight decrypt loop)",
                })
            loops.sort(key=lambda l: l.get("size", 0))

            return {
                "ok": True,
                "nodes": G.number_of_nodes(),
                "edges": G.number_of_edges(),
                "iterations_run": len(iters),
                "bottleneck_nodes": bottlenecks,
                "loops": loops[:20],
                "dispatcher_candidates": dispatchers[:20],
                "dead_blocks": [],
                "note": (f"{G.number_of_nodes()} blocks, {len(loops)} loop region(s), "
                         f"{len(dispatchers)} dispatcher candidate(s). "
                         "Bottleneck nodes are the best symbolic-execution targets."),
            }
        except Exception as e:
            return tool_error(e, context="hybrid_unicorn_networkx_exec_graph")

