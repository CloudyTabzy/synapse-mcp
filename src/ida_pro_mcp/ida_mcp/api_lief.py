"""LIEF binary format analysis and modification tools.

Provides unified PE/ELF/Mach-O parsing, modification, PE Authenticode
verification, Rich Header decoding, CFG guard table analysis, and an IDA-
bridge tool that compares LIEF's raw parse against the loaded IDB.

Requires: pip install lief>=0.15.0
Extended features (DWARF/PDB): LIEF Extended commercial license.
"""
from __future__ import annotations

import collections
import fnmatch
import hashlib
import math
import os
from typing import Annotated, NotRequired, TypedDict

import idaapi
import ida_name
import idc
import idautils

from .rpc import tool, unsafe
from .sync import idasync
from .utils import tool_error, item_error, normalize_list_input

# ---------------------------------------------------------------------------
# Optional imports
# ---------------------------------------------------------------------------

try:
    import lief as _lief
    LIEF_AVAILABLE = True
except ImportError:
    _lief = None  # type: ignore[assignment]
    LIEF_AVAILABLE = False

LIEF_EXTENDED_AVAILABLE = False
if LIEF_AVAILABLE:
    # lief.dwarf is importable even on the free build (stub module), so
    # import success is not a reliable indicator. Use the official attribute.
    LIEF_EXTENDED_AVAILABLE = bool(getattr(_lief, "__extended__", False))

YARA_AVAILABLE = False
_yara = None  # type: ignore[assignment]
try:
    import yara as _yara  # type: ignore[import-not-found]
    YARA_AVAILABLE = True
except ImportError:
    pass

# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


_IDA_DB_EXTENSIONS = frozenset({".i64", ".idb", ".id0", ".id1", ".nam", ".til"})


def _resolve_lief_path(file_path: str) -> str:
    """Return file_path if given, else the IDB's source binary path.

    Raises ValueError when the resolved path is an IDA database file so that
    every lief_* tool gives an actionable error instead of a raw LIEF parse
    failure.  All lief tool outer try/except blocks propagate this naturally.
    """
    path = file_path if file_path else (idaapi.get_input_file_path() or "")
    if not path:
        return path
    _, ext = os.path.splitext(path.lower())
    if ext in _IDA_DB_EXTENSIONS:
        tip = ""
        try:
            src = idaapi.get_input_file_path() or ""
            if src and src != path:
                tip = f" IDA source binary: {src}"
        except Exception:
            pass
        raise ValueError(
            f"Path is an IDA database ({ext}), not a parseable binary. "
            f"Pass the source PE/ELF/Mach-O path instead.{tip}"
        )
    return path


def _entropy_class(ent: float | None) -> tuple[str, str]:
    """Return (entropy_class, recommendation) for a section entropy value."""
    if ent is None:
        return ("unknown", "analyze")
    if ent > 7.2:
        return ("encrypted", "dump_at_runtime")
    if ent > 6.0:
        return ("compressed", "dump_at_runtime")
    if ent > 4.5:
        return ("code", "analyze")
    return ("data", "skip")


def _lief_write(binary, output_path: str) -> None:
    """Write a LIEF binary to disk, using the simplest available API.

    Prefers binary.write() (LIEF 0.16+) over the explicit Builder pattern to
    avoid config_t constructor incompatibilities across LIEF minor versions.
    Falls back to the old Builder API for LIEF 0.15.
    """
    if hasattr(binary, "write") and callable(binary.write):
        binary.write(output_path)
    else:
        # LIEF 0.15 fallback — Builder took binary positionally without config
        if isinstance(binary, _lief.PE.Binary):
            builder = _lief.PE.Builder(binary)
        else:
            builder = _lief.ELF.Builder(binary)
        builder.build()
        builder.write(output_path)


def _format_name(binary) -> str:
    """Return a human-readable format string for a parsed lief.Binary."""
    if not LIEF_AVAILABLE or binary is None:
        return "unknown"
    try:
        # isinstance is reliable across all LIEF versions; enum names changed in 0.17
        if isinstance(binary, _lief.PE.Binary):
            return "PE"
        if isinstance(binary, _lief.ELF.Binary):
            return "ELF"
        if hasattr(_lief, "MachO") and isinstance(binary, _lief.MachO.Binary):
            return "MachO"
        if hasattr(_lief, "COFF") and isinstance(binary, _lief.COFF.Binary):
            return "COFF"
        # Fallback: derive from the format enum string ("FORMATS.PE" → "PE")
        return str(getattr(binary, "format", "unknown")).split(".")[-1]
    except Exception:
        return "unknown"


def _section_is_executable(section) -> bool:
    """Return True if a LIEF section has execute permissions."""
    if not LIEF_AVAILABLE:
        return False
    try:
        if hasattr(section, "characteristics_lists"):
            return _lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE in section.characteristics_lists
        if hasattr(section, "flags_list"):
            return _lief.ELF.Section.FLAGS.EXECINSTR in section.flags_list
    except Exception:
        pass
    return False


def _entropy(data: bytes) -> float:
    """Shannon entropy of a byte sequence, rounded to 4 decimal places."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    h = 0.0
    for f in freq:
        if f:
            p = f / n
            h -= p * math.log2(p)
    return round(h, 4)


def _extract_strings(
    data: bytes,
    offset_base: int,
    min_len: int,
    section_name: str,
    encoding: str,
    results: list,
    limit: int,
) -> bool:
    """Extract ASCII and/or UTF-16LE strings from a byte region.

    Returns True when the limit is hit.
    """
    if not data:
        return False
    if encoding in ("ascii", "both"):
        i = 0
        while i < len(data):
            j = i
            while j < len(data) and 32 <= data[j] < 127:
                j += 1
            if j - i >= min_len:
                results.append({
                    "value": data[i:j].decode("ascii", errors="replace"),
                    "encoding": "ascii",
                    "offset": offset_base + i,
                    "section": section_name,
                })
                if len(results) >= limit:
                    return True
            i = j + 1
    if encoding in ("utf16", "both"):
        i = 0
        while i + 1 < len(data):
            j = i
            while j + 1 < len(data) and 32 <= data[j] < 127 and data[j + 1] == 0:
                j += 2
            if (j - i) // 2 >= min_len:
                results.append({
                    "value": data[i:j].decode("utf-16-le", errors="replace"),
                    "encoding": "utf16",
                    "offset": offset_base + i,
                    "section": section_name,
                })
                if len(results) >= limit:
                    return True
            if i + 1 < len(data) and data[i + 1] == 0:
                i += 2
            else:
                i += 1
    return False


_AUTO_PREFIXES = (
    "sub_", "off_", "dword_", "word_", "byte_", "unk_", "loc_",
    "nullsub_", "j__", "j_sub_", "qword_", "xmmword_", "ymmword_",
    "stru_", "asc_", "def_",
)


def _is_auto_name(name: str) -> bool:
    return not name or any(name.startswith(p) for p in _AUTO_PREFIXES)


def _try_demangle(name: str) -> str | None:
    """Demangle a C++ symbol name.  Returns None (never a string "None") if
    demangling fails or produces no improvement over the raw name.

    Strategy:
    1. LIEF's built-in demangler (lief.demangle / lief.PE.demangle) — present
       in LIEF 0.15+ but may return None for names it cannot handle.
    2. IDA's own demangler (ida_name.demangle_name) — always available inside
       the plugin and handles MSVC ?-mangled names reliably.
    """
    if not name:
        return None
    # --- LIEF demangler ---
    try:
        demangle_fn = (
            getattr(_lief, "demangle", None)
            or getattr(getattr(_lief, "PE", None), "demangle", None)
        )
        if demangle_fn:
            result = demangle_fn(name)   # may return None — do NOT str() blindly
            if result is not None:
                d = str(result)
                if d and d != name:
                    return d
    except Exception:
        pass
    # --- IDA demangler fallback (handles MSVC ?-names that LIEF may miss) ---
    try:
        d = ida_name.demangle_name(name, ida_name.MNG_LONG_FORM)
        if d and d != name:
            return d
    except Exception:
        pass
    return None


def _match_pattern(raw: str | None, pattern: str) -> bool:
    """Return True if raw name (or its demangled form) matches pattern.

    Pattern rules (case-insensitive):
    - Contains no wildcards → treated as substring (*pattern*)
    - Contains * or ?       → standard glob (fnmatch)
    """
    if not raw:
        return False
    p = pattern.lower()
    if "*" not in p and "?" not in p:
        p = f"*{p}*"
    raw_l = raw.lower()
    if fnmatch.fnmatch(raw_l, p):
        return True
    dem = _try_demangle(raw)
    if dem:
        return fnmatch.fnmatch(dem.lower(), p)
    return False


# Rich Header product ID table (subset of public database)
# Format: {product_id: (component_name, vs_version_hint)}
_RICH_PRODUCT_NAMES: dict[int, tuple[str, str]] = {
    0x0001: ("Import Library",    "MSVC"),
    0x0002: ("Linker",            "MSVC 5.0 (VS 97)"),
    0x0006: ("MASM",              "VS 6.0"),
    0x0007: ("Linker",            "VS 6.0"),
    0x0008: ("Resource Compiler", "VS 6.0"),
    0x000A: ("C/C++ Compiler",    "VS 6.0"),
    0x000B: ("ASM Compiler",      "VS 6.0"),
    0x000E: ("Linker",            "VS 7.0 (2002)"),
    0x000F: ("C/C++ Compiler",    "VS 7.0 (2002)"),
    0x0019: ("Linker",            "VS 7.1 (2003)"),
    0x001C: ("C/C++ Compiler",    "VS 7.1 (2003)"),
    0x005E: ("MASM",              "VS 8.0 (2005)"),
    0x0060: ("Linker",            "VS 8.0 (2005)"),
    0x0061: ("C/C++ Compiler",    "VS 8.0 (2005)"),
    0x0083: ("Linker",            "VS 9.0 (2008)"),
    0x0084: ("C/C++ Compiler",    "VS 9.0 (2008)"),
    0x009D: ("Linker",            "VS 10.0 (2010)"),
    0x009E: ("C/C++ Compiler",    "VS 10.0 (2010)"),
    0x00AA: ("Linker",            "VS 11.0 (2012)"),
    0x00AB: ("C/C++ Compiler",    "VS 11.0 (2012)"),
    0x00B9: ("Linker",            "VS 12.0 (2013)"),
    0x00BA: ("C/C++ Compiler",    "VS 12.0 (2013)"),
    0x00C7: ("Linker",            "VS 14.0 (2015)"),
    0x00C8: ("C/C++ Compiler",    "VS 14.0 (2015)"),
    0x00D6: ("Linker",            "VS 15.x (2017)"),
    0x00D7: ("C/C++ Compiler",    "VS 15.x (2017)"),
    0x00E3: ("Linker",            "VS 16.x (2019)"),
    0x00E4: ("C/C++ Compiler",    "VS 16.x (2019)"),
    0x00EC: ("Linker",            "VS 17.x (2022)"),
    0x00ED: ("C/C++ Compiler",    "VS 17.x (2022)"),
}

# IDA database extensions — LIEF cannot parse these as PE/ELF binaries
_IDA_EXTENSIONS = frozenset({".i64", ".idb", ".id0", ".id1", ".id2", ".nam", ".til"})

# IDA-created synthetic segments that have no direct counterpart in the raw binary.
# These should not be flagged as anomalies in lief_compare_to_idb.
_IDA_SYNTHETIC_SEGMENTS = frozenset({
    "HEADER",    # PE header segment IDA creates
    ".idata",    # IDA's synthetic view of the import table (merged into .text in some compilers)
    "extern",    # IDA-generated external thunk segment
    "LOAD",      # ELF LOAD segment name used by some IDA loaders
    "INTERP",    # ELF interpreter path segment
    "_INIT_",    # ELF .init section
    "_FINI_",    # ELF .fini section
    ".plt",      # ELF PLT stubs (sometimes split by IDA)
    ".got",      # ELF GOT
    ".got.plt",  # ELF combined GOT/PLT
})

# ---------------------------------------------------------------------------
# TypedDicts
# ---------------------------------------------------------------------------


class LiefStatusResult(TypedDict, total=False):
    ok: bool
    available: bool
    version: str
    extended_available: bool
    supported_formats: list[str]
    error: str


class LiefInfoResult(TypedDict, total=False):
    ok: bool
    format: str
    arch: str
    bits: int
    is_executable: bool
    is_library: bool
    is_pie: bool
    nx: bool
    entrypoint: str
    imagebase: str
    section_count: int
    import_count: int
    export_count: int
    has_debug_info: bool
    has_signature: bool
    header: dict
    error: str
    error_type: str
    hint: str


class ChecksecResult(TypedDict, total=False):
    ok: bool
    format: str
    nx: bool
    dynamic_base: bool
    high_entropy_va: bool
    force_integrity: bool
    safe_seh: bool
    cfg: bool
    authenticode: bool
    relro: str
    pie: bool
    canary: bool
    score: int
    summary: list[str]
    error: str
    error_type: str
    hint: str


class LiefSectionEntry(TypedDict, total=False):
    name: str
    virtual_address: str
    virtual_size: int
    file_offset: int
    file_size: int
    entropy: float
    entropy_class: str      # "encrypted" | "compressed" | "code" | "data" | "unknown"
    recommendation: str     # "dump_at_runtime" | "analyze" | "skip"
    characteristics: list[str]
    is_executable: bool
    is_readable: bool
    is_writable: bool
    content_hex: str


class LiefSectionsResult(TypedDict, total=False):
    ok: bool
    format: str
    sections: list[LiefSectionEntry]
    total: int
    error: str
    error_type: str
    hint: str


class LiefImportEntry(TypedDict, total=False):
    name: str | None
    ordinal: int | None
    iat_address: str
    is_delay_import: bool
    demangled_name: str | None


class LiefImportLib(TypedDict):
    name: str
    is_delay_import: bool
    functions: list[LiefImportEntry]


class LiefImportsResult(TypedDict, total=False):
    ok: bool
    format: str
    libraries: list[LiefImportLib]
    total_imports: int
    matched_imports: int
    delay_import_count: int
    needed_libraries: list[str]   # ELF only: all NEEDED library names from .dynamic
    filter_pattern: str
    library_filter: str
    error: str
    error_type: str
    hint: str


class LiefExportEntry(TypedDict, total=False):
    name: str | None
    ordinal: int
    address: str
    is_forwarded: bool
    forwarded_to: str | None
    demangled_name: str | None


class LiefExportsResult(TypedDict, total=False):
    ok: bool
    format: str
    dll_name: str | None
    base_ordinal: int
    exports: list[LiefExportEntry]
    total_exports: int
    matched_exports: int
    filter_pattern: str
    error: str
    error_type: str
    hint: str


class LiefIatResolveResult(TypedDict, total=False):
    ok: bool
    dll_name: str
    func_name: str
    demangled_name: str | None
    ordinal: int | None
    is_ordinal: bool
    is_delay_import: bool
    iat_va: str        # VA using PE's own imagebase
    iat_va_idb: str    # VA rebased to IDA's loaded imagebase
    idb_name: str | None  # IDA symbol at that address (e.g. "__imp_CreateFileW")
    error: str
    error_type: str
    hint: str


class LiefStringEntry(TypedDict, total=False):
    value: str
    encoding: str
    offset: int
    section: str


class LiefStringsResult(TypedDict, total=False):
    ok: bool
    strings: list[LiefStringEntry]
    total: int
    truncated: bool
    error: str
    error_type: str
    hint: str


class LiefTlsCallbackEntry(TypedDict, total=False):
    address: str
    ida_name: str | None


class LiefTlsResult(TypedDict, total=False):
    ok: bool
    format: str
    has_tls: bool
    raw_data_start: str
    raw_data_end: str
    index_address: str
    callbacks: list[LiefTlsCallbackEntry]
    callback_count: int
    error: str
    error_type: str
    hint: str


class LiefSignerInfo(TypedDict, total=False):
    issuer: str
    subject: str
    serial: str
    not_before: str
    not_after: str
    signature_algorithm: str


class LiefCertInfo(TypedDict, total=False):
    subject: str
    issuer: str
    serial: str
    not_before: str
    not_after: str
    is_ca: bool


class LiefSignatureResult(TypedDict, total=False):
    ok: bool
    format: str
    has_signature: bool
    signature_count: int
    verification_result: str
    is_valid: bool
    authentihash_computed: str
    authentihash_signed: str
    hashes_match: bool
    digest_algorithm: str
    signers: list[LiefSignerInfo]
    certificates: list[LiefCertInfo]
    has_countersignature: bool
    countersign_timestamp: str | None
    error: str
    error_type: str
    hint: str


class LiefRichEntry(TypedDict):
    id: int
    build: int
    count: int
    product_name: str
    vs_version: str


class LiefRichHeaderResult(TypedDict, total=False):
    ok: bool
    format: str
    has_rich_header: bool
    xor_key: str
    raw_hash: str
    entries: list[LiefRichEntry]
    compiler_guess: str
    linker_version: str | None
    error: str
    error_type: str
    hint: str


class LiefOverlayResult(TypedDict, total=False):
    ok: bool
    format: str
    has_overlay: bool
    overlay_offset: int
    overlay_size: int
    overlay_hex: str
    overlay_type: str | None
    overlay_mime: str | None
    entropy: float
    notes: list[str]
    error: str
    error_type: str
    hint: str


class LiefGuardEntry(TypedDict, total=False):
    rva: str
    address: str
    flags: list[str]
    ida_name: str | None


class LiefGuardResult(TypedDict, total=False):
    ok: bool
    format: str
    cfg_enabled: bool
    guard_cf_functions: list[LiefGuardEntry]
    guard_cf_count: int
    guard_longjump_targets: list[str]
    guard_eh_cont_targets: list[str]
    notes: list[str]
    error: str
    error_type: str
    hint: str


class LiefEntryPointDiff(TypedDict):
    lief: str
    ida: str
    match: bool


class LiefSectionSizeMismatch(TypedDict):
    name: str
    lief_size: int
    ida_size: int


class LiefSectionDiff(TypedDict, total=False):
    lief_only: list[str]
    ida_only: list[str]
    size_mismatches: list[LiefSectionSizeMismatch]


class LiefImportDiff(TypedDict):
    lief_total: int
    ida_total: int
    lief_only: list[str]
    ida_only: list[str]


class LiefExportDiff(TypedDict):
    lief_total: int
    ida_total: int
    mismatch_count: int


class LiefIdbDiffResult(TypedDict, total=False):
    ok: bool
    format: str
    entry_point: LiefEntryPointDiff
    sections: LiefSectionDiff
    imports: LiefImportDiff
    exports: LiefExportDiff
    anomalies: list[str]
    error: str
    error_type: str
    hint: str


class LiefModifyResult(TypedDict, total=False):
    ok: bool
    output_path: str
    action: str
    detail: str
    original_size: int
    output_size: int
    error: str
    error_type: str
    hint: str


class LiefYaraMatch(TypedDict, total=False):
    rule: str
    tags: list[str]
    meta: dict
    strings: list[dict]


class LiefYaraSectionResult(TypedDict, total=False):
    section: str
    virtual_address: str
    size: int
    entropy: float
    is_executable: bool
    rules_matched: list[str]
    match_details: list[LiefYaraMatch]


class HybridLiefYaraResult(TypedDict, total=False):
    ok: bool
    sections_scanned: int
    total_rule_hits: int
    matches: list[LiefYaraSectionResult]
    error: str
    error_type: str
    hint: str


class HybridExploitAssessResult(TypedDict, total=False):
    ok: bool
    checksec_score: int
    missing_mitigations: list[str]
    cfg_guard_count: int
    is_signed: bool
    signature_valid: bool | None
    has_overlay: bool
    overlay_type: str | None
    exploitability_rating: str
    attack_surface: list[str]
    error: str
    error_type: str
    hint: str


class LiefSymbolChange(TypedDict):
    address: str
    old_name: str
    new_name: str
    applied: bool
    source: str


class HybridSymbolSyncResult(TypedDict, total=False):
    ok: bool
    proposed_count: int
    applied_count: int
    skipped_count: int
    not_found_count: int
    changes: list[LiefSymbolChange]
    error: str
    error_type: str
    hint: str


# ---------------------------------------------------------------------------
# lief_status — always registered even when lief is absent
# ---------------------------------------------------------------------------


@tool
@idasync
def lief_status() -> LiefStatusResult:
    """Probe LIEF library availability and version.

    Always registered regardless of whether lief is installed.
    extended_available is True only when LIEF Extended (commercial) is present."""
    if not LIEF_AVAILABLE:
        return {"ok": True, "available": False, "version": "", "extended_available": False}
    return {
        "ok": True,
        "available": True,
        "version": getattr(_lief, "__version__", "unknown"),
        "extended_available": LIEF_EXTENDED_AVAILABLE,
        "supported_formats": ["PE", "ELF", "MachO", "COFF"],
    }


# ---------------------------------------------------------------------------
# All remaining tools — only registered when lief is installed
# ---------------------------------------------------------------------------

if LIEF_AVAILABLE:

    # -----------------------------------------------------------------------
    # H.1 — lief_info
    # -----------------------------------------------------------------------

    @tool
    @idasync
    def lief_info(
        file_path: Annotated[str, "Path to binary file; empty string uses the IDB source file"] = "",
    ) -> LiefInfoResult:
        """Parse a binary and return high-level metadata: format, architecture,
        entry point, image base, section/import/export counts, and format-
        specific header fields. Works for PE, ELF, Mach-O, and COFF."""
        try:
            path = _resolve_lief_path(file_path)
            binary = _lief.parse(path)
            if binary is None:
                return {**tool_error(ValueError(f"LIEF could not parse: {path}")), "ok": False}

            fmt = _format_name(binary)
            ep = getattr(binary, "entrypoint", 0) or 0
            is_pie = bool(getattr(binary, "is_pie", False))
            nx = bool(getattr(binary, "nx", False))

            # Section / import / export counts (best-effort)
            sec_count = len(list(binary.sections))
            imp_count = 0
            exp_count = 0

            bits = 64
            arch = "unknown"
            imagebase = "0x0"
            header: dict = {}
            is_exec = False
            is_lib = False
            has_dbg = False
            has_sig = False

            if isinstance(binary, _lief.PE.Binary):
                pe = binary
                mach = pe.header.machine
                mach_str = str(mach).split(".")[-1]
                bits = 32 if "I386" in mach_str or "ARM" == mach_str else 64
                arch_map = {
                    "AMD64": "x86_64", "I386": "i386",
                    "ARM64": "AArch64", "ARM": "ARM",
                    "RISCV64": "RISC-V 64", "RISCV32": "RISC-V 32",
                }
                arch = arch_map.get(mach_str, mach_str)
                imagebase = hex(pe.optional_header.imagebase)
                # pe.entrypoint (inherited from lief.Binary) returns the absolute VA;
                # the old addressof_entry_point attribute name was wrong — it's
                # addressof_entrypoint (no underscore), but using the parent property
                # is simpler and version-stable.
                ep = pe.entrypoint
                sub = str(pe.optional_header.subsystem).split(".")[-1]
                is_exec = "WINDOWS_GUI" in sub or "WINDOWS_CUI" in sub
                _pe_chars = (
                    getattr(pe.header, "characteristics_list", None)
                    or getattr(pe.header, "characteristics_lists", None)
                    or []
                )
                is_lib = sub == "NATIVE" or bool(
                    _pe_chars and any("DLL" in str(c) for c in _pe_chars)
                )
                for imp in pe.imports:
                    imp_count += len(list(imp.entries))
                exp = pe.get_export()
                if exp:
                    exp_count = len(list(exp.entries))
                has_dbg = pe.has_debug
                has_sig = bool(pe.signatures)
                _dll_chars = (
                    getattr(pe.optional_header, "dll_characteristics_lists", None)
                    or getattr(pe.optional_header, "dll_characteristics_list", None)
                    or []
                )
                header = {
                    "machine": mach_str,
                    "characteristics": [str(c).split(".")[-1] for c in _pe_chars],
                    "time_date_stamp": (
                        getattr(pe.header, "time_date_stamps", None)
                        or getattr(pe.header, "time_date_stamp", 0)
                        or 0
                    ),
                    "subsystem": sub,
                    "dll_characteristics": [str(c).split(".")[-1] for c in _dll_chars],
                }

            elif isinstance(binary, _lief.ELF.Binary):
                elf = binary
                mach = elf.header.machine_type
                mach_str = str(mach).split(".")[-1]
                arch_map_elf = {
                    "x86_64": "x86_64", "i386": "i386",
                    "AARCH64": "AArch64", "ARM": "ARM",
                    "RISCV": "RISC-V", "MIPS": "MIPS",
                }
                arch = arch_map_elf.get(mach_str, mach_str)
                bits = 32 if elf.header.identity_class == _lief.ELF.Header.CLASS.ELF32 else 64
                ftype = str(elf.header.file_type).split(".")[-1]
                is_exec = ftype == "EXECUTABLE"
                is_lib = ftype == "SHARED"
                undef_syms = [s for s in elf.dynamic_symbols
                              if str(getattr(s, "shndx", "")).endswith("UNDEF")]
                imp_count = len(undef_syms)
                exp_syms = [s for s in elf.dynamic_symbols
                            if getattr(s, "exported", False)]
                exp_count = len(exp_syms)
                header = {
                    "machine": mach_str,
                    "file_type": ftype,
                    "os_abi": str(elf.header.os_abi).split(".")[-1],
                    "flags": elf.header.flags,
                }

            return {
                "ok": True,
                "format": fmt,
                "arch": arch,
                "bits": bits,
                "is_executable": is_exec,
                "is_library": is_lib,
                "is_pie": is_pie,
                "nx": nx,
                "entrypoint": hex(ep),
                "imagebase": imagebase,
                "section_count": sec_count,
                "import_count": imp_count,
                "export_count": exp_count,
                "has_debug_info": has_dbg,
                "has_signature": has_sig,
                "header": header,
            }
        except Exception as e:
            return {**tool_error(e), "ok": False}

    # -----------------------------------------------------------------------
    # H.2 — lief_checksec
    # -----------------------------------------------------------------------

    @tool
    @idasync
    def lief_checksec(
        file_path: Annotated[str, "Path to binary file; empty string uses the IDB source file"] = "",
    ) -> ChecksecResult:
        """Check binary security mitigations (NX, ASLR, CFG, RELRO, canary, etc.).

        Returns a per-mitigation bool, a numeric score (1 point each), and a
        human-readable summary list. Supports PE and ELF formats."""
        try:
            path = _resolve_lief_path(file_path)
            binary = _lief.parse(path)
            if binary is None:
                return {**tool_error(ValueError(f"LIEF could not parse: {path}")), "ok": False}

            fmt = _format_name(binary)
            summary: list[str] = []
            score = 0

            if isinstance(binary, _lief.PE.Binary):
                pe = binary
                chars = (
                    getattr(pe.optional_header, "dll_characteristics_lists", None)
                    or getattr(pe.optional_header, "dll_characteristics_list", None)
                    or []
                )
                DLL = _lief.PE.OptionalHeader.DLL_CHARACTERISTICS

                def _has(flag) -> bool:
                    try:
                        return flag in chars
                    except Exception:
                        return False

                nx           = _has(DLL.NX_COMPAT)
                dynamic_base = _has(DLL.DYNAMIC_BASE)
                high_entropy = _has(DLL.HIGH_ENTROPY_VA)
                force_integ  = _has(DLL.FORCE_INTEGRITY)
                cfg          = _has(DLL.GUARD_CF)
                no_seh       = _has(DLL.NO_SEH)
                authenticode = bool(pe.signatures)

                lc = pe.load_configuration
                safe_seh = (
                    not no_seh and lc is not None and
                    getattr(lc, "se_handler_count", 0) > 0
                )

                for name, val in [
                    ("NX (DEP)", nx), ("ASLR (dynamic base)", dynamic_base),
                    ("High-entropy VA", high_entropy), ("Force integrity", force_integ),
                    ("CFG", cfg), ("SafeSEH", safe_seh), ("Authenticode", authenticode),
                ]:
                    state = "enabled" if val else "disabled"
                    summary.append(f"{name}: {state}")
                    if val:
                        score += 1

                return {
                    "ok": True, "format": "PE",
                    "nx": nx, "dynamic_base": dynamic_base,
                    "high_entropy_va": high_entropy, "force_integrity": force_integ,
                    "safe_seh": safe_seh, "cfg": cfg, "authenticode": authenticode,
                    "score": score, "summary": summary,
                }

            elif isinstance(binary, _lief.ELF.Binary):
                elf = binary

                # RELRO
                has_relro_seg = any(
                    getattr(seg.type, "name", str(seg.type)) in ("GNU_RELRO",)
                    for seg in elf.segments
                )
                has_bind_now = False
                for de in elf.dynamic_entries:
                    tag_name = getattr(de.tag, "name", str(de.tag))
                    if tag_name in ("BIND_NOW",):
                        has_bind_now = True
                        break
                    if tag_name == "FLAGS" and hasattr(de, "flags"):
                        try:
                            if _lief.ELF.DynamicEntryFlags.FLAG.BIND_NOW in de.flags:
                                has_bind_now = True
                                break
                        except Exception:
                            pass

                relro = "none"
                if has_relro_seg and has_bind_now:
                    relro = "full"
                elif has_relro_seg:
                    relro = "partial"

                # Canary
                canary = any(
                    getattr(s, "name", "") == "__stack_chk_fail"
                    for s in elf.dynamic_symbols
                )

                # NX: PT_GNU_STACK must NOT have X flag
                nx = True
                for seg in elf.segments:
                    if getattr(seg.type, "name", str(seg.type)) == "GNU_STACK":
                        try:
                            nx = not bool(seg.flags & _lief.ELF.Segment.FLAGS.X)
                        except Exception:
                            pass
                        break

                # PIE: ET_DYN
                pie = str(elf.header.file_type).split(".")[-1] == "SHARED"

                for name, val in [
                    ("NX", nx), ("PIE", pie), ("Canary", canary),
                    (f"RELRO ({relro})", relro != "none"),
                ]:
                    state = "enabled" if val else "disabled"
                    summary.append(f"{name}: {state}")
                    if val:
                        score += 1

                return {
                    "ok": True, "format": "ELF",
                    "nx": nx, "pie": pie, "canary": canary, "relro": relro,
                    "score": score, "summary": summary,
                }

            return {
                "ok": True, "format": fmt,
                "score": 0, "summary": [f"Format {fmt}: limited checksec support"],
            }
        except Exception as e:
            return {**tool_error(e), "ok": False}

    # -----------------------------------------------------------------------
    # H.3 — lief_sections
    # -----------------------------------------------------------------------

    @tool
    @idasync
    def lief_sections(
        file_path: Annotated[str, "Path to binary file; empty string uses the IDB source file"] = "",
        include_content: Annotated[bool, "Include first 512 bytes of each section as hex (default: false)"] = False,
    ) -> LiefSectionsResult:
        """List all sections with virtual address, size, entropy, permissions,
        and optional content preview. Works for PE, ELF, and Mach-O."""
        try:
            path = _resolve_lief_path(file_path)
            binary = _lief.parse(path)
            if binary is None:
                return {**tool_error(ValueError(f"LIEF could not parse: {path}")), "ok": False}

            fmt = _format_name(binary)
            entries: list[LiefSectionEntry] = []

            for sec in binary.sections:
                name = sec.name.strip("\x00") if sec.name else ""
                try:
                    ent = sec.entropy
                except Exception:
                    ent = None

                chars: list[str] = []
                is_exec = is_read = is_write = False
                try:
                    if hasattr(sec, "characteristics_lists"):
                        PE_CHARS = _lief.PE.Section.CHARACTERISTICS
                        chars = [str(c).split(".")[-1] for c in sec.characteristics_lists]
                        is_exec  = PE_CHARS.MEM_EXECUTE in sec.characteristics_lists
                        is_read  = PE_CHARS.MEM_READ    in sec.characteristics_lists
                        is_write = PE_CHARS.MEM_WRITE   in sec.characteristics_lists
                    elif hasattr(sec, "flags_list"):
                        ELF_FLAGS = _lief.ELF.Section.FLAGS
                        chars = [str(f).split(".")[-1] for f in sec.flags_list]
                        is_exec  = ELF_FLAGS.EXECINSTR in sec.flags_list
                        is_write = ELF_FLAGS.WRITE     in sec.flags_list
                        is_read  = True
                except Exception:
                    pass

                ec, rec = _entropy_class(ent)
                entry: LiefSectionEntry = {
                    "name": name,
                    "virtual_address": hex(sec.virtual_address),
                    "virtual_size": sec.virtual_size,
                    "file_offset": sec.offset,
                    "file_size": sec.size,
                    "entropy": ent,
                    "entropy_class": ec,
                    "recommendation": rec,
                    "characteristics": chars,
                    "is_executable": is_exec,
                    "is_readable": is_read,
                    "is_writable": is_write,
                }
                if include_content:
                    try:
                        preview = bytes(sec.content)[:512]
                        entry["content_hex"] = preview.hex(" ", 1)
                    except Exception:
                        pass
                entries.append(entry)

            return {"ok": True, "format": fmt, "sections": entries, "total": len(entries)}
        except Exception as e:
            return {**tool_error(e), "ok": False}

    # -----------------------------------------------------------------------
    # H.4 — lief_imports
    # -----------------------------------------------------------------------

    @tool
    @idasync
    def lief_imports(
        file_path: Annotated[str, "Path to binary file; empty string uses the IDB source file"] = "",
        include_delay: Annotated[bool, "Include delay-load imports for PE (default: true)"] = True,
        pattern: Annotated[
            str,
            "Glob/substring filter on function name or demangled name (case-insensitive). "
            "Plain text matches as substring; wildcards (* ?) use glob rules. "
            "Examples: 'CreateFile', '*RenderDevice*', '?_7Foo*'. Empty = return all.",
        ] = "",
        library_filter: Annotated[
            str,
            "Filter to a specific DLL by name (case-insensitive substring). "
            "Examples: 'kernel32', 'Core.dll'. Empty = all libraries.",
        ] = "",
    ) -> LiefImportsResult:
        """List imported libraries and functions with IAT addresses and C++ demangling.
        PE: regular + delay imports. ELF: NEEDED libraries + undefined dynamic symbols.
        Use pattern= to search by function name (glob/substring, matches raw or demangled).
        Use library_filter= to narrow to one DLL. Returns matched_imports vs total_imports
        so agents know how many entries were filtered out."""
        try:
            path = _resolve_lief_path(file_path)
            binary = _lief.parse(path)
            if binary is None:
                return {**tool_error(ValueError(f"LIEF could not parse: {path}")), "ok": False}

            fmt = _format_name(binary)
            libs: list[LiefImportLib] = []
            total = 0
            delay_count = 0
            elf_needed_all: list[str] = []  # populated in the ELF path below

            if isinstance(binary, _lief.PE.Binary):
                pe = binary
                for imp in pe.imports:
                    entries: list[LiefImportEntry] = []
                    for fn in imp.entries:
                        fname = fn.name if fn.name else None
                        entries.append({
                            "name": fname,
                            "ordinal": fn.ordinal if fn.is_ordinal else None,
                            "iat_address": hex(fn.iat_address) if fn.iat_address else "0x0",
                            "is_delay_import": False,
                            "demangled_name": _try_demangle(fname) if fname else None,
                        })
                        total += 1
                    libs.append({"name": imp.name, "is_delay_import": False, "functions": entries})

                if include_delay:
                    for dimp in pe.delay_imports:
                        entries = []
                        for fn in dimp.entries:
                            fname = fn.name if fn.name else None
                            # DelayImportEntry has no .iat_address (only ImportEntry does);
                            # .iat_value holds the raw slot value, not the slot VA.
                            iat_addr = getattr(fn, "iat_address", None)
                            entries.append({
                                "name": fname,
                                "ordinal": fn.ordinal if fn.is_ordinal else None,
                                "iat_address": hex(iat_addr) if iat_addr else "0x0",
                                "is_delay_import": True,
                                "demangled_name": _try_demangle(fname) if fname else None,
                            })
                            total += 1
                            delay_count += 1
                        libs.append({"name": dimp.name, "is_delay_import": True, "functions": entries})

            elif isinstance(binary, _lief.ELF.Binary):
                elf = binary
                # Collect NEEDED library names from the dynamic section
                needed = [
                    str(de.name) for de in elf.dynamic_entries
                    if getattr(de.tag, "name", str(de.tag)) == "NEEDED"
                ]
                # Collect undefined dynamic symbols (ELF does not map individual symbols
                # to specific libraries without GNU version info, so all symbols are listed
                # under a single synthetic entry; library_filter matches against all NEEDED
                # library names so agents can still filter by library correctly).
                undef_syms: list[LiefImportEntry] = []
                for sym in elf.dynamic_symbols:
                    shndx = str(getattr(sym, "shndx", "")).split(".")[-1]
                    if shndx == "UNDEF" and sym.name:
                        undef_syms.append({
                            "name": sym.name,
                            "ordinal": None,
                            "iat_address": "0x0",
                            "is_delay_import": False,
                            "demangled_name": _try_demangle(sym.name),
                        })
                        total += 1
                # Single entry containing all undefined symbols; name = first NEEDED lib.
                lib_entry_name = needed[0] if needed else "(dynamic)"
                if undef_syms or needed:
                    libs.append({
                        "name": lib_entry_name,
                        "is_delay_import": False,
                        "functions": undef_syms,
                    })
                elf_needed_all = needed

            # Apply filters
            lib_f = library_filter.lower()
            if lib_f:
                # For ELF the single synthetic entry is named after only the first NEEDED
                # library; match against the full NEEDED list instead so
                # library_filter="pthread" still finds libpthread symbols.
                if elf_needed_all:
                    elf_lib_match = any(lib_f in n.lower() for n in elf_needed_all)
                    libs = libs if elf_lib_match else []
                else:
                    libs = [lib for lib in libs if lib_f in lib["name"].lower()]
            matched = 0
            if pattern:
                filtered_libs: list[LiefImportLib] = []
                for lib in libs:
                    fns = [fn for fn in lib["functions"] if _match_pattern(fn.get("name"), pattern)]
                    matched += len(fns)
                    if fns:
                        filtered_libs.append({**lib, "functions": fns})
                libs = filtered_libs
            else:
                matched = sum(len(lib["functions"]) for lib in libs)

            result: LiefImportsResult = {
                "ok": True, "format": fmt, "libraries": libs,
                "total_imports": total, "matched_imports": matched,
                "delay_import_count": delay_count,
                **({"needed_libraries": elf_needed_all} if elf_needed_all else {}),
            }
            if pattern:
                result["filter_pattern"] = pattern
            if library_filter:
                result["library_filter"] = library_filter
            # Guide agents when a compound filter silently empties the result.
            if matched == 0 and total > 0:
                if pattern and library_filter:
                    result["hint"] = (
                        f"Pattern '{pattern}' matched 0 functions in library '{library_filter}'. "
                        f"Try pattern='' to see all {total} imports from that library, "
                        f"or library_filter='' to search across all {total} imports."
                    )
                elif pattern:
                    result["hint"] = (
                        f"Pattern '{pattern}' matched 0 of {total} imports. "
                        "Try a broader pattern or check spelling — matching is case-insensitive substring/glob."
                    )
                elif library_filter:
                    result["hint"] = (
                        f"library_filter='{library_filter}' matched no libraries. "
                        "Check the exact library name with library_filter='' to see all imported libraries."
                    )
            return result
        except Exception as e:
            return {**tool_error(e), "ok": False}

    # -----------------------------------------------------------------------
    # H.5 — lief_exports
    # -----------------------------------------------------------------------

    @tool
    @idasync
    def lief_exports(
        file_path: Annotated[str, "Path to binary file; empty string uses the IDB source file"] = "",
        pattern: Annotated[
            str,
            "Glob/substring filter on export name or demangled name (case-insensitive). "
            "Plain text matches as substring; wildcards (* ?) use glob rules. "
            "Examples: 'RenderDevice', '??_7URender*', '_ZN3Foo*'. Empty = return all.",
        ] = "",
    ) -> LiefExportsResult:
        """List exported symbols with ordinals, addresses, and forwarding information.
        PE: uses the export directory. ELF: uses dynamic symbols with defined binding.
        Use pattern= to filter by name (glob/substring, matches raw or demangled name).
        Returns matched_exports vs total_exports so agents know how many were filtered."""
        try:
            path = _resolve_lief_path(file_path)
            binary = _lief.parse(path)
            if binary is None:
                return {**tool_error(ValueError(f"LIEF could not parse: {path}")), "ok": False}

            fmt = _format_name(binary)

            if isinstance(binary, _lief.PE.Binary):
                pe = binary
                exp = pe.get_export()
                if exp is None:
                    return {
                        "ok": True, "format": "PE", "dll_name": None,
                        "base_ordinal": 0, "exports": [], "total_exports": 0,
                    }
                entries: list[LiefExportEntry] = []
                for fn in exp.entries:
                    name = fn.name if fn.name else None
                    is_fwd = bool(getattr(fn, "is_forwarded", False))
                    fw = fn.forward_information if is_fwd else None
                    fwd_name: str | None = None
                    if fw is not None:
                        fwd_name = (
                            getattr(fw, "function", None)
                            or getattr(fw, "function_name", None)
                        )
                    entries.append({
                        "name": name,
                        "ordinal": fn.ordinal,
                        "address": hex(fn.address),
                        "is_forwarded": is_fwd,
                        "forwarded_to": fwd_name,
                        "demangled_name": _try_demangle(name) if name else None,
                    })
                total_pe = len(entries)
                if pattern:
                    entries = [e for e in entries if _match_pattern(e.get("name"), pattern)]
                r: LiefExportsResult = {
                    "ok": True, "format": "PE",
                    "dll_name": exp.name if exp.name else None,
                    "base_ordinal": getattr(exp, "ordinal_base", 0) or 0,
                    "exports": entries,
                    "total_exports": total_pe,
                    "matched_exports": len(entries),
                }
                if pattern:
                    r["filter_pattern"] = pattern
                return r

            elif isinstance(binary, _lief.ELF.Binary):
                elf = binary
                entries = []
                for sym in elf.dynamic_symbols:
                    shndx = str(getattr(sym, "shndx", "")).split(".")[-1]
                    if shndx != "UNDEF" and getattr(sym, "exported", False) and sym.name:
                        entries.append({
                            "name": sym.name,
                            "ordinal": 0,
                            "address": hex(sym.value),
                            "is_forwarded": False,
                            "forwarded_to": None,
                            "demangled_name": _try_demangle(sym.name),
                        })
                total_elf = len(entries)
                if pattern:
                    entries = [e for e in entries if _match_pattern(e.get("name"), pattern)]
                r = {
                    "ok": True, "format": "ELF",
                    "dll_name": None, "base_ordinal": 0,
                    "exports": entries,
                    "total_exports": total_elf,
                    "matched_exports": len(entries),
                }
                if pattern:
                    r["filter_pattern"] = pattern
                return r

            return {"ok": True, "format": fmt, "exports": [], "total_exports": 0, "matched_exports": 0}
        except Exception as e:
            return {**tool_error(e), "ok": False}

    # -----------------------------------------------------------------------
    # H.5b — lief_iat_resolve
    # -----------------------------------------------------------------------

    @tool
    @idasync
    def lief_iat_resolve(
        dll_name: Annotated[
            str,
            "DLL name to search (case-insensitive substring, e.g. 'kernel32', 'Core.dll').",
        ],
        func_name: Annotated[
            str,
            "Imported function name (case-insensitive substring or glob, e.g. 'CreateFileW', '*Render*').",
        ],
        file_path: Annotated[str, "Path to binary; empty string uses the IDB source file"] = "",
    ) -> LiefIatResolveResult:
        """Resolve an imported function to its IAT slot address in IDA.

        Given a DLL name and function name, finds the matching IAT entry and
        returns both the static VA (from the PE file) and the IDA-rebased VA
        (accounting for ASLR / IDB rebase). The IDA-rebased address is what
        you need for hooking or patching in the loaded IDB.

        Also looks up the IDA symbol name at that address (e.g. '__imp_CreateFileW',
        'ds:CreateFileW') so you know exactly what IDA calls it.

        On no match: returns ok=False with a 'candidates' list of all imports
        from matching DLLs so the agent can pick the right name.
        """
        try:
            path = _resolve_lief_path(file_path)
            binary = _lief.parse(path)
            if binary is None:
                return {**tool_error(ValueError(f"LIEF could not parse: {path}")), "ok": False}

            if not isinstance(binary, _lief.PE.Binary):
                return {
                    **tool_error(ValueError("lief_iat_resolve only supports PE binaries")),
                    "ok": False,
                }

            pe = binary
            pe_imagebase = pe.optional_header.imagebase
            idb_imagebase = idaapi.get_imagebase()
            rebase_delta = idb_imagebase - pe_imagebase

            dll_f = dll_name.lower()
            fn_p = func_name.lower()
            if "*" not in fn_p and "?" not in fn_p:
                fn_p = f"*{fn_p}*"

            def _iter_all_imports():
                """Yield (imp, is_delay) tuples for regular + delay imports."""
                for imp in pe.imports:
                    yield imp, False
                if hasattr(pe, "delay_imports"):
                    for imp in pe.delay_imports:
                        yield imp, True

            # Collect all imports from matching DLLs
            candidates: list[dict] = []
            for imp, is_delay in _iter_all_imports():
                if dll_f not in imp.name.lower():
                    continue
                for fn in imp.entries:
                    fname = fn.name if fn.name else None
                    # DelayImportEntry has no .iat_address; fall back gracefully.
                    raw_iat = getattr(fn, "iat_address", None)
                    iat_str = hex(raw_iat) if raw_iat else "0x0"
                    iat_idb_str = hex(raw_iat + rebase_delta) if raw_iat else "0x0"
                    if fname and fnmatch.fnmatch(fname.lower(), fn_p):
                        idb_sym = (
                            idc.get_name(raw_iat + rebase_delta, idc.GN_VISIBLE)
                            if raw_iat else None
                        ) or None
                        return {
                            "ok": True,
                            "dll_name": imp.name,
                            "func_name": fname,
                            "demangled_name": _try_demangle(fname),
                            "ordinal": fn.ordinal if fn.is_ordinal else None,
                            "is_ordinal": bool(fn.is_ordinal),
                            "is_delay_import": is_delay,
                            "iat_va": iat_str,
                            "iat_va_idb": iat_idb_str,
                            "idb_name": idb_sym,
                        }
                    if fname:
                        candidates.append({
                            "dll": imp.name,
                            "name": fname,
                            "demangled": _try_demangle(fname),
                            "iat_va": iat_str,
                            "iat_va_idb": iat_idb_str,
                        })

            # No exact match — tell agent what IS available in those DLLs
            dll_candidates = [c for c in candidates if dll_f in c["dll"].lower()]
            hint = (
                f"No import matching '{func_name}' found in DLLs containing '{dll_name}'. "
                + (
                    f"{len(dll_candidates)} import(s) from matching DLLs listed in 'candidates'."
                    if dll_candidates
                    else "No DLLs matching that name found either — check the DLL name."
                )
            )
            return {
                "ok": False,
                "dll_name": dll_name,
                "func_name": func_name,
                "error": hint,
                "hint": hint,
                "candidates": dll_candidates[:30],
            }
        except Exception as e:
            return {**tool_error(e), "ok": False}

    # -----------------------------------------------------------------------
    # H.6 — lief_strings
    # -----------------------------------------------------------------------

    @tool
    @idasync
    def lief_strings(
        file_path: Annotated[str, "Path to binary file; empty string uses the IDB source file"] = "",
        min_length: Annotated[int, "Minimum string length to include (default: 6)"] = 6,
        max_results: Annotated[int, "Maximum total strings to return (default: 2000)"] = 2000,
        encoding: Annotated[str, "Encoding filter: 'ascii' (default), 'utf16', or 'both'"] = "ascii",
        sections: Annotated[
            list[str] | str,
            "Limit scan to these section names; empty list scans all sections",
        ] = [],
        max_section_size: Annotated[int, "Skip sections larger than this many bytes (default: 10MB)"] = 10_000_000,
        skip_executable_sections: Annotated[
            bool,
            "Skip sections with execute permission to avoid machine-code false positives (default: true)",
        ] = True,
    ) -> LiefStringsResult:
        """Extract printable strings from binary sections and overlay.

        Scans each section for ASCII and/or UTF-16LE sequences meeting the
        minimum length. Executable sections (.text) are skipped by default
        because machine code produces many short garbage strings. Sections
        larger than max_section_size are also skipped. Also scans the PE
        overlay when present."""
        try:
            path = _resolve_lief_path(file_path)
            binary = _lief.parse(path)
            if binary is None:
                return {**tool_error(ValueError(f"LIEF could not parse: {path}")), "ok": False}

            enc = encoding.lower().strip()
            if enc not in ("ascii", "utf16", "both"):
                enc = "ascii"

            filter_secs = set(normalize_list_input(sections)) if sections else None
            results: list[LiefStringEntry] = []
            truncated = False

            for sec in binary.sections:
                name = sec.name.strip("\x00") if sec.name else ""
                if filter_secs and name not in filter_secs:
                    continue
                if sec.size > max_section_size:
                    continue
                if skip_executable_sections and _section_is_executable(sec):
                    continue
                try:
                    content = bytes(sec.content)
                except Exception:
                    continue
                if not content:
                    continue
                truncated = _extract_strings(content, sec.offset, min_length, name, enc, results, max_results)
                if truncated:
                    break

            # Also scan PE overlay
            if not truncated and not filter_secs and hasattr(binary, "overlay"):
                try:
                    overlay = bytes(binary.overlay)
                    if overlay:
                        last_end = max((s.offset + s.size for s in binary.sections), default=0)
                        truncated = _extract_strings(overlay, last_end, min_length, "overlay", enc, results, max_results)
                except Exception:
                    pass

            return {
                "ok": True, "strings": results,
                "total": len(results), "truncated": truncated,
            }
        except Exception as e:
            return {**tool_error(e), "ok": False}

    # -----------------------------------------------------------------------
    # H.7 — lief_tls_callbacks
    # -----------------------------------------------------------------------

    @tool
    @idasync
    def lief_tls_callbacks(
        file_path: Annotated[str, "Path to binary file; empty string uses the IDB source file"] = "",
    ) -> LiefTlsResult:
        """List PE TLS callbacks. Returns has_tls=false for non-PE formats.

        TLS callbacks run before the binary entry point and are commonly used
        by packers and anti-debug code. IDA names are bridged for each
        callback VA when available."""
        try:
            path = _resolve_lief_path(file_path)
            binary = _lief.parse(path)
            if binary is None:
                return {**tool_error(ValueError(f"LIEF could not parse: {path}")), "ok": False}

            fmt = _format_name(binary)
            if not isinstance(binary, _lief.PE.Binary):
                return {"ok": True, "format": fmt, "has_tls": False, "callbacks": [], "callback_count": 0}

            pe = binary
            if not pe.has_tls:
                return {"ok": True, "format": "PE", "has_tls": False, "callbacks": [], "callback_count": 0}
            tls = pe.tls
            if tls is None:
                return {"ok": True, "format": "PE", "has_tls": False, "callbacks": [], "callback_count": 0}

            try:
                start, end = tls.addressof_raw_data
            except (TypeError, ValueError):
                start = end = 0

            idx_addr = getattr(tls, "addressof_index", 0) or 0
            pe_imagebase = pe.optional_header.imagebase
            idb_imagebase = idaapi.get_imagebase()
            cbs: list[LiefTlsCallbackEntry] = []
            for va in (tls.callbacks or []):
                # tls.callbacks holds VAs using the PE's declared imagebase; rebase
                # to IDA's loaded imagebase so the name lookup is correct.
                va_idb = va - pe_imagebase + idb_imagebase
                ida_sym = idc.get_name(va_idb) or None
                if ida_sym and _is_auto_name(ida_sym):
                    ida_sym = None
                cbs.append({"address": hex(va), "ida_name": ida_sym})

            return {
                "ok": True, "format": "PE", "has_tls": True,
                "raw_data_start": hex(start), "raw_data_end": hex(end),
                "index_address": hex(idx_addr),
                "callbacks": cbs, "callback_count": len(cbs),
                "hint": "VA values are from the raw file; may differ from IDA loaded address if ASLR applied",
            }
        except Exception as e:
            return {**tool_error(e), "ok": False}

    # -----------------------------------------------------------------------
    # H.8 — lief_verify_signature ⭐
    # -----------------------------------------------------------------------

    @tool
    @idasync
    def lief_verify_signature(
        file_path: Annotated[str, "Path to binary file; empty string uses the IDB source file"] = "",
        checks: Annotated[
            str,
            "Verification depth: 'all' (full chain, default), 'hash_only', "
            "'lifetime_signing', or 'skip_cert_time'",
        ] = "all",
    ) -> LiefSignatureResult:
        """Verify Authenticode (PE digital signature) and return the full cert
        chain, signer info, computed vs. signed authentihash comparison, and
        countersignature timestamp.

        This is the only Python-native Authenticode verifier that does not
        require WinTrust.dll or an OpenSSL CLI call."""
        try:
            path = _resolve_lief_path(file_path)
            binary = _lief.parse(path)
            if binary is None:
                return {**tool_error(ValueError(f"LIEF could not parse: {path}")), "ok": False}

            fmt = _format_name(binary)
            if not isinstance(binary, _lief.PE.Binary):
                return {"ok": True, "format": fmt, "has_signature": False, "is_valid": False, "hashes_match": False}

            pe = binary
            if not pe.signatures:
                return {
                    "ok": True, "format": "PE", "has_signature": False,
                    "signature_count": 0, "is_valid": False, "hashes_match": False,
                }

            # Map check name to LIEF flag
            try:
                VCK = _lief.PE.Signature.VERIFICATION_CHECKS
                checks_map = {
                    "all":              getattr(VCK, "DEFAULT",          VCK.DEFAULT if hasattr(VCK, "DEFAULT") else 0),
                    "hash_only":        getattr(VCK, "HASH_ONLY",        None),
                    "lifetime_signing": getattr(VCK, "LIFETIME_SIGNING", None),
                    "skip_cert_time":   getattr(VCK, "SKIP_CERT_TIME",   None),
                }
                check_flag = checks_map.get(checks) or checks_map["all"]
            except Exception:
                check_flag = None

            try:
                result_flags = pe.verify_signature(check_flag) if check_flag else pe.verify_signature()
                VF = _lief.PE.Signature.VERIFICATION_FLAGS
                is_valid = result_flags == VF.OK
                result_str = str(result_flags).split(".")[-1]
            except Exception:
                is_valid = False
                result_str = "UNKNOWN"

            sig = pe.signatures[0]

            # Authentihash
            try:
                alg = getattr(sig, "digest_algorithm", None)
                alg_map = {}
                try:
                    ALGS = _lief.PE.ALGORITHMS
                    alg_map = {ALGS.MD5: ALGS.MD5, ALGS.SHA_1: ALGS.SHA_1, ALGS.SHA_256: ALGS.SHA_256}
                except Exception:
                    pass
                compute_alg = alg_map.get(alg)
                if compute_alg is not None:
                    computed = bytes(pe.authentihash(compute_alg))
                else:
                    computed = bytes(pe.authentihash(_lief.PE.ALGORITHMS.SHA_256))
                signed = bytes(sig.content_info.digest)
                hashes_match = computed == signed
                computed_hex = computed.hex()
                signed_hex = signed.hex()
                alg_str = str(alg).split(".")[-1] if alg else "SHA_256"
            except Exception:
                hashes_match = False
                computed_hex = signed_hex = ""
                alg_str = "unknown"

            # Certificates
            certs: list[LiefCertInfo] = []
            try:
                for cert in sig.certificates:
                    sn = getattr(cert, "serial_number", b"")
                    certs.append({
                        "subject": str(cert.subject),
                        "issuer": str(cert.issuer),
                        "serial": sn.hex(":") if isinstance(sn, (bytes, bytearray)) else str(sn),
                        "not_before": str(cert.valid_from),
                        "not_after": str(cert.valid_to),
                        "is_ca": getattr(cert, "is_ca", False),
                    })
            except Exception:
                pass

            # Signers
            signers: list[LiefSignerInfo] = []
            try:
                for signer in sig.signers:
                    cert = getattr(signer, "cert", None)
                    sn = getattr(signer, "serial_number", b"")
                    signers.append({
                        "issuer": str(signer.issuer),
                        "subject": str(cert.subject) if cert else "",
                        "serial": sn.hex(":") if isinstance(sn, (bytes, bytearray)) else str(sn),
                        "not_before": str(cert.valid_from) if cert else "",
                        "not_after": str(cert.valid_to) if cert else "",
                        "signature_algorithm": str(getattr(signer, "digest_algorithm", "")).split(".")[-1],
                    })
            except Exception:
                pass

            # Countersignature
            has_counter = False
            counter_ts = None
            try:
                if sig.signers:
                    cs = sig.signers[0].pkcs9_countersignature
                    if cs:
                        has_counter = True
                        counter_ts = str(cs.sign_time)
            except Exception:
                pass

            return {
                "ok": True, "format": "PE",
                "has_signature": True, "signature_count": len(pe.signatures),
                "verification_result": result_str, "is_valid": is_valid,
                "authentihash_computed": computed_hex, "authentihash_signed": signed_hex,
                "hashes_match": hashes_match, "digest_algorithm": alg_str,
                "signers": signers, "certificates": certs,
                "has_countersignature": has_counter, "countersign_timestamp": counter_ts,
            }
        except Exception as e:
            return {**tool_error(e), "ok": False}

    # -----------------------------------------------------------------------
    # H.9 — lief_rich_header ⭐
    # -----------------------------------------------------------------------

    @tool
    @idasync
    def lief_rich_header(
        file_path: Annotated[str, "Path to binary file; empty string uses the IDB source file"] = "",
    ) -> LiefRichHeaderResult:
        """Decode the PE Rich Header — an undocumented structure encoding the
        Visual Studio compiler component IDs and build numbers used to link the
        binary. Primary technique for malware attribution and compiler fingerprinting.

        Returns per-entry product names (from the embedded ~30-entry lookup
        table), a best-guess VS version, the XOR key, and a SHA-256 fingerprint
        of the decoded entries for attribution matching."""
        try:
            path = _resolve_lief_path(file_path)
            binary = _lief.parse(path)
            if binary is None:
                return {**tool_error(ValueError(f"LIEF could not parse: {path}")), "ok": False}

            fmt = _format_name(binary)
            if not isinstance(binary, _lief.PE.Binary):
                return {"ok": True, "format": fmt, "has_rich_header": False, "entries": []}

            pe = binary
            rh = pe.rich_header
            if rh is None:
                return {"ok": True, "format": "PE", "has_rich_header": False, "entries": []}

            entries: list[LiefRichEntry] = []
            linker_ver: str | None = None
            vs_versions_seen: list[str] = []

            for entry in rh.entries:
                pid = getattr(entry, "id", 0)
                build = getattr(entry, "build_id", 0)
                count = getattr(entry, "count", 0)
                if pid == 0:
                    continue  # skip DanS marker
                name, vs = _RICH_PRODUCT_NAMES.get(pid, (f"Unknown (0x{pid:04X})", "Unknown"))
                if "Linker" in name and not linker_ver:
                    linker_ver = f"{name} build {build} ({vs})"
                vs_versions_seen.append(vs)
                entries.append({
                    "id": pid, "build": build, "count": count,
                    "product_name": f"{name} build {build}",
                    "vs_version": vs,
                })

            compiler_guess = "Unknown"
            if vs_versions_seen:
                counter = collections.Counter(vs_versions_seen)
                compiler_guess = counter.most_common(1)[0][0]

            # Fingerprint: SHA-256 of decoded entry bytes
            raw_bytes = b""
            for e in entries:
                raw_bytes += e["id"].to_bytes(2, "little")
                raw_bytes += e["build"].to_bytes(2, "little")
                raw_bytes += e["count"].to_bytes(4, "little")
            raw_hash = hashlib.sha256(raw_bytes).hexdigest()[:16] if raw_bytes else ""

            unknown_count = sum(1 for e in entries if e["vs_version"] == "Unknown")
            coverage_note: str | None = None
            if entries and unknown_count > len(entries) // 2:
                coverage_note = (
                    f"{unknown_count}/{len(entries)} compiler IDs not in the built-in table "
                    "(likely a pre-VS2005 or non-MSVC toolchain). "
                    "Full attribution requires the complete RichPE database (~500 entries)."
                )

            return {
                "ok": True, "format": "PE", "has_rich_header": True,
                "xor_key": hex(rh.key),
                "raw_hash": raw_hash,
                "entries": entries,
                "compiler_guess": compiler_guess,
                "linker_version": linker_ver,
                "unknown_count": unknown_count,
                "coverage_note": coverage_note,
            }
        except Exception as e:
            return {**tool_error(e), "ok": False}

    # -----------------------------------------------------------------------
    # H.10 — lief_pe_overlay ⭐
    # -----------------------------------------------------------------------

    @tool
    @idasync
    def lief_pe_overlay(
        file_path: Annotated[str, "Path to binary file; empty string uses the IDB source file"] = "",
        max_extract_bytes: Annotated[int, "Max overlay bytes to hex-dump in the result (default: 256)"] = 256,
        identify_type: Annotated[bool, "Attempt file-type identification on the overlay (default: true)"] = True,
    ) -> LiefOverlayResult:
        """Inspect data appended after the last PE section (the overlay).

        Overlay data is common in: UPX-packed binaries (decompressor stub),
        NSIS/Inno SFX installers (cabinet), droppers (embedded PE/shellcode),
        and certificate padding. Returns entropy, hex preview, and optional
        magic-byte file-type identification."""
        try:
            path = _resolve_lief_path(file_path)
            binary = _lief.parse(path)
            if binary is None:
                return {**tool_error(ValueError(f"LIEF could not parse: {path}")), "ok": False}

            fmt = _format_name(binary)
            if not isinstance(binary, _lief.PE.Binary):
                return {"ok": True, "format": fmt, "has_overlay": False}

            pe = binary
            try:
                overlay = bytes(pe.overlay)
            except Exception:
                overlay = b""

            if not overlay:
                return {"ok": True, "format": "PE", "has_overlay": False, "overlay_offset": 0, "overlay_size": 0}

            # Compute overlay file offset
            overlay_offset = 0
            for sec in pe.sections:
                end = sec.offset + sec.size
                if end > overlay_offset:
                    overlay_offset = end

            ent = _entropy(overlay[:4096])
            preview = overlay[:max_extract_bytes]
            overlay_hex = preview.hex()

            overlay_type: str | None = None
            overlay_mime: str | None = None
            if identify_type:
                try:
                    from . import api_filetype as _ft
                    if getattr(_ft, "FILETYPE_AVAILABLE", False) and _ft._filetype_lib is not None:
                        ft = _ft._filetype_lib.guess(preview)
                        if ft:
                            overlay_type = ft.extension
                            overlay_mime = ft.mime
                except Exception:
                    pass

            notes: list[str] = []
            if ent > 7.0:
                notes.append("High entropy — compressed or encrypted data")
            if overlay_type in ("zip", "rar", "7z", "gz", "xz"):
                notes.append(f"Possible self-extracting archive ({overlay_type})")
            if overlay_type in ("exe", "dll"):
                notes.append("Embedded PE executable in overlay")
            overlay_size = len(overlay)
            if overlay_size > 1_000_000:
                notes.append(f"Large overlay ({overlay_size // 1024} KB) — possible embedded payload")

            return {
                "ok": True, "format": "PE", "has_overlay": True,
                "overlay_offset": overlay_offset,
                "overlay_size": overlay_size,
                "overlay_hex": overlay_hex,
                "overlay_type": overlay_type,
                "overlay_mime": overlay_mime,
                "entropy": ent,
                "notes": notes,
            }
        except Exception as e:
            return {**tool_error(e), "ok": False}

    # -----------------------------------------------------------------------
    # H.11 — lief_guard_functions ⭐
    # -----------------------------------------------------------------------

    @tool
    @idasync
    def lief_guard_functions(
        file_path: Annotated[str, "Path to binary file; empty string uses the IDB source file"] = "",
    ) -> LiefGuardResult:
        """Read the Windows Control Flow Guard (CFG) tables from the PE load
        configuration directory.

        Returns every guarded indirect-call target (guard_cf_functions) with
        RVA, absolute VA, flags, and the IDA name for that address when known.
        Essential for CFG-bypass exploit research — reveals which function
        pointers Windows considers valid indirect-call targets."""
        try:
            path = _resolve_lief_path(file_path)
            binary = _lief.parse(path)
            if binary is None:
                return {**tool_error(ValueError(f"LIEF could not parse: {path}")), "ok": False}

            fmt = _format_name(binary)
            if not isinstance(binary, _lief.PE.Binary):
                return {
                    "ok": True, "format": fmt, "cfg_enabled": False,
                    "guard_cf_functions": [], "guard_cf_count": 0,
                }

            pe = binary
            try:
                DLL = _lief.PE.OptionalHeader.DLL_CHARACTERISTICS
                cfg_enabled = DLL.GUARD_CF in pe.optional_header.dll_characteristics_lists
            except Exception:
                cfg_enabled = False

            lc = pe.load_configuration
            if not cfg_enabled or lc is None:
                return {
                    "ok": True, "format": "PE", "cfg_enabled": cfg_enabled,
                    "guard_cf_functions": [], "guard_cf_count": 0, "notes": [],
                }

            pe_imagebase = pe.optional_header.imagebase
            idb_imagebase = idaapi.get_imagebase()
            guard_funcs = getattr(lc, "guard_cf_functions", []) or []
            entries: list[LiefGuardEntry] = []

            for fn in guard_funcs:
                rva = getattr(fn, "rva", 0) or 0
                va = pe_imagebase + rva          # static VA from the PE file
                va_idb = idb_imagebase + rva     # IDA-loaded VA for symbol lookup
                flags: list[str] = []
                raw_flags = getattr(fn, "flags", 0) or 0
                if raw_flags & 0x01: flags.append("FID_SUPPRESSED")
                if raw_flags & 0x02: flags.append("EXPORT_SUPPRESSED")
                if raw_flags & 0x04: flags.append("LONGJMP_TARGET")
                ida_sym = idc.get_name(va_idb) or None
                if ida_sym and _is_auto_name(ida_sym):
                    ida_sym = None
                entries.append({"rva": hex(rva), "address": hex(va), "flags": flags, "ida_name": ida_sym})

            lj_targets = [hex(pe_imagebase + getattr(r, "rva", 0)) for r in (getattr(lc, "guard_longjump_targets", []) or [])]
            eh_targets = [hex(pe_imagebase + getattr(r, "rva", 0)) for r in (getattr(lc, "guard_eh_continuation_targets", []) or [])]

            notes: list[str] = []
            if len(entries) > 1000:
                notes.append(f"{len(entries)} guard entries — typical for a CRT-linked binary")
            if not entries:
                notes.append("CFG flag set but guard table is empty — may be stripped or minimal build")

            return {
                "ok": True, "format": "PE", "cfg_enabled": cfg_enabled,
                "guard_cf_functions": entries, "guard_cf_count": len(entries),
                "guard_longjump_targets": lj_targets,
                "guard_eh_cont_targets": eh_targets,
                "notes": notes,
            }
        except Exception as e:
            return {**tool_error(e), "ok": False}

    # -----------------------------------------------------------------------
    # H.12 — lief_compare_to_idb ⭐
    # -----------------------------------------------------------------------

    @tool
    @idasync
    def lief_compare_to_idb(
        file_path: Annotated[str, "Path to binary file; empty string uses the IDB source file"] = "",
    ) -> LiefIdbDiffResult:
        """Compare LIEF's raw file parse against the currently loaded IDB.

        Diffs entry point, section layout, import names, and export counts.
        Anomalies suggest packer tricks, loader overrides, obfuscated imports
        (GetProcAddress), or IDA loader failures. Unique killer feature: no
        other tool cross-references the raw binary against the IDB state."""
        try:
            path = _resolve_lief_path(file_path)
            binary = _lief.parse(path)
            if binary is None:
                return {**tool_error(ValueError(f"LIEF could not parse: {path}")), "ok": False}

            fmt = _format_name(binary)
            anomalies: list[str] = []

            # --- Entry point ---
            lief_ep = binary.entrypoint or 0
            ida_ep_raw = idaapi.inf_get_start_ip()
            if ida_ep_raw == idaapi.BADADDR:
                ida_ep_str = "0x?"
                ep_match = False
                anomalies.append("IDA has no defined start address (BADADDR)")
            else:
                ida_ep_str = hex(ida_ep_raw)
                ep_match = (lief_ep == ida_ep_raw)
                if not ep_match:
                    anomalies.append(
                        f"Entry point mismatch: LIEF={hex(lief_ep)} IDA={ida_ep_str} — "
                        "possible packer or loader override"
                    )

            # --- Sections vs IDA segments ---
            lief_secs: dict[str, int] = {}
            for s in binary.sections:
                n = s.name.strip("\x00") if s.name else ""
                lief_secs[n] = s.virtual_size

            ida_segs: dict[str, int] = {}
            for seg_ea in idautils.Segments():
                n = idc.get_segm_name(seg_ea) or ""
                size = idc.get_segm_end(seg_ea) - seg_ea
                if n:
                    ida_segs[n] = size

            lief_only = [n for n in lief_secs if n not in ida_segs]
            ida_only  = [n for n in ida_segs  if n and n not in lief_secs]
            # Separate known IDA artifacts from genuine anomalies
            ida_only_synthetic = [n for n in ida_only if n in _IDA_SYNTHETIC_SEGMENTS]
            ida_only_real      = [n for n in ida_only if n not in _IDA_SYNTHETIC_SEGMENTS]
            mismatches: list[LiefSectionSizeMismatch] = []
            for n in lief_secs:
                if n in ida_segs:
                    ls, is_ = lief_secs[n], ida_segs[n]
                    if ls and is_ and abs(ls - is_) > max(64, min(ls, is_) * 0.1):
                        mismatches.append({"name": n, "lief_size": ls, "ida_size": is_})

            if lief_only:
                anomalies.append(
                    f"{len(lief_only)} LIEF section(s) have no IDA segment: "
                    f"{', '.join(lief_only[:5])}"
                )
            if ida_only_synthetic:
                # Informational — not a real anomaly
                anomalies.append(
                    f"IDA synthetic segments (normal, not anomalies): "
                    f"{', '.join(ida_only_synthetic)}"
                )

            # --- Imports ---
            lief_imports_set: set[str] = set()
            if isinstance(binary, _lief.PE.Binary):
                for imp in binary.imports:
                    for fn in imp.entries:
                        if fn.name:
                            lief_imports_set.add(fn.name)

            ida_imports_set: set[str] = set()
            n_mods = idaapi.get_import_module_qty()
            for i in range(n_mods):
                def _cb(ea, name, ord, _acc=ida_imports_set):
                    if name:
                        _acc.add(name)
                    return True
                idaapi.enum_import_names(i, _cb)

            lief_only_imp = list(lief_imports_set - ida_imports_set)[:20]
            ida_only_imp  = list(ida_imports_set  - lief_imports_set)[:20]

            if len(lief_imports_set - ida_imports_set) > 5:
                anomalies.append(
                    f"{len(lief_imports_set - ida_imports_set)} import(s) LIEF found that IDA did not resolve — "
                    "possible GetProcAddress-based dynamic loading"
                )

            # --- Exports ---
            lief_exp_count = 0
            if isinstance(binary, _lief.PE.Binary):
                exp = binary.get_export()
                if exp:
                    lief_exp_count = len(list(exp.entries))
            ida_exp_count = idaapi.get_entry_qty()

            exp_delta = abs(lief_exp_count - ida_exp_count)
            exp_note: str | None = None
            if exp_delta > 0:
                if lief_exp_count == 0 and ida_exp_count <= 2:
                    exp_note = (
                        "Expected — IDA's entry_qty includes the program entry point; "
                        "LIEF counts only the PE export directory (empty for most EXEs)"
                    )
                elif exp_delta <= 3:
                    exp_note = (
                        f"Small discrepancy ({exp_delta}) — possible causes: "
                        "forwarded export counted differently, IDA-added thunk, "
                        "or program entry point included in IDA's count"
                    )
                elif lief_exp_count > ida_exp_count:
                    exp_note = (
                        f"LIEF sees {exp_delta} more exports than IDA — "
                        "some exports may not have been parsed by IDA's loader"
                    )

            return {
                "ok": True, "format": fmt,
                "entry_point": {"lief": hex(lief_ep), "ida": ida_ep_str, "match": ep_match},
                "sections": {
                    "lief_only": lief_only,
                    "ida_only": ida_only,
                    "ida_only_synthetic": ida_only_synthetic,
                    "size_mismatches": mismatches,
                },
                "imports": {
                    "lief_total": len(lief_imports_set),
                    "ida_total": len(ida_imports_set),
                    "lief_only": lief_only_imp,
                    "ida_only": ida_only_imp,
                },
                "exports": {
                    "lief_total": lief_exp_count,
                    "ida_total": ida_exp_count,
                    "mismatch_count": exp_delta,
                    "note": exp_note,
                },
                "anomalies": anomalies,
            }
        except Exception as e:
            return {**tool_error(e), "ok": False}

    # -----------------------------------------------------------------------
    # H.13 — lief_add_section  (@unsafe)
    # -----------------------------------------------------------------------

    @unsafe
    @tool
    @idasync
    def lief_add_section(
        section_name: Annotated[str, "Section name (max 8 chars for PE)"],
        content_hex: Annotated[str, "Section content as hex bytes, spaces allowed (e.g. '90 90 90')"],
        output_path: Annotated[str, "Output path for the modified binary"],
        file_path: Annotated[str, "Path to source binary; empty string uses the IDB source file"] = "",
        characteristics: Annotated[
            list[str] | str,
            "PE section flags: MEM_READ, MEM_WRITE, MEM_EXECUTE, CNT_CODE (default: ['MEM_READ'])",
        ] = ["MEM_READ"],
        virtual_address: Annotated[int, "Preferred virtual address RVA (0 lets LIEF choose)"] = 0,
    ) -> LiefModifyResult:
        """Add a new section to a PE or ELF binary and write to output_path.

        The source binary is never modified. Leave file_path empty to use the
        IDB's original source binary. PE section names are silently truncated
        to 8 characters. content_hex accepts space-separated or run-together
        hex (e.g. '90 90 90' or '909090')."""
        try:
            import pathlib
            src = _resolve_lief_path(file_path)
            ext = os.path.splitext(src)[1].lower()
            if ext in _IDA_EXTENSIONS:
                return {
                    "ok": False,
                    "error": f"'{os.path.basename(src)}' is an IDA database, not a raw binary",
                    "hint": "Pass the path to the original PE/ELF file, or leave file_path empty to auto-use the IDB source binary.",
                }
            if not os.path.isfile(src):
                return {"ok": False, "error": f"Source file not found: {src}"}
            if not output_path:
                return {"ok": False, "error": "output_path is required"}
            out_dir = pathlib.Path(output_path).parent
            if not out_dir.exists():
                return {"ok": False, "error": f"Output directory does not exist: {out_dir}"}

            try:
                content_bytes = bytes.fromhex(content_hex.replace(" ", ""))
            except ValueError as e:
                return {**tool_error(e), "ok": False, "hint": "content_hex must be valid hex"}

            binary = _lief.parse(src)
            if binary is None:
                return {"ok": False, "error": f"LIEF could not parse: {src}"}

            orig_size = os.path.getsize(src)
            detail_parts: list[str] = []

            if isinstance(binary, _lief.PE.Binary):
                pe = binary
                name = section_name[:8]
                if len(section_name) > 8:
                    detail_parts.append(f"Section name truncated to '{name}'")
                sec = _lief.PE.Section(name)
                sec.content = list(content_bytes)
                if virtual_address:
                    sec.virtual_address = virtual_address
                char_names = normalize_list_input(characteristics)
                try:
                    PE_CHARS = _lief.PE.Section.CHARACTERISTICS
                    char_map = {
                        "MEM_READ":    PE_CHARS.MEM_READ,
                        "MEM_WRITE":   PE_CHARS.MEM_WRITE,
                        "MEM_EXECUTE": PE_CHARS.MEM_EXECUTE,
                        "CNT_CODE":    PE_CHARS.CNT_CODE,
                    }
                    for c in char_names:
                        flag = char_map.get(c.upper())
                        if flag is not None:
                            sec += flag
                except Exception:
                    pass
                pe.add_section(sec)
                _lief_write(pe, output_path)

            elif isinstance(binary, _lief.ELF.Binary):
                elf = binary
                sec = _lief.ELF.Section(section_name)
                sec.content = list(content_bytes)
                elf.add(sec)
                _lief_write(elf, output_path)

            else:
                return {"ok": False, "error": f"lief_add_section not supported for {_format_name(binary)}"}

            out_size = os.path.getsize(output_path)
            return {
                "ok": True, "output_path": output_path,
                "action": "add_section",
                "detail": "; ".join(detail_parts) if detail_parts else f"Added section '{section_name}'",
                "original_size": orig_size, "output_size": out_size,
            }
        except Exception as e:
            return {**tool_error(e), "ok": False}

    # -----------------------------------------------------------------------
    # H.14 — lief_patch_import  (@unsafe)
    # -----------------------------------------------------------------------

    @unsafe
    @tool
    @idasync
    def lief_patch_import(
        library: Annotated[str, "DLL name (e.g. 'kernel32.dll')"],
        function_name: Annotated[str, "Function to add, rename, or remove"],
        action: Annotated[str, "Operation: 'add', 'rename', or 'remove'"],
        output_path: Annotated[str, "Output path for the modified binary"],
        file_path: Annotated[str, "Path to source PE binary; empty string uses the IDB source file"] = "",
        new_function_name: Annotated[str, "New name for rename action (ignored for add/remove)"] = "",
    ) -> LiefModifyResult:
        """Add, rename, or remove an import entry in a PE binary.

        Writes a new binary to output_path — the source is never modified.
        Use 'add' to inject a new imported function, 'rename' to replace a
        name in the IAT, or 'remove' to delete an entry."""
        try:
            src = _resolve_lief_path(file_path)
            ext = os.path.splitext(src)[1].lower()
            if ext in _IDA_EXTENSIONS:
                return {
                    "ok": False,
                    "error": f"'{os.path.basename(src)}' is an IDA database, not a raw binary",
                    "hint": "Pass the path to the original PE file, or leave file_path empty to auto-use the IDB source binary.",
                }
            if not os.path.isfile(src):
                return {"ok": False, "error": f"Source file not found: {src}"}
            if not output_path:
                return {"ok": False, "error": "output_path is required"}

            binary = _lief.parse(src)
            if binary is None:
                return {"ok": False, "error": f"LIEF could not parse: {src}"}
            if not isinstance(binary, _lief.PE.Binary):
                return {"ok": False, "error": "lief_patch_import only supports PE binaries"}

            pe = binary
            orig_size = os.path.getsize(src)
            lib_lower = library.lower()

            def _find_import(name_lower: str):
                for imp in pe.imports:
                    if imp.name.lower() == name_lower:
                        return imp
                return None

            if action == "add":
                imp = _find_import(lib_lower)
                if imp is None:
                    new_imp = _lief.PE.Import(library)
                    new_imp.add_entry(function_name)
                    pe.add_import(new_imp)
                else:
                    imp.add_entry(function_name)
                detail = f"Added {library}!{function_name}"

            elif action == "rename":
                if not new_function_name:
                    return {"ok": False, "error": "new_function_name required for rename"}
                imp = _find_import(lib_lower)
                if imp is None:
                    return {"ok": False, "error": f"Library '{library}' not found"}
                entry = imp.get_entry(function_name)
                if entry is None:
                    return {"ok": False, "error": f"Function '{function_name}' not found in '{library}'"}
                entry.name = new_function_name
                detail = f"Renamed {library}!{function_name} → {new_function_name}"

            elif action == "remove":
                imp = _find_import(lib_lower)
                if imp:
                    imp.remove_entry(function_name)
                detail = f"Removed {library}!{function_name}"

            else:
                return {"ok": False, "error": f"Unknown action '{action}' — use add, rename, or remove"}

            _lief_write(pe, output_path)
            out_size = os.path.getsize(output_path)

            return {
                "ok": True, "output_path": output_path, "action": action,
                "detail": detail, "original_size": orig_size, "output_size": out_size,
            }
        except Exception as e:
            return {**tool_error(e), "ok": False}

    # -----------------------------------------------------------------------
    # H.15 — lief_strip_metadata  (@unsafe)
    # -----------------------------------------------------------------------

    @unsafe
    @tool
    @idasync
    def lief_strip_metadata(
        file_path: Annotated[str, "Path to source PE binary; empty string uses the IDB source file"] = "",
        output_path: Annotated[str, "Output path for the modified binary"] = "",
        strip_debug: Annotated[bool, "Remove debug directory entries (default: true)"] = True,
        strip_rich_header: Annotated[bool, "Zero out Rich Header entries (default: false)"] = False,
        strip_pdb_path: Annotated[bool, "Empty the PDB filename from CodeView (default: true)"] = True,
        strip_signature: Annotated[bool, "Remove Authenticode signature (default: false)"] = False,
    ) -> LiefModifyResult:
        """Strip metadata from a PE binary for privacy or anti-attribution.

        Writes to output_path — the source is never modified. Warning: stripping
        the Authenticode signature changes the file hash and invalidates all
        existing signature checks."""
        try:
            src = _resolve_lief_path(file_path)
            ext = os.path.splitext(src)[1].lower()
            if ext in _IDA_EXTENSIONS:
                return {
                    "ok": False,
                    "error": f"'{os.path.basename(src)}' is an IDA database, not a raw binary",
                    "hint": "Pass the path to the original PE file, or leave file_path empty to auto-use the IDB source binary.",
                }
            if not os.path.isfile(src):
                return {"ok": False, "error": f"Source file not found: {src}"}
            if not output_path:
                return {"ok": False, "error": "output_path is required"}

            binary = _lief.parse(src)
            if binary is None:
                return {"ok": False, "error": f"LIEF could not parse: {src}"}
            if not isinstance(binary, _lief.PE.Binary):
                return {"ok": False, "error": "lief_strip_metadata only supports PE binaries"}

            pe = binary
            orig_size = os.path.getsize(src)
            stripped: list[str] = []

            if strip_debug and pe.has_debug:
                try:
                    pe.remove_all_debug()
                    stripped.append("debug_directory")
                except AttributeError:
                    for dbg in list(pe.debug):
                        pe.remove(dbg)
                    stripped.append("debug_entries")

            if strip_rich_header:
                rh = pe.rich_header
                if rh is not None:
                    try:
                        rh.clear()
                        stripped.append("rich_header")
                    except Exception:
                        pass

            if strip_pdb_path:
                for dbg_entry in (pe.debug or []):
                    try:
                        if str(getattr(dbg_entry, "type", "")).split(".")[-1] == "CODEVIEW":
                            cv = dbg_entry.code_view
                            if cv and hasattr(cv, "filename"):
                                cv.filename = ""
                                stripped.append("pdb_path")
                                break
                    except Exception:
                        pass

            if strip_signature:
                try:
                    pe.remove_signature()
                    stripped.append("authenticode_signature")
                except Exception:
                    pass

            _lief_write(pe, output_path)
            out_size = os.path.getsize(output_path)

            detail = f"Stripped: {', '.join(stripped)}" if stripped else "Nothing stripped"
            if "authenticode_signature" in stripped:
                detail += " (WARNING: PE hash changed — signature checks will fail)"

            return {
                "ok": True, "output_path": output_path, "action": "strip_metadata",
                "detail": detail, "original_size": orig_size, "output_size": out_size,
            }
        except Exception as e:
            return {**tool_error(e), "ok": False}

    # -----------------------------------------------------------------------
    # H.F.1 — hybrid_lief_yara_section_scan
    # -----------------------------------------------------------------------

    @tool
    @idasync
    def hybrid_lief_yara_section_scan(
        yara_rules: Annotated[
            str,
            "YARA rule source string or path to a .yar file",
        ],
        file_path: Annotated[str, "Path to binary file; empty string uses the IDB source file"] = "",
        section_names: Annotated[
            list[str] | str,
            "Limit scan to these section names; empty list scans all sections",
        ] = [],
        max_section_bytes: Annotated[int, "Skip sections larger than this many bytes (default: 10MB)"] = 10_000_000,
    ) -> HybridLiefYaraResult:
        """Scan individual binary sections with YARA rules.

        Combines LIEF section enumeration with YARA pattern matching: each
        section's bytes are fed to the compiled ruleset independently, so you
        can pinpoint which section triggered a rule. Results include entropy
        and permissions for every section even when no rules match."""
        if not YARA_AVAILABLE:
            return {
                **tool_error(ImportError("yara-python not installed")), "ok": False,
                "hint": "Install with: uv run ida-pro-mcp --install-deps yara",
            }
        try:
            # Compile rules
            rules_src = yara_rules.strip()
            try:
                if rules_src.endswith(".yar") and os.path.isfile(rules_src):
                    compiled = _yara.compile(filepath=rules_src)
                else:
                    compiled = _yara.compile(source=rules_src)
            except Exception as e:
                return {**tool_error(e), "ok": False, "hint": "Check YARA rule syntax"}

            path = _resolve_lief_path(file_path)
            binary = _lief.parse(path)
            if binary is None:
                return {**tool_error(ValueError(f"LIEF could not parse: {path}")), "ok": False}

            filter_set = set(normalize_list_input(section_names)) if section_names else None
            results: list[LiefYaraSectionResult] = []
            total_hits = 0

            for sec in binary.sections:
                name = sec.name.strip("\x00") if sec.name else ""
                if filter_set and name not in filter_set:
                    continue
                if sec.size > max_section_bytes:
                    continue
                try:
                    content = bytes(sec.content)
                except Exception:
                    continue
                if not content:
                    continue

                try:
                    ent = sec.entropy
                except Exception:
                    ent = None

                matches = compiled.match(data=content)
                match_details: list[LiefYaraMatch] = []
                for m in (matches or []):
                    detail: LiefYaraMatch = {
                        "rule": m.rule,
                        "tags": list(m.tags),
                        "meta": dict(m.meta),
                        "strings": [],
                    }
                    for s in m.strings:
                        if s.instances:
                            inst = s.instances[0]
                            detail["strings"].append({
                                "identifier": s.identifier,
                                "offset": inst.offset,
                                "data_hex": inst.matched_data.hex(),
                            })
                    match_details.append(detail)
                    total_hits += 1

                results.append({
                    "section": name,
                    "virtual_address": hex(sec.virtual_address),
                    "size": len(content),
                    "entropy": ent,
                    "is_executable": _section_is_executable(sec),
                    "rules_matched": [m.rule for m in (matches or [])],
                    "match_details": match_details,
                })

            return {
                "ok": True, "sections_scanned": len(results),
                "total_rule_hits": total_hits, "matches": results,
            }
        except Exception as e:
            return {**tool_error(e), "ok": False}

    # -----------------------------------------------------------------------
    # H.F.2 — hybrid_lief_checksec_exploit_assess
    # -----------------------------------------------------------------------

    @tool
    @idasync
    def hybrid_lief_checksec_exploit_assess(
        file_path: Annotated[str, "Path to binary file; empty string uses the IDB source file"] = "",
    ) -> HybridExploitAssessResult:
        """Composite exploit-surface assessment: checksec + CFG table + signature
        validity + overlay detection, synthesized into an exploitability rating.

        Rating: HIGH (<=2 mitigations), MEDIUM (3-4), LOW (5+). The
        attack_surface list explains each finding in plain language."""
        try:
            path = _resolve_lief_path(file_path)
            binary = _lief.parse(path)
            if binary is None:
                return {**tool_error(ValueError(f"LIEF could not parse: {path}")), "ok": False}

            # --- Inline checksec ---
            score = 0
            missing: list[str] = []
            cfg_flag = False
            is_signed = False
            sig_valid: bool | None = None

            if isinstance(binary, _lief.PE.Binary):
                pe = binary
                chars = (
                    getattr(pe.optional_header, "dll_characteristics_lists", None)
                    or getattr(pe.optional_header, "dll_characteristics_list", None)
                    or []
                )
                DLL = _lief.PE.OptionalHeader.DLL_CHARACTERISTICS

                def _has(flag) -> bool:
                    try: return flag in chars
                    except Exception: return False

                for label, flag in [
                    ("NX", DLL.NX_COMPAT), ("ASLR", DLL.DYNAMIC_BASE),
                    ("HighEntropy", DLL.HIGH_ENTROPY_VA), ("CFG", DLL.GUARD_CF),
                ]:
                    enabled = _has(flag)
                    if enabled:
                        score += 1
                    else:
                        missing.append(label)
                    if label == "CFG":
                        cfg_flag = enabled

                is_signed = bool(pe.signatures)
                if is_signed:
                    score += 1
                    try:
                        result_flags = pe.verify_signature()
                        sig_valid = str(result_flags).split(".")[-1] == "OK"
                    except Exception:
                        sig_valid = None
                else:
                    missing.append("Authenticode")

            elif isinstance(binary, _lief.ELF.Binary):
                # NX: PT_GNU_STACK must not have execute flag
                nx = True
                for seg in binary.segments:
                    if getattr(seg.type, "name", str(seg.type)) == "GNU_STACK":
                        try:
                            nx = not bool(seg.flags & _lief.ELF.Segment.FLAGS.X)
                        except Exception:
                            pass
                        break
                if nx: score += 1
                else: missing.append("NX")
                # PIE: ET_DYN (is_pie available in LIEF 0.15+)
                pie = getattr(binary, "is_pie", None)
                if pie is None:
                    pie = str(binary.header.file_type).split(".")[-1] == "SHARED"
                if pie: score += 1
                else: missing.append("PIE")

            # --- Inline CFG guard count ---
            guard_count = 0
            if isinstance(binary, _lief.PE.Binary) and cfg_flag:
                lc = binary.load_configuration
                if lc is not None:
                    guard_count = len(getattr(lc, "guard_cf_functions", []) or [])

            # --- Inline overlay detection ---
            has_overlay = False
            overlay_type: str | None = None
            if isinstance(binary, _lief.PE.Binary):
                try:
                    ovl = bytes(binary.overlay)
                    if ovl:
                        has_overlay = True
                        try:
                            from . import api_filetype as _ft
                            if getattr(_ft, "FILETYPE_AVAILABLE", False) and _ft._filetype_lib is not None:
                                ft = _ft._filetype_lib.guess(ovl[:256])
                                if ft:
                                    overlay_type = ft.extension
                        except Exception:
                            pass
                except Exception:
                    pass

            # --- Rating ---
            attack_surface: list[str] = []
            rating = "LOW"
            if score <= 2:
                rating = "HIGH"
                attack_surface.append(f"Only {score}/5+ mitigations enabled — minimal exploit resistance")
            elif score <= 4:
                rating = "MEDIUM"

            if not is_signed:
                attack_surface.append("Unsigned binary — can be patched without invalidating Authenticode")
            elif sig_valid is False:
                attack_surface.append("Signature invalid — binary may have been tampered with after signing")

            if has_overlay:
                if overlay_type:
                    attack_surface.append(f"Overlay detected ({overlay_type}) — may be packed; real code not visible")
                else:
                    attack_surface.append("Overlay detected — possible appended payload")

            if cfg_flag and guard_count == 0:
                attack_surface.append("CFG flag set but guard table is empty — CFG protection is nominal only")

            for m in missing[:3]:
                attack_surface.append(f"Missing mitigation: {m}")

            return {
                "ok": True,
                "checksec_score": score,
                "missing_mitigations": missing,
                "cfg_guard_count": guard_count,
                "is_signed": is_signed,
                "signature_valid": sig_valid,
                "has_overlay": has_overlay,
                "overlay_type": overlay_type,
                "exploitability_rating": rating,
                "attack_surface": attack_surface,
            }
        except Exception as e:
            return {**tool_error(e), "ok": False}

    # -----------------------------------------------------------------------
    # H.F.3 — hybrid_lief_sync_symbols  (@unsafe when dry_run=False)
    # -----------------------------------------------------------------------

    @unsafe
    @tool
    @idasync
    def hybrid_lief_sync_symbols(
        file_path: Annotated[str, "Path to binary file; empty string uses the IDB source file"] = "",
        source: Annotated[
            str,
            "Symbol source: 'exports' (PE export dir / ELF exported syms), "
            "'dynamic' (ELF dynamic symbols), or 'debug' (LIEF Extended DWARF/PDB only)",
        ] = "exports",
        dry_run: Annotated[bool, "Preview changes without applying them (default: true)"] = True,
        prefix: Annotated[str, "Optional prefix to prepend to every applied name"] = "",
        overwrite_named: Annotated[bool, "Overwrite existing non-auto IDA names (default: false)"] = False,
    ) -> HybridSymbolSyncResult:
        """Sync symbol names from LIEF (export table, dynamic symbols, or DWARF)
        into the IDA database.

        Only addresses with IDA auto-names (sub_, off_, unk_, etc.) are renamed
        by default. Use dry_run=true first to review what would change.
        The 'debug' source requires LIEF Extended (commercial license)."""
        try:
            if source == "debug" and not LIEF_EXTENDED_AVAILABLE:
                return {
                    **tool_error(ImportError("LIEF Extended required for debug symbol source")),
                    "ok": False,
                    "hint": "LIEF Extended (commercial) provides DWARF/PDB reader. "
                            "See https://lief.re/extended for licensing.",
                }

            path = _resolve_lief_path(file_path)
            binary = _lief.parse(path)
            if binary is None:
                return {**tool_error(ValueError(f"LIEF could not parse: {path}")), "ok": False}

            candidates: list[tuple[int, str, str]] = []  # (va, name, source_tag)

            if source in ("exports", "both"):
                if isinstance(binary, _lief.PE.Binary):
                    exp = binary.get_export()
                    if exp:
                        imagebase = binary.optional_header.imagebase
                        for fn in exp.entries:
                            if fn.name and fn.address:
                                va = imagebase + fn.address
                                candidates.append((va, fn.name, "export"))
                elif isinstance(binary, _lief.ELF.Binary):
                    for sym in binary.dynamic_symbols:
                        shndx = str(getattr(sym, "shndx", "")).split(".")[-1]
                        if shndx != "UNDEF" and getattr(sym, "exported", False) and sym.name and sym.value:
                            candidates.append((sym.value, sym.name, "dynamic_symbol"))

            if source in ("dynamic", "both"):
                if isinstance(binary, _lief.ELF.Binary):
                    for sym in binary.symbols:
                        sym_type = str(getattr(sym, "type", "")).split(".")[-1]
                        if sym.name and sym.value and sym_type in ("FUNC", "OBJECT"):
                            candidates.append((sym.value, sym.name, "dynamic_symbol"))

            if source == "debug" and LIEF_EXTENDED_AVAILABLE:
                try:
                    dbg = binary.debug_info()
                    if dbg:
                        for fn in dbg.functions:
                            if fn.name and fn.address:
                                candidates.append((fn.address, fn.name, "dwarf_function"))
                except Exception:
                    pass

            # Deduplicate by VA (prefer DWARF > export)
            seen_va: dict[int, tuple[str, str]] = {}
            priority = {"dwarf_function": 0, "export": 1, "dynamic_symbol": 2}
            for va, name, src in candidates:
                if va not in seen_va or priority.get(src, 9) < priority.get(seen_va[va][1], 9):
                    seen_va[va] = (name, src)

            changes: list[LiefSymbolChange] = []
            applied = skipped = not_found = 0

            for va, (lief_name, src) in seen_va.items():
                full_name = f"{prefix}{lief_name}" if prefix else lief_name
                ida_name = idc.get_name(va) or ""

                if not overwrite_named and not _is_auto_name(ida_name):
                    skipped += 1
                    changes.append({
                        "address": hex(va), "old_name": ida_name,
                        "new_name": full_name, "applied": False, "source": src,
                    })
                    continue

                if not idaapi.is_mapped(va):
                    not_found += 1
                    continue

                if dry_run:
                    changes.append({
                        "address": hex(va), "old_name": ida_name,
                        "new_name": full_name, "applied": False, "source": src,
                    })
                    # dry_run: nothing actually applied — proposed_count covers this
                else:
                    ok_flag = bool(idc.set_name(va, full_name, idc.SN_NOWARN | idc.SN_NOCHECK))
                    changes.append({
                        "address": hex(va), "old_name": ida_name,
                        "new_name": full_name, "applied": ok_flag, "source": src,
                    })
                    if ok_flag:
                        applied += 1

            return {
                "ok": True,
                "proposed_count": len(seen_va),
                "applied_count": applied,
                "skipped_count": skipped,
                "not_found_count": not_found,
                "changes": changes,
            }
        except Exception as e:
            return {**tool_error(e), "ok": False}
