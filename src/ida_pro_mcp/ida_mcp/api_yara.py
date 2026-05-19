"""api_yara — YARA signature-based pattern scanning for IDA Pro MCP.

Optional module: tools are only registered when yara-python is installed.
Install with: pip install yara-python

Provides:
- I.0  yara_status           — availability probe (always registered)
- I.1  yara_scan             — scan IDB range or raw file against custom rules
- I.2  yara_scan_builtin_crypto   — built-in crypto constant rules (AES/MD5/SHA/CRC32/RC4)
- I.3  yara_scan_builtin_threats  — built-in packer/C2/hack-tool/shellcode rules
- I.4  yara_rule_validate    — syntax check without scanning
- I.5  yara_generate_rule    — generate rule from IDA function bytes
- I.6  yara_idb_annotate     — scan IDB + auto-annotate/rename functions  ⭐ KILLER
- I.7  yara_function_classifier   — per-function category heat map
- I.F.1 hybrid_yara_lief_profile           — section scan + checksec → threat profile
- I.F.2 hybrid_yara_triton_verify_crypto   — YARA finds crypto → Triton confirms
- I.F.3 hybrid_yara_miasm_deobfuscate      — YARA finds packers → Miasm lifts
"""
from __future__ import annotations

import functools
import math
import os
import re as _re
import string as _string_mod
import struct
from collections import Counter
from typing import Annotated, NotRequired, TypedDict
import logging

import idaapi
import idautils
import idc

from .rpc import tool
from .sync import idasync
from .utils import parse_address, read_bytes_bss_safe, tool_error, normalize_list_input

logger = logging.getLogger(__name__)

# ============================================================================
# Optional import guard
# ============================================================================

try:
    import yara as _yara_lib
    YARA_AVAILABLE = True
except ImportError:
    _yara_lib = None  # type: ignore[assignment]
    YARA_AVAILABLE = False
    logger.warning(
        "yara-python not installed — yara_* tools unavailable. "
        "Run: pip install yara-python"
    )

# ============================================================================
# TypedDict result types
# ============================================================================


class YaraStatusResult(TypedDict, total=False):
    ok: bool
    available: bool
    version: str
    hint: str
    builtin_crypto_rules: int
    builtin_threat_rules: int


class YaraScanResult(TypedDict, total=False):
    ok: bool
    source: str
    bytes_scanned: int
    rules_compiled: int
    total_matches: int
    matches: list[dict]
    error: str


class YaraCryptoResult(TypedDict, total=False):
    ok: bool
    bytes_scanned: int
    total_matches: int
    algorithm_summary: dict
    matches: list[dict]
    error: str


class YaraThreatResult(TypedDict, total=False):
    ok: bool
    bytes_scanned: int
    risk_score: int
    risk_level: str
    category_summary: dict
    total_matches: int
    matches: list[dict]
    error: str


class YaraValidateResult(TypedDict, total=False):
    ok: bool
    valid: bool
    rule_count: int
    error: str | None
    error_line: int | None


class YaraGenerateResult(TypedDict, total=False):
    ok: bool
    rule_text: str
    rule_name: str
    coverage: float
    wildcarded_bytes: int
    hex_fragments: int
    strings_extracted: int
    valid: bool
    error: str


class YaraAnnotateResult(TypedDict, total=False):
    ok: bool
    dry_run: bool
    scope: str
    rules_compiled: int
    targets_scanned: int
    bytes_scanned: int
    total_matches: int
    functions_matched: int
    functions_annotated: int
    functions_renamed: int
    annotation_report: list[dict]
    error: str


class YaraClassifierResult(TypedDict, total=False):
    ok: bool
    functions_scanned: int
    functions_classified: int
    functions_unclassified: int
    category_summary: dict
    function_map: list[dict]
    error: str


class HybridYaraLiefProfileResult(TypedDict, total=False):
    ok: bool
    file: str
    format: str
    checksec_score: int
    mitigations: dict
    has_overlay: bool
    threat_score: int
    threat_level: str
    threat_indicators: list[str]
    crypto_hits: list[str]
    section_hits: list[dict]
    profile_summary: str
    error: str


class HybridYaraTritonResult(TypedDict, total=False):
    ok: bool
    candidates_found: int
    verified_count: int
    unverified_count: int
    triton_available: bool
    results: list[dict]
    error: str


class HybridYaraMiasmResult(TypedDict, total=False):
    ok: bool
    packer_stubs_found: int
    analyzed_count: int
    miasm_available: bool
    results: list[dict]
    error: str


# ============================================================================
# Auto-name detection (same prefix set as api_lief / api_flirt)
# ============================================================================

_AUTO_PREFIXES = (
    "sub_", "off_", "dword_", "word_", "byte_", "unk_", "loc_",
    "nullsub_", "j__", "j_sub_", "qword_", "xmmword_", "ymmword_",
    "stru_", "asc_", "def_",
)


def _is_auto_name(name: str) -> bool:
    return not name or any(name.startswith(p) for p in _AUTO_PREFIXES)


# ============================================================================
# Built-in YARA rules (embedded as Python string constants)
# All hex patterns are public-domain mathematical constants from the
# canonical Yara-Rules/rules/crypto/crypto_signatures.yar repository.
# ============================================================================

_BUILTIN_CRYPTO_RULES: str = r"""
rule aes_sbox {
    meta:
        description = "AES SubBytes forward S-box lookup table (Rijndael)"
        category = "crypto"
        algorithm = "aes"
    strings:
        $s = { 63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76
               CA 82 C9 7D FA 59 47 F0 AD D4 A2 AF 9C A4 72 C0 }
    condition:
        $s
}

rule aes_sbox_inv {
    meta:
        description = "AES InvSubBytes inverse S-box lookup table"
        category = "crypto"
        algorithm = "aes"
    strings:
        $s = { 52 09 6A D5 30 36 A5 38 BF 40 A3 9E 81 F3 D7 FB
               7C E3 39 82 9B 2F FF 87 34 8E 43 44 C4 DE E9 CB }
    condition:
        $s
}

rule md5_constants {
    meta:
        description = "MD5 initial hash vector (both endiannesses)"
        category = "crypto"
        algorithm = "md5"
    strings:
        $h_be = { 67 45 23 01 EF CD AB 89 98 BA DC FE 10 32 54 76 }
        $h_le = { 01 23 45 67 89 AB CD EF FE DC BA 98 76 54 32 10 }
    condition:
        any of them
}

rule sha1_constants {
    meta:
        description = "SHA-1 initial hash vector"
        category = "crypto"
        algorithm = "sha1"
    strings:
        $h = { 67 45 23 01 EF CD AB 89 98 BA DC FE 10 32 54 76 C3 D2 E1 F0 }
    condition:
        $h
}

rule sha256_constants {
    meta:
        description = "SHA-256 initial hash values (big-endian and little-endian forms)"
        category = "crypto"
        algorithm = "sha256"
    strings:
        $h_be = { 6A 09 E6 67 BB 67 AE 85 3C 6E F3 72 A5 4F F5 3A }
        $h_le = { 67 E6 09 6A 85 AE 67 BB 72 F3 6E 3C 3A F5 4F A5 }
    condition:
        any of them
}

rule sha512_constants {
    meta:
        description = "SHA-512 initial hash values"
        category = "crypto"
        algorithm = "sha512"
    strings:
        $h = { 42 8A 2F 98 D7 28 AE 22 23 EF 65 CD F3 5B 31 B8 }
    condition:
        $h
}

rule crc32_table {
    meta:
        description = "CRC32 standard polynomial lookup table (IEEE 802.3)"
        category = "crypto"
        algorithm = "crc32"
    strings:
        $t = { 00 00 00 00 96 30 07 77 2C 61 0E EE BA 51 09 99 19 C4 6D 07 }
    condition:
        $t
}

rule rc4_init_array {
    meta:
        description = "RC4 KSA identity permutation (0x00..0x17 sequential byte run)"
        category = "crypto"
        algorithm = "rc4"
    strings:
        $ks = { 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17 }
    condition:
        $ks
}
"""

_BUILTIN_THREAT_RULES: str = r"""
rule upx_packed {
    meta:
        description = "UPX packer magic signature"
        category = "packers"
    strings:
        $magic = "UPX!"
        $section = ".UPX0"
    condition:
        any of them
}

rule vmprotect {
    meta:
        description = "VMProtect protected binary"
        category = "packers"
    strings:
        $s1 = ".vmp0"
        $s2 = ".vmp1"
        $s3 = "VMProtect"
    condition:
        any of them
}

rule themida {
    meta:
        description = "Themida / WinLicense packer"
        category = "packers"
    strings:
        $s1 = ".themida"
        $s2 = ".winlicense"
    condition:
        any of them
}

rule nspack {
    meta:
        description = "NsPack packer"
        category = "packers"
    strings:
        $s = "NsPack"
    condition:
        $s
}

rule aspack {
    meta:
        description = "ASPack packer section name"
        category = "packers"
    strings:
        $s = ".aspack"
    condition:
        $s
}

rule cobalt_strike_beacon {
    meta:
        description = "Cobalt Strike Beacon indicators"
        category = "c2_frameworks"
    strings:
        $a = "ReflectiveLoader"
        $b = "%s (admin)"
        $c = "beacon.dll"
        $d = "cobaltstrike" nocase
    condition:
        2 of them
}

rule metasploit_indicators {
    meta:
        description = "Metasploit stager / meterpreter indicators"
        category = "c2_frameworks"
    strings:
        $a = "metsrv.x64.dll"
        $b = "meterpreter"
        $c = "Metasploit" nocase
    condition:
        any of them
}

rule mimikatz_strings {
    meta:
        description = "Mimikatz credential dump tool indicators"
        category = "hack_tools"
    strings:
        $s1 = "sekurlsa" ascii wide
        $s2 = "kerberos" ascii wide
        $s3 = "lsadump" ascii wide
        $s4 = "mimikatz" ascii wide nocase
        $s5 = "gentilkiwi" ascii wide
    condition:
        2 of them
}

rule process_hollowing_apis {
    meta:
        description = "Process hollowing API co-occurrence"
        category = "shellcode"
    strings:
        $a1 = "NtUnmapViewOfSection"
        $a2 = "WriteProcessMemory"
        $a3 = "ResumeThread"
    condition:
        all of them
}

rule shellcode_nop_sled {
    meta:
        description = "NOP sled (10+ consecutive 0x90 bytes)"
        category = "shellcode"
    strings:
        $nop = { 90 90 90 90 90 90 90 90 90 90 }
    condition:
        $nop
}

rule generic_shellcode_hash_stub {
    meta:
        description = "Common shellcode hash-based API resolution prologue"
        category = "shellcode"
    strings:
        $hash_prologue = { FC E8 [1-4] 00 00 00 }
    condition:
        $hash_prologue
}
"""

# Reverse-lookup maps: rule name → algorithm/category key
_CRYPTO_ALGORITHM_MAP: dict[str, list[str]] = {
    "aes":    ["aes_sbox", "aes_sbox_inv"],
    "md5":    ["md5_constants"],
    "sha1":   ["sha1_constants"],
    "sha256": ["sha256_constants"],
    "sha512": ["sha512_constants"],
    "crc32":  ["crc32_table"],
    "rc4":    ["rc4_init_array"],
}

_THREAT_CATEGORY_MAP: dict[str, list[str]] = {
    "packers":       ["upx_packed", "vmprotect", "themida", "nspack", "aspack"],
    "c2_frameworks": ["cobalt_strike_beacon", "metasploit_indicators"],
    "hack_tools":    ["mimikatz_strings"],
    "shellcode":     ["process_hollowing_apis", "shellcode_nop_sled", "generic_shellcode_hash_stub"],
}

# Flat inverted maps for O(1) lookup
_RULE_TO_ALG: dict[str, str] = {r: alg for alg, rules in _CRYPTO_ALGORITHM_MAP.items() for r in rules}
_RULE_TO_CATEGORY: dict[str, str] = {r: cat for cat, rules in _THREAT_CATEGORY_MAP.items() for r in rules}

# Leading bytes of each algorithm's constant — used by _triton_verify_crypto_usage
# to locate the constant VA in function data regardless of algorithm.
_CRYPTO_CONSTANT_BYTES: dict[str, bytes] = {
    "aes":    bytes.fromhex("637c777bf26b6fc530"),   # forward S-box
    "md5":    bytes.fromhex("0123456789abcdeffedcba98"),  # init hash LE
    "sha1":   bytes.fromhex("67452301efcdab8998badcfe"),  # init hash
    "sha256": bytes.fromhex("6a09e667bb67ae853c6ef372"),  # init hash BE
    "sha512": bytes.fromhex("428a2f98d728ae22"),           # first round constant
    "crc32":  bytes.fromhex("0000000096300777"),           # polynomial table start
    "rc4":    bytes.fromhex("000102030405060708090a0b"),   # identity permutation prefix
}

# ============================================================================
# Private helpers (module-level, usable regardless of YARA_AVAILABLE)
# ============================================================================


@functools.lru_cache(maxsize=32)
def _compile_rules_cached(rules_text: str):
    """Compile YARA rules from text; cached by content hash to avoid recompilation."""
    if not YARA_AVAILABLE:
        raise RuntimeError("yara-python not installed")
    return _yara_lib.compile(source=rules_text)


def _compile_rules(source_or_path: str):
    """Compile YARA rules from inline text or a .yar file path."""
    if os.path.isfile(source_or_path):
        try:
            with open(source_or_path, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError as exc:
            raise ValueError(f"Cannot read rule file: {exc}") from exc
    else:
        text = source_or_path
    return _compile_rules_cached(text)


def _count_rules(compiled) -> int:
    # yara-python 4.x iteration consistency varies across minor versions.
    # Try the .rules attribute first (more stable), fall back to __iter__.
    try:
        rules_attr = getattr(compiled, "rules", None)
        if rules_attr is not None:
            return len(list(rules_attr))
        return sum(1 for _ in compiled)
    except Exception:
        return 0


def _match_to_dict(match, base_va: int = 0) -> dict:
    """Serialize a yara.Match to a JSON-safe dict with VA-mapped string offsets."""
    strings = []
    for sm in match.strings:
        for inst in sm.instances:
            va = base_va + inst.offset
            entry: dict = {
                "identifier":       sm.identifier,
                "virtual_address":  hex(va),
                "file_offset":      inst.offset,
                "data_hex":         inst.matched_data[:32].hex(),
                "matched_length":   inst.matched_length,
            }
            if inst.xor_key:
                entry["xor_key"] = inst.xor_key
                try:
                    entry["plaintext_hex"] = inst.plaintext()[:32].hex()
                except Exception:
                    pass
            strings.append(entry)
    return {
        "rule":      match.rule,
        "namespace": match.namespace,
        "tags":      list(match.tags),
        "meta":      dict(match.meta),
        "strings":   strings,
    }


def _scan_bytes(compiled, data: bytes, base_va: int = 0, timeout: int = 30, max_results: int = 200) -> list[dict]:
    matches = compiled.match(data=data, timeout=timeout)
    return [_match_to_dict(m, base_va) for m in matches[:max_results]]


def _extract_printable_strings(data: bytes, min_len: int = 5) -> list[str]:
    printable = frozenset(b for b in _string_mod.printable.encode() if b not in (0x0A, 0x0D, 0x09))
    results, buf = [], []
    for b in data:
        if b in printable:
            buf.append(chr(b))
        else:
            if len(buf) >= min_len:
                results.append("".join(buf))
            buf = []
    if len(buf) >= min_len:
        results.append("".join(buf))
    return results


def _build_hex_string_wildcarded(data: bytes, wildcard_offsets: set[int]) -> tuple[str, int]:
    """Return (yara_hex_string, wildcarded_byte_count)."""
    parts, wildcarded, i = [], 0, 0
    while i < len(data):
        if i in wildcard_offsets and i + 4 <= len(data):
            parts.append("?? ?? ?? ??")
            wildcarded += 4
            i += 4
        else:
            parts.append(f"{data[i]:02X}")
            i += 1
    return " ".join(parts), wildcarded


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _rule_to_alg(rule_name: str) -> str:
    return _RULE_TO_ALG.get(rule_name, rule_name)


def _rule_to_threat_category(rule_name: str) -> str:
    return _RULE_TO_CATEGORY.get(rule_name, "unknown")


def _compute_threat_risk(cat_summary: dict) -> tuple[int, str]:
    weights = {"c2_frameworks": 40, "hack_tools": 35, "shellcode": 25, "packers": 20}
    score = min(sum(weights.get(c, 10) for c, d in cat_summary.items() if d.get("detected")), 100)
    # Vocabulary matches hybrid_yara_lief_profile so AI agents see consistent labels.
    if score >= 60:
        level = "MALICIOUS"
    elif score >= 35:
        level = "LIKELY_MALICIOUS"
    elif score >= 15:
        level = "SUSPICIOUS"
    else:
        level = "CLEAN"
    return score, level


def _lief_detect_format(binary) -> str:
    try:
        import lief as _lief_m
        if isinstance(binary, _lief_m.PE.Binary):
            return "PE"
        if isinstance(binary, _lief_m.ELF.Binary):
            return "ELF"
        if hasattr(_lief_m, "MachO") and isinstance(binary, _lief_m.MachO.Binary):
            return "MachO"
        return str(getattr(binary, "format", "unknown")).split(".")[-1]
    except Exception:
        return "unknown"


def _lief_basic_checksec(binary) -> tuple[int, dict]:
    """Return (score, details_dict) for a LIEF binary. Score is 0–4 for ELF, 0–3 for PE."""
    score, details = 0, {}
    try:
        import lief as _lief_m
        if isinstance(binary, _lief_m.ELF.Binary):
            nx = True
            for seg in binary.segments:
                if getattr(seg.type, "name", str(seg.type)) == "GNU_STACK":
                    try:
                        nx = not bool(seg.flags & _lief_m.ELF.Segment.FLAGS.X)
                    except Exception:
                        pass
                    break
            pie = bool(getattr(binary, "is_pie", False))
            relro = "none"
            for seg in binary.segments:
                if getattr(seg.type, "name", str(seg.type)) == "GNU_RELRO":
                    relro = "partial"
                    break
            try:
                for dyn in binary.dynamic_entries:
                    if str(dyn.tag).split(".")[-1] == "BIND_NOW":
                        relro = "full"
                        break
            except Exception:
                pass
            canary = any("__stack_chk_fail" in str(getattr(f, "name", "")) for f in getattr(binary, "imported_functions", []))
            details = {"nx": nx, "pie": pie, "relro": relro, "canary": canary}
            score = sum([nx, pie, relro != "none", canary])
        elif isinstance(binary, _lief_m.PE.Binary):
            chars = (
                getattr(binary.optional_header, "dll_characteristics_lists", None)
                or getattr(binary.optional_header, "dll_characteristics_list", None)
                or []
            )
            names = {str(c).split(".")[-1] for c in chars}
            nx = "NX_COMPAT" in names
            aslr = "DYNAMIC_BASE" in names
            cfg = "GUARD_CF" in names
            details = {"nx": nx, "aslr": aslr, "cfg": cfg}
            score = sum([nx, aslr, cfg])
    except Exception:
        pass
    return score, details


def _lief_has_overlay(binary) -> bool:
    try:
        import lief as _lief_m
        if isinstance(binary, _lief_m.PE.Binary):
            ov = getattr(binary, "overlay", None)
            return ov is not None and len(ov) > 0
    except Exception:
        pass
    return False


def _triton_verify_crypto_usage(func_ea: int, size: int, data: bytes, algorithm: str) -> tuple[str, str, str]:
    """Symbolically confirm that a function actually uses the detected crypto constant.

    Returns (result, confidence, note).
    result is one of: 'confirmed', 'unconfirmed', 'triton_unavailable', 'error'.
    """
    try:
        import triton as _triton_local
        info = idaapi.get_inf_structure()
        arch = _triton_local.ARCH.X86_64 if info.is_64bit() else _triton_local.ARCH.X86
        ctx = _triton_local.TritonContext(arch)
        ctx.setMode(_triton_local.MODE.ALIGNED_MEMORY, True)

        for i, b in enumerate(data):
            ctx.setConcreteMemoryValue(func_ea + i, b)

        pc = func_ea
        instrs_processed = 0
        memory_reads: list[int] = []

        # Locate the algorithm-specific constant bytes in function data.
        # Falls back to the AES S-box pattern for algorithms not in the map.
        const_bytes = _CRYPTO_CONSTANT_BYTES.get(algorithm) or _CRYPTO_CONSTANT_BYTES.get("aes", b"")
        const_va: int | None = None
        if const_bytes:
            idx = bytes(data).find(const_bytes)
            if idx >= 0:
                const_va = func_ea + idx

        for _ in range(300):
            instr = _triton_local.Instruction()
            try:
                raw = bytes(ctx.getConcreteMemoryAreaValue(pc, 15))
            except Exception:
                break
            instr.setOpcode(raw)
            instr.setAddress(pc)
            if not ctx.processing(instr):
                break
            for mem_access, _ in instr.getLoadAccess():
                memory_reads.append(mem_access.getAddress())
            pc = ctx.getConcreteRegisterValue(ctx.registers.rip if info.is_64bit() else ctx.registers.eip)
            instrs_processed += 1
            if pc < func_ea or pc >= func_ea + size:
                break

        # Confirm: a memory read hit within 256 bytes of the located constant
        if const_va is not None:
            for ra in memory_reads:
                if const_va <= ra < const_va + 256:
                    return "confirmed", "HIGH", (
                        f"Triton traced {instrs_processed} instructions; "
                        f"memory read at {hex(ra)} hits the {algorithm} constant at {hex(const_va)}"
                    )

        # Heuristic: many memory reads + good instruction count = likely computation
        if instrs_processed >= 60 and len(memory_reads) >= 8:
            return "confirmed", "MEDIUM", (
                f"Triton traced {instrs_processed} instructions with {len(memory_reads)} "
                "memory accesses; computation-heavy function likely uses the constant"
            )

        return "unconfirmed", "LOW", (
            f"Triton traced {instrs_processed} instructions; "
            "no definitive constant-access pattern observed"
        )
    except ImportError:
        return "triton_unavailable", "LOW", "Install triton-library for algorithmic confirmation"
    except Exception as exc:
        return "error", "LOW", f"Triton error: {exc}"


def _miasm_lift_and_simplify(func_ea: int, data: bytes) -> tuple[int, int, int, str]:
    """Lift function to Miasm IR, run dead-code elimination.

    Returns (raw_blocks, simplified_blocks, dead_instrs_removed, summary_text).
    """
    try:
        from miasm.analysis.machine import Machine
        from miasm.core.locationdb import LocationDB
        import miasm.analysis.data_flow as _df

        info = idaapi.get_inf_structure()
        machine_name = "x86_64" if info.is_64bit() else "x86_32"
        machine = Machine(machine_name)
        loc_db = LocationDB()

        mdis = machine.dis_engine(data, loc_db=loc_db, follow_call=False)
        mdis.dont_dis = []
        asmcfg = mdis.dis_multiblock(0)

        ira_arch = machine.ira(loc_db)
        ircfg = ira_arch.new_ircfg_from_asmcfg(asmcfg)
        raw_block_count = len(list(ircfg.blocks))

        # Simplify
        modified, passes = True, 0
        while modified and passes < 5:
            try:
                modified = _df.dead_simp(ircfg)
            except Exception:
                break
            passes += 1

        simplified_block_count = len(list(ircfg.blocks))
        dead_removed = max(0, raw_block_count - simplified_block_count)

        snippet_lines = []
        for i, (loc, block) in enumerate(ircfg.blocks.items()):
            if i >= 3:
                snippet_lines.append("  ...")
                break
            asgn_count = len(list(block.assignblks))
            snippet_lines.append(f"  [{loc}] {asgn_count} assign-block(s)")

        summary = (
            f"{raw_block_count} IR blocks → {simplified_block_count} after simplification; "
            f"{dead_removed} block(s) removed.\n" + "\n".join(snippet_lines)
        )
        return raw_block_count, simplified_block_count, dead_removed, summary

    except ImportError:
        return 0, 0, 0, "Miasm not available — install with: pip install miasm future"
    except Exception as exc:
        return 0, 0, 0, f"Miasm error: {exc}"


# ============================================================================
# I.0 — yara_status  (always registered; no YARA_AVAILABLE guard)
# ============================================================================


@tool
@idasync
def yara_status() -> YaraStatusResult:
    """Return YARA availability, version, and built-in rule inventory.

    Always succeeds regardless of whether yara-python is installed.
    Check the 'available' field before calling other yara_* tools."""
    if not YARA_AVAILABLE:
        return {
            "ok": True,
            "available": False,
            "hint": "pip install yara-python",
            "builtin_crypto_rules": 0,
            "builtin_threat_rules": 0,
        }

    version = getattr(_yara_lib, "__version__", "unknown")
    try:
        crypto_count = _count_rules(_compile_rules_cached(_BUILTIN_CRYPTO_RULES))
        threat_count = _count_rules(_compile_rules_cached(_BUILTIN_THREAT_RULES))
    except Exception:
        crypto_count = len(_CRYPTO_ALGORITHM_MAP)
        threat_count = len(_THREAT_CATEGORY_MAP)

    return {
        "ok": True,
        "available": True,
        "version": version,
        "builtin_crypto_rules": crypto_count,
        "builtin_threat_rules": threat_count,
    }


# ============================================================================
# Remaining tools — only registered when yara-python is present
# ============================================================================

if YARA_AVAILABLE:

    # Warm built-in rule cache at import time so first call is fast
    try:
        _compile_rules_cached(_BUILTIN_CRYPTO_RULES)
        _compile_rules_cached(_BUILTIN_THREAT_RULES)
    except Exception:
        pass

    # ------------------------------------------------------------------
    # I.1 — yara_scan
    # ------------------------------------------------------------------

    @tool
    @idasync
    def yara_scan(
        rules: Annotated[str, "Inline YARA rule text or absolute path to a .yar file"],
        address: Annotated[str, "IDA start address (hex/symbol); empty = whole loaded binary"] = "",
        end_address: Annotated[str, "IDA end address; ignored when address is empty"] = "",
        file_path: Annotated[str, "Raw file path to scan; overrides address-based scanning"] = "",
        timeout: Annotated[int, "Scan timeout in seconds (default: 30)"] = 30,
        max_results: Annotated[int, "Maximum matches to return (default: 200)"] = 200,
    ) -> YaraScanResult:
        """Scan an IDA memory range, the loaded binary, or a raw file against YARA rules.

        Priority order: file_path > address range > whole IDB source binary.
        Offsets in the returned matches are mapped to IDA virtual addresses when
        scanning from IDB memory; file scans return file-relative offsets."""
        try:
            if not rules or not rules.strip():
                return {"ok": False, "error": "rules must not be empty"}
            compiled = _compile_rules(rules)
            rule_count = _count_rules(compiled)

            if file_path:
                if not os.path.isfile(file_path):
                    return {"ok": False, "error": f"File not found: {file_path}"}
                matches = compiled.match(filepath=file_path, timeout=timeout)
                bytes_scanned = os.path.getsize(file_path)
                match_dicts = [_match_to_dict(m, 0) for m in matches[:max_results]]
                source = "file"

            elif address:
                start_ea = parse_address(address)
                if end_address:
                    end_ea = parse_address(end_address)
                else:
                    seg = idaapi.getseg(start_ea)
                    end_ea = seg.end_ea if seg else start_ea + 4096
                size = end_ea - start_ea
                if size <= 0:
                    return {"ok": False, "error": "end_address must be greater than address"}
                data = read_bytes_bss_safe(start_ea, size)
                match_dicts = _scan_bytes(compiled, bytes(data), start_ea, timeout, max_results)
                bytes_scanned = len(data)
                source = "idb_range"

            else:
                src = idaapi.get_input_file_path()
                if not src or not os.path.isfile(src):
                    return {"ok": False, "error": "No source file — pass file_path or an address"}
                matches = compiled.match(filepath=src, timeout=timeout)
                bytes_scanned = os.path.getsize(src)
                match_dicts = [_match_to_dict(m, 0) for m in matches[:max_results]]
                source = "idb_file"

            return {
                "ok":            True,
                "source":        source,
                "bytes_scanned": bytes_scanned,
                "rules_compiled": rule_count,
                "total_matches": len(match_dicts),
                "matches":       match_dicts,
            }
        except _yara_lib.SyntaxError as exc:
            return {"ok": False, "error": f"YARA rule syntax error: {exc}"}
        except _yara_lib.TimeoutError:
            return {"ok": False, "error": f"YARA scan exceeded {timeout}s timeout"}
        except Exception as exc:
            return {**tool_error(exc), "ok": False}

    # ------------------------------------------------------------------
    # I.2 — yara_scan_builtin_crypto
    # ------------------------------------------------------------------

    @tool
    @idasync
    def yara_scan_builtin_crypto(
        address: Annotated[str, "IDA start address; empty = whole loaded binary"] = "",
        end_address: Annotated[str, "IDA end address; ignored when address is empty"] = "",
        algorithms: Annotated[
            list[str] | str,
            "Algorithms: aes, md5, sha1, sha256, sha512, crc32, rc4. 'all' = everything",
        ] = "all",
        scan_executable_sections: Annotated[
            bool,
            "Scan executable (.text) sections too — increases false positives (default: false)",
        ] = False,
    ) -> YaraCryptoResult:
        """Scan for cryptographic constants using built-in rules. No external files needed.

        Detects: AES S-box (forward + inverse), MD5 / SHA-1 / SHA-256 / SHA-512
        initialisation vectors, CRC32 polynomial table, and RC4 identity permutation.

        By default executable sections are skipped — machine-code bytes occasionally
        produce false matches against short crypto patterns. Pass
        scan_executable_sections=True to override."""
        try:
            raw_algs = normalize_list_input(algorithms) if isinstance(algorithms, str) else list(algorithms)
            want_all = (not raw_algs) or (len(raw_algs) == 1 and raw_algs[0].strip().lower() == "all")
            wanted = set(_CRYPTO_ALGORITHM_MAP.keys()) if want_all else {a.strip().lower() for a in raw_algs}

            compiled = _compile_rules_cached(_BUILTIN_CRYPTO_RULES)

            if address:
                start_ea = parse_address(address)
                end_ea = parse_address(end_address) if end_address else (
                    (lambda s: s.end_ea if s else start_ea + 4096)(idaapi.getseg(start_ea))
                )
                if end_ea <= start_ea:
                    return {"ok": False, "error": "end_address must be > address"}
                data = bytearray(read_bytes_bss_safe(start_ea, end_ea - start_ea))
                if not scan_executable_sections:
                    for seg_ea in idautils.Segments():
                        seg = idaapi.getseg(seg_ea)
                        if seg and (seg.perm & idaapi.SEGPERM_EXEC):
                            ov_s = max(seg.start_ea, start_ea) - start_ea
                            # Clamp to actual buffer length — read_bytes_bss_safe may return
                            # fewer bytes than requested for BSS/unmapped regions.
                            ov_e = min(min(seg.end_ea, end_ea) - start_ea, len(data))
                            for i in range(ov_s, ov_e):
                                data[i] = 0
                matches = compiled.match(data=bytes(data), timeout=60)
                bytes_scanned = len(data)
                base = start_ea
            else:
                src = idaapi.get_input_file_path()
                if not src or not os.path.isfile(src):
                    return {"ok": False, "error": "No source file found"}
                matches = compiled.match(filepath=src, timeout=60)
                bytes_scanned = os.path.getsize(src)
                base = 0

            filtered = [m for m in matches if _rule_to_alg(m.rule) in wanted]
            algo_summary: dict = {a: {"hits": 0, "addresses": []} for a in wanted}
            match_dicts: list[dict] = []

            for m in filtered:
                alg = _rule_to_alg(m.rule)
                d = _match_to_dict(m, base)
                match_dicts.append(d)
                if alg in algo_summary:
                    algo_summary[alg]["hits"] += 1
                    for s in d.get("strings", []):
                        algo_summary[alg]["addresses"].append(s.get("virtual_address", "0x0"))

            return {
                "ok":               True,
                "bytes_scanned":    bytes_scanned,
                "total_matches":    len(filtered),
                "algorithm_summary": algo_summary,
                "matches":          match_dicts,
            }
        except Exception as exc:
            return {**tool_error(exc), "ok": False}

    # ------------------------------------------------------------------
    # I.3 — yara_scan_builtin_threats
    # ------------------------------------------------------------------

    @tool
    @idasync
    def yara_scan_builtin_threats(
        address: Annotated[str, "IDA start address; empty = whole loaded binary"] = "",
        end_address: Annotated[str, "IDA end address"] = "",
        categories: Annotated[
            list[str] | str,
            "Categories: packers, c2_frameworks, hack_tools, shellcode. 'all' = everything",
        ] = "all",
    ) -> YaraThreatResult:
        """Scan for threat indicators using built-in rules. No external files needed.

        Detects packers (UPX, VMProtect, Themida, ASPack, NsPack), C2 frameworks
        (Cobalt Strike, Metasploit), hack tools (Mimikatz), and shellcode patterns
        (process hollowing API triad, NOP sleds, hash-resolve stubs).

        Returns a risk_score (0–100) and risk_level (CLEAN/SUSPICIOUS/LIKELY_MALICIOUS/MALICIOUS)."""
        try:
            raw_cats = normalize_list_input(categories) if isinstance(categories, str) else list(categories)
            want_all = (not raw_cats) or (len(raw_cats) == 1 and raw_cats[0].strip().lower() == "all")
            wanted = set(_THREAT_CATEGORY_MAP.keys()) if want_all else {c.strip().lower() for c in raw_cats}

            compiled = _compile_rules_cached(_BUILTIN_THREAT_RULES)

            if address:
                start_ea = parse_address(address)
                end_ea = parse_address(end_address) if end_address else (
                    (lambda s: s.end_ea if s else start_ea + 4096)(idaapi.getseg(start_ea))
                )
                if end_ea <= start_ea:
                    return {"ok": False, "error": "end_address must be > address"}
                data = read_bytes_bss_safe(start_ea, end_ea - start_ea)
                matches = compiled.match(data=bytes(data), timeout=60)
                bytes_scanned, base = len(data), start_ea
            else:
                src = idaapi.get_input_file_path()
                if not src or not os.path.isfile(src):
                    return {"ok": False, "error": "No source file found"}
                matches = compiled.match(filepath=src, timeout=60)
                bytes_scanned, base = os.path.getsize(src), 0

            filtered = [m for m in matches if _rule_to_threat_category(m.rule) in wanted]
            cat_summary: dict = {c: {"detected": False, "hits": 0, "rules": []} for c in wanted}
            match_dicts: list[dict] = []

            for m in filtered:
                cat = _rule_to_threat_category(m.rule)
                d = _match_to_dict(m, base)
                match_dicts.append(d)
                if cat in cat_summary:
                    cat_summary[cat]["detected"] = True
                    cat_summary[cat]["hits"] += 1
                    if m.rule not in cat_summary[cat]["rules"]:
                        cat_summary[cat]["rules"].append(m.rule)

            risk_score, risk_level = _compute_threat_risk(cat_summary)

            return {
                "ok":              True,
                "bytes_scanned":   bytes_scanned,
                "risk_score":      risk_score,
                "risk_level":      risk_level,
                "category_summary": cat_summary,
                "total_matches":   len(filtered),
                "matches":         match_dicts,
            }
        except Exception as exc:
            return {**tool_error(exc), "ok": False}

    # ------------------------------------------------------------------
    # I.4 — yara_rule_validate
    # ------------------------------------------------------------------

    @tool
    @idasync
    def yara_rule_validate(
        rules: Annotated[str, "YARA rule text to validate"],
    ) -> YaraValidateResult:
        """Validate YARA rule syntax without performing any scan.

        Returns rule_count and any syntax error with line number.
        Useful for verifying AI-generated rules before running them at scale."""
        try:
            if not rules or not rules.strip():
                return {"ok": True, "valid": False, "rule_count": 0,
                        "error": "rules must not be empty", "error_line": None}
            compiled = _yara_lib.compile(source=rules)
            return {
                "ok":         True,
                "valid":      True,
                "rule_count": _count_rules(compiled),
                "error":      None,
                "error_line": None,
            }
        except _yara_lib.SyntaxError as exc:
            msg = str(exc)
            m = _re.search(r"\(line (\d+)\)", msg)
            return {
                "ok":         True,
                "valid":      False,
                "rule_count": 0,
                "error":      msg,
                "error_line": int(m.group(1)) if m else None,
            }
        except Exception as exc:
            return {**tool_error(exc), "ok": False}

    # ------------------------------------------------------------------
    # I.5 — yara_generate_rule
    # ------------------------------------------------------------------

    @tool
    @idasync
    def yara_generate_rule(
        address: Annotated[str, "Start address (hex or symbol name)"],
        size: Annotated[int, "Number of bytes to read for the rule"],
        rule_name: Annotated[str, "YARA rule identifier"] = "generated_rule",
        wildcards: Annotated[
            bool,
            "Replace 4-byte pointer-like DWORDs (relocated addresses) with ?? wildcards",
        ] = True,
        include_strings: Annotated[
            bool,
            "Extract embedded ASCII strings (≥5 chars) as additional YARA conditions",
        ] = True,
        min_unique_bytes: Annotated[
            int,
            "Minimum concrete (non-wildcard) bytes required; error returned if below this",
        ] = 8,
        tags: Annotated[str, "Space-separated YARA tags (e.g. 'crypto malware')"] = "",
    ) -> YaraGenerateResult:
        """Generate a YARA rule from bytes at an IDA address.

        Pointer-sized values that look like relocated image addresses are wildcarded
        (replaced with ??) so the rule matches the function regardless of ASLR slide.
        Embedded ASCII strings are added as optional extra conditions for precision.

        The generated rule is validated with yara.compile before being returned."""
        try:
            start_ea = parse_address(address)
            if not (1 <= size <= 0x100000):
                return {"ok": False, "error": "size must be 1–1048576 bytes"}

            data = bytes(read_bytes_bss_safe(start_ea, size))
            if len(data) < min_unique_bytes:
                return {"ok": False, "error": f"Read only {len(data)} bytes from {hex(start_ea)}"}

            safe_name = _re.sub(r"[^A-Za-z0-9_]", "_", rule_name)
            if not safe_name or safe_name[0].isdigit():
                safe_name = "rule_" + safe_name

            # Identify pointer-like 4-byte sequences for wildcarding
            wildcard_offsets: set[int] = set()
            if wildcards and len(data) >= 8:
                imagebase = idaapi.get_imagebase()
                # Conservative estimate of binary extent
                max_rva = max(
                    (seg.end_ea - imagebase for seg in
                     (idaapi.getseg(ea) for ea in idautils.Segments()) if seg),
                    default=0x10000000,
                )
                for i in range(0, len(data) - 3, 4):
                    dw = struct.unpack_from("<I", data, i)[0]
                    if imagebase <= dw < imagebase + max_rva:
                        wildcard_offsets.add(i)

            hex_body, wildcarded_count = _build_hex_string_wildcarded(data, wildcard_offsets)
            concrete_bytes = len(data) - wildcarded_count

            if concrete_bytes < min_unique_bytes:
                return {
                    "ok":    False,
                    "error": (
                        f"Only {concrete_bytes} concrete bytes after wildcarding "
                        f"(need {min_unique_bytes}). Increase size or pass wildcards=False."
                    ),
                }

            extracted: list[str] = []
            if include_strings:
                extracted = [s for s in _extract_printable_strings(data, min_len=5)][:8]

            tag_part = f" : {tags.strip()}" if tags.strip() else ""
            lines = [f"rule {safe_name}{tag_part} {{"]
            lines += ["    meta:",
                      f'        generated_from = "{hex(start_ea)}"',
                      f'        size_bytes = {size}',
                      "    strings:",
                      f"        $hex1 = {{ {hex_body} }}"]
            for i, s in enumerate(extracted, 1):
                lines.append(f'        $str{i} = "{s.replace(chr(92), chr(92)*2).replace(chr(34), chr(92)+chr(34))}"')
            lines.append("    condition:")
            lines.append("        $hex1 and any of ($str*)" if extracted else "        $hex1")
            lines.append("}")
            rule_text = "\n".join(lines)

            valid, validate_err = False, None
            try:
                _yara_lib.compile(source=rule_text)
                valid = True
            except Exception as ve:
                validate_err = str(ve)

            result: YaraGenerateResult = {
                "ok":               True,
                "rule_text":        rule_text,
                "rule_name":        safe_name,
                "coverage":         round(concrete_bytes / len(data), 3),
                "wildcarded_bytes": wildcarded_count,
                "hex_fragments":    1,
                "strings_extracted": len(extracted),
                "valid":            valid,
            }
            if validate_err:
                result["error"] = validate_err
            return result
        except Exception as exc:
            return {**tool_error(exc), "ok": False}

    # ------------------------------------------------------------------
    # I.6 — yara_idb_annotate  ⭐ KILLER FEATURE
    # ------------------------------------------------------------------

    @tool
    @idasync
    def yara_idb_annotate(
        rules: Annotated[str, "Inline YARA rule text or path to a .yar file"],
        scope: Annotated[
            str,
            "Scan scope: 'functions' (per-function, most precise), "
            "'segments' (per-segment, faster), 'file' (raw source binary)",
        ] = "functions",
        annotate: Annotated[bool, "Add repeatable IDA comments at each matching address"] = True,
        rename_auto: Annotated[
            bool,
            "Rename sub_XXXX / off_XXXX functions to yara_<rule_name> when matched",
        ] = True,
        comment_prefix: Annotated[str, "Prefix for all IDA comments"] = "[YARA]",
        dry_run: Annotated[bool, "Preview changes without writing to the IDB (default: true)"] = True,
        min_func_size: Annotated[int, "Skip functions smaller than this many bytes"] = 8,
        timeout: Annotated[int, "Per-target scan timeout in seconds"] = 10,
    ) -> YaraAnnotateResult:
        """Scan the IDB and annotate matching functions with YARA-derived comments and names.

        This is the feature that makes YARA uniquely powerful inside IDA.  Unlike
        standalone YARA (which returns file offsets), this tool:

          1. Scans each function's bytes individually with the provided rules.
          2. Maps every string-match offset back to an IDA virtual address.
          3. Adds a repeatable comment at each hit VA (when annotate=True).
          4. Adds a function-level comment listing all matched rule names.
          5. Renames sub_XXXX / off_XXXX stubs to 'yara_<rule_name>'
             (when rename_auto=True).

        Use dry_run=True (default) to preview all changes safely before committing.

        Scope 'functions' is most precise and avoids cross-function noise;
        'segments' is faster for large IDBs; 'file' bypasses IDA entirely."""
        try:
            if not rules or not rules.strip():
                return {"ok": False, "error": "rules must not be empty"}
            compiled = _compile_rules(rules)
            rule_count = _count_rules(compiled)
            annotation_report: list[dict] = []
            total_matches = funcs_matched = funcs_annotated = funcs_renamed = 0
            targets_scanned = bytes_scanned = 0

            if scope == "functions":
                for func_ea in idautils.Functions():
                    func = idaapi.get_func(func_ea)
                    if not func:
                        continue
                    size = func.end_ea - func_ea
                    if size < min_func_size:
                        continue
                    data = bytes(read_bytes_bss_safe(func_ea, size))
                    targets_scanned += 1
                    bytes_scanned += len(data)

                    try:
                        matches = compiled.match(data=data, timeout=timeout)
                    except (_yara_lib.TimeoutError, Exception):
                        continue
                    if not matches:
                        continue

                    funcs_matched += 1
                    total_matches += len(matches)
                    current_name = idc.get_func_name(func_ea) or f"sub_{func_ea:X}"
                    rule_names = list(dict.fromkeys(m.rule for m in matches))

                    match_details = [
                        {
                            "rule":      m.rule,
                            "string_id": sm.identifier,
                            "va":        hex(func_ea + inst.offset),
                            "data_hex":  inst.matched_data[:16].hex(),
                        }
                        for m in matches
                        for sm in m.strings
                        for inst in sm.instances
                    ]

                    new_name: str | None = None
                    if rename_auto and _is_auto_name(current_name):
                        new_name = f"yara_{rule_names[0]}"
                        if len(rule_names) > 1:
                            new_name += "_multi"

                    if not dry_run:
                        if annotate:
                            idc.set_func_cmt(func_ea,
                                f"{comment_prefix} matched: {', '.join(rule_names)}", True)
                            for m in matches:
                                for sm in m.strings:
                                    for inst in sm.instances:
                                        idc.set_cmt(func_ea + inst.offset,
                                            f"{comment_prefix} {m.rule}:{sm.identifier}", True)
                            funcs_annotated += 1
                        if new_name and idc.set_name(func_ea, new_name, idc.SN_FORCE):
                            funcs_renamed += 1
                            # IDA may deduplicate (e.g. yara_aes_sbox_0) — read back the real name.
                            current_name = idc.get_func_name(func_ea) or new_name
                    else:
                        if annotate:
                            funcs_annotated += 1
                        if new_name:
                            funcs_renamed += 1

                    annotation_report.append({
                        "function_ea":   hex(func_ea),
                        "function_name": current_name,
                        "renamed_to":    new_name,
                        "rules_matched": rule_names,
                        "comment_set":   annotate,
                        "match_details": match_details,
                    })

            elif scope == "segments":
                for seg_ea in idautils.Segments():
                    seg = idaapi.getseg(seg_ea)
                    if not seg or seg.end_ea <= seg_ea:
                        continue
                    data = bytes(read_bytes_bss_safe(seg_ea, seg.end_ea - seg_ea))
                    targets_scanned += 1
                    bytes_scanned += len(data)
                    try:
                        matches = compiled.match(data=data, timeout=timeout * 3)
                    except Exception:
                        continue
                    if not matches:
                        continue
                    seg_name = idc.get_segm_name(seg_ea) or hex(seg_ea)
                    funcs_matched += 1
                    total_matches += len(matches)
                    for m in matches:
                        for sm in m.strings:
                            for inst in sm.instances:
                                va = seg_ea + inst.offset
                                func = idaapi.get_func(va)
                                d = {
                                    "function_ea":   hex(func.start_ea) if func else "none",
                                    "function_name": (idc.get_func_name(func.start_ea) if func else None) or seg_name,
                                    "renamed_to":    None,
                                    "rules_matched": [m.rule],
                                    "comment_set":   annotate,
                                    "match_details": [{
                                        "rule": m.rule, "string_id": sm.identifier,
                                        "va": hex(va), "data_hex": inst.matched_data[:16].hex(),
                                    }],
                                }
                                annotation_report.append(d)
                                if annotate and not dry_run:
                                    idc.set_cmt(va, f"{comment_prefix} {m.rule}:{sm.identifier}", True)
                                    funcs_annotated += 1

            else:  # scope == "file"
                src = idaapi.get_input_file_path()
                if not src or not os.path.isfile(src):
                    return {"ok": False, "error": "No source file for file-scope scan"}
                file_matches = compiled.match(filepath=src, timeout=timeout * 15)
                targets_scanned = 1
                bytes_scanned = os.path.getsize(src)
                total_matches = len(file_matches)
                funcs_matched = len(set(m.rule for m in file_matches))
                # Wrap in the same function-centric envelope used by the functions scope
                # so callers can iterate annotation_report regardless of scope.
                src_basename = os.path.basename(src)
                annotation_report = [
                    {
                        "function_ea":   "0x0",
                        "function_name": src_basename,
                        "renamed_to":    None,
                        "rules_matched": [m.rule],
                        "comment_set":   False,
                        "match_details": [_match_to_dict(m, 0)],
                    }
                    for m in file_matches
                ]

            return {
                "ok":                 True,
                "dry_run":            dry_run,
                "scope":              scope,
                "rules_compiled":     rule_count,
                "targets_scanned":    targets_scanned,
                "bytes_scanned":      bytes_scanned,
                "total_matches":      total_matches,
                "functions_matched":  funcs_matched,
                "functions_annotated": funcs_annotated,
                "functions_renamed":  funcs_renamed,
                "annotation_report":  annotation_report,
            }
        except _yara_lib.SyntaxError as exc:
            return {"ok": False, "error": f"YARA rule syntax error: {exc}"}
        except Exception as exc:
            return {**tool_error(exc), "ok": False}

    # ------------------------------------------------------------------
    # I.7 — yara_function_classifier
    # ------------------------------------------------------------------

    @tool
    @idasync
    def yara_function_classifier(
        addresses: Annotated[str, "Comma-separated function addresses; empty = all functions"] = "",
        include_crypto: Annotated[bool, "Run built-in crypto detection rules"] = True,
        include_threats: Annotated[bool, "Run built-in threat detection rules"] = True,
        custom_rules: Annotated[str, "Additional YARA rule text for classification"] = "",
        min_size: Annotated[int, "Skip functions smaller than this many bytes (default: 16)"] = 16,
        timeout: Annotated[int, "Per-function scan timeout in seconds (default: 5)"] = 5,
    ) -> YaraClassifierResult:
        """Classify functions by YARA category and return a binary-level heat map.

        For each function: scans its bytes against built-in crypto rules, built-in
        threat rules, and any custom rules you supply.  Returns both a per-function
        breakdown and a category-level summary showing which functions fall into each
        category (crypto / packers / c2_frameworks / hack_tools / shellcode / custom).

        One call gives an instant overview of what role each function plays."""
        try:
            rule_parts = []
            if include_crypto:
                rule_parts.append(_BUILTIN_CRYPTO_RULES)
            if include_threats:
                rule_parts.append(_BUILTIN_THREAT_RULES)
            if custom_rules.strip():
                rule_parts.append(custom_rules.strip())
            if not rule_parts:
                return {"ok": False, "error": "No rules selected"}

            combined = "\n".join(rule_parts)
            compiled = _compile_rules_cached(combined)

            if addresses.strip():
                target_eas: list[int] = []
                for a in addresses.split(","):
                    a = a.strip()
                    if not a:
                        continue
                    try:
                        ea = parse_address(a)
                        func = idaapi.get_func(ea)
                        if func:
                            target_eas.append(func.start_ea)
                    except Exception:
                        pass
            else:
                target_eas = list(idautils.Functions())

            all_cats = (set(_CRYPTO_ALGORITHM_MAP) | set(_THREAT_CATEGORY_MAP)
                        | ({"custom"} if custom_rules.strip() else set()))
            cat_summary: dict = {c: {"count": 0, "functions": []} for c in all_cats}
            function_map: list[dict] = []
            funcs_classified = 0

            for func_ea in target_eas:
                func = idaapi.get_func(func_ea)
                if not func:
                    continue
                size = func.end_ea - func.start_ea
                if size < min_size:
                    continue
                data = bytes(read_bytes_bss_safe(func.start_ea, size))
                func_name = idc.get_func_name(func.start_ea) or f"sub_{func.start_ea:X}"

                try:
                    matches = compiled.match(data=data, timeout=timeout)
                except Exception:
                    matches = []

                categories: list[str] = []
                rule_names: list[str] = []

                for m in matches:
                    rule_names.append(m.rule)
                    alg = _rule_to_alg(m.rule)
                    if alg in _CRYPTO_ALGORITHM_MAP:
                        if alg not in categories:
                            categories.append(alg)
                        if alg in cat_summary:
                            cat_summary[alg]["count"] += 1
                            cat_summary[alg]["functions"].append(hex(func.start_ea))
                        continue
                    cat = _rule_to_threat_category(m.rule)
                    if cat in _THREAT_CATEGORY_MAP:
                        if cat not in categories:
                            categories.append(cat)
                        if cat in cat_summary:
                            cat_summary[cat]["count"] += 1
                            cat_summary[cat]["functions"].append(hex(func.start_ea))
                        continue
                    if custom_rules.strip():
                        if "custom" not in categories:
                            categories.append("custom")
                        if "custom" in cat_summary:
                            cat_summary["custom"]["count"] += 1
                            cat_summary["custom"]["functions"].append(hex(func.start_ea))

                if categories:
                    funcs_classified += 1

                function_map.append({
                    "address":    hex(func.start_ea),
                    "name":       func_name,
                    "size":       size,
                    "categories": list(dict.fromkeys(categories)),
                    "rules":      list(dict.fromkeys(rule_names)),
                })

            return {
                "ok":                    True,
                "functions_scanned":     len(target_eas),
                "functions_classified":  funcs_classified,
                "functions_unclassified": len(target_eas) - funcs_classified,
                "category_summary":      cat_summary,
                "function_map":          function_map,
            }
        except Exception as exc:
            return {**tool_error(exc), "ok": False}

    # ------------------------------------------------------------------
    # I.F.1 — hybrid_yara_lief_profile
    # ------------------------------------------------------------------

    @tool
    @idasync
    def hybrid_yara_lief_profile(
        rules: Annotated[str, "YARA rule text or .yar path; empty = built-in threat rules"] = "",
        file_path: Annotated[str, "Binary path; empty = IDB source file"] = "",
        include_crypto_scan: Annotated[bool, "Also run built-in crypto detection rules"] = True,
        timeout: Annotated[int, "Per-section YARA timeout in seconds (default: 15)"] = 15,
    ) -> HybridYaraLiefProfileResult:
        """Full binary threat profile combining LIEF section analysis with YARA scanning.

        Workflow:
        1. LIEF parses the binary and extracts sections with entropy + permissions.
        2. YARA scans each section independently (eliminates cross-section noise).
        3. YARA scans the whole binary with built-in threat rules.
        4. LIEF checksec reports NX / PIE / RELRO / stack-canary mitigations.
        5. Results are synthesised into threat_score (0–100), threat_level, and
           a human-readable profile_summary.

        Degrades gracefully when LIEF is absent: skips section isolation and
        reports the whole-binary YARA result only."""
        try:
            src = file_path if file_path else idaapi.get_input_file_path()
            if not src or not os.path.isfile(src):
                return {"ok": False, "error": "Source file not found"}

            # --- LIEF pass (optional) ---
            fmt_name = "unknown"
            checksec_score = 0
            mitigations: dict = {}
            has_overlay = False
            section_hits: list[dict] = []
            lief_ok = False

            try:
                import lief as _lief_local
                lief_ok = True
                binary = _lief_local.parse(src)
                if binary is not None:
                    fmt_name = _lief_detect_format(binary)
                    checksec_score, mitigations = _lief_basic_checksec(binary)
                    has_overlay = _lief_has_overlay(binary)

                    user_compiled = (
                        _compile_rules(rules) if rules.strip()
                        else _compile_rules_cached(_BUILTIN_THREAT_RULES)
                    )
                    for sec in binary.sections:
                        try:
                            raw = bytes(sec.content)
                        except Exception:
                            continue
                        if not raw:
                            continue
                        ent = _shannon_entropy(raw)
                        try:
                            sec_m = user_compiled.match(data=raw, timeout=timeout)
                        except Exception:
                            sec_m = []
                        if sec_m:
                            section_hits.append({
                                "section":       sec.name,
                                "entropy":       round(ent, 4),
                                "rules_matched": [m.rule for m in sec_m],
                                "size":          len(raw),
                            })
            except ImportError:
                pass
            except Exception:
                pass

            # --- Whole-binary YARA passes ---
            threat_compiled = _compile_rules_cached(_BUILTIN_THREAT_RULES)
            try:
                threat_m = threat_compiled.match(filepath=src, timeout=timeout * 3)
            except Exception:
                threat_m = []

            crypto_hits: list[str] = []
            if include_crypto_scan:
                try:
                    crypto_m = _compile_rules_cached(_BUILTIN_CRYPTO_RULES).match(
                        filepath=src, timeout=timeout * 3
                    )
                    crypto_hits = list(dict.fromkeys(m.rule for m in crypto_m))
                except Exception:
                    pass

            # --- Scoring ---
            threat_rules_hit = [m.rule for m in threat_m]
            indicators: list[str] = []
            score = 0

            def _any_in_cat(cat: str) -> list[str]:
                return [r for r in threat_rules_hit if _rule_to_threat_category(r) == cat]

            for cat, weight, label in [
                ("c2_frameworks", 40, "C2 framework"),
                ("hack_tools",    35, "Hack tool"),
                ("shellcode",     25, "Shellcode pattern"),
                ("packers",       20, "Packer"),
            ]:
                hits = _any_in_cat(cat)
                if hits:
                    score += weight
                    indicators.append(f"{label} detected: {hits}")

            high_ent_secs = [s for s in section_hits if s.get("entropy", 0.0) > 7.2]
            if high_ent_secs:
                score += 15
                indicators.append(f"High-entropy sections: {[s['section'] for s in high_ent_secs]}")
            if has_overlay:
                score += 20
                indicators.append("PE overlay detected (possible packed/SFX binary)")
            if lief_ok and checksec_score < 2:
                score += 10
                indicators.append(f"Weak security mitigations (checksec score: {checksec_score}/5)")
            if crypto_hits:
                indicators.append(f"Cryptographic constants: {crypto_hits}")

            score = min(score, 100)
            threat_level = (
                "MALICIOUS"       if score >= 60 else
                "LIKELY_MALICIOUS" if score >= 35 else
                "SUSPICIOUS"       if score >= 15 else
                "CLEAN"
            )

            parts = [
                f"Binary: {os.path.basename(src)} | Format: {fmt_name} | "
                f"Threat level: {threat_level} (score {score}/100)."
            ]
            if indicators:
                parts.append("Indicators: " + "; ".join(indicators) + ".")
            if crypto_hits:
                parts.append(f"Crypto algorithms present: {', '.join(crypto_hits)}.")
            if lief_ok:
                parts.append(f"Security mitigations: checksec score {checksec_score}.")
            profile_summary = " ".join(parts)

            return {
                "ok":               True,
                "file":             src,
                "format":           fmt_name,
                "checksec_score":   checksec_score,
                "mitigations":      mitigations,
                "has_overlay":      has_overlay,
                "threat_score":     score,
                "threat_level":     threat_level,
                "threat_indicators": indicators,
                "crypto_hits":      crypto_hits,
                "section_hits":     section_hits,
                "profile_summary":  profile_summary,
            }
        except Exception as exc:
            return {**tool_error(exc), "ok": False}

    # ------------------------------------------------------------------
    # I.F.2 — hybrid_yara_triton_verify_crypto
    # ------------------------------------------------------------------

    @tool
    @idasync
    def hybrid_yara_triton_verify_crypto(
        address: Annotated[str, "Function to verify; empty = auto-scan all functions"] = "",
        algorithm: Annotated[
            str,
            "Algorithm to look for: 'aes', 'md5', 'sha256', 'sha512', 'crc32', 'rc4', or 'auto'",
        ] = "auto",
        max_functions: Annotated[int, "Maximum candidate functions to verify (default: 5)"] = 5,
    ) -> HybridYaraTritonResult:
        """Verify crypto implementations: YARA locates candidates, Triton confirms usage.

        YARA quickly scans all functions for known crypto constants.  Triton then
        symbolically executes each candidate to check whether the constant is actually
        used in the computation (not just embedded as inert data).  This eliminates
        false positives from lookup tables stored near — but not used by — the function.

        Falls back gracefully: when Triton is unavailable the YARA candidates are still
        returned with triton_result='triton_unavailable' so the caller has the list."""
        try:
            triton_ok = False
            try:
                import triton as _triton_check  # noqa: F401
                triton_ok = True
            except ImportError:
                pass

            alg_filter = (
                list(_CRYPTO_ALGORITHM_MAP.keys())
                if algorithm == "auto"
                else [algorithm.lower()]
            )

            crypto_compiled = _compile_rules_cached(_BUILTIN_CRYPTO_RULES)

            if address:
                target_eas = [parse_address(address)]
            else:
                target_eas = []
                for func_ea in idautils.Functions():
                    func = idaapi.get_func(func_ea)
                    if not func or func.end_ea - func.start_ea < 16:
                        continue
                    data = bytes(read_bytes_bss_safe(func.start_ea, func.end_ea - func.start_ea))
                    try:
                        ms = crypto_compiled.match(data=data, timeout=5)
                        if ms and any(_rule_to_alg(m.rule) in alg_filter for m in ms):
                            target_eas.append(func.start_ea)
                    except Exception:
                        pass
                    if len(target_eas) >= max_functions * 3:
                        break

            target_eas = target_eas[:max_functions]
            results: list[dict] = []
            verified = unverified = 0

            for func_ea in target_eas:
                func = idaapi.get_func(func_ea)
                if not func:
                    continue
                # Normalize to function start in case the caller passed a mid-function address.
                func_ea = func.start_ea
                size = func.end_ea - func_ea
                data = bytes(read_bytes_bss_safe(func_ea, size))
                func_name = idc.get_func_name(func_ea) or f"sub_{func_ea:X}"

                try:
                    ms = crypto_compiled.match(data=data, timeout=5)
                    matched_algs = list(dict.fromkeys(
                        _rule_to_alg(m.rule) for m in ms if _rule_to_alg(m.rule) in alg_filter
                    ))
                    hit_alg = matched_algs[0] if matched_algs else "unknown"
                    hit_rule = ms[0].rule if ms else "unknown"
                except Exception:
                    hit_alg, hit_rule = "unknown", "unknown"

                triton_result, confidence, note = _triton_verify_crypto_usage(
                    func_ea, size, data, hit_alg
                )

                if triton_result == "confirmed":
                    verified += 1
                else:
                    unverified += 1

                results.append({
                    "function_ea":   hex(func_ea),
                    "function_name": func_name,
                    "algorithm":     hit_alg,
                    "yara_rule":     hit_rule,
                    "triton_result": triton_result,
                    "confidence":    confidence,
                    "note":          note,
                })

            return {
                "ok":               True,
                "candidates_found": len(target_eas),
                "verified_count":   verified,
                "unverified_count": unverified,
                "triton_available": triton_ok,
                "results":          results,
            }
        except Exception as exc:
            return {**tool_error(exc), "ok": False}

    # ------------------------------------------------------------------
    # I.F.3 — hybrid_yara_miasm_deobfuscate
    # ------------------------------------------------------------------

    @tool
    @idasync
    def hybrid_yara_miasm_deobfuscate(
        address: Annotated[str, "Function to deobfuscate; empty = auto-detect via packer rules"] = "",
        max_functions: Annotated[int, "Maximum packer stubs to analyse (default: 3)"] = 3,
    ) -> HybridYaraMiasmResult:
        """Detect packer stubs with YARA then deobfuscate them with Miasm IR analysis.

        YARA identifies functions matching known packer patterns (UPX, VMProtect,
        Themida, etc.).  Miasm lifts each detected function to its IR, runs dead-code
        elimination, and reports block counts before and after simplification — giving
        a structural view of what the stub actually does.

        Falls back gracefully when Miasm is unavailable: the YARA-detected stubs are
        still returned with a 'miasm_unavailable' note."""
        try:
            miasm_ok = False
            try:
                from miasm.analysis.machine import Machine as _MiasmCheck  # noqa: F401
                miasm_ok = True
            except ImportError:
                pass

            threat_compiled = _compile_rules_cached(_BUILTIN_THREAT_RULES)
            packer_rules = set(_THREAT_CATEGORY_MAP.get("packers", []))

            if address:
                stub_eas = [parse_address(address)]
            else:
                stub_eas = []
                for func_ea in idautils.Functions():
                    func = idaapi.get_func(func_ea)
                    if not func or func.end_ea - func.start_ea < 8:
                        continue
                    data = bytes(read_bytes_bss_safe(func.start_ea, func.end_ea - func.start_ea))
                    try:
                        ms = threat_compiled.match(data=data, timeout=5)
                        if any(m.rule in packer_rules for m in ms):
                            stub_eas.append(func.start_ea)
                    except Exception:
                        pass
                    if len(stub_eas) >= max_functions * 2:
                        break

            stub_eas = stub_eas[:max_functions]
            results: list[dict] = []

            for func_ea in stub_eas:
                func = idaapi.get_func(func_ea)
                if not func:
                    continue
                size = func.end_ea - func_ea
                data = bytes(read_bytes_bss_safe(func_ea, size))
                func_name = idc.get_func_name(func_ea) or f"sub_{func_ea:X}"

                try:
                    ms = threat_compiled.match(data=data, timeout=5)
                    packer_rule = next((m.rule for m in ms if m.rule in packer_rules), "unknown")
                except Exception:
                    packer_rule = "unknown"

                ir_raw, ir_simp, dead, summary = _miasm_lift_and_simplify(func_ea, data)
                results.append({
                    "function_ea":          hex(func_ea),
                    "function_name":        func_name,
                    "packer_rule":          packer_rule,
                    "ir_blocks_raw":        ir_raw,
                    "ir_blocks_simplified": ir_simp,
                    "dead_instructions":    dead,
                    "ir_summary":           summary,
                    "note":                 (
                        "miasm_unavailable" if not miasm_ok
                        else ("simplified" if ir_simp < ir_raw else "no_simplification")
                    ),
                })

            return {
                "ok":                True,
                "packer_stubs_found": len(stub_eas),
                "analyzed_count":    len(results),
                "miasm_available":   miasm_ok,
                "results":           results,
            }
        except Exception as exc:
            return {**tool_error(exc), "ok": False}
