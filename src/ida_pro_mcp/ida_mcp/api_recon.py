"""Reconnaissance tools for stripped, /Gy-optimised PE binaries.

These tools complement the standard MCP toolkit when classic xrefs, strings,
and function boundaries are missing. They are read-only by default; the one
tool that mutates the IDB (find_function_prologues with create=True) is gated
behind @unsafe.

Implements the workflow documented in BinaryReverseEngineering.md:
- get_binary_sections        — I.   Infrastructure of Nothingness
- find_global_writers        — II.  / III. The Powerline / Writer technique
- find_vtable_candidates     — II.  VTable DNA Search
- list_functions_in_range    — X.   Multi-Function Cross-Reference / Cluster
- find_indirect_calls        — VI.  / VIII. COM vtable call pattern scanning
- identify_vtable_call       — VIII. Contextual Byte Pattern Analysis
- analyze_cleanup_function   — IX.  Structure Archaeology via Cleanup
- find_function_prologues    — VI.  / XI. Force-create missed functions
"""

from __future__ import annotations

import fnmatch

from typing import Annotated, NotRequired, TypedDict

import ida_bytes
import ida_funcs
import ida_idp
import ida_name
import ida_segment
import ida_typeinf
import ida_ua
import ida_xref
import idaapi
import idautils
import idc

from .rpc import tool, unsafe
from .sync import idasync, IDAError
from .utils import parse_address, tool_error
from . import compat


# ============================================================================
# IDA version compatibility
# ============================================================================
# These tools were developed against IDA 9.3 and tested on >= 9.0. The IDA
# APIs used here (ida_segment, ida_xref, ida_funcs, ida_ua, ida_idp, idautils)
# are stable across 7.x–9.x, but the user is warned at runtime when an older
# IDA is detected so they know support is best-effort.

_MIN_TESTED_VERSION: tuple[int, int] = (9, 0)
_TARGET_VERSION: tuple[int, int] = (9, 3)
_ida_version_cache: tuple[int, int] | None = None


def _get_ida_version() -> tuple[int, int]:
    """Return (major, minor) IDA kernel version, cached after first call.

    IDA 9.3+ disallows calling ``idaapi.get_kernel_version()`` from non-main
    threads, so we never call it at import time. All tools in this module are
    ``@idasync``-decorated, meaning the first call lands on the main thread —
    safe to probe from there.
    """
    global _ida_version_cache
    if _ida_version_cache is None:
        try:
            raw = idaapi.get_kernel_version() or ""
            parts = raw.split(".")
            major = int(parts[0]) if parts and parts[0].isdigit() else 0
            minor = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
            _ida_version_cache = (major, minor)
        except Exception:
            _ida_version_cache = (0, 0)
    return _ida_version_cache


def _version_warnings() -> list[str]:
    """Return runtime warnings about the host IDA version, or [] if all good."""
    maj, minor = _get_ida_version()
    if maj == 0:
        return []  # couldn't detect — stay quiet rather than guess
    if (maj, minor) < _MIN_TESTED_VERSION:
        return [
            f"api_recon was developed against IDA {_TARGET_VERSION[0]}.{_TARGET_VERSION[1]} "
            f"and tested on IDA >= {_MIN_TESTED_VERSION[0]}.{_MIN_TESTED_VERSION[1]}. "
            f"You are running IDA {maj}.{minor}. The APIs used here are mostly stable, "
            f"but results may differ; please verify findings on a known-good IDB."
        ]
    return []


def _annotate(result: dict) -> dict:
    """Attach version warnings to a tool result when applicable."""
    warnings = _version_warnings()
    if warnings:
        # Don't clobber tool-specific warnings if a tool already set the field.
        existing = result.get("warnings") or []
        result["warnings"] = list(existing) + warnings
    return result


# ============================================================================
# Constants
# ============================================================================

# x64 indirect-call prefix byte for `call [reg+offset]` / `call [reg]`.
# Encoding: FF /2 with various ModR/M bytes — second byte determines reg+mode.
# We detect via decoded instruction (NN_callni + o_displ/o_phrase) rather than
# raw bytes, but keep this for reference.
_INDIRECT_CALL_OPCODE = 0xFF

# Common x64 function prologues. Each entry is (pattern_bytes, mask_bytes, name).
# Mask uses 0x00 for wildcard bytes and 0xFF for must-match.
_X64_PROLOGUES: list[tuple[bytes, bytes, str]] = [
    # mov [rsp+disp8], rbx ; mov [rsp+disp8], rsi  (very common MSVC saving)
    (b"\x48\x89\x5C\x24\x00", b"\xFF\xFF\xFF\xFF\x00", "mov [rsp+?], rbx"),
    (b"\x48\x89\x74\x24\x00", b"\xFF\xFF\xFF\xFF\x00", "mov [rsp+?], rsi"),
    (b"\x48\x89\x7C\x24\x00", b"\xFF\xFF\xFF\xFF\x00", "mov [rsp+?], rdi"),
    (b"\x48\x89\x4C\x24\x00", b"\xFF\xFF\xFF\xFF\x00", "mov [rsp+?], rcx"),
    # Classic frame setup
    (b"\x55\x48\x8B\xEC", b"\xFF\xFF\xFF\xFF", "push rbp; mov rbp, rsp"),
    (b"\x40\x55", b"\xFF\xFF", "push rbp (REX)"),
    (b"\x40\x53", b"\xFF\xFF", "push rbx (REX)"),
    (b"\x40\x57", b"\xFF\xFF", "push rdi (REX)"),
    (b"\x40\x56", b"\xFF\xFF", "push rsi (REX)"),
    # sub rsp, imm8 / imm32
    (b"\x48\x83\xEC\x00", b"\xFF\xFF\xFF\x00", "sub rsp, imm8"),
    (b"\x48\x81\xEC\x00\x00\x00\x00", b"\xFF\xFF\xFF\x00\x00\x00\x00", "sub rsp, imm32"),
]

_X86_PROLOGUES: list[tuple[bytes, bytes, str]] = [
    (b"\x55\x8B\xEC", b"\xFF\xFF\xFF", "push ebp; mov ebp, esp"),
    (b"\x83\xEC\x00", b"\xFF\xFF\x00", "sub esp, imm8"),
    (b"\x81\xEC\x00\x00\x00\x00", b"\xFF\xFF\x00\x00\x00\x00", "sub esp, imm32"),
]


# ============================================================================
# Result types
# ============================================================================


class SectionInfo(TypedDict, total=False):
    name: str
    start: str
    end: str
    size: int
    perm: str
    bitness: int
    type: str
    sclass: str


class SectionsResult(TypedDict, total=False):
    ok: bool
    sections: list[SectionInfo]
    count: int
    error: str
    warnings: list[str]


class WriterSite(TypedDict, total=False):
    addr: str
    func: str
    func_name: str
    disasm: str


class WritersResult(TypedDict, total=False):
    ok: bool
    target: str
    writers: list[WriterSite]
    count: int
    error: str
    warnings: list[str]


class VTableCandidate(TypedDict, total=False):
    addr: str
    section: str
    pointer_count: int
    first_target: str
    targets: list[str]
    is_named: bool
    name: str


class VTablesResult(TypedDict, total=False):
    ok: bool
    section: str
    candidates: list[VTableCandidate]
    count: int
    error: str
    warnings: list[str]


class FunctionEntry(TypedDict, total=False):
    addr: str
    name: str
    size: int
    is_library: bool
    has_type: bool


class UndefinedCodeCandidate(TypedDict, total=False):
    addr: str
    size: int


class FunctionsRangeResult(TypedDict, total=False):
    ok: bool
    start: str
    end: str
    functions: list[FunctionEntry]
    count: int
    undefined_code_regions: list[UndefinedCodeCandidate]
    hint: str
    error: str
    warnings: list[str]


class IndirectCallSite(TypedDict, total=False):
    addr: str
    func: str
    base_reg: str
    offset: int
    offset_hex: str
    disasm: str


class IndirectCallsResult(TypedDict, total=False):
    ok: bool
    start: str
    end: str
    sites: list[IndirectCallSite]
    by_offset: dict[str, int]
    count: int
    error: str
    warnings: list[str]


class TraceStep(TypedDict, total=False):
    addr: str
    disasm: str
    base_reg: str
    src_reg: str
    src_offset: int
    src_offset_hex: str


class TraceResult(TypedDict, total=False):
    ok: bool
    call_addr: str
    base_reg: str
    chain: list[TraceStep]
    final_source: NotRequired[str]
    error: str
    warnings: list[str]


class ReleaseSite(TypedDict, total=False):
    call_addr: str
    base_reg: str
    object_offset: int
    object_offset_hex: str
    disasm: str


class CleanupResult(TypedDict, total=False):
    ok: bool
    func: str
    releases: list[ReleaseSite]
    inferred_fields: list[dict]
    count: int
    error: str
    warnings: list[str]


class PrologueHit(TypedDict, total=False):
    addr: str
    pattern: str
    created: bool
    create_error: NotRequired[str]


class ProloguesResult(TypedDict, total=False):
    ok: bool
    start: str
    end: str
    arch: str
    hits: list[PrologueHit]
    candidates_found: int
    functions_created: int
    error: str
    warnings: list[str]


# ============================================================================
# Helpers
# ============================================================================


def _perm_string(seg: ida_segment.segment_t) -> str:
    perm = getattr(seg, "perm", 0) or 0
    chars = []
    chars.append("r" if perm & ida_segment.SEGPERM_READ else "-")
    chars.append("w" if perm & ida_segment.SEGPERM_WRITE else "-")
    chars.append("x" if perm & ida_segment.SEGPERM_EXEC else "-")
    return "".join(chars)


def _seg_type_str(seg: ida_segment.segment_t) -> str:
    type_map = {
        idaapi.SEG_CODE: "code",
        idaapi.SEG_DATA: "data",
        idaapi.SEG_BSS: "bss",
        idaapi.SEG_XTRN: "xtrn",
        idaapi.SEG_NORM: "norm",
        idaapi.SEG_ABSSYM: "abssym",
        idaapi.SEG_COMM: "comm",
        idaapi.SEG_IMEM: "imem",
        idaapi.SEG_GRP: "grp",
        idaapi.SEG_NULL: "null",
        idaapi.SEG_UNDF: "undf",
    }
    return type_map.get(getattr(seg, "type", -1), f"type_{getattr(seg, 'type', -1)}")


def _is_code_address(ea: int) -> bool:
    """Check whether `ea` resolves into a segment marked as executable code."""
    if ea == idaapi.BADADDR or ea == 0:
        return False
    seg = ida_segment.getseg(ea)
    if seg is None:
        return False
    if seg.type == idaapi.SEG_CODE:
        return True
    # Some PE .text segments don't get SEG_CODE if loader is unusual; check perm.
    if getattr(seg, "perm", 0) & ida_segment.SEGPERM_EXEC:
        return True
    return False


def _safe_disasm(ea: int) -> str:
    try:
        import ida_lines

        raw = ida_lines.generate_disasm_line(ea, 0)
        return ida_lines.tag_remove(raw) if raw else ""
    except Exception:
        return idc.GetDisasm(ea) or ""


def _reg_name(reg_id: int, width: int = 8) -> str:
    """Return the register name for a given ID using IDA's processor module.

    Uses ``ida_idp.get_reg_name`` (the documented API). ``idaapi.get_reg_name``
    is a re-export but the canonical home is ``ida_idp``. Falls back to a
    synthetic ``r{id}`` token if the lookup fails so callers always get a
    string.
    """
    try:
        name = ida_idp.get_reg_name(reg_id, width)
        if name:
            return name
    except Exception:
        pass
    # Older IDA builds occasionally expose this only via idaapi.
    try:
        name = idaapi.get_reg_name(reg_id, width)
        if name:
            return name
    except Exception:
        pass
    return f"r{reg_id}"


def _decoded_or_none(ea: int) -> ida_ua.insn_t | None:
    insn = ida_ua.insn_t()
    if ida_ua.decode_insn(insn, ea) <= 0:
        return None
    return insn


def _is_indirect_call(insn: ida_ua.insn_t) -> bool:
    if insn is None:
        return False
    return insn.itype in (
        getattr(ida_idp, "NN_callni", -1),
        getattr(ida_idp, "NN_callfi", -1),
    )


def _section_by_name(name: str) -> ida_segment.segment_t | None:
    """Find a segment by exact case-insensitive name match."""
    name_l = name.lower()
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        if seg is None:
            continue
        seg_name = ida_segment.get_segm_name(seg) or ""
        if seg_name.lower() == name_l:
            return seg
    return None


# ============================================================================
# Tools
# ============================================================================


@tool
@idasync
def get_binary_sections() -> SectionsResult:
    """Enumerate every segment/section in the loaded binary.

    Returns name, address range, size in bytes, permissions (rwx), bitness,
    semantic type, and segment class for each segment. Essential first step
    when working with stripped binaries — tells you exactly where `.text`,
    `.rdata`, `.bss`, `.data` live so subsequent recon tools can target them.
    """
    try:
        sections: list[SectionInfo] = []
        for seg_ea in idautils.Segments():
            seg = ida_segment.getseg(seg_ea)
            if seg is None:
                continue
            name = ida_segment.get_segm_name(seg) or ""
            sclass = ida_segment.get_segm_class(seg) or ""
            sections.append(
                {
                    "name": name,
                    "start": hex(seg.start_ea),
                    "end": hex(seg.end_ea),
                    "size": int(seg.end_ea - seg.start_ea),
                    "perm": _perm_string(seg),
                    "bitness": int(getattr(seg, "bitness", -1)),
                    "type": _seg_type_str(seg),
                    "sclass": sclass,
                }
            )
        return _annotate({"ok": True, "sections": sections, "count": len(sections)})
    except Exception as e:
        return _annotate({**tool_error(e, "enumerate IDB segments"), "sections": [], "count": 0})


@tool
@idasync
def find_global_writers(
    addr: Annotated[str, "Address or name of the global to find writers for"],
    limit: Annotated[int, "Cap on returned writer sites (default 200)"] = 200,
) -> WritersResult:
    """Find every instruction that WRITES to a given global address.

    Uses IDA's data-xref database filtered to write-type references (`dr_W`).
    This is the "powerline" technique from the protocol — when `/Gy` has
    erased call-graph xrefs, follow the current by tracking who populates
    each global instead.

    Returns writer sites with the enclosing function and the disassembly of
    the writing instruction so you can quickly distinguish "init writer"
    from "per-frame updater".
    """
    try:
        target_ea = parse_address(addr)
    except (IDAError, Exception) as e:
        return _annotate({**tool_error(e, f"resolve address {addr!r}"), "target": addr})

    try:
        writers: list[WriterSite] = []
        xb = ida_xref.xrefblk_t()
        ok = xb.first_to(target_ea, ida_xref.XREF_ALL)
        while ok and len(writers) < limit:
            # The `.type` field uses dref_t for data xrefs and cref_t for code
            # xrefs — the integer values overlap (e.g. cref_t.fl_CN == 18 vs
            # dref_t.dr_W == 2). Always gate on `.iscode` before comparing to
            # dr_W. Calls/jumps to a global aren't "writes" in the protocol
            # sense anyway.
            if (not xb.iscode) and xb.type == ida_xref.dr_W:
                from_ea = xb.frm
                func = ida_funcs.get_func(from_ea)
                writers.append(
                    {
                        "addr": hex(from_ea),
                        "func": hex(func.start_ea) if func else "",
                        "func_name": ida_funcs.get_func_name(func.start_ea) if func else "",
                        "disasm": _safe_disasm(from_ea),
                    }
                )
            ok = xb.next_to()

        return _annotate({
            "ok": True,
            "target": hex(target_ea),
            "writers": writers,
            "count": len(writers),
        })
    except Exception as e:
        return _annotate({**tool_error(e, f"scan xrefs to {hex(target_ea)}"), "target": hex(target_ea)})


@tool
@idasync
def find_vtable_candidates(
    section: Annotated[str, "Section to scan (default '.rdata')"] = ".rdata",
    min_pointers: Annotated[
        int, "Minimum consecutive code pointers to qualify (default 3)"
    ] = 3,
    pointer_size: Annotated[int, "Pointer width: 4 or 8 (default 0 = auto-detect from IDB bitness)"] = 0,
    max_targets_per_vtable: Annotated[
        int, "Max function targets to include per candidate (default 10)"
    ] = 10,
) -> VTablesResult:
    """Scan a section for arrays of consecutive code pointers — VTable DNA.

    Walks `section` (default `.rdata`) reading `pointer_size`-wide values.
    Any run of `min_pointers`+ consecutive values that all point into an
    executable segment is reported as a VTable candidate.

    `pointer_size` defaults to 0 (auto-detect): 4 for 32-bit IDBs, 8 for
    64-bit IDBs. Override explicitly for mixed-bitness binaries.

    Returns the run's start address, length, sample target functions, and
    whether IDA already named the address. AI agents can then probe each
    candidate's call sites with `find_global_writers` (to see who installs
    it) or `find_indirect_calls` (to see who calls through it).
    """
    if pointer_size == 0:
        pointer_size = 8 if compat.inf_is_64bit() else 4
    if pointer_size not in (4, 8):
        return _annotate({"ok": False, "section": section, "error": "pointer_size must be 4 or 8"})

    seg = _section_by_name(section)
    if seg is None:
        return _annotate({"ok": False, "section": section, "error": f"section {section!r} not found"})

    try:
        candidates: list[VTableCandidate] = []
        ea = seg.start_ea
        get_ptr = ida_bytes.get_qword if pointer_size == 8 else ida_bytes.get_dword

        while ea + pointer_size <= seg.end_ea:
            # Probe the candidate run starting at ea
            run_targets: list[int] = []
            probe = ea
            while probe + pointer_size <= seg.end_ea:
                ptr = get_ptr(probe)
                if not _is_code_address(ptr):
                    break
                run_targets.append(ptr)
                probe += pointer_size

            if len(run_targets) >= min_pointers:
                first = run_targets[0]
                name = idc.get_name(ea, idc.GN_VISIBLE) or ""
                targets_hex = [hex(t) for t in run_targets[:max_targets_per_vtable]]
                candidates.append(
                    {
                        "addr": hex(ea),
                        "section": section,
                        "pointer_count": len(run_targets),
                        "first_target": hex(first),
                        "targets": targets_hex,
                        "is_named": bool(name),
                        "name": name,
                    }
                )
                # Skip past this run so we don't report overlapping sub-runs.
                ea = probe
            else:
                ea += pointer_size

        return _annotate({
            "ok": True,
            "section": section,
            "pointer_size": pointer_size,
            "candidates": candidates,
            "count": len(candidates),
        })
    except Exception as e:
        return _annotate({**tool_error(e, f"vtable scan in {section!r}"), "section": section})


def _read_vtable_single(
    vtable_ea: int,
    vtable_name: str,
    limit: int,
    include_decompile: bool,
) -> dict:
    """Read one vtable and return a result dict (never raises)."""
    try:
        ptr_size = 8 if compat.inf_is_64bit() else 4
        get_ptr = ida_bytes.get_qword if ptr_size == 8 else ida_bytes.get_dword

        entries: list[dict] = []
        decompile_cache: dict[int, str] = {}

        for idx in range(limit):
            slot_ea = vtable_ea + idx * ptr_size
            if not idaapi.is_loaded(slot_ea):
                break
            func_ea_raw = get_ptr(slot_ea)
            if func_ea_raw == 0 or func_ea_raw == idaapi.BADADDR:
                break
            if not _is_code_address(func_ea_raw):
                if idx == 0:
                    continue
                break

            func_name = (
                idc.get_name(func_ea_raw, idc.GN_VISIBLE)
                or ida_funcs.get_func_name(func_ea_raw)
                or hex(func_ea_raw)
            )
            entry: dict = {
                "index": idx,
                "slot_ea": hex(slot_ea),
                "func_ea": hex(func_ea_raw),
                "func_name": func_name,
            }

            if include_decompile:
                if func_ea_raw not in decompile_cache:
                    try:
                        import ida_hexrays as _hr
                        import ida_kernwin as _kw
                        import ida_lines as _il
                        if _hr.init_hexrays_plugin():
                            cfunc = _hr.decompile(func_ea_raw)
                            if cfunc:
                                sv = cfunc.get_pseudocode()
                                lines = [
                                    _il.tag_remove(sv[i].line)
                                    for i in range(min(5, len(sv)))
                                ]
                                decompile_cache[func_ea_raw] = "\n".join(lines)
                            else:
                                decompile_cache[func_ea_raw] = ""
                        else:
                            decompile_cache[func_ea_raw] = ""
                    except Exception as exc:
                        decompile_cache[func_ea_raw] = f"// decompile failed: {exc}"
                snippet = decompile_cache[func_ea_raw]
                if snippet:
                    entry["decompile"] = snippet

            entries.append(entry)

        if not entries:
            return _annotate({
                "ok": False,
                "vtable_ea": hex(vtable_ea),
                "vtable_name": vtable_name,
                "error": (
                    "No valid function pointers found at this address. "
                    "Verify the address points to the start of a vtable "
                    f"(ptr_size={ptr_size}, "
                    f"first word={hex(get_ptr(vtable_ea))})."
                ),
            })

        return _annotate({
            "ok": True,
            "vtable_ea": hex(vtable_ea),
            "vtable_name": vtable_name,
            "ptr_size": ptr_size,
            "count": len(entries),
            "entries": entries,
        })
    except Exception as e:
        return _annotate({
            "ok": False,
            "vtable_ea": hex(vtable_ea),
            "vtable_name": vtable_name,
            "error": str(e),
        })


@tool
@idasync
def dump_vtable(
    addr: Annotated[
        str | None,
        "Direct vtable address (hex or named symbol like '??_7FooClass@@6B@'). "
        "Reads the vtable at this specific address. Cannot be combined with addrs=.",
    ] = None,
    addrs: Annotated[
        list[str] | None,
        "Batch mode: list of vtable addresses to dump in one call. "
        "Returns a 'vtables' dict keyed by address. Cannot be combined with addr= or class_name=.",
    ] = None,
    class_name: Annotated[
        str | None,
        "Class name or glob pattern to search IDB vtable symbols "
        "(e.g. 'URenderDevice', '*Render*', '??_7UFoo*', '_ZTV*Foo*'). "
        "Supports * and ? wildcards (case-insensitive). Plain text is treated as *substring*. "
        "Searches mangled names AND demangled names. Ignored when addr= or addrs= is set.",
    ] = None,
    limit: Annotated[int, "Max vtable slots to read per vtable (default: 128)"] = 128,
    include_decompile: Annotated[
        bool,
        "Include first 5 pseudocode lines per method. Token-expensive — "
        "use only on small vtables or specific entries of interest.",
    ] = False,
) -> dict:
    """Read one or more virtual function tables and list all method pointers with names.

    Three input modes (one is required):
    - addr=      : read one vtable at a specific address
    - addrs=     : read multiple vtables in one call (batch mode)
    - class_name=: search IDB symbols for vtable names matching a glob/substring pattern

    class_name search matches against both mangled (??_7Foo@@6B@, _ZTVFoo) and
    demangled names. Wildcards (* ?) are supported; plain text is auto-wrapped as *text*.
    If multiple symbols match, returns all candidates — use addr= to pick one.

    Batch (addrs=) result shape:
      {"ok": true, "vtables": {"0x...": {...single result...}, ...},
       "success_count": N, "fail_count": M}

    Single result shape:
      {"ok": true, "vtable_ea": "0x...", "vtable_name": "...", "count": N,
       "entries": [{"index": N, "slot_ea": "0x...", "func_ea": "0x...",
                    "func_name": "...", "decompile": "..."}]}
    """
    try:
        # --- Batch mode ---
        if addrs is not None:
            if not addrs:
                return _annotate({"ok": False, "error": "addrs= list is empty."})
            results: dict[str, dict] = {}
            success = 0
            fail = 0
            for raw_addr in addrs:
                try:
                    ea = parse_address(raw_addr)
                    name = idc.get_name(ea, idc.GN_VISIBLE) or hex(ea)
                    r = _read_vtable_single(ea, name, limit, include_decompile)
                    results[hex(ea)] = r
                    if r.get("ok"):
                        success += 1
                    else:
                        fail += 1
                except Exception as exc:
                    results[raw_addr] = _annotate({"ok": False, "error": str(exc)})
                    fail += 1
            return _annotate({
                "ok": fail == 0,
                "vtables": results,
                "success_count": success,
                "fail_count": fail,
            })

        # --- Single addr mode ---
        if addr is not None:
            vtable_ea = parse_address(addr)
            vtable_name = idc.get_name(vtable_ea, idc.GN_VISIBLE) or hex(vtable_ea)
            return _read_vtable_single(vtable_ea, vtable_name, limit, include_decompile)

        # --- class_name search mode ---
        if class_name:
            pat = class_name.lower()
            if "*" not in pat and "?" not in pat:
                pat = f"*{pat}*"

            _VTABLE_MARKERS = ("vtable", "vftable", "??_7", "_ztv")
            search_hits: list[dict] = []

            for name_ea, name in idautils.Names():
                nl = name.lower()
                if not any(m in nl for m in _VTABLE_MARKERS):
                    continue
                matched = fnmatch.fnmatch(nl, pat)
                if not matched:
                    try:
                        dem = idc.demangle_name(name, idc.INF_SHORT_DN) or ""
                        matched = fnmatch.fnmatch(dem.lower(), pat)
                    except Exception:
                        dem = ""
                else:
                    try:
                        dem = idc.demangle_name(name, idc.INF_SHORT_DN) or ""
                    except Exception:
                        dem = ""
                if matched:
                    search_hits.append({"ea": hex(name_ea), "name": name, "demangled": dem})

            if not search_hits:
                # Helpful: show what vtable symbols DO exist so agent can refine
                sample: list[dict] = []
                for name_ea, name in idautils.Names():
                    if any(m in name.lower() for m in _VTABLE_MARKERS):
                        try:
                            dem = idc.demangle_name(name, idc.INF_SHORT_DN) or ""
                        except Exception:
                            dem = ""
                        sample.append({"ea": hex(name_ea), "name": name, "demangled": dem})
                        if len(sample) >= 20:
                            break
                return _annotate({
                    "ok": False,
                    "class_name": class_name,
                    "error": (
                        f"No vtable symbols matched '{class_name}' (searched mangled + demangled). "
                        "Tips: use a shorter substring, check spelling, or call find_regex to "
                        "browse all IDB names. Pass addr= if you already know the vtable address."
                    ),
                    "vtable_symbols_sample": sample,
                })

            if len(search_hits) > 1:
                return _annotate({
                    "ok": False,
                    "class_name": class_name,
                    "error": (
                        f"Found {len(search_hits)} vtable symbols matching '{class_name}'. "
                        "Use addr= with one of the candidate addresses, or narrow class_name."
                    ),
                    "candidates": search_hits[:20],
                })

            hit = search_hits[0]
            vtable_ea = int(hit["ea"], 16)
            vtable_name = hit["name"]
            return _read_vtable_single(vtable_ea, vtable_name, limit, include_decompile)

        return _annotate({
            "ok": False,
            "error": (
                "Provide one of: addr= (single address), addrs= (batch list), "
                "or class_name= (symbol search)."
            ),
        })

    except Exception as e:
        return _annotate(tool_error(e, "dump_vtable"))


def _scan_undefined_code(start_ea: int, end_ea: int, max_hits: int = 5) -> list[UndefinedCodeCandidate]:
    """Scan [start_ea, end_ea) for contiguous code-flagged bytes not in any function.

    Walks ``idautils.Heads()`` (capped at 10 000 items) looking for items that
    are code but not part of any function.  Consecutive such items are merged
    into a single run and returned as ``UndefinedCodeCandidate`` entries.
    """
    candidates: list[UndefinedCodeCandidate] = []
    run_start: int | None = None
    run_end: int = 0
    checked = 0

    for ea in idautils.Heads(start_ea, end_ea):
        if checked >= 10_000:
            break
        checked += 1
        flags = idc.get_full_flags(ea)
        if idc.is_code(flags) and not ida_bytes.is_func(flags):
            item_size = max(1, idc.get_item_size(ea))
            if run_start is None:
                run_start = ea
                run_end = ea + item_size
            else:
                run_end = ea + item_size
        else:
            if run_start is not None:
                candidates.append({"addr": hex(run_start), "size": run_end - run_start})
                run_start = None
                if len(candidates) >= max_hits:
                    break

    if run_start is not None:
        candidates.append({"addr": hex(run_start), "size": run_end - run_start})

    return candidates[:max_hits]


@tool
@idasync
def list_functions_in_range(
    start: Annotated[str, "Range start address (hex or name)"],
    end: Annotated[str, "Range end address (exclusive, hex or name)"],
    include_unnamed: Annotated[
        bool, "Include auto-named sub_XXXXX functions (default True)"
    ] = True,
) -> FunctionsRangeResult:
    """List every known function whose entry point falls in [start, end).

    The cluster-analysis primitive from protocol section X — when XREFs are
    gone, pull every function in a 4 KB-or-so window around your target,
    decompile them all, and look for shared globals and struct offsets.

    When no functions are found, ``undefined_code_regions`` lists code-flagged
    byte runs in the range that IDA has not yet promoted to functions. Use
    ``find_function_prologues`` or ``scan_and_define_funcs`` to create them,
    then re-run this tool.
    """
    try:
        start_ea = parse_address(start)
        end_ea = parse_address(end)
    except (IDAError, Exception) as e:
        return _annotate({**tool_error(e, f"resolve address range {start!r}-{end!r}"), "start": start, "end": end})

    if end_ea <= start_ea:
        return _annotate({
            "ok": False,
            "start": hex(start_ea),
            "end": hex(end_ea),
            "error": "end must be > start",
        })

    try:
        functions: list[FunctionEntry] = []
        for func_ea in idautils.Functions(start_ea, end_ea):
            func = ida_funcs.get_func(func_ea)
            if func is None:
                continue
            name = ida_funcs.get_func_name(func_ea) or ""
            is_auto_sub = name.startswith("sub_")
            if is_auto_sub and not include_unnamed:
                continue
            functions.append(
                {
                    "addr": hex(func.start_ea),
                    "name": name,
                    "size": int(func.end_ea - func.start_ea),
                    "is_library": bool(func.flags & ida_funcs.FUNC_LIB),
                    "has_type": bool(idc.get_type(func.start_ea)),
                }
            )

        result: dict = {
            "ok": True,
            "start": hex(start_ea),
            "end": hex(end_ea),
            "functions": functions,
            "count": len(functions),
        }

        # Scan for undefined code in the range so callers know what's missing
        undef_regions = _scan_undefined_code(start_ea, end_ea)
        if undef_regions:
            result["undefined_code_regions"] = undef_regions
            if not functions:
                result["hint"] = (
                    "No functions defined in this range, but code-flagged bytes were found. "
                    "Run find_function_prologues or scan_and_define_funcs on this range to "
                    "create the missing function entries, then re-run list_functions_in_range."
                )

        return _annotate(result)
    except Exception as e:
        return _annotate({
            **tool_error(e, f"list functions {hex(start_ea)}-{hex(end_ea)}"),
            "start": hex(start_ea),
            "end": hex(end_ea),
        })


@tool
@idasync
def find_indirect_calls(
    start: Annotated[str, "Range start address or function name"],
    end: Annotated[
        str,
        "Range end address (exclusive). Pass empty string to use the function "
        "containing `start`.",
    ] = "",
    offset_filter: Annotated[
        int,
        "Only return calls at this vtable offset. -1 = no filter. Common values: "
        "0x10 (IUnknown::Release), 0x40 (IDXGISwapChain::Present).",
    ] = -1,
    limit: Annotated[int, "Cap on returned call sites (default 500)"] = 500,
) -> IndirectCallsResult:
    """Find all `call [reg+offset]` (and `call [reg]`) sites in a range.

    The COM vtable-call discovery primitive. Use `offset_filter=0x40` to
    locate every potential `Present` call in a binary, or `0x10` to find
    every `Release`. The return includes the base register and exact offset
    of each call plus a histogram (`by_offset`) of how many calls hit each
    offset — useful for fingerprinting which COM interface dominates a
    function.
    """
    try:
        start_ea = parse_address(start)
    except (IDAError, Exception) as e:
        return _annotate({**tool_error(e, f"resolve start address {start!r}"), "start": start, "end": end})

    if end:
        try:
            end_ea = parse_address(end)
        except (IDAError, Exception) as e:
            return _annotate({**tool_error(e, f"resolve end address {end!r}"), "start": hex(start_ea), "end": end})
    else:
        func = ida_funcs.get_func(start_ea)
        if func is None:
            return _annotate({
                "ok": False,
                "start": hex(start_ea),
                "end": end,
                "error": "no end given and no function at start",
            })
        start_ea = func.start_ea
        end_ea = func.end_ea

    if end_ea <= start_ea:
        return _annotate({
            "ok": False,
            "start": hex(start_ea),
            "end": hex(end_ea),
            "error": "end must be > start",
        })

    try:
        sites: list[IndirectCallSite] = []
        by_offset: dict[str, int] = {}
        instructions_scanned = 0
        ea = start_ea
        while ea < end_ea and len(sites) < limit:
            insn = _decoded_or_none(ea)
            if insn is None:
                ea = idc.next_head(ea, end_ea)
                if ea == idaapi.BADADDR or ea <= 0:
                    break
                continue

            instructions_scanned += 1
            if _is_indirect_call(insn):
                # ops[0] for an indirect call is the target memory operand.
                op = insn.ops[0]
                base_reg = ""
                disp = 0
                matched = False
                if op.type == ida_ua.o_displ:
                    # [reg + offset]
                    base_reg = _reg_name(op.reg, 8)
                    disp = int(op.addr) if op.addr else 0
                    matched = True
                elif op.type == ida_ua.o_phrase:
                    # [reg] — no displacement
                    base_reg = _reg_name(op.reg, 8)
                    disp = 0
                    matched = True

                if matched and (offset_filter < 0 or disp == offset_filter):
                    func = ida_funcs.get_func(ea)
                    sites.append(
                        {
                            "addr": hex(ea),
                            "func": hex(func.start_ea) if func else "",
                            "base_reg": base_reg,
                            "offset": disp,
                            "offset_hex": hex(disp),
                            "disasm": _safe_disasm(ea),
                        }
                    )
                    key = hex(disp)
                    by_offset[key] = by_offset.get(key, 0) + 1

            ea += insn.size if insn.size else 1

        note = None
        if len(sites) == 0:
            note = f"Scanned {instructions_scanned} instructions, found 0 indirect calls. Verify the address range contains decoded code and that the binary is x86/x64."
        return _annotate({
            "ok": True,
            "start": hex(start_ea),
            "end": hex(end_ea),
            "sites": sites,
            "by_offset": by_offset,
            "count": len(sites),
            "instructions_scanned": instructions_scanned,
            **({"note": note} if note else {}),
        })
    except Exception as e:
        return _annotate({
            **tool_error(e, f"indirect call scan {hex(start_ea)}-{hex(end_ea)}"),
            "start": hex(start_ea),
            "end": hex(end_ea),
        })


@tool
@idasync
def identify_vtable_call(
    call_addr: Annotated[str, "Address of an indirect `call [reg+offset]` instruction"],
    lookback: Annotated[
        int, "How many instructions to walk backwards (default 8)"
    ] = 8,
) -> TraceResult:
    """Trace backwards from an indirect call to identify what loaded the base reg.

    Given an EA like `call [rax+0x40]`, walks up to `lookback` previous
    instructions looking for `mov rax, [rcx+0x18]`-style loads — the chain
    that established which object `this` actually points to. This is the
    protocol's "verify the object" step: a raw `FF 50 40` could be Present,
    VSSetShader, or MakeWindowAssociation depending on what `rax` holds.

    Returns the chain of register-loading instructions found, terminating
    when no further load is detected.
    """
    try:
        ea = parse_address(call_addr)
    except (IDAError, Exception) as e:
        return _annotate({**tool_error(e, f"resolve call address {call_addr!r}"), "call_addr": call_addr, "base_reg": "", "chain": []})

    try:
        insn = _decoded_or_none(ea)
        if insn is None or not _is_indirect_call(insn):
            return _annotate({
                "ok": False,
                "call_addr": hex(ea),
                "base_reg": "",
                "chain": [],
                "error": "not an indirect call instruction",
            })

        # Extract the base register of the indirect call
        op = insn.ops[0]
        if op.type not in (ida_ua.o_displ, ida_ua.o_phrase):
            return _annotate({
                "ok": False,
                "call_addr": hex(ea),
                "base_reg": "",
                "chain": [],
                "error": "indirect call but operand is not reg-indirect",
            })
        target_reg = op.reg
        target_reg_name = _reg_name(target_reg, 8)

        chain: list[TraceStep] = []
        cur = ea
        steps_remaining = lookback
        current_target = target_reg

        while steps_remaining > 0:
            prev = idc.prev_head(cur, 0)
            if prev == idaapi.BADADDR or prev <= 0 or prev >= cur:
                break
            prev_insn = _decoded_or_none(prev)
            if prev_insn is None:
                cur = prev
                steps_remaining -= 1
                continue

            # We care about MOV that writes to current_target
            if prev_insn.itype == getattr(ida_idp, "NN_mov", -1):
                dst = prev_insn.ops[0]
                src = prev_insn.ops[1]
                if dst.type == ida_ua.o_reg and dst.reg == current_target:
                    step: TraceStep = {
                        "addr": hex(prev),
                        "disasm": _safe_disasm(prev),
                        "base_reg": _reg_name(current_target, 8),
                        "src_reg": "",
                        "src_offset": 0,
                        "src_offset_hex": "0x0",
                    }
                    if src.type == ida_ua.o_displ:
                        step["src_reg"] = _reg_name(src.reg, 8)
                        step["src_offset"] = int(src.addr) if src.addr else 0
                        step["src_offset_hex"] = hex(step["src_offset"])
                        chain.append(step)
                        # Walk further back: where did src.reg come from?
                        current_target = src.reg
                    elif src.type == ida_ua.o_phrase:
                        step["src_reg"] = _reg_name(src.reg, 8)
                        step["src_offset"] = 0
                        step["src_offset_hex"] = "0x0"
                        chain.append(step)
                        current_target = src.reg
                    elif src.type == ida_ua.o_reg:
                        step["src_reg"] = _reg_name(src.reg, 8)
                        chain.append(step)
                        current_target = src.reg
                    elif src.type == ida_ua.o_mem:
                        # Loaded from a global — that's our terminal source.
                        step["src_reg"] = ""
                        step["src_offset"] = int(src.addr) if src.addr else 0
                        step["src_offset_hex"] = hex(step["src_offset"])
                        chain.append(step)
                        result: TraceResult = {
                            "ok": True,
                            "call_addr": hex(ea),
                            "base_reg": target_reg_name,
                            "chain": chain,
                            "final_source": f"global @ {step['src_offset_hex']}",
                        }
                        return _annotate(result)
                    else:
                        chain.append(step)
                        break

            cur = prev
            steps_remaining -= 1

        return _annotate({
            "ok": True,
            "call_addr": hex(ea),
            "base_reg": target_reg_name,
            "chain": chain,
        })
    except Exception as e:
        return _annotate({
            **tool_error(e, f"trace vtable call at {call_addr}"),
            "call_addr": call_addr,
            "base_reg": "",
            "chain": [],
        })


@tool
@idasync
def analyze_cleanup_function(
    addr: Annotated[str, "Function address or name to analyse"],
    release_offset: Annotated[
        int,
        "VTable offset of the Release-like method (default 0x10 = IUnknown::Release)",
    ] = 0x10,
) -> CleanupResult:
    """Mine a cleanup function for struct layout via Release() patterns.

    Implements protocol section IX. Walks the function looking for indirect
    calls at the given vtable offset (default `0x10` = `IUnknown::Release`).
    For each one, traces back to find what struct field was loaded into the
    `this` register, and emits an inferred field map:

        +0x00 → COM_object_A
        +0x08 → COM_object_B
        +0x18 → swapchain
        ...

    Returns the raw release sites plus a sorted `inferred_fields` list ready
    to feed into struct creation.
    """
    try:
        ea = parse_address(addr)
    except (IDAError, Exception) as e:
        return _annotate({**tool_error(e, f"resolve function address {addr!r}"), "func": addr})

    func = ida_funcs.get_func(ea)
    if func is None:
        return _annotate({"ok": False, "func": hex(ea), "error": f"no function at {hex(ea)}"})

    try:
        releases: list[ReleaseSite] = []
        inferred: dict[int, str] = {}  # offset -> example call addr

        cur = func.start_ea
        while cur < func.end_ea:
            insn = _decoded_or_none(cur)
            if insn is None:
                nxt = idc.next_head(cur, func.end_ea)
                if nxt == idaapi.BADADDR or nxt <= cur:
                    break
                cur = nxt
                continue

            if _is_indirect_call(insn):
                op = insn.ops[0]
                if op.type == ida_ua.o_displ and int(op.addr or 0) == release_offset:
                    base_reg_name = _reg_name(op.reg, 8)
                    # Walk back to find which struct offset loaded the `this` ptr.
                    obj_offset = _find_this_load_offset(cur, op.reg, lookback=10)
                    releases.append(
                        {
                            "call_addr": hex(cur),
                            "base_reg": base_reg_name,
                            "object_offset": obj_offset if obj_offset is not None else -1,
                            "object_offset_hex": hex(obj_offset) if obj_offset is not None else "?",
                            "disasm": _safe_disasm(cur),
                        }
                    )
                    if obj_offset is not None and obj_offset not in inferred:
                        inferred[obj_offset] = hex(cur)

            cur += insn.size if insn.size else 1

        inferred_fields = [
            {
                "offset": off,
                "offset_hex": hex(off),
                "suggested_name": f"field_{off:x}",
                "suggested_type": "void*",
                "example_release_site": example,
            }
            for off, example in sorted(inferred.items())
        ]

        return _annotate({
            "ok": True,
            "func": hex(func.start_ea),
            "releases": releases,
            "inferred_fields": inferred_fields,
            "count": len(releases),
        })
    except Exception as e:
        return _annotate({**tool_error(e, f"analyze cleanup at {hex(func.start_ea)}"), "func": hex(func.start_ea)})


def _find_this_load_offset(call_ea: int, base_reg: int, lookback: int) -> int | None:
    """For a `call [base_reg + off]`, walk back to find `mov base_reg, [param + N]`.

    Returns the struct offset `N` (the field of the caller's param-1 struct
    that held the COM object) or None if the chain doesn't terminate in a
    displacement load.
    """
    cur = call_ea
    target = base_reg
    steps = lookback
    while steps > 0:
        prev = idc.prev_head(cur, 0)
        if prev == idaapi.BADADDR or prev <= 0 or prev >= cur:
            return None
        prev_insn = _decoded_or_none(prev)
        if prev_insn is None:
            cur = prev
            steps -= 1
            continue
        if prev_insn.itype == getattr(ida_idp, "NN_mov", -1):
            dst = prev_insn.ops[0]
            src = prev_insn.ops[1]
            if dst.type == ida_ua.o_reg and dst.reg == target:
                if src.type == ida_ua.o_displ:
                    return int(src.addr) if src.addr else 0
                if src.type == ida_ua.o_phrase:
                    return 0
                if src.type == ida_ua.o_reg:
                    target = src.reg
                else:
                    return None
        cur = prev
        steps -= 1
    return None


def _match_with_mask(data: bytes, pattern: bytes, mask: bytes) -> bool:
    if len(data) < len(pattern):
        return False
    for i, p in enumerate(pattern):
        m = mask[i]
        if m == 0:
            continue
        if (data[i] & m) != (p & m):
            return False
    return True


@unsafe
@tool
@idasync
def find_function_prologues(
    start: Annotated[str, "Range start address or section name (e.g. '.text')"],
    end: Annotated[
        str,
        "Range end address (exclusive). Empty string + section name uses that section's end.",
    ] = "",
    arch: Annotated[str, "Architecture: 'x64' or 'x86' (default 'x64')"] = "x64",
    create: Annotated[
        bool,
        "When True, call ida_funcs.add_func on each hit to materialise the function "
        "(@unsafe — modifies IDB). Default False = dry-run only.",
    ] = False,
    limit: Annotated[int, "Cap on reported hits (default 1000)"] = 1000,
) -> ProloguesResult:
    """Scan an address range for common function prologues.

    `/Gy` packs functions tightly and IDA can miss boundaries inside the dust.
    This tool reads the byte stream of an unanalysed range looking for prologue
    signatures (`mov [rsp+?], rbx`, `push rbp`, `sub rsp, ?`, etc.) and reports
    the addresses where IDA does not yet recognise a function start.

    Set `create=True` (the @unsafe path) to have the tool call
    `ida_funcs.add_func` on each fresh candidate — useful for rapidly
    materialising large chunks of stripped code.
    """
    # Accept section names ('.text') for `start`. The parse_address path also
    # accepts "0x1400xxxx" or a symbol name.
    seg = _section_by_name(start) if start.startswith(".") else None
    try:
        if seg is not None:
            start_ea = seg.start_ea
            end_ea = parse_address(end) if end else seg.end_ea
        else:
            start_ea = parse_address(start)
            if not end:
                func = ida_funcs.get_func(start_ea)
                if func is None:
                    return _annotate({
                        "ok": False,
                        "start": hex(start_ea),
                        "end": end,
                        "arch": arch,
                        "hits": [],
                        "candidates_found": 0,
                        "functions_created": 0,
                        "error": "no end given and no function at start",
                    })
                end_ea = func.end_ea
            else:
                end_ea = parse_address(end)
    except (IDAError, Exception) as e:
        return _annotate({
            **tool_error(e, f"parse address for prologue scan (start={start!r})"),
            "start": start,
            "end": end,
            "arch": arch,
            "hits": [],
            "candidates_found": 0,
            "functions_created": 0,
        })

    if end_ea <= start_ea:
        return _annotate({
            "ok": False,
            "start": hex(start_ea),
            "end": hex(end_ea),
            "arch": arch,
            "hits": [],
            "candidates_found": 0,
            "functions_created": 0,
            "error": "end must be > start",
        })

    prologues = _X64_PROLOGUES if arch == "x64" else _X86_PROLOGUES
    max_pat_len = max(len(p) for p, _, _ in prologues)

    try:
        hits: list[PrologueHit] = []
        created = 0
        ea = start_ea
        while ea < end_ea and len(hits) < limit:
            # Skip addresses already inside a known function.
            existing = ida_funcs.get_func(ea)
            if existing is not None and existing.start_ea == ea:
                ea += 1
                continue
            if existing is not None:
                # Inside a function but not the start — skip to function end.
                ea = existing.end_ea
                continue

            data = ida_bytes.get_bytes(ea, max_pat_len)
            if not data:
                ea += 1
                continue

            matched_name: str | None = None
            for pattern, mask, name in prologues:
                if _match_with_mask(data, pattern, mask):
                    matched_name = name
                    break

            if matched_name is None:
                ea += 1
                continue

            hit: PrologueHit = {
                "addr": hex(ea),
                "pattern": matched_name,
                "created": False,
            }
            if create:
                try:
                    if ida_funcs.add_func(ea):
                        hit["created"] = True
                        created += 1
                    else:
                        hit["create_error"] = "add_func returned False"
                except Exception as add_e:
                    hit["create_error"] = str(add_e)
            hits.append(hit)

            # Move past this candidate.  If we created a function, jump to its
            # end; otherwise advance one byte to allow overlapping detections
            # (rare, but happens with packed code).
            new_func = ida_funcs.get_func(ea)
            if new_func is not None and new_func.start_ea == ea:
                ea = new_func.end_ea
            else:
                ea += 1

        return _annotate({
            "ok": True,
            "start": hex(start_ea),
            "end": hex(end_ea),
            "arch": arch,
            "hits": hits,
            "candidates_found": len(hits),
            "functions_created": created,
        })
    except Exception as e:
        return _annotate({
            **tool_error(e, f"prologue scan {hex(start_ea)}-{hex(end_ea)} ({arch})"),
            "start": hex(start_ea),
            "end": hex(end_ea),
            "arch": arch,
            "hits": [],
            "candidates_found": 0,
            "functions_created": 0,
        })


# ============================================================================
# COM / DirectX vtable knowledge base
# ============================================================================

# Flat vtable layouts for well-known COM interfaces (slot 0 = first entry).
# Each list contains the method names in vtable order, including inherited ones.
# Source: DirectX SDK headers / Windows SDK (dxgi.h, d3d11.h, d3d9.h, d3d12.h).
_COM_VTABLE_DB: dict[str, list[str]] = {
    "IUnknown": [
        "QueryInterface",           # 0
        "AddRef",                   # 1
        "Release",                  # 2
    ],
    "IDispatch": [
        "QueryInterface",           # 0
        "AddRef",                   # 1
        "Release",                  # 2
        "GetTypeInfoCount",         # 3
        "GetTypeInfo",              # 4
        "GetIDsOfNames",            # 5
        "Invoke",                   # 6
    ],
    "IDXGIObject": [
        "QueryInterface",           # 0
        "AddRef",                   # 1
        "Release",                  # 2
        "SetPrivateData",           # 3
        "SetPrivateDataInterface",  # 4
        "GetPrivateData",           # 5
        "GetParent",                # 6
    ],
    "IDXGIDeviceSubObject": [
        "QueryInterface",           # 0
        "AddRef",                   # 1
        "Release",                  # 2
        "SetPrivateData",           # 3
        "SetPrivateDataInterface",  # 4
        "GetPrivateData",           # 5
        "GetParent",                # 6
        "GetDevice",                # 7
    ],
    "IDXGISwapChain": [
        # IUnknown
        "QueryInterface",           # 0
        "AddRef",                   # 1
        "Release",                  # 2
        # IDXGIObject
        "SetPrivateData",           # 3
        "SetPrivateDataInterface",  # 4
        "GetPrivateData",           # 5
        "GetParent",                # 6
        # IDXGIDeviceSubObject
        "GetDevice",                # 7
        # IDXGISwapChain
        "Present",                  # 8  ← render loop
        "GetBuffer",                # 9
        "SetFullscreenState",       # 10
        "GetFullscreenState",       # 11
        "GetDesc",                  # 12
        "ResizeBuffers",            # 13
        "ResizeTarget",             # 14
        "GetContainingOutput",      # 15
        "GetFrameStatistics",       # 16
        "GetLastPresentCount",      # 17
    ],
    "IDXGISwapChain1": [
        # IUnknown
        "QueryInterface",           # 0
        "AddRef",                   # 1
        "Release",                  # 2
        # IDXGIObject
        "SetPrivateData",           # 3
        "SetPrivateDataInterface",  # 4
        "GetPrivateData",           # 5
        "GetParent",                # 6
        # IDXGIDeviceSubObject
        "GetDevice",                # 7
        # IDXGISwapChain
        "Present",                  # 8
        "GetBuffer",                # 9
        "SetFullscreenState",       # 10
        "GetFullscreenState",       # 11
        "GetDesc",                  # 12
        "ResizeBuffers",            # 13
        "ResizeTarget",             # 14
        "GetContainingOutput",      # 15
        "GetFrameStatistics",       # 16
        "GetLastPresentCount",      # 17
        # IDXGISwapChain1
        "GetDesc1",                 # 18
        "GetFullscreenDesc",        # 19
        "GetHwnd",                  # 20
        "GetCoreWindow",            # 21
        "Present1",                 # 22  ← render loop (DX11.1+)
        "IsTemporaryMonoSupported", # 23
        "GetRestrictToOutput",      # 24
        "SetBackgroundColor",       # 25
        "GetBackgroundColor",       # 26
        "SetRotation",              # 27
        "GetRotation",              # 28
    ],
    "IDXGISwapChain2": [
        # slots 0-28: same as IDXGISwapChain1
        "QueryInterface", "AddRef", "Release",
        "SetPrivateData", "SetPrivateDataInterface", "GetPrivateData", "GetParent",
        "GetDevice",
        "Present", "GetBuffer", "SetFullscreenState", "GetFullscreenState",
        "GetDesc", "ResizeBuffers", "ResizeTarget", "GetContainingOutput",
        "GetFrameStatistics", "GetLastPresentCount",
        "GetDesc1", "GetFullscreenDesc", "GetHwnd", "GetCoreWindow",
        "Present1", "IsTemporaryMonoSupported", "GetRestrictToOutput",
        "SetBackgroundColor", "GetBackgroundColor", "SetRotation", "GetRotation",
        # IDXGISwapChain2
        "SetSourceSize",                # 29
        "GetSourceSize",                # 30
        "SetMaximumFrameLatency",       # 31
        "GetMaximumFrameLatency",       # 32
        "GetFrameLatencyWaitableObject",# 33
        "SetMatrixTransform",           # 34
        "GetMatrixTransform",           # 35
    ],
    "IDXGISwapChain3": [
        # slots 0-35: IDXGISwapChain2
        "QueryInterface", "AddRef", "Release",
        "SetPrivateData", "SetPrivateDataInterface", "GetPrivateData", "GetParent",
        "GetDevice",
        "Present", "GetBuffer", "SetFullscreenState", "GetFullscreenState",
        "GetDesc", "ResizeBuffers", "ResizeTarget", "GetContainingOutput",
        "GetFrameStatistics", "GetLastPresentCount",
        "GetDesc1", "GetFullscreenDesc", "GetHwnd", "GetCoreWindow",
        "Present1", "IsTemporaryMonoSupported", "GetRestrictToOutput",
        "SetBackgroundColor", "GetBackgroundColor", "SetRotation", "GetRotation",
        "SetSourceSize", "GetSourceSize", "SetMaximumFrameLatency",
        "GetMaximumFrameLatency", "GetFrameLatencyWaitableObject",
        "SetMatrixTransform", "GetMatrixTransform",
        # IDXGISwapChain3
        "GetCurrentBackBufferIndex",    # 36
        "CheckColorSpaceSupport",       # 37
        "SetColorSpace1",               # 38
        "ResizeBuffers1",               # 39
    ],
    "IDXGISwapChain4": [
        # slots 0-39: IDXGISwapChain3
        "QueryInterface", "AddRef", "Release",
        "SetPrivateData", "SetPrivateDataInterface", "GetPrivateData", "GetParent",
        "GetDevice",
        "Present", "GetBuffer", "SetFullscreenState", "GetFullscreenState",
        "GetDesc", "ResizeBuffers", "ResizeTarget", "GetContainingOutput",
        "GetFrameStatistics", "GetLastPresentCount",
        "GetDesc1", "GetFullscreenDesc", "GetHwnd", "GetCoreWindow",
        "Present1", "IsTemporaryMonoSupported", "GetRestrictToOutput",
        "SetBackgroundColor", "GetBackgroundColor", "SetRotation", "GetRotation",
        "SetSourceSize", "GetSourceSize", "SetMaximumFrameLatency",
        "GetMaximumFrameLatency", "GetFrameLatencyWaitableObject",
        "SetMatrixTransform", "GetMatrixTransform",
        "GetCurrentBackBufferIndex", "CheckColorSpaceSupport",
        "SetColorSpace1", "ResizeBuffers1",
        # IDXGISwapChain4
        "SetHDRMetaData",               # 40
    ],
    "IDirect3D9": [
        "QueryInterface",               # 0
        "AddRef",                       # 1
        "Release",                      # 2
        "RegisterSoftwareDevice",       # 3
        "GetAdapterCount",              # 4
        "GetAdapterIdentifier",         # 5
        "GetAdapterModeCount",          # 6
        "EnumAdapterModes",             # 7
        "GetAdapterDisplayMode",        # 8
        "CheckDeviceType",              # 9
        "CheckDeviceFormat",            # 10
        "CheckDeviceMultiSampleType",   # 11
        "CheckDepthStencilMatch",       # 12
        "CheckDeviceFormatConversion",  # 13
        "GetDeviceCaps",                # 14
        "GetAdapterMonitor",            # 15
        "CreateDevice",                 # 16
    ],
    "IDirect3DDevice9": [
        "QueryInterface",               # 0
        "AddRef",                       # 1
        "Release",                      # 2
        "TestCooperativeLevel",         # 3
        "GetAvailableTextureMem",       # 4
        "EvictManagedResources",        # 5
        "GetDirect3D",                  # 6
        "GetDeviceCaps",                # 7
        "GetDisplayMode",               # 8
        "GetCreationParameters",        # 9
        "SetCursorProperties",          # 10
        "SetCursorPosition",            # 11
        "ShowCursor",                   # 12
        "CreateAdditionalSwapChain",    # 13
        "GetSwapChain",                 # 14
        "GetNumberOfSwapChains",        # 15
        "Reset",                        # 16
        "Present",                      # 17  ← render loop (D3D9)
        "GetBackBuffer",                # 18
        "GetRasterStatus",              # 19
        "SetDialogBoxMode",             # 20
        "SetGammaRamp",                 # 21
        "GetGammaRamp",                 # 22
        "CreateTexture",                # 23
        "CreateVolumeTexture",          # 24
        "CreateCubeTexture",            # 25
        "CreateVertexBuffer",           # 26
        "CreateIndexBuffer",            # 27
        "CreateRenderTarget",           # 28
        "CreateDepthStencilSurface",    # 29
        "UpdateSurface",                # 30
        "UpdateTexture",                # 31
        "GetRenderTargetData",          # 32
        "GetFrontBufferData",           # 33
        "StretchRect",                  # 34
        "ColorFill",                    # 35
        "CreateOffscreenPlainSurface",  # 36
        "SetRenderTarget",              # 37
        "GetRenderTarget",              # 38
        "SetDepthStencilSurface",       # 39
        "GetDepthStencilSurface",       # 40
        "BeginScene",                   # 41
        "EndScene",                     # 42
        "Clear",                        # 43
        "SetTransform",                 # 44
        "GetTransform",                 # 45
        "MultiplyTransform",            # 46
        "SetViewport",                  # 47
        "GetViewport",                  # 48
        "SetMaterial",                  # 49
        "GetMaterial",                  # 50
        "SetLight",                     # 51
        "GetLight",                     # 52
        "LightEnable",                  # 53
        "GetLightEnable",               # 54
        "SetClipPlane",                 # 55
        "GetClipPlane",                 # 56
        "SetRenderState",               # 57
        "GetRenderState",               # 58
        "CreateStateBlock",             # 59
        "BeginStateBlock",              # 60
        "EndStateBlock",                # 61
        "SetClipStatus",                # 62
        "GetClipStatus",                # 63
        "GetTexture",                   # 64
        "SetTexture",                   # 65
        "GetTextureStageState",         # 66
        "SetTextureStageState",         # 67
        "GetSamplerState",              # 68
        "SetSamplerState",              # 69
        "ValidateDevice",               # 70
        "SetPaletteEntries",            # 71
        "GetPaletteEntries",            # 72
        "SetCurrentTexturePalette",     # 73
        "GetCurrentTexturePalette",     # 74
        "SetScissorRect",               # 75
        "GetScissorRect",               # 76
        "SetSoftwareVertexProcessing",  # 77
        "GetSoftwareVertexProcessing",  # 78
        "SetNPatchMode",                # 79
        "GetNPatchMode",                # 80
        "DrawPrimitive",                # 81
        "DrawIndexedPrimitive",         # 82
        "DrawPrimitiveUP",              # 83
        "DrawIndexedPrimitiveUP",       # 84
        "ProcessVertices",              # 85
        "CreateVertexDeclaration",      # 86
        "SetVertexDeclaration",         # 87
        "GetVertexDeclaration",         # 88
        "SetFVF",                       # 89
        "GetFVF",                       # 90
        "CreateVertexShader",           # 91
        "SetVertexShader",              # 92
        "GetVertexShader",              # 93
        "SetVertexShaderConstantF",     # 94
        "GetVertexShaderConstantF",     # 95
        "SetVertexShaderConstantI",     # 96
        "GetVertexShaderConstantI",     # 97
        "SetVertexShaderConstantB",     # 98
        "GetVertexShaderConstantB",     # 99
        "SetStreamSource",              # 100
        "GetStreamSource",              # 101
        "SetStreamSourceFreq",          # 102
        "GetStreamSourceFreq",          # 103
        "SetIndices",                   # 104
        "GetIndices",                   # 105
        "CreatePixelShader",            # 106
        "SetPixelShader",               # 107
        "GetPixelShader",               # 108
        "SetPixelShaderConstantF",      # 109
        "GetPixelShaderConstantF",      # 110
        "SetPixelShaderConstantI",      # 111
        "GetPixelShaderConstantI",      # 112
        "SetPixelShaderConstantB",      # 113
        "GetPixelShaderConstantB",      # 114
        "DrawRectPatch",                # 115
        "DrawTriPatch",                 # 116
        "DeletePatch",                  # 117
        "CreateQuery",                  # 118
    ],
    "ID3D11Device": [
        # IUnknown
        "QueryInterface",               # 0
        "AddRef",                       # 1
        "Release",                      # 2
        # ID3D11Device
        "CreateBuffer",                 # 3
        "CreateTexture1D",              # 4
        "CreateTexture2D",              # 5
        "CreateTexture3D",              # 6
        "CreateShaderResourceView",     # 7
        "CreateUnorderedAccessView",    # 8
        "CreateRenderTargetView",       # 9
        "CreateDepthStencilView",       # 10
        "CreateInputLayout",            # 11
        "CreateVertexShader",           # 12
        "CreateGeometryShader",         # 13
        "CreateGeometryShaderWithStreamOutput", # 14
        "CreatePixelShader",            # 15
        "CreateHullShader",             # 16
        "CreateDomainShader",           # 17
        "CreateComputeShader",          # 18
        "CreateClassLinkage",           # 19
        "CreateBlendState",             # 20
        "CreateDepthStencilState",      # 21
        "CreateRasterizerState",        # 22
        "CreateSamplerState",           # 23
        "CreateQuery",                  # 24
        "CreatePredicate",              # 25
        "CreateCounter",                # 26
        "CreateDeferredContext",        # 27
        "OpenSharedResource",           # 28
        "CheckFormatSupport",           # 29
        "CheckMultisampleQualityLevels",# 30
        "CheckCounterInfo",             # 31
        "CheckCounter",                 # 32
        "CheckFeatureSupport",          # 33
        "GetPrivateData",               # 34
        "SetPrivateData",               # 35
        "SetPrivateDataInterface",      # 36
        "GetFeatureLevel",              # 37
        "GetCreationFlags",             # 38
        "GetDeviceRemovedReason",       # 39
        "GetImmediateContext",          # 40
        "SetExceptionMode",             # 41
        "GetExceptionMode",             # 42
    ],
    # ID3D12Object (base for all D3D12 resources)
    "ID3D12Object": [
        "QueryInterface",               # 0
        "AddRef",                       # 1
        "Release",                      # 2
        "GetPrivateData",               # 3
        "SetPrivateData",               # 4
        "SetPrivateDataInterface",      # 5
        "SetName",                      # 6
    ],
    "ID3D12CommandQueue": [
        # IUnknown + ID3D12Object + ID3D12DeviceChild + ID3D12Pageable
        "QueryInterface",               # 0
        "AddRef",                       # 1
        "Release",                      # 2
        "GetPrivateData",               # 3
        "SetPrivateData",               # 4
        "SetPrivateDataInterface",      # 5
        "SetName",                      # 6
        "GetDevice",                    # 7  (ID3D12DeviceChild)
        # ID3D12CommandQueue
        "UpdateTileMappings",           # 8
        "CopyTileMappings",             # 9
        "ExecuteCommandLists",          # 10  ← D3D12 frame submit
        "SetMarker",                    # 11
        "BeginEvent",                   # 12
        "EndEvent",                     # 13
        "Signal",                       # 14
        "Wait",                         # 15
        "GetTimestampFrequency",        # 16
        "GetClockCalibration",          # 17
        "GetDesc",                      # 18
    ],
}

# Reverse lookup: method name → [(interface, slot_index), ...]
_COM_METHOD_REVERSE: dict[str, list[tuple[str, int]]] = {}
for _iface, _methods in _COM_VTABLE_DB.items():
    for _slot, _method in enumerate(_methods):
        _COM_METHOD_REVERSE.setdefault(_method, []).append((_iface, _slot))

# Render-loop vtable call signatures: (interface, method, slot_index, description)
# Used by find_render_loop to locate frame-presentation calls.
_RENDER_LOOP_SIGNATURES: list[tuple[str, str, int, str]] = [
    ("IDXGISwapChain",  "Present",             8,  "DXGI swap chain present (DX10/11)"),
    ("IDXGISwapChain1", "Present1",            22, "DXGI swap chain present1 (DX11.1+)"),
    ("IDirect3DDevice9","Present",             17, "Direct3D 9 device present"),
    ("ID3D12CommandQueue", "ExecuteCommandLists", 10, "D3D12 submit command lists"),
]


class ComMethodResult(TypedDict, total=False):
    slot: int
    offset_hex: str
    method: str
    interface: str
    inherited_from: str | None


class ComVtableResult(TypedDict, total=False):
    ok: bool
    interface: str
    source: str
    method_count: int
    methods: list[ComMethodResult]
    vtable_ea: str | None
    error: str
    error_type: str
    hint: str


class RenderLoopHit(TypedDict, total=False):
    func_ea: str
    func_name: str
    call_ea: str
    vtable_slot: int
    vtable_offset_hex: str
    interface: str
    method: str
    description: str


class RenderLoopResult(TypedDict, total=False):
    ok: bool
    ptr_size: int
    hits: list[RenderLoopHit]
    hits_count: int
    functions_scanned: int
    error: str
    error_type: str
    hint: str


def _try_ida_type_vtable(interface: str) -> list[str] | None:
    """Try to read a COM vtable layout from IDA's type library.

    IDA stores COM interface types as a struct named ``{Interface}Vtbl``
    whose members are function pointers in vtable order.  If the user
    loaded a DirectX type library (via Load type library... or FLIRT),
    this returns the method names; otherwise returns None.
    """
    try:
        vtbl_name = f"{interface}Vtbl"
        tif = ida_typeinf.tinfo_t()
        if not tif.get_named_type(None, vtbl_name):
            return None
        if not tif.is_udt():
            return None
        udt = ida_typeinf.udt_type_data_t()
        if not tif.get_udt_details(udt):
            return None
        names: list[str] = []
        for udm in udt:
            names.append(udm.name or f"slot_{len(names)}")
        return names if names else None
    except Exception:
        return None


def _build_method_table(
    interface: str,
    methods: list[str],
    ptr_size: int,
) -> list[ComMethodResult]:
    """Convert a flat method name list into ComMethodResult records."""
    out: list[ComMethodResult] = []
    for slot, method in enumerate(methods):
        out.append({
            "slot": slot,
            "offset_hex": hex(slot * ptr_size),
            "method": method,
            "interface": interface,
        })
    return out


@tool
@idasync
def resolve_com_vtable(
    interface: Annotated[
        str | None,
        "COM interface name, e.g. 'IDXGISwapChain', 'IDirect3DDevice9', 'ID3D11Device'. "
        "Case-insensitive prefix matching supported (e.g. 'dxgiswap' finds IDXGISwapChain*).",
    ] = None,
    index: Annotated[
        int | None,
        "Return only the method at this vtable slot index (0-based). "
        "Omit to return all methods.",
    ] = None,
    method: Annotated[
        str | None,
        "Look up a method name across all known interfaces (e.g. 'Present'). "
        "Returns every interface and slot where this method appears.",
    ] = None,
    addr: Annotated[
        str | None,
        "Read the actual vtable at this address and annotate each slot with the "
        "resolved method name. Requires interface= to know which layout to use.",
    ] = None,
    ptr_size: Annotated[
        int | None,
        "Pointer size in bytes: 4 (32-bit) or 8 (64-bit). "
        "Defaults to the IDB's native pointer size.",
    ] = None,
    list_interfaces: Annotated[
        bool,
        "List all known interface names in the database. Useful for tab-completion.",
    ] = False,
) -> dict:
    """Resolve COM/DirectX vtable method names by interface and slot index.

    Covers the most common graphics APIs:
    - DXGI: IUnknown, IDXGIObject, IDXGIDeviceSubObject,
            IDXGISwapChain/1/2/3/4
    - D3D9: IDirect3D9, IDirect3DDevice9
    - D3D11: ID3D11Device
    - D3D12: ID3D12Object, ID3D12CommandQueue

    Usage patterns:

    **Look up one slot:**
      ``resolve_com_vtable(interface="IDXGISwapChain", index=8)``
      → {slot: 8, method: "Present", offset_hex: "0x40"}

    **Full interface table:**
      ``resolve_com_vtable(interface="IDXGISwapChain")``
      → list of all 18 methods with slot numbers and offsets

    **Reverse lookup by name:**
      ``resolve_com_vtable(method="Present")``
      → all interfaces + slots where Present appears

    **Read vtable from IDB address:**
      ``resolve_com_vtable(interface="IDXGISwapChain", addr="0x14012A3F0")``
      → reads function pointers from IDB, correlates with known methods

    **List all known interfaces:**
      ``resolve_com_vtable(list_interfaces=True)``

    Sources checked in order: IDA type library (if DirectX headers loaded),
    then the built-in database.
    """
    try:
        # Determine native pointer size
        if ptr_size is None:
            ptr_size = 8 if compat.inf_is_64bit() else 4

        # --- list_interfaces mode ---
        if list_interfaces:
            known = sorted(_COM_VTABLE_DB.keys())
            return _annotate({
                "ok": True,
                "interfaces": known,
                "count": len(known),
                "hint": "Use interface= with any of these names, or a case-insensitive prefix.",
            })

        # --- reverse lookup by method name ---
        if method and not interface:
            hits = _COM_METHOD_REVERSE.get(method, [])
            if not hits:
                # Try case-insensitive
                ml = method.lower()
                hits = [
                    (iface, slot)
                    for meth_name, entries in _COM_METHOD_REVERSE.items()
                    if meth_name.lower() == ml
                    for iface, slot in entries
                ]
            if not hits:
                return _annotate({
                    "ok": False,
                    "error": f"Method '{method}' not found in any known COM interface.",
                    "hint": "Use list_interfaces=True to see all interfaces, or check spelling.",
                })
            results = []
            for iface, slot in sorted(hits, key=lambda t: (t[0], t[1])):
                results.append({
                    "interface": iface,
                    "slot": slot,
                    "offset_hex": hex(slot * ptr_size),
                    "method": method,
                })
            return _annotate({
                "ok": True,
                "method": method,
                "matches": results,
                "count": len(results),
            })

        if not interface:
            return _annotate({
                "ok": False,
                "error": "Provide interface=, method=, or list_interfaces=True.",
                "hint": "Example: resolve_com_vtable(interface='IDXGISwapChain', index=8)",
            })

        # --- Resolve interface name (case-insensitive prefix) ---
        iface_resolved: str | None = None
        il = interface.lower()
        # Exact match first
        for name in _COM_VTABLE_DB:
            if name.lower() == il:
                iface_resolved = name
                break
        # Prefix match
        if not iface_resolved:
            candidates = [n for n in _COM_VTABLE_DB if n.lower().startswith(il)]
            if len(candidates) == 1:
                iface_resolved = candidates[0]
            elif len(candidates) > 1:
                return _annotate({
                    "ok": False,
                    "error": f"Prefix '{interface}' matches multiple interfaces: {candidates}",
                    "hint": "Use a more specific name.",
                })
        if not iface_resolved:
            return _annotate({
                "ok": False,
                "error": f"Unknown COM interface '{interface}'.",
                "hint": "Use list_interfaces=True to see all known interfaces.",
            })

        # --- Load method list: IDA type library first, then built-in DB ---
        source = "builtin"
        methods = _try_ida_type_vtable(iface_resolved)
        if methods:
            source = "ida_typelibrary"
        else:
            methods = _COM_VTABLE_DB[iface_resolved]

        # --- Filter by index ---
        if index is not None:
            if index < 0 or index >= len(methods):
                return _annotate({
                    "ok": False,
                    "interface": iface_resolved,
                    "error": f"Slot {index} out of range (0-{len(methods)-1} for {iface_resolved}).",
                })
            entry: ComMethodResult = {
                "slot": index,
                "offset_hex": hex(index * ptr_size),
                "method": methods[index],
                "interface": iface_resolved,
            }
            result: ComVtableResult = {
                "ok": True,
                "interface": iface_resolved,
                "source": source,
                "method_count": len(methods),
                "methods": [entry],
            }
            return _annotate(result)

        method_table = _build_method_table(iface_resolved, methods, ptr_size)

        # --- Optionally read actual vtable from IDB ---
        vtable_ea_str: str | None = None
        if addr:
            try:
                vtable_ea = parse_address(addr)
                vtable_ea_str = hex(vtable_ea)
                for entry in method_table:
                    slot = entry["slot"]
                    slot_ea = vtable_ea + slot * ptr_size
                    if ptr_size == 8:
                        func_ea = idc.get_qword(slot_ea)
                    else:
                        func_ea = idc.get_wide_dword(slot_ea)
                    if func_ea and func_ea != idaapi.BADADDR:
                        entry["func_ea"] = hex(func_ea)
                        entry["func_name"] = (
                            ida_funcs.get_func_name(func_ea)
                            or idc.get_name(func_ea, idc.GN_VISIBLE)
                            or ""
                        )
            except Exception as addr_e:
                return _annotate({
                    "ok": False,
                    "interface": iface_resolved,
                    "error": f"Could not read vtable at '{addr}': {addr_e}",
                })

        out: dict = {
            "ok": True,
            "interface": iface_resolved,
            "source": source,
            "method_count": len(methods),
            "methods": method_table,
            # Opt out of TOON tabular encoding — method tables are structural
            # COM data, not row-oriented data, and losing structuredContent
            # breaks MCP schema validation for callers expecting a dict.
            "_toon_skip": True,
        }
        if vtable_ea_str is not None:
            out["vtable_ea"] = vtable_ea_str
        return _annotate(out)

    except Exception as e:
        return _annotate({**tool_error(e, f"resolve_com_vtable({interface!r})"), "interface": interface})


@tool
@idasync
def find_render_loop(
    section: Annotated[
        str,
        "Section to scan. Default '.text'. Can also be a hex range 'start:end' "
        "or the special value 'all' to scan every executable segment.",
    ] = ".text",
    apis: Annotated[
        list[str] | str | None,
        "Limit detection to specific APIs. Choices: 'dxgi', 'd3d9', 'd3d12', or 'all' (default). "
        "Example: ['dxgi', 'd3d9']",
    ] = None,
    limit: Annotated[int, "Max hits to return (default 50)"] = 50,
    include_disasm: Annotated[
        bool,
        "Include the disassembly line at each call site. Default True.",
    ] = True,
) -> RenderLoopResult:
    """Scan binary for Direct3D / DXGI frame-presentation call sites.

    Identifies functions that contain vtable calls matching known render-loop
    signatures:

    | API      | Method                      | Slot | Offset (64-bit) |
    |----------|-----------------------------|------|-----------------|
    | DXGI     | IDXGISwapChain::Present     | 8    | 0x40            |
    | DXGI     | IDXGISwapChain1::Present1   | 22   | 0xB0            |
    | D3D9     | IDirect3DDevice9::Present   | 17   | 0x88 (64) / 0x44 (32) |
    | D3D12    | ID3D12CommandQueue::ExecuteCommandLists | 10 | 0x50   |

    Detection is assembly-level: looks for ``call [reg + N]`` instructions
    where N matches a known Present/ExecuteCommandLists vtable offset, making
    it fast and decompiler-independent.

    Returns the containing function address + call site for each hit.
    Use ``identify_vtable_call`` to trace the object register backward to
    confirm which specific COM object is being called.
    """
    try:
        ptr_size = 8 if compat.inf_is_64bit() else 4

        # Build the set of (offset, sig) pairs to scan for
        api_filter: set[str] = set()
        if apis is None or apis == "all":
            api_filter = {"dxgi", "d3d9", "d3d12"}
        else:
            if isinstance(apis, str):
                apis = [apis]
            for a in apis:
                api_filter.add(a.lower().strip())

        sigs_to_scan: list[tuple[int, str, str, str]] = []
        for iface, meth, slot, desc in _RENDER_LOOP_SIGNATURES:
            tag = "dxgi" if "DXGI" in iface or "D3D11" in iface else \
                  "d3d9" if "D3D9" in iface or "Direct3D9" in iface or "Direct3DDevice9" in iface else \
                  "d3d12"
            if tag not in api_filter:
                continue
            offset = slot * ptr_size
            sigs_to_scan.append((offset, iface, meth, desc))

        if not sigs_to_scan:
            return _annotate({
                "ok": False,
                "ptr_size": ptr_size,
                "hits": [],
                "hits_count": 0,
                "functions_scanned": 0,
                "error": "No signatures selected. Check the apis= parameter.",
            })

        # Determine address ranges to scan
        ranges: list[tuple[int, int]] = []
        if section == "all":
            for seg_ea in idautils.Segments():
                seg = ida_segment.getseg(seg_ea)
                if seg and (seg.perm & ida_segment.SEGPERM_EXEC):
                    ranges.append((seg.start_ea, seg.end_ea))
        elif ":" in section:
            parts = section.split(":", 1)
            try:
                ranges.append((parse_address(parts[0]), parse_address(parts[1])))
            except Exception as e:
                return _annotate({
                    **tool_error(e, f"parse range '{section}'"),
                    "ptr_size": ptr_size, "hits": [], "hits_count": 0, "functions_scanned": 0,
                })
        else:
            seg = _section_by_name(section)
            if seg is None:
                return _annotate({
                    "ok": False,
                    "ptr_size": ptr_size,
                    "hits": [], "hits_count": 0, "functions_scanned": 0,
                    "error": f"Section '{section}' not found. Use get_binary_sections to list available sections.",
                })
            ranges.append((seg.start_ea, seg.end_ea))

        # Build offset set for fast O(1) lookup per instruction
        offset_to_sigs: dict[int, list[tuple[str, str, str]]] = {}
        for offset, iface, meth, desc in sigs_to_scan:
            offset_to_sigs.setdefault(offset, []).append((iface, meth, desc))

        hits: list[RenderLoopHit] = []
        functions_seen: set[int] = set()

        for start_ea, end_ea in ranges:
            ea = start_ea
            while ea < end_ea and len(hits) < limit:
                insn = _decoded_or_none(ea)
                if insn is None:
                    ea += 1
                    continue

                # We want: call [reg + const_offset]
                # IDA opcode: NN_call + operand type o_displ
                is_call = (insn.itype == getattr(ida_idp, "NN_call", -1) or
                           insn.itype == getattr(ida_idp, "NN_callfi", -1) or
                           insn.itype == getattr(ida_idp, "NN_callni", -1))

                if is_call:
                    op = insn.ops[0]
                    if op.type == ida_ua.o_displ:
                        # op.addr holds the displacement
                        disp = int(op.addr) & 0xFFFFFFFF
                        # Sign-extend 32-bit disp for 64-bit addresses
                        if disp >= 0x80000000:
                            disp -= 0x100000000
                        if disp in offset_to_sigs and disp >= 0:
                            for iface, meth, desc in offset_to_sigs[disp]:
                                pfn = ida_funcs.get_func(ea)
                                func_ea = pfn.start_ea if pfn else ea
                                func_name = (ida_funcs.get_func_name(func_ea)
                                             or idc.get_name(func_ea, idc.GN_VISIBLE)
                                             or hex(func_ea))
                                hit: RenderLoopHit = {
                                    "func_ea": hex(func_ea),
                                    "func_name": func_name,
                                    "call_ea": hex(ea),
                                    "vtable_slot": disp // ptr_size,
                                    "vtable_offset_hex": hex(disp),
                                    "interface": iface,
                                    "method": meth,
                                    "description": desc,
                                }
                                if include_disasm:
                                    hit["disasm"] = _safe_disasm(ea)
                                hits.append(hit)
                                functions_seen.add(func_ea)

                ea += max(insn.size, 1)

        render_result: dict = {
            "ok": True,
            "ptr_size": ptr_size,
            "hits": hits,
            "hits_count": len(hits),
            "functions_scanned": len(functions_seen),
        }
        if hits:
            render_result["hint"] = (
                "Use identify_vtable_call(call_addr=hit['call_ea']) to trace "
                "the object register backward and confirm the COM interface type."
            )
        return _annotate(render_result)

    except Exception as e:
        return _annotate({
            **tool_error(e, "find_render_loop"),
            "ptr_size": 8,
            "hits": [],
            "hits_count": 0,
            "functions_scanned": 0,
        })
