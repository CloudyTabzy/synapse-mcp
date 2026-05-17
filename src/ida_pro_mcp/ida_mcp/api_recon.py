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

from typing import Annotated, NotRequired, TypedDict

import ida_bytes
import ida_funcs
import ida_idp
import ida_segment
import ida_ua
import ida_xref
import idaapi
import idautils
import idc

from .rpc import tool, unsafe
from .sync import idasync, IDAError
from .utils import parse_address, tool_error


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


class FunctionsRangeResult(TypedDict, total=False):
    ok: bool
    start: str
    end: str
    functions: list[FunctionEntry]
    count: int
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
    max_results: Annotated[int, "Cap on returned writer sites (default 200)"] = 200,
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
        while ok and len(writers) < max_results:
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
    pointer_size: Annotated[int, "Pointer width: 4 or 8 (default 8 for x64)"] = 8,
    max_targets_per_vtable: Annotated[
        int, "Max function targets to include per candidate (default 10)"
    ] = 10,
) -> VTablesResult:
    """Scan a section for arrays of consecutive code pointers — VTable DNA.

    Walks `section` (default `.rdata`) reading `pointer_size`-wide values.
    Any run of `min_pointers`+ consecutive values that all point into an
    executable segment is reported as a VTable candidate.

    Returns the run's start address, length, sample target functions, and
    whether IDA already named the address. AI agents can then probe each
    candidate's call sites with `find_global_writers` (to see who installs
    it) or `find_indirect_calls` (to see who calls through it).
    """
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
            "candidates": candidates,
            "count": len(candidates),
        })
    except Exception as e:
        return _annotate({**tool_error(e, f"vtable scan in {section!r}"), "section": section})


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
        return _annotate({
            "ok": True,
            "start": hex(start_ea),
            "end": hex(end_ea),
            "functions": functions,
            "count": len(functions),
        })
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
    max_results: Annotated[int, "Cap on returned call sites (default 500)"] = 500,
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
        ea = start_ea
        while ea < end_ea and len(sites) < max_results:
            insn = _decoded_or_none(ea)
            if insn is None:
                ea = idc.next_head(ea, end_ea)
                if ea == idaapi.BADADDR or ea <= 0:
                    break
                continue

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

        return _annotate({
            "ok": True,
            "start": hex(start_ea),
            "end": hex(end_ea),
            "sites": sites,
            "by_offset": by_offset,
            "count": len(sites),
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
    max_results: Annotated[int, "Cap on reported hits (default 1000)"] = 1000,
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
        while ea < end_ea and len(hits) < max_results:
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
