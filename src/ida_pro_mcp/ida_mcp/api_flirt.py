"""FLIRT signature and type library tools for IDA Pro MCP.

FLIRT (Fast Library Identification and Recognition Technology) signatures allow
IDA to automatically identify library functions in stripped binaries.

Type libraries (.til) provide rich struct/enum/prototype definitions for system
APIs, enriching decompiler output with named types instead of raw integers.
"""

import logging
import os
from typing import Annotated, NotRequired, TypedDict

import ida_auto
import ida_bytes
import ida_funcs
import ida_segment
import ida_typeinf
import idautils
import idc

from .utils import tool_error, item_error
from .rpc import tool
from .sync import idasync, tool_timeout

logger = logging.getLogger(__name__)


# ============================================================================
# Result types
# ============================================================================


class ApplyFlirtResult(TypedDict, total=False):
    ok: bool
    signature_name: str
    sig_count: int
    lib_functions_before: int
    lib_functions_after: int
    new_lib_functions: int
    error: str


class LoadTilResult(TypedDict, total=False):
    ok: bool
    name: str
    description: str
    error: str


class TilInfo(TypedDict, total=False):
    name: str
    description: str


class ListTilResult(TypedDict, total=False):
    ok: bool
    libraries: list[TilInfo]
    count: int
    error: str


class SigCandidate(TypedDict, total=False):
    addr: str
    name: str
    size_bytes: int
    confidence: float
    suggested_name: str | None
    is_lib_match: bool
    reasons: list[str]
    match_type: str


class SuggestCandidatesResult(TypedDict, total=False):
    ok: bool
    segment: str
    scanned: int
    library_funcs_indexed: int
    candidates: list[SigCandidate]
    error: str
    error_type: str
    hint: str


# ============================================================================
# Internal helpers
# ============================================================================


def _count_lib_funcs() -> int:
    """Count functions currently marked as library functions."""
    count = 0
    for ea in idautils.Functions():
        f = ida_funcs.get_func(ea)
        if f and (f.flags & ida_funcs.FUNC_LIB):
            count += 1
    return count


_UNNAMED_PREFIXES = ("sub_", "j_", "nullsub_", "unknown_libname_")


def _is_auto_named(name: str) -> bool:
    return not name or any(name.startswith(p) for p in _UNNAMED_PREFIXES)


def _get_func_prologue(func, n: int = 16) -> bytes:
    if not func:
        return b""
    size = min(n, func.end_ea - func.start_ea)
    if size <= 0:
        return b""
    data = ida_bytes.get_bytes(func.start_ea, size)
    return data or b""


def _prologue_match_score(a: bytes, b: bytes, n: int = 16) -> tuple[float, float]:
    """Step-filtered byte-level match. Returns (step_score, raw_ratio)."""
    cmp_len = min(len(a), len(b), n)
    if cmp_len == 0:
        return 0.0, 0.0
    matches = sum(1 for x, y in zip(a[:cmp_len], b[:cmp_len]) if x == y)
    ratio = matches / cmp_len
    if ratio >= 1.0:
        return 1.0, ratio
    if ratio >= 0.875:
        return 0.75, ratio
    if ratio >= 0.75:
        return 0.50, ratio
    return 0.0, ratio


def _get_named_callees(func) -> frozenset[str]:
    """Named (non-auto) direct-call targets of the function."""
    result: set[str] = set()
    if not func:
        return frozenset()
    try:
        for head in idautils.Heads(func.start_ea, func.end_ea):
            if not idc.is_call_insn(head):
                continue
            for ref in idautils.CodeRefsFrom(head, 0):
                if ref == head:
                    continue
                ref_name = ida_funcs.get_func_name(ref) or ""
                if ref_name and not _is_auto_named(ref_name):
                    result.add(ref_name)
    except Exception as e:
        logger.debug("_get_named_callees failed at 0x%x: %s", func.start_ea, e)
    return frozenset(result)


def _get_string_refs(func) -> frozenset[int]:
    """Addresses of string-literal data xrefs from the function."""
    result: set[int] = set()
    if not func:
        return frozenset()
    try:
        for head in idautils.Heads(func.start_ea, func.end_ea):
            for ref in idautils.DataRefsFrom(head):
                flags = ida_bytes.get_full_flags(ref)
                if ida_bytes.is_strlit(flags):
                    result.add(ref)
    except Exception as e:
        logger.debug("_get_string_refs failed at 0x%x: %s", func.start_ea, e)
    return frozenset(result)


def _resolve_sig_name(raw: str) -> tuple[str, str | None]:
    """Return (bare_name, error_or_None).

    Accepts:
    - A bare name like 'vc32rtf' or 'vc32rtf.sig' — IDA looks in its sig/ dir.
    - A full absolute path to a .sig file — we extract the basename.

    Returns the name without extension that plan_to_apply_idasgn expects.
    """
    raw = raw.strip()
    if not raw:
        return "", "Signature name must not be empty"

    # Detect full path: contains a directory separator
    if os.sep in raw or (os.altsep and os.altsep in raw) or raw.startswith("/"):
        if not os.path.isfile(raw):
            return "", f"File not found: {raw}"
        return os.path.splitext(os.path.basename(raw))[0], None

    # Bare name: just strip the extension if present
    return os.path.splitext(raw)[0], None


# ============================================================================
# Tools
# ============================================================================


@tool
@idasync
def apply_flirt_signature(
    sig_name: Annotated[
        str,
        "Signature name without extension searched in IDA's sig/ directory "
        "(e.g. 'vc32rtf'), or full path to a .sig file on disk.",
    ],
) -> ApplyFlirtResult:
    """Apply a FLIRT signature file to identify library functions in the current IDB.

    IDA looks up bare names (no extension) in its own sig/ directory.
    Pass a full path when the .sig file lives outside IDA's installation.
    After scheduling the signature, IDA's auto-analysis runs to completion
    before the tool returns, so new_lib_functions reflects the actual delta.

    Note: .pat (pattern) files must first be compiled to .sig using the
    sigmake tool before they can be applied here.
    """
    try:
        fname, err = _resolve_sig_name(sig_name)
        if err:
            return {"ok": False, "error": err}

        before = _count_lib_funcs()

        sig_count = ida_funcs.plan_to_apply_idasgn(fname)
        if sig_count <= 0:
            return {
                "ok": False,
                "error": (
                    f"Failed to load signature '{fname}' "
                    f"(plan_to_apply_idasgn returned {sig_count}). "
                    "Ensure the .sig file exists in IDA's sig/ directory."
                ),
            }

        # Wait for IDA's auto-analysis to process the newly scheduled sigs.
        ida_auto.auto_wait()

        after = _count_lib_funcs()
        return {
            "ok": True,
            "signature_name": fname,
            "sig_count": sig_count,
            "lib_functions_before": before,
            "lib_functions_after": after,
            "new_lib_functions": after - before,
        }

    except Exception as e:
        logger.exception("apply_flirt_signature failed")
        return tool_error(e)


@tool
@idasync
def load_type_library(
    name: Annotated[
        str,
        "Type library name without extension searched in IDA's til/ directory "
        "(e.g. 'mssdk64_win10'), or full path to a .til file.",
    ],
) -> LoadTilResult:
    """Load a type library (.til) into the current IDB.

    Type libraries provide struct/enum/prototype definitions for system APIs.
    Loading one enriches decompiler output with proper named types (HANDLE,
    LPCWSTR, etc.) instead of raw integers.

    IDA searches its own til/ directory for bare names. Supply a full path
    when the file is outside IDA's installation.

    Return codes from IDA:
    - ADDTIL_OK (1): successfully added.
    - ADDTIL_COMP (2): already loaded as a dependency of another library.
    - ADDTIL_FAILED (0): not found or incompatible.
    """
    try:
        raw = name.strip()
        if not raw:
            return {"ok": False, "error": "Name must not be empty"}

        if os.sep in raw or (os.altsep and os.altsep in raw) or raw.startswith("/"):
            if not os.path.isfile(raw):
                return {"ok": False, "error": f"File not found: {raw}"}
            til_name = os.path.splitext(os.path.basename(raw))[0]
        else:
            til_name = os.path.splitext(raw)[0]

        # ADDTIL_FAILED=0, ADDTIL_OK=1, ADDTIL_COMP=2
        rc = ida_typeinf.add_til(til_name, 0)
        if rc == 0:
            return {
                "ok": False,
                "error": (
                    f"Failed to load type library '{til_name}'. "
                    "Ensure it exists in IDA's til/ directory and is compatible with the current architecture."
                ),
            }

        # Retrieve the description from the newly loaded TIL if available.
        description = ""
        try:
            # get_idati() returns the local IDB type library; walk its bases
            # to find the one we just loaded by name.
            til = ida_typeinf.get_idati()
            if til is not None:
                queue = [til]
                seen: set[int] = set()
                while queue:
                    t = queue.pop(0)
                    if id(t) in seen:
                        continue
                    seen.add(id(t))
                    if (t.name or "").lower() == til_name.lower():
                        description = t.desc or ""
                        break
                    for i in range(t.nbases):
                        dep = t.base(i)
                        if dep is not None:
                            queue.append(dep)
        except Exception:
            pass

        already = rc == 2  # ADDTIL_COMP
        return {
            "ok": True,
            "name": til_name,
            "description": description,
            **({"note": "Already loaded as a dependency"} if already else {}),
        }

    except Exception as e:
        logger.exception("load_type_library failed")
        return tool_error(e)


@tool
@idasync
def list_type_libraries() -> ListTilResult:
    """List all type libraries currently active in the IDB.

    Returns the name and description of every TIL loaded into the current
    database, including transitive dependencies. Use load_type_library to
    add more.
    """
    try:
        til = ida_typeinf.get_idati()
        if til is None:
            return {"ok": True, "libraries": [], "count": 0}

        libs: list[TilInfo] = []
        seen: set[int] = set()
        queue = [til]

        while queue:
            t = queue.pop(0)
            if id(t) in seen:
                continue
            seen.add(id(t))
            libs.append({"name": t.name or "", "description": t.desc or ""})
            for i in range(t.nbases):
                dep = t.base(i)
                if dep is not None:
                    queue.append(dep)

        return {"ok": True, "libraries": libs, "count": len(libs)}

    except Exception as e:
        logger.exception("list_type_libraries failed")
        return tool_error(e)


@tool
@idasync
@tool_timeout(120.0)
def sig_suggest_candidates(
    segment: Annotated[str, "Code segment to scan for unnamed functions (default '.text')"] = ".text",
    min_confidence: Annotated[float, "Minimum confidence 0.0-1.0 (default 0.40)"] = 0.40,
    max_results: Annotated[int, "Maximum candidates returned (default 50)"] = 50,
    max_scan: Annotated[int, "Cap on unnamed functions evaluated (default 500)"] = 500,
) -> SuggestCandidatesResult:
    """Suggest names for unnamed functions after FLIRT identification stalls.

    Scores each unnamed function (sub_XXXX) in the target segment against an
    index of already-named functions using three signals:
    - Prologue byte match (<=0.40): first 16 bytes, step-filtered at 75%/87.5%/100%.
    - Callee Jaccard similarity (<=0.40): overlap of named direct-call targets.
    - String literal overlap (<=0.20): shared string-literal addresses.

    Returns a ranked list with suggested_name, confidence, and reasons.
    Use as a FLIRT feedback loop: apply_flirt_signature -> sig_suggest_candidates
    -> review -> rename_function -> repeat.
    """
    try:
        seg = ida_segment.get_segm_by_name(segment)
        if seg is None:
            return {
                "ok": False,
                "error": f"Segment {segment!r} not found",
                "segment": segment,
                "hint": "Call list_segments to find the correct segment name and retry.",
            }

        min_confidence = max(0.0, min(1.0, min_confidence))

        # Build named-function index (global scope, lazy callee/string fields)
        named_entries: list[dict] = []
        for func_ea in idautils.Functions():
            func = ida_funcs.get_func(func_ea)
            if not func:
                continue
            name = ida_funcs.get_func_name(func_ea) or ""
            if _is_auto_named(name):
                continue
            prologue = _get_func_prologue(func, 16)
            if not prologue:
                continue
            named_entries.append({
                "name": name,
                "ea": func_ea,
                "func": func,
                "prologue": prologue,
                "is_lib": bool(func.flags & ida_funcs.FUNC_LIB),
                "callees": None,
                "strings": None,
            })

        # Collect unnamed functions in segment
        unnamed_funcs: list = []
        for func_ea in idautils.Functions(seg.start_ea, seg.end_ea):
            func = ida_funcs.get_func(func_ea)
            if not func:
                continue
            name = ida_funcs.get_func_name(func_ea) or ""
            if _is_auto_named(name):
                unnamed_funcs.append(func)
            if len(unnamed_funcs) >= max_scan:
                break

        if not named_entries:
            return {
                "ok": True,
                "segment": segment,
                "scanned": len(unnamed_funcs),
                "library_funcs_indexed": 0,
                "candidates": [],
            }

        candidates: list[SigCandidate] = []

        for func in unnamed_funcs:
            func_ea = func.start_ea
            size_bytes = func.end_ea - func.start_ea
            prologue = _get_func_prologue(func, 16)

            # Signal A: prologue
            best_pro_entry, best_pro_raw, best_pro_ratio = None, 0.0, 0.0
            if prologue:
                for entry in named_entries:
                    s, r = _prologue_match_score(prologue, entry["prologue"])
                    if s > best_pro_raw:
                        best_pro_raw, best_pro_ratio, best_pro_entry = s, r, entry
            pro_contribution = best_pro_raw * 0.40

            # Signal B: callees Jaccard
            best_cal_entry, best_cal_raw = None, 0.0
            func_callees = _get_named_callees(func)
            if func_callees:
                for entry in named_entries:
                    if entry["callees"] is None:
                        entry["callees"] = _get_named_callees(entry["func"])
                    ref = entry["callees"]
                    if not ref:
                        continue
                    j = len(func_callees & ref) / len(func_callees | ref)
                    if j > best_cal_raw:
                        best_cal_raw, best_cal_entry = j, entry
            cal_contribution = best_cal_raw * 0.40

            # Signal C: string xref overlap
            best_str_entry, best_str_raw = None, 0.0
            func_strings = _get_string_refs(func)
            if func_strings:
                for entry in named_entries:
                    if entry["strings"] is None:
                        entry["strings"] = _get_string_refs(entry["func"])
                    ref = entry["strings"]
                    if not ref:
                        continue
                    s = len(func_strings & ref) / max(len(func_strings), len(ref))
                    if s > best_str_raw:
                        best_str_raw, best_str_entry = s, entry
            str_contribution = min(best_str_raw, 1.0) * 0.20

            total = min(pro_contribution + cal_contribution + str_contribution, 1.0)
            if total < min_confidence:
                continue

            # Dominant signal -> suggested name
            scores = [
                ("prologue", pro_contribution, best_pro_entry),
                ("callees",  cal_contribution, best_cal_entry),
                ("strings",  str_contribution, best_str_entry),
            ]
            dominant_type, _, best_entry = max(scores, key=lambda x: x[1])
            if best_entry is None:
                best_entry = next((e for _, _, e in scores if e is not None), None)

            suggested_name = best_entry["name"] if best_entry else None
            is_lib_match = best_entry["is_lib"] if best_entry else False

            reasons: list[str] = []
            if best_pro_raw >= 0.50 and best_pro_entry:
                reasons.append(
                    f"prologue {best_pro_ratio:.0%} byte match with '{best_pro_entry['name']}'"
                )
            if best_cal_raw >= 0.30 and best_cal_entry:
                reasons.append(
                    f"callees {best_cal_raw:.0%} Jaccard with '{best_cal_entry['name']}'"
                )
            if best_str_raw > 0 and best_str_entry:
                reasons.append(f"shares string refs with '{best_str_entry['name']}'")

            candidates.append({
                "addr": hex(func_ea),
                "name": ida_funcs.get_func_name(func_ea) or hex(func_ea),
                "size_bytes": size_bytes,
                "confidence": round(total, 3),
                "suggested_name": suggested_name,
                "is_lib_match": is_lib_match,
                "reasons": reasons,
                "match_type": dominant_type,
            })

        candidates.sort(key=lambda c: c["confidence"], reverse=True)

        return {
            "ok": True,
            "segment": segment,
            "scanned": len(unnamed_funcs),
            "library_funcs_indexed": len(named_entries),
            "candidates": candidates[:max_results],
        }

    except Exception as e:
        logger.exception("sig_suggest_candidates failed")
        return tool_error(e)
