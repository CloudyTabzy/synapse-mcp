"""Composite analysis tools that aggregate multiple data sources."""

from __future__ import annotations

from collections import defaultdict
from typing import Annotated, Any, TypedDict
import time

from .rpc import tool, unsafe
from .sync import idasync, tool_timeout, IDAError
from .utils import (
    parse_address,
    get_function,
    get_prototype,
    get_callees,
    get_callers,
    get_all_xrefs,
    get_all_comments,
    extract_function_strings,
    extract_function_constants,
    get_stack_frame_variables_internal,
    decompile_function_safe,
    get_assembly_lines,
    normalize_list_input,
    tool_error,
    item_error,
)
# Shared decompile-failure classification — avoids duplicating the MERR_* map
from .api_analysis import _classify_merr, _DECOMPILE_DEFAULT_HINT  # noqa: PLC2701
from .api_analysis import _hash_function_bytes, _score_function_completeness

# Optional engine helpers — imported at module level with safe fallbacks.
# These are plain functions (no @idasync) so they can be called from
# within another @idasync tool without reentrancy issues.
try:
    from .api_numpy import NUMPY_AVAILABLE, _collect_mnemonics
except Exception:
    NUMPY_AVAILABLE = False
    _collect_mnemonics = None  # type: ignore[assignment]

try:
    from .api_networkx import NETWORKX_AVAILABLE, _function_cfg_impl, _graph_metrics_impl, _get_cached
except Exception:
    NETWORKX_AVAILABLE = False
    _function_cfg_impl = None  # type: ignore[assignment]
    _graph_metrics_impl = None  # type: ignore[assignment]
    _get_cached = None  # type: ignore[assignment]

try:
    from .api_miasm import MIASM_AVAILABLE, _manager, _ircfg_edges, _ir_blocks_to_dict, _iter_ircfg_blocks
except Exception:
    MIASM_AVAILABLE = False
    _manager = None  # type: ignore[assignment]
    _ircfg_edges = None  # type: ignore[assignment]
    _ir_blocks_to_dict = None  # type: ignore[assignment]
    _iter_ircfg_blocks = None  # type: ignore[assignment]

try:
    from .api_triton import TRITON_AVAILABLE, _get_ctx, _CTX_KEY, _detect_arch_from_ida, _build_ctx
    from .api_triton import _process_function_instructions_linear
except Exception:
    TRITON_AVAILABLE = False
    _get_ctx = None  # type: ignore[assignment]
    _CTX_KEY = "default"
    _detect_arch_from_ida = None  # type: ignore[assignment]
    _build_ctx = None  # type: ignore[assignment]
    _process_function_instructions_linear = None  # type: ignore[assignment]

# Max decompile lines before truncation.
_DECOMPILE_LINE_CAP = 100
# Max strings/constants returned in compact mode.
_TOP_STRINGS = 10
_TOP_CONSTANTS = 10
# Constants filtered out of extract_function_constants results.
_BORING_CONSTANTS = frozenset({0, 1, -1, 0xFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF})


class BasicBlockSummary(TypedDict):
    count: int
    cyclomatic_complexity: int


class AnalyzeFunctionResult(TypedDict, total=False):
    addr: str
    name: str
    prototype: str | None
    size: int
    decompiled: str | None
    decompile_truncated: int
    decompile_failure_reason: str   # "no_license" | "code_is_data" | "unsupported_isa" | "too_complex" | "timeout" | "unknown"
    decompile_hint: str             # context-specific remediation hint when decompile failed
    assembly: str | None
    strings: list[str]
    constants: list[dict[str, Any]]
    callees: list[str]
    callers: list[str]
    xrefs: dict[str, Any]
    comments: dict[str, Any]
    basic_blocks: BasicBlockSummary
    error: str | None


class AnalyzeFunctionFullResult(TypedDict, total=False):
    ok: bool
    function: dict[str, Any]
    structure: dict[str, Any]
    code: dict[str, Any]
    completeness: dict[str, Any]
    hash: dict[str, Any]
    statistics: dict[str, Any]
    graph: dict[str, Any]
    ir: dict[str, Any]
    symbolic: dict[str, Any]
    summary: str
    timing_ms: dict[str, int]
    engines_available: dict[str, bool]
    engines_used: dict[str, bool]
    error: str


class ComponentFunctionSummary(TypedDict, total=False):
    addr: str
    name: str
    prototype: str | None
    size: int
    callees: list[str]
    strings: list[str]
    basic_blocks: int
    complexity: int
    error: str


ComponentGraphEdge = TypedDict(
    "ComponentGraphEdge",
    {"from": str, "to": str, "name": str},
)


class InternalCallGraph(TypedDict):
    nodes: list[str]
    edges: list[ComponentGraphEdge]


class SharedGlobalInfo(TypedDict):
    addr: str
    name: str
    accessed_by: list[str]


class AnalyzeComponentResult(TypedDict, total=False):
    functions: list[ComponentFunctionSummary]
    internal_call_graph: InternalCallGraph
    shared_globals: list[SharedGlobalInfo]
    interface_functions: list[str]
    internal_only: list[str]
    string_usage: dict[str, list[str]]
    error: str


class DiffBeforeAfterResult(TypedDict, total=False):
    before: str | None
    after: str | None
    action_applied: str
    changes_detected: bool
    error: str


class FindFunctionsByStringResult(TypedDict, total=False):
    ok: bool
    pattern: str
    functions: list[dict[str, Any]]
    total: int
    error: str | None


class FindCallersOfImportResult(TypedDict, total=False):
    ok: bool
    import_name: str
    import_addr: str | None
    functions: list[dict[str, Any]]
    total: int
    next_offset: int | None
    has_more: bool
    suggestions: list[str]
    error: str | None
    error_type: str
    hint: str


class TraceDataFlowNode(TypedDict):
    addr: str
    func: str | None
    instruction: str | None
    type: str
    name: str | None
    depth: int


TraceDataFlowEdge = TypedDict(
    "TraceDataFlowEdge",
    {"from": str, "to": str, "type": str},
)


class TraceDataFlowResult(TypedDict, total=False):
    start: str
    direction: str
    depth_reached: int
    nodes: list[TraceDataFlowNode]
    edges: list[TraceDataFlowEdge]
    error: str


# ---------------------------------------------------------------------------
# Internal helpers (no @tool — called from within @idasync context)
# ---------------------------------------------------------------------------

def _resolve_addr(addr: str) -> int:
    """Resolve address or name to ea. Raises IDAError on failure."""
    import idaapi

    try:
        return parse_address(addr)
    except IDAError:
        ea = idaapi.get_name_ea(idaapi.BADADDR, addr)
        if ea == idaapi.BADADDR:
            raise IDAError(f"Address/name not found: {addr!r}")
        return ea


def _basic_block_info(ea: int) -> BasicBlockSummary:
    """Return block count and cyclomatic complexity for the function at *ea*."""
    import idaapi

    func = idaapi.get_func(ea)
    if func is None:
        return {"count": 0, "cyclomatic_complexity": 0}

    fc = idaapi.FlowChart(func)
    nodes = 0
    edges = 0
    for block in fc:
        nodes += 1
        for _ in block.succs():
            edges += 1

    return {"count": nodes, "cyclomatic_complexity": edges - nodes + 2}


def _compute_obfuscation_score(func_ea: int) -> dict | None:
    """Fast obfuscation screening using only IDA native APIs (no Miasm).

    Returns a composite score and raw metrics, or None if the function
    cannot be analysed.
    """
    import idaapi
    import ida_funcs

    func = idaapi.get_func(func_ea)
    if func is None:
        return None
    size = func.end_ea - func.start_ea
    if size <= 0:
        return None

    fc = idaapi.FlowChart(func)
    block_count = 0
    edge_count = 0
    for block in fc:
        block_count += 1
        edge_count += len(list(block.succs()))
    if block_count == 0:
        return None

    cc = edge_count - block_count + 2

    # Three normalized signals
    branch_density = edge_count / block_count
    block_size_score = block_count / max(size / 20, 1)
    complexity_score = min(cc / 20, 3.0)

    score = (
        branch_density * 0.35
        + min(block_size_score, 5.0) * 0.35
        + complexity_score * 0.30
    )

    return {
        "block_count": block_count,
        "edge_count": edge_count,
        "cyclomatic_complexity": cc,
        "size": size,
        "obfuscation_score": round(score, 2),
    }


def _filter_constants(raw: list[dict], limit: int = _TOP_CONSTANTS) -> list[dict]:
    """Drop boring constants, return top N by absolute value."""
    out = []
    for c in raw:
        val = c.get("value", 0)
        if not isinstance(val, int):
            continue
        if abs(val) < 0x100 or val in _BORING_CONSTANTS:
            continue
        out.append(c)
    out.sort(key=lambda c: abs(c.get("value", 0)) if isinstance(c.get("value"), int) else 0, reverse=True)
    return out[:limit]


def _cap_decompile(code: str | None) -> tuple[str | None, int | None]:
    """Cap decompiled output at _DECOMPILE_LINE_CAP lines.
    Returns (possibly_truncated_code, total_lines_or_None)."""
    if code is None:
        return None, None
    lines = code.split("\n")
    total = len(lines)
    if total <= _DECOMPILE_LINE_CAP:
        return code, None  # not truncated
    truncated = "\n".join(lines[:_DECOMPILE_LINE_CAP])
    return truncated, total


def _compact_strings(raw: list[dict], limit: int = _TOP_STRINGS) -> list[str]:
    """Return just the string values, deduplicated, capped at limit."""
    seen: set[str] = set()
    out: list[str] = []
    for s in raw:
        val = s.get("value") or s.get("string", "")
        if val and val not in seen:
            seen.add(val)
            out.append(val)
            if len(out) >= limit:
                break
    return out


def _compact_callees(raw: list[dict]) -> list[str]:
    """Return just callee names/addresses as strings."""
    return [c.get("name") or c.get("addr", "?") for c in raw]


def _analyze_function_internal(
    ea: int, *, include_asm: bool = False
) -> AnalyzeFunctionResult:
    """Core analysis logic — must be called from an @idasync context.

    Returns a compact response by default: decompilation capped at 100 lines,
    top 10 strings as values only, top 10 non-trivial constants, no disassembly.
    Pass include_asm=True to include full disassembly."""
    import idaapi

    result: dict = {"addr": hex(ea), "error": None}

    try:
        func = idaapi.get_func(ea)
        if func is None:
            result["error"] = f"No function at {hex(ea)}"
            return result

        result["name"] = idaapi.get_func_name(ea) or ""
        result["prototype"] = get_prototype(func)
        result["size"] = func.end_ea - func.start_ea

        # Decompilation — capped at _DECOMPILE_LINE_CAP lines.
        try:
            raw_code = decompile_function_safe(ea)
            code, total_lines = _cap_decompile(raw_code)
            result["decompiled"] = code
            if total_lines is not None:
                result["decompile_truncated"] = total_lines
            if code is None:
                failure_reason = "unknown"
                hint = _DECOMPILE_DEFAULT_HINT
                try:
                    import ida_hexrays as _hr
                    if _hr.init_hexrays_plugin():
                        hf = _hr.hexrays_failure_t()
                        try:
                            _hr.decompile(ea, hf)
                        except _hr.DecompilationFailure:
                            failure_reason, hint = _classify_merr(hf)
                except Exception:
                    pass
                result["decompile_failure_reason"] = failure_reason
                result["decompile_hint"] = hint
        except Exception:
            result["decompiled"] = None

        # Assembly — opt-in only.
        if include_asm:
            try:
                result["assembly"] = get_assembly_lines(ea)
            except Exception:
                result["assembly"] = None

        # Strings — top 10 values only.
        result["strings"] = _compact_strings(extract_function_strings(ea))
        # Constants — top 10 non-trivial.
        result["constants"] = _filter_constants(extract_function_constants(ea))
        # Callees/callers — names only.
        result["callees"] = _compact_callees(get_callees(hex(ea)))
        result["callers"] = _compact_callees(get_callers(hex(ea)))
        result["xrefs"] = get_all_xrefs(ea)
        result["comments"] = get_all_comments(ea)
        result["basic_blocks"] = _basic_block_info(ea)

    except Exception as exc:
        result["error"] = str(exc)

    return result


# ---------------------------------------------------------------------------
# Tool 1 — analyze_function
# ---------------------------------------------------------------------------


@tool
@idasync
@tool_timeout(120.0)
def analyze_function(
    addr: Annotated[str, "Function address or name"],
    include_asm: Annotated[bool, "Include full disassembly (default: false, saves tokens)"] = False,
) -> AnalyzeFunctionResult:
    """Compact single-function analysis: pseudocode, strings, constants, callers, callees, xrefs, blocks.

    This is the best "one-stop shop" for understanding a single function.
    It returns decompiled pseudocode (capped at 100 lines), cross-references,
    string/constants references, caller/callee lists, and basic-block counts.

    For metrics-only profiling without decompilation, use ``func_profile``.
    For configurable section selection, use ``analyze_batch``.
    For the most powerful cross-engine analysis (Miasm IR + Triton symbolic),
    use ``hybrid_analyze_function``.

    See also: analyze_batch (configurable sections), func_profile (metrics-only),
    hybrid_analyze_function (cross-engine deep dive), trace_data_chain (multi-hop data flow).
    """

    try:
        ea = _resolve_addr(addr)
    except IDAError as exc:
        return {"addr": addr, "ok": False, "error": str(exc)}

    return _analyze_function_internal(ea, include_asm=include_asm)


# ---------------------------------------------------------------------------
# Internal helpers for analyze_function_full
# ---------------------------------------------------------------------------


def _cap_decompile_lines(code: str | None, max_lines: int) -> tuple[str | None, int | None]:
    """Truncate decompiled code to max_lines, returning (code, total_lines_or_None)."""
    if code is None:
        return None, None
    lines = code.splitlines()
    total = len(lines)
    if max_lines > 0 and total > max_lines:
        return "\n".join(lines[:max_lines]) + f"\n... ({total - max_lines} more lines)", total
    return code, None


def _function_jump_targets_internal(ea: int) -> list[dict[str, Any]]:
    """Return jump targets for a function using plain IDA APIs."""
    import idaapi
    import idautils
    import ida_ua

    jumps: list[dict[str, Any]] = []
    func = idaapi.get_func(ea)
    if func is None:
        return jumps

    for item_ea in idautils.FuncItems(ea):
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, item_ea) <= 0:
            continue
        mnem = insn.get_canon_mnem().lower()
        is_jump = idaapi.is_jump_insn(insn)
        is_call = idaapi.is_call_insn(insn)
        if not is_jump and not is_call:
            continue

        kind = "indirect"
        target = None
        if is_call:
            kind = "call"
        elif insn.ops[0].type in (idaapi.o_near, idaapi.o_far):
            kind = "unconditional" if mnem in ("jmp", "b", "br") else "conditional"
            target_val = insn.ops[0].addr
            if target_val != idaapi.BADADDR:
                target = hex(target_val)
        else:
            if mnem in (
                "jz", "je", "jnz", "jne", "ja", "jae", "jb", "jbe",
                "jg", "jge", "jl", "jle", "jo", "jno", "js", "jns",
                "jp", "jnp", "jc", "jnc",
            ):
                kind = "conditional"

        jumps.append({
            "ea": hex(item_ea),
            "target": target,
            "kind": kind,
            "mnemonic": mnem,
        })
    return jumps


def _analyze_function_full_internal(
    ea: int,
    *,
    include_disasm: bool = True,
    include_decompile: bool = True,
    include_numpy: bool = True,
    include_networkx: bool = True,
    include_miasm: bool = True,
    include_triton: bool = False,
    max_disasm_insns: int = 100,
    max_decompile_lines: int = 100,
    max_strings: int = 15,
    max_constants: int = 15,
    triton_max_insns: int = 500,
    triton_solve_timeout_ms: int = 10000,
) -> AnalyzeFunctionFullResult:
    """Core logic for analyze_function_full — must be called from @idasync context."""
    import idaapi
    import idautils
    import ida_funcs

    timing: dict[str, int] = {}
    engines_available: dict[str, bool] = {
        "core": True,
        "numpy": bool(NUMPY_AVAILABLE),
        "networkx": bool(NETWORKX_AVAILABLE),
        "miasm": bool(MIASM_AVAILABLE),
        "triton": bool(TRITON_AVAILABLE),
    }
    engines_used: dict[str, bool] = {"core": True}

    func = idaapi.get_func(ea)
    if func is None:
        return {
            "ok": False,
            "error": f"No function at {hex(ea)}",
            "engines_available": engines_available,
            "engines_used": engines_used,
            "timing_ms": timing,
            "summary": f"No function found at {hex(ea)}.",
        }

    func_name = ida_funcs.get_func_name(ea) or f"sub_{ea:X}"
    func_size = func.end_ea - func.start_ea

    # --- Core: function metadata ---
    t0 = time.perf_counter()
    function_meta: dict[str, Any] = {
        "addr": hex(ea),
        "name": func_name,
        "size": func_size,
        "prototype": get_prototype(func),
        "is_thunk": bool(func.flags & ida_funcs.FUNC_THUNK),
        "is_library": bool(func.flags & ida_funcs.FUNC_LIB),
        "is_noret": bool(func.flags & ida_funcs.FUNC_NORET),
    }

    # --- Core: structure ---
    bb_info = _basic_block_info(ea)
    jumps = _function_jump_targets_internal(ea)

    insn_count = 0
    for _ in idautils.FuncItems(ea):
        insn_count += 1

    structure: dict[str, Any] = {
        "instruction_count": insn_count,
        "basic_block_count": bb_info["count"],
        "cyclomatic_complexity": bb_info["cyclomatic_complexity"],
        "caller_count": len(get_callers(hex(ea))),
        "callee_count": len(get_callees(hex(ea))),
        "jump_targets": jumps[:20],
        "jump_count": len(jumps),
    }

    # --- Core: code ---
    code_section: dict[str, Any] = {}

    if include_decompile:
        try:
            raw_code = decompile_function_safe(ea)
            code_section["decompiled"], truncated = _cap_decompile_lines(raw_code, max_decompile_lines)
            if truncated:
                code_section["decompile_truncated"] = truncated
        except Exception as exc:
            code_section["decompiled"] = None
            code_section["decompile_error"] = str(exc)

    if include_disasm:
        try:
            asm_lines = get_assembly_lines(ea)
            if asm_lines:
                lines = asm_lines.splitlines()
                if max_disasm_insns > 0 and len(lines) > max_disasm_insns:
                    code_section["disasm"] = "\n".join(lines[:max_disasm_insns]) + f"\n... ({len(lines) - max_disasm_insns} more instructions)"
                    code_section["disasm_truncated"] = len(lines)
                else:
                    code_section["disasm"] = asm_lines
            else:
                code_section["disasm"] = None
        except Exception as exc:
            code_section["disasm"] = None
            code_section["disasm_error"] = str(exc)

    # Strings
    raw_strings = extract_function_strings(ea)
    seen_strings: set[str] = set()
    unique_strings: list[str] = []
    for s in raw_strings:
        val = s.get("value") or s.get("string", "")
        if val and val not in seen_strings:
            seen_strings.add(val)
            unique_strings.append(val)
            if len(unique_strings) >= max_strings:
                break
    code_section["strings"] = unique_strings
    code_section["string_count"] = len(seen_strings)

    # Constants
    raw_constants = extract_function_constants(ea)
    interesting_constants: list[dict[str, Any]] = []
    for c in raw_constants:
        val = c.get("value")
        if val in _BORING_CONSTANTS:
            continue
        interesting_constants.append(c)
        if len(interesting_constants) >= max_constants:
            break
    code_section["constants"] = interesting_constants

    code_section["xrefs"] = get_all_xrefs(ea)
    code_section["comments"] = get_all_comments(ea)

    timing["core"] = int((time.perf_counter() - t0) * 1000)

    # --- Core: completeness ---
    t0 = time.perf_counter()
    completeness: dict[str, Any] = _score_function_completeness(ea)
    timing["completeness"] = int((time.perf_counter() - t0) * 1000)

    # --- Core: hash ---
    t0 = time.perf_counter()
    try:
        digest, nbytes, hash_insn_count = _hash_function_bytes(ea)
        hash_info: dict[str, Any] = {
            "sha256": f"sha256:{digest}",
            "normalized_bytes": nbytes,
            "instruction_count": hash_insn_count,
        }
    except Exception as exc:
        hash_info = {"error": str(exc)}
    timing["hash"] = int((time.perf_counter() - t0) * 1000)

    # --- NumPy: opcode histogram ---
    statistics: dict[str, Any] = {"available": False}
    if NUMPY_AVAILABLE and include_numpy:
        t0 = time.perf_counter()
        engines_used["numpy"] = True
        try:
            if _collect_mnemonics is not None:
                mnems = _collect_mnemonics(0, 0, func)
                total = len(mnems)
                if total > 0:
                    counts: dict[str, int] = {}
                    for m in mnems:
                        counts[m] = counts.get(m, 0) + 1

                    sorted_counts = sorted(counts.items(), key=lambda x: x[1], reverse=True)
                    top = [{"mnemonic": m, "count": c, "ratio": round(c / total, 4)} for m, c in sorted_counts[:15]]

                    _OPC_BRANCH = frozenset({
                        "jmp", "je", "jne", "jz", "jnz", "ja", "jae", "jb", "jbe",
                        "jg", "jge", "jl", "jle", "jo", "jno", "js", "jns",
                        "jp", "jnp", "jc", "jnc", "call", "ret", "retn",
                    })
                    _OPC_CALL = frozenset({"call"})
                    _OPC_RET = frozenset({"ret", "retn", "retf"})
                    _OPC_ARITH = frozenset({
                        "add", "sub", "mul", "imul", "div", "idiv", "inc", "dec",
                        "neg", "sal", "and", "or", "xor", "not", "shl", "shr",
                        "sar", "rol", "ror", "adc", "sbb",
                    })
                    _OPC_DATA = frozenset({"mov", "movzx", "movsx", "movsxd", "lea", "movabs", "xchg"})
                    _OPC_STACK = frozenset({"push", "pop", "pusha", "popa", "pushf", "popf", "pushfd", "popfd"})
                    _OPC_NOP = frozenset({"nop", "fnop"})

                    def _grp(group: frozenset[str]) -> int:
                        return sum(counts.get(m, 0) for m in group)

                    ratios = {
                        "branch": round(_grp(_OPC_BRANCH) / total, 4),
                        "call": round(_grp(_OPC_CALL) / total, 4),
                        "ret": round(_grp(_OPC_RET) / total, 4),
                        "arith": round(_grp(_OPC_ARITH) / total, 4),
                        "data_move": round(_grp(_OPC_DATA) / total, 4),
                        "stack": round(_grp(_OPC_STACK) / total, 4),
                        "nop": round(_grp(_OPC_NOP) / total, 4),
                    }

                    import numpy as np
                    cvals = np.array(list(counts.values()), dtype=np.float64)
                    p = cvals / total
                    dist_entropy = float(-np.sum(p * np.log2(p)))

                    anomalies: list[str] = []
                    if ratios["nop"] > 0.15:
                        anomalies.append("high_nop_ratio")
                    if dist_entropy < 2.0 and total > 20:
                        anomalies.append("low_diversity")
                    if sorted_counts and sorted_counts[0][1] / total > 0.5:
                        anomalies.append("single_dominant_mnemonic")

                    statistics = {
                        "available": True,
                        "instruction_count": total,
                        "unique_mnemonics": len(counts),
                        "distribution_entropy": round(dist_entropy, 4),
                        "top_mnemonics": top,
                        "ratios": ratios,
                        "anomalies": anomalies,
                    }
        except Exception as exc:
            statistics = {"available": False, "error": str(exc)}
        timing["numpy"] = int((time.perf_counter() - t0) * 1000)

    # --- NetworkX: CFG + dominators + metrics ---
    graph: dict[str, Any] = {"available": False}
    if NETWORKX_AVAILABLE and include_networkx:
        t0 = time.perf_counter()
        engines_used["networkx"] = True
        try:
            if _function_cfg_impl is not None and _get_cached is not None:
                cfg_res = _function_cfg_impl(hex(ea))
                if cfg_res.get("ok"):
                    graph_id = cfg_res["graph_id"]
                    graph["cfg"] = {
                        "graph_id": graph_id,
                        "node_count": cfg_res.get("node_count", 0),
                        "edge_count": cfg_res.get("edge_count", 0),
                        "is_dag": cfg_res.get("is_dag", False),
                        "density": cfg_res.get("density", 0.0),
                    }

                    if _graph_metrics_impl is not None:
                        metrics_res = _graph_metrics_impl(graph_id)
                        if metrics_res.get("ok"):
                            graph["metrics"] = {
                                "density": metrics_res.get("density", 0.0),
                                "avg_in_degree": metrics_res.get("avg_in_degree", 0.0),
                                "avg_out_degree": metrics_res.get("avg_out_degree", 0.0),
                                "weakly_connected_components": metrics_res.get("weakly_connected_components", 0),
                                "strongly_connected_components": metrics_res.get("strongly_connected_components", 0),
                            }

                    entry = _get_cached(graph_id)
                    if entry is not None:
                        G = entry["graph"]
                        import networkx as _nx
                        if G.number_of_nodes() > 0:
                            entry_block = ea
                            if not G.has_node(entry_block):
                                entry_block = min(G.nodes())
                            try:
                                idoms = _nx.immediate_dominators(G, entry_block)
                                idom_list: list[dict[str, str]] = []
                                loop_headers: list[str] = []
                                seen_loops: set[str] = set()
                                for b, d in idoms.items():
                                    b_str = hex(b) if isinstance(b, int) else str(b)
                                    d_str = hex(d) if isinstance(d, int) else str(d)
                                    idom_list.append({"block": b_str, "idom": d_str})
                                    for pred in G.predecessors(b):
                                        if pred in idoms and idoms[pred] == b:
                                            if b_str not in seen_loops:
                                                seen_loops.add(b_str)
                                                loop_headers.append(b_str)
                                            break
                                graph["dominators"] = {
                                    "block_count": len(idom_list),
                                    "immediate_dominators": idom_list,
                                    "loop_headers": loop_headers,
                                }
                            except Exception:
                                pass
                else:
                    graph["cfg_error"] = cfg_res.get("error", "CFG build failed")
        except Exception as exc:
            graph = {"available": False, "error": str(exc)}
        timing["networkx"] = int((time.perf_counter() - t0) * 1000)

    # --- Miasm: IR lift + CFG summary + side effects ---
    ir: dict[str, Any] = {"available": False}
    if MIASM_AVAILABLE and include_miasm:
        t0 = time.perf_counter()
        engines_used["miasm"] = True
        try:
            if _manager is not None and _ircfg_edges is not None and _ir_blocks_to_dict is not None and _iter_ircfg_blocks is not None:
                data = _manager.get_bytes(func.start_ea, func.end_ea)
                if data is not None:
                    mdis, loc_db = _manager.get_mdis(data, func.start_ea)
                    asmcfg = mdis.dis_multiblock(func.start_ea)

                    block_count = 0
                    edge_count = 0
                    for block in asmcfg.blocks:
                        block_count += 1
                        for dst in block.bto:
                            edge_count += 1

                    ir["cfg_summary"] = {
                        "block_count": block_count,
                        "edge_count": edge_count,
                        "cyclomatic_complexity": edge_count - block_count + 2,
                    }

                    lifter = _manager.machine.lifter_model_call(loc_db)
                    ircfg = lifter.new_ircfg_from_asmcfg(asmcfg)

                    edges = [{"src": str(s), "dst": str(d)} for s, d in _ircfg_edges(ircfg)]
                    ir["lift"] = {
                        "function_ea": hex(func.start_ea),
                        "blocks": _ir_blocks_to_dict(ircfg),
                        "edges": edges[:100],
                        "edge_count": len(edges),
                    }

                    # Side effects using get_expr_ids from miasm (imported via api_miasm)
                    from .api_miasm import get_expr_ids as _miasm_get_expr_ids
                    written: set[str] = set()
                    read: set[str] = set()
                    for _, irblock in _iter_ircfg_blocks(ircfg):
                        for assignblk in irblock:
                            for dst, src in assignblk.items():
                                written.add(str(dst))
                                for expr_id in _miasm_get_expr_ids(src):
                                    read.add(str(expr_id))
                    ir["side_effects"] = {
                        "registers_read": sorted(read)[:50],
                        "registers_written": sorted(written)[:50],
                    }
                else:
                    ir["error"] = "Could not read function bytes"
        except Exception as exc:
            ir = {"available": False, "error": str(exc)}
        timing["miasm"] = int((time.perf_counter() - t0) * 1000)

    # --- Triton: symbolic trace + path constraints + solve ---
    symbolic: dict[str, Any] = {"available": False}
    if TRITON_AVAILABLE and include_triton:
        t0 = time.perf_counter()
        engines_used["triton"] = True
        try:
            if _detect_arch_from_ida is not None and _build_ctx is not None and _process_function_instructions_linear is not None:
                # Initialize or reuse context
                try:
                    ctx = _get_ctx(_CTX_KEY)
                except Exception:
                    arch = _detect_arch_from_ida()
                    ctx = _build_ctx(arch, pc_tracking_symbolic=True)
                    from .api_triton import _set_ctx
                    _set_ctx(_CTX_KEY, ctx)

                records, truncated, _ = _process_function_instructions_linear(
                    ctx, func.start_ea, func.end_ea, triton_max_insns
                )

                symbolic["trace"] = {
                    "instructions_processed": len(records),
                    "truncated": truncated,
                }

                # Path constraints (inline — cannot call @idasync triton_get_path_constraints)
                try:
                    all_sym_var_names = {sv.getName() for sv in ctx.getSymbolicVariables().values()}
                    pcs = ctx.getPathConstraints()
                    pc_items: list[dict[str, Any]] = []
                    symbolic_count = 0
                    concrete_count = 0
                    for pc in pcs:
                        branches: list[dict[str, Any]] = []
                        pc_has_symbolic = False
                        for branch in pc.getBranchConstraints():
                            ast_str = str(branch["constraint"])
                            has_sym = bool(all_sym_var_names & set(ast_str.split()))
                            if has_sym:
                                ctype = "symbolic"
                                pc_has_symbolic = True
                            else:
                                ast_lower = ast_str.strip()
                                if ast_lower in ("true", "#b1", "(= #b1 #b1)"):
                                    ctype = "concrete_true"
                                elif ast_lower in ("false", "#b0", "(= #b1 #b0)"):
                                    ctype = "concrete_false"
                                else:
                                    ctype = "concrete"
                            branches.append({
                                "is_taken": branch["isTaken"],
                                "src_addr": hex(branch["srcAddr"]),
                                "dst_addr": hex(branch["dstAddr"]),
                                "constraint_type": ctype,
                            })
                        if pc_has_symbolic:
                            symbolic_count += 1
                        else:
                            concrete_count += 1
                        pc_items.append({
                            "source_addr": hex(pc.getSourceAddress()),
                            "taken_addr": hex(pc.getTakenAddress()),
                            "branches": branches,
                            "has_symbolic": pc_has_symbolic,
                        })
                    symbolic["path_constraints"] = {
                        "count": len(pc_items),
                        "symbolic_count": symbolic_count,
                        "concrete_count": concrete_count,
                    }
                except Exception as exc:
                    symbolic["path_constraints"] = {"error": str(exc)}

                # Solve (inline — cannot call @idasync triton_solve_path_constraints)
                try:
                    ast_ctx = ctx.getAstContext()
                    predicate = ctx.getPathPredicate()
                    model = ctx.getModel(predicate, timeout=triton_solve_timeout_ms)
                    if model:
                        result: dict[str, str] = {}
                        for var_id, solver_model in model.items():
                            sv = solver_model.getVariable()
                            alias = sv.getAlias() or sv.getName()
                            result[alias] = hex(solver_model.getValue())
                        symbolic["solve"] = {"sat": True, "model": result}
                    else:
                        from .api_triton import _constraint_diagnostics
                        diag = _constraint_diagnostics(ctx)
                        symbolic["solve"] = {"sat": False, "diagnostics": diag}
                except Exception as exc:
                    symbolic["solve"] = {"error": str(exc)}
        except Exception as exc:
            symbolic = {"available": False, "error": str(exc)}
        timing["triton"] = int((time.perf_counter() - t0) * 1000)

    # --- Summary synthesis ---
    summary_parts: list[str] = []

    if func_size < 64:
        size_desc = f"Small ({func_size} bytes, {insn_count} insns)"
    elif func_size < 512:
        size_desc = f"Medium ({func_size} bytes, {insn_count} insns)"
    else:
        size_desc = f"Large ({func_size} bytes, {insn_count} insns)"

    summary_parts.append(
        f"{func_name} at {hex(ea)} — {size_desc}, {bb_info['count']} blocks, complexity {bb_info['cyclomatic_complexity']}."
    )

    grade = completeness.get("grade", "F")
    score = completeness.get("score", 0)
    summary_parts.append(f"Documentation grade: {grade} ({score}/100).")

    anomaly_flags: list[str] = []
    if statistics.get("available"):
        if statistics.get("anomalies"):
            anomaly_flags.extend(statistics["anomalies"])
        if statistics.get("ratios", {}).get("nop", 0) > 0.1:
            anomaly_flags.append("unusual_nop_ratio")

    if structure.get("jump_count", 0) > structure.get("basic_block_count", 0) * 2:
        anomaly_flags.append("high_branch_density")

    if ir.get("available") and ir.get("cfg_summary", {}).get("cyclomatic_complexity", 0) > 20:
        anomaly_flags.append("high_cyclomatic_complexity")

    if anomaly_flags:
        summary_parts.append(f"Anomalies detected: {', '.join(dict.fromkeys(anomaly_flags))}.")

    engine_notes: list[str] = []
    if graph.get("available") and graph.get("dominators", {}).get("loop_headers"):
        engine_notes.append(f"NetworkX found {len(graph['dominators']['loop_headers'])} loop header(s)")
    if ir.get("available"):
        engine_notes.append(f"Miasm lifted {ir.get('lift', {}).get('edge_count', 0)} IR edges")
    if symbolic.get("available"):
        engine_notes.append(f"Triton traced {symbolic.get('trace', {}).get('instructions_processed', 0)} instructions")

    if engine_notes:
        summary_parts.append("Engine highlights: " + "; ".join(engine_notes) + ".")

    if score >= 80 and not anomaly_flags:
        rec = "Well-documented function with no obvious anomalies."
    elif anomaly_flags:
        if "high_nop_ratio" in anomaly_flags or "low_diversity" in anomaly_flags:
            rec = "Obfuscation signatures detected — consider hybrid_iterative_deobfuscate."
        else:
            rec = "Structural anomalies detected — review jump targets and control flow."
    elif score < 40:
        rec = "Poorly documented — consider renaming, typing, and adding comments."
    else:
        rec = "Moderate documentation — review missing items."

    summary_parts.append(rec)
    summary = " ".join(summary_parts)

    return {
        "ok": True,
        "function": function_meta,
        "structure": structure,
        "code": code_section,
        "completeness": completeness,
        "hash": hash_info,
        "statistics": statistics,
        "graph": graph,
        "ir": ir,
        "symbolic": symbolic,
        "summary": summary,
        "timing_ms": timing,
        "engines_available": engines_available,
        "engines_used": engines_used,
    }


# ---------------------------------------------------------------------------
# Tool 2 — analyze_function_full
# ---------------------------------------------------------------------------


@tool
@idasync
@tool_timeout(180.0, prefer_async=True)
def analyze_function_full(
    address: Annotated[str, "Function address or name (hex string or symbol)"],
    include_disasm: Annotated[bool, "Include full disassembly (default: True)"] = True,
    include_decompile: Annotated[bool, "Include decompiled pseudocode (default: True)"] = True,
    include_numpy: Annotated[bool, "Include NumPy statistical analysis (default: True)"] = True,
    include_networkx: Annotated[bool, "Include NetworkX graph metrics (default: True)"] = True,
    include_miasm: Annotated[bool, "Include Miasm IR analysis (default: True)"] = True,
    include_triton: Annotated[bool, "Include Triton symbolic execution (default: False)"] = False,
    max_disasm_insns: Annotated[int, "Max disassembly instructions (0 = unlimited)"] = 100,
    max_decompile_lines: Annotated[int, "Max decompile lines (0 = unlimited)"] = 100,
    max_strings: Annotated[int, "Max string references"] = 15,
    max_constants: Annotated[int, "Max interesting constants"] = 15,
    triton_max_insns: Annotated[int, "Max instructions for Triton trace"] = 500,
    triton_solve_timeout_ms: Annotated[int, "Timeout for Z3 solving"] = 10000,
) -> AnalyzeFunctionFullResult:
    """Complete multi-engine dossier for a single function.

    Combines core IDA analysis (metadata, structure, code, strings, constants,
    xrefs, comments) with optional deep analysis from NumPy, NetworkX, Miasm,
    and Triton. Each engine runs in an isolated phase — if one fails, the
    rest still return data.

    **Recommended first call:** Use default parameters for a comprehensive
    snapshot without the heavy Triton phase. Add ``include_triton=True`` only
    when you need symbolic execution or path-constraint solving.

    **Performance:** Core analysis is typically < 2s. NumPy and NetworkX add
    ~1–3s each. Miasm adds ~2–5s. Triton can add 30–60s depending on
    instruction count — use ``triton_max_insns`` to cap it.

    Returns per-phase timing in ``timing_ms`` and a synthesized ``summary``
    string with size, documentation grade, anomalies, and next-step advice.

    See also: analyze_function (compact single-engine), hybrid_analyze_function
    (Miasm + Triton cross-engine deep dive), func_profile (metrics-only).
    """
    try:
        ea = _resolve_addr(address)
    except IDAError as exc:
        return {
            "ok": False,
            "error": str(exc),
            "summary": f"Cannot resolve address: {address}.",
            "timing_ms": {},
            "engines_available": {},
            "engines_used": {},
        }

    return _analyze_function_full_internal(
        ea,
        include_disasm=include_disasm,
        include_decompile=include_decompile,
        include_numpy=include_numpy,
        include_networkx=include_networkx,
        include_miasm=include_miasm,
        include_triton=include_triton,
        max_disasm_insns=max_disasm_insns,
        max_decompile_lines=max_decompile_lines,
        max_strings=max_strings,
        max_constants=max_constants,
        triton_max_insns=triton_max_insns,
        triton_solve_timeout_ms=triton_solve_timeout_ms,
    )


# ---------------------------------------------------------------------------
# Tool 3 — analyze_component
# ---------------------------------------------------------------------------


@tool
@idasync
@tool_timeout(180.0)
def analyze_component(
    addrs: Annotated[list[str] | str, "Function addresses (comma-separated or list)"],
) -> AnalyzeComponentResult:
    """Analyze related functions as a group: per-function summaries, internal call graph, shared data."""

    import idaapi
    import idautils

    raw = normalize_list_input(addrs)
    if not raw:
        return {"ok": False, "error": "Empty address list"}

    ea_map: dict[int, str] = {}
    for a in raw:
        try:
            ea_map[_resolve_addr(a)] = a
        except IDAError:
            return {"ok": False, "error": f"Cannot resolve address: {a!r}"}

    ea_set = set(ea_map.keys())

    # --- Per-function COMPACT summary (no decompile, no disasm) ---
    functions: list[dict] = []
    for ea in ea_set:
        func = idaapi.get_func(ea)
        if func is None:
            functions.append({"addr": hex(ea), "error": "No function"})
            continue
        name = idaapi.get_func_name(ea) or ""
        strings_raw = extract_function_strings(ea)
        top_strings = _compact_strings(strings_raw, limit=5)
        callee_list = _compact_callees(get_callees(hex(ea)))
        bb = _basic_block_info(ea)
        functions.append({
            "addr": hex(ea),
            "name": name,
            "prototype": get_prototype(func),
            "size": func.end_ea - func.start_ea,
            "callees": callee_list,
            "strings": top_strings,
            "basic_blocks": bb["count"],
            "complexity": bb["cyclomatic_complexity"],
        })

    # --- Internal call graph ---
    nodes = [hex(ea) for ea in ea_set]
    edges: list[dict] = []
    for ea in ea_set:
        for callee in (get_callees(hex(ea)) or []):
            callee_ea = callee.get("addr")
            if isinstance(callee_ea, str):
                try:
                    callee_ea = int(callee_ea, 16)
                except (ValueError, TypeError):
                    continue
            if callee_ea in ea_set:
                edges.append({
                    "from": hex(ea),
                    "to": hex(callee_ea),
                    "name": callee.get("name", ""),
                })

    # --- Shared globals ---
    func_globals: dict[int, set[int]] = {}
    for ea in ea_set:
        globals_accessed: set[int] = set()
        func = idaapi.get_func(ea)
        if func is None:
            func_globals[ea] = globals_accessed
            continue
        for head in idautils.Heads(func.start_ea, func.end_ea):
            for xref in idautils.XrefsFrom(head, 0):
                if xref.iscode:
                    continue
                ref_func = idaapi.get_func(xref.to)
                if ref_func is None and idaapi.is_loaded(xref.to):
                    globals_accessed.add(xref.to)
        func_globals[ea] = globals_accessed

    global_refcount: dict[int, list[str]] = defaultdict(list)
    for ea, gset in func_globals.items():
        fname = idaapi.get_func_name(ea) or hex(ea)
        for g in gset:
            global_refcount[g].append(fname)

    shared_globals = []
    for g_ea, accessors in sorted(global_refcount.items()):
        if len(accessors) >= 2:
            shared_globals.append({
                "addr": hex(g_ea),
                "name": idaapi.get_name(g_ea) or hex(g_ea),
                "accessed_by": sorted(accessors),
            })

    # --- Interface vs internal ---
    interface_functions: list[str] = []
    internal_only: list[str] = []
    for ea in ea_set:
        callers = get_callers(hex(ea))
        has_external = False
        for c in (callers or []):
            caller_addr = c.get("addr") or c.get("start_ea")
            if isinstance(caller_addr, str):
                try:
                    caller_addr = int(caller_addr, 16)
                except (ValueError, TypeError):
                    has_external = True
                    break
            if caller_addr not in ea_set:
                has_external = True
                break
        if has_external:
            interface_functions.append(hex(ea))
        else:
            internal_only.append(hex(ea))

    # --- String usage across functions ---
    string_funcs: dict[str, set[str]] = defaultdict(set)
    for ea in ea_set:
        fname = idaapi.get_func_name(ea) or hex(ea)
        for s in (extract_function_strings(ea) or []):
            sval = s.get("value") or s.get("string", "")
            if sval:
                string_funcs[sval].add(fname)

    string_usage = {
        s: sorted(fnames)
        for s, fnames in sorted(string_funcs.items())
        if len(fnames) >= 2
    }

    return {
        "functions": functions,
        "internal_call_graph": {"nodes": nodes, "edges": edges},
        "shared_globals": shared_globals,
        "interface_functions": interface_functions,
        "internal_only": internal_only,
        "string_usage": string_usage,
    }


# ---------------------------------------------------------------------------
# Tool 3 — diff_before_after
# ---------------------------------------------------------------------------

_VALID_ACTIONS = frozenset({"rename_func", "set_type", "set_comment"})



@unsafe
@tool
@idasync
@tool_timeout(120.0)
def diff_before_after(
    addr: Annotated[str, "Function address"],
    action: Annotated[str, "Action: 'rename_func', 'set_type', 'set_comment'"],
    action_args: Annotated[dict, "Arguments for the action"],
) -> DiffBeforeAfterResult:
    """Rename a function, set its type, or add a comment, and immediately see the
    before/after decompilation side by side. Use this instead of calling rename
    then decompile separately when you want to verify that a rename or type change
    actually improved readability. Actions: 'rename_func' (action_args: {name: str}),
    'set_type' (action_args: {type: str}), 'set_comment' (action_args: {comment: str}).
    Returns {before, after, action_applied, changes_detected}. Especially useful
    during batch renaming to confirm each change had the intended effect."""

    import idaapi
    import ida_hexrays
    import ida_typeinf

    if action not in _VALID_ACTIONS:
        return {"error": f"Invalid action {action!r}. Must be one of: {', '.join(sorted(_VALID_ACTIONS))}"}

    try:
        ea = _resolve_addr(addr)
    except IDAError as exc:
        return {"error": str(exc)}

    func = idaapi.get_func(ea)
    if func is None:
        return {"error": f"No function at {hex(ea)}"}

    # --- Before ---
    before = decompile_function_safe(ea)

    # --- Apply action ---
    applied: str
    try:
        if action == "rename_func":
            name = action_args.get("name")
            if not name:
                return {"error": "action_args must contain 'name'"}
            ok = idaapi.set_name(ea, name, idaapi.SN_CHECK)
            if not ok:
                return {"error": f"set_name failed for {name!r}"}
            applied = f"Renamed to {name!r}"

        elif action == "set_type":
            type_str = action_args.get("type")
            if not type_str:
                return {"error": "action_args must contain 'type'"}
            from .api_types import _parse_function_tinfo
            try:
                tif = _parse_function_tinfo(type_str)
            except ValueError:
                return {"error": f"Failed to parse type: {type_str!r}"}
            ok = ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE)
            if not ok:
                return {"error": f"apply_tinfo failed for {type_str!r}"}
            applied = f"Set type to {type_str!r}"

        elif action == "set_comment":
            comment = action_args.get("comment")
            if comment is None:
                return {"error": "action_args must contain 'comment'"}
            idaapi.set_cmt(ea, comment, False)
            applied = f"Set comment: {comment!r}"

        else:
            return {"error": f"Unhandled action {action!r}"}
    except Exception as exc:
        return {"ok": False, "error": f"Action {action!r} failed: {type(exc).__name__}: {exc}"}

    # --- After (invalidate Hex-Rays cache so we see the change) ---
    ida_hexrays.mark_cfunc_dirty(ea)
    after = decompile_function_safe(ea)

    return {
        "before": before,
        "after": after,
        "action_applied": applied,
        "changes_detected": before != after,
    }


@tool
@idasync
@tool_timeout(60.0)
def find_functions_by_string(
    pattern: Annotated[str, "String pattern to search for (substring match, case-sensitive)"],
    limit: Annotated[int, "Max functions to return (default: 100, max: 1000)"] = 100,
) -> FindFunctionsByStringResult:
    """Find all functions that reference a given string pattern.

    Searches the IDB string table for substring matches, then resolves
    cross-references back to their containing functions. Returns a deduplicated
    list of functions with the specific string addresses that triggered the match.

    Workflow: Use this to locate code that handles a UI message, error text,
    or protocol constant without manually chaining find_regex + xrefs_to calls.

    See also: find_regex (regex search across strings/symbols),
    xrefs_to (single-hop references), analyze_function (deep per-function analysis).
    """
    try:
        import idaapi
        import idautils
        import ida_funcs
        from .api_core import _get_strings_cache
        strings = _get_strings_cache()
        matched_addrs: list[tuple[int, str]] = []
        for ea, text in strings:
            if pattern in text:
                matched_addrs.append((ea, text))

        if not matched_addrs:
            return {
                "ok": True,
                "pattern": pattern,
                "functions": [],
                "total": 0,
                "error": None,
            }

        func_map: dict[int, dict] = {}
        for str_ea, text in matched_addrs:
            for xref in idautils.XrefsTo(str_ea, 0):
                caller_func = idaapi.get_func(xref.frm)
                if not caller_func:
                    continue
                fstart = caller_func.start_ea
                if fstart not in func_map:
                    fname = ida_funcs.get_func_name(fstart) or f"sub_{fstart:X}"
                    func_map[fstart] = {
                        "addr": hex(fstart),
                        "name": fname,
                        "matches": [],
                    }
                match_info = {"string_addr": hex(str_ea), "string": text}
                # Dedupe match entries per function
                if match_info not in func_map[fstart]["matches"]:
                    func_map[fstart]["matches"].append(match_info)

        func_list = list(func_map.values())
        total = len(func_list)
        if limit > 0 and len(func_list) > limit:
            func_list = func_list[:limit]

        return {
            "ok": True,
            "pattern": pattern,
            "functions": func_list,
            "total": total,
            "error": None,
        }
    except Exception as e:
        return {"ok": False, "pattern": pattern, "functions": [], "total": 0, **item_error(e, "find_functions_by_string")}


@tool
@idasync
@tool_timeout(60.0)
def find_callers_of_import(
    name: Annotated[str, "Import name to search for (e.g. 'CreateFileW', 'recv', 'memcpy') — case-insensitive"],
    limit: Annotated[int, "Max caller functions per page (default: 100, max: 1000)"] = 100,
    offset: Annotated[int, "Skip first N caller functions — pass next_offset from a previous result to page forward (default: 0)"] = 0,
) -> FindCallersOfImportResult:
    """Find all functions that call a given imported API.

    Resolves the import name to its IAT slot, then traces all code references
    back to their containing functions. Returns a deduplicated list of callers.
    Name matching is case-insensitive. Multiple IAT slots for the same name are merged.
    When no match is found, a ``suggestions`` list of similar import names is returned
    so the agent can retry with the correct spelling (e.g. passing "CreateFile" will
    suggest "CreateFileA" and "CreateFileW").

    Workflow: Use this when you see a suspicious API (e.g. CreateRemoteThread,
    VirtualProtect) and want to find every function that invokes it.

    See also: trace_data_chain (multi-hop data flow from the import),
    xrefs_to (raw xrefs to the IAT slot), analyze_function (deep caller analysis).
    """
    try:
        from .api_core import _collect_imports
        import idaapi
        import ida_funcs
        import idautils

        if limit <= 0 or limit > 1000:
            limit = 1000
        if offset < 0:
            offset = 0

        name_lower = name.lower()
        all_imports = _collect_imports()
        matched = [
            imp for imp in all_imports
            if (imp.get("imported_name") or "").lower() == name_lower
        ]

        if not matched:
            import difflib
            all_names = [imp.get("imported_name") or "" for imp in all_imports if imp.get("imported_name")]
            suggestions = difflib.get_close_matches(name, all_names, n=5, cutoff=0.5)
            # Also catch simple prefix matches that difflib misses (e.g. "CreateFile" → "CreateFileW")
            if not suggestions:
                suggestions = [n for n in all_names if n.lower().startswith(name_lower)][:5]
            return {
                "ok": True,
                "import_name": name,
                "import_addr": None,
                "functions": [],
                "total": 0,
                "next_offset": None,
                "has_more": False,
                "suggestions": suggestions,
                "error": None,
            }

        # Merge all IAT slots for this import (some binaries bind the same name twice)
        func_map: dict[int, dict] = {}
        import_addr = matched[0]["addr"]
        for imp in matched:
            target_addr = int(imp["addr"], 16)
            for call_ea in idautils.CodeRefsTo(target_addr, 0):
                caller_func = idaapi.get_func(call_ea)
                if not caller_func:
                    continue
                fstart = caller_func.start_ea
                if fstart not in func_map:
                    fname = ida_funcs.get_func_name(fstart) or f"sub_{fstart:X}"
                    func_map[fstart] = {
                        "addr": hex(fstart),
                        "name": fname,
                        "call_sites": [],
                    }
                site = hex(call_ea)
                if site not in func_map[fstart]["call_sites"]:
                    func_map[fstart]["call_sites"].append(site)

        all_funcs = list(func_map.values())
        total = len(all_funcs)
        page_funcs = all_funcs[offset: offset + limit]
        next_off: int | None = (offset + limit) if (offset + limit < total) else None

        return {
            "ok": True,
            "import_name": name,
            "import_addr": import_addr,
            "functions": page_funcs,
            "total": total,
            "next_offset": next_off,
            "has_more": next_off is not None,
            "error": None,
        }
    except Exception as e:
        return {
            "ok": False,
            "import_name": name,
            "import_addr": None,
            "functions": [],
            "total": 0,
            "next_offset": None,
            "has_more": False,
            **item_error(e, "find_callers_of_import"),
        }


# ---------------------------------------------------------------------------
# Tool 4 — trace_data_flow
# ---------------------------------------------------------------------------

_MAX_TRACE_NODES = 200
_MAX_TRACE_EDGES = 500



@tool
@idasync
@tool_timeout(120.0)
def trace_data_flow(
    addr: Annotated[str, "Starting address"],
    direction: Annotated[str, "'forward' (xrefs from) or 'backward' (xrefs to)"] = "forward",
    max_depth: Annotated[int, "Maximum traversal depth"] = 5,
) -> TraceDataFlowResult:
    """Follow cross-references from or to an address, automatically traversing
    multiple hops. Use 'forward' to see where data flows TO (xrefs-from), or
    'backward' to see where data flows FROM (xrefs-to). At each node in the
    traversal, returns the function name, instruction, and whether it's code or
    data. Use this when you find an interesting string, constant, or global and
    want to understand every code path that touches it without manually chaining
    xrefs_to calls. Do not use for call graph traversal — use callgraph for that.
    max_depth controls how many hops to follow (default 5, max 20).

    See also: trace_data_chain (more powerful multi-hop BFS with cross-function
    expansion and detailed xref type classification), xrefs_to (single-hop references).
    """

    import idaapi
    import idautils
    import idc
    from collections import deque

    if direction not in ("forward", "backward"):
        return {"error": f"direction must be 'forward' or 'backward', got {direction!r}"}

    try:
        start_ea = _resolve_addr(addr)
    except IDAError as exc:
        return {"error": str(exc)}

    if max_depth < 1:
        max_depth = 1
    if max_depth > 20:
        max_depth = 20

    visited: set[int] = set()
    nodes: list[dict] = []
    edges: list[dict] = []
    depth_reached = 0

    # BFS queue: (ea, depth)
    queue: deque[tuple[int, int]] = deque()
    queue.append((start_ea, 0))
    visited.add(start_ea)

    while queue and len(nodes) < _MAX_TRACE_NODES:
        ea, depth = queue.popleft()
        if depth > max_depth:
            continue
        if depth > depth_reached:
            depth_reached = depth

        # Build node info.
        func = idaapi.get_func(ea)
        func_name = idaapi.get_func_name(ea) if func else None
        insn_text = idc.GetDisasm(ea) if idaapi.is_loaded(ea) else None

        # Determine if this address references a global/string.
        name_at = idaapi.get_name(ea)
        node_type = "code"
        if func is None and idaapi.is_loaded(ea):
            node_type = "data"

        nodes.append({
            "addr": hex(ea),
            "func": func_name,
            "instruction": insn_text,
            "type": node_type,
            "name": name_at if name_at else None,
            "depth": depth,
        })

        if depth >= max_depth:
            continue

        # Follow xrefs in the requested direction.
        if direction == "forward":
            xrefs = list(idautils.XrefsFrom(ea, 0))
        else:
            xrefs = list(idautils.XrefsTo(ea, 0))

        for xref in xrefs:
            if len(edges) >= _MAX_TRACE_EDGES:
                break
            target = xref.to if direction == "forward" else xref.frm
            # Classify xref type.
            xtype = "code" if xref.iscode else "data"

            edges.append({
                "from": hex(ea) if direction == "forward" else hex(target),
                "to": hex(target) if direction == "forward" else hex(ea),
                "type": xtype,
            })

            if target not in visited and len(nodes) + len(queue) < _MAX_TRACE_NODES:
                visited.add(target)
                queue.append((target, depth + 1))

    return {
        "start": hex(start_ea),
        "direction": direction,
        "depth_reached": depth_reached,
        "nodes": nodes,
        "edges": edges,
    }


# ============================================================================
# Hybrid cross-engine workflows
# ============================================================================

class HybridAnalysisResult(TypedDict, total=False):
    ok: bool
    function_ea: str
    miasm: dict
    triton: dict
    solver: dict
    error: str


class HybridPatchCandidate(TypedDict):
    address: str
    size: int
    reason: str


class HybridPatchResult(TypedDict, total=False):
    ok: bool
    function_ea: str
    dry_run: bool
    candidates: list[HybridPatchCandidate]
    patches_applied: int
    error: str


@tool
@idasync
@tool_timeout(180.0)
def hybrid_analyze_function(
    address: Annotated[str, "Function address (hex or symbol name)."],
    symbolize_args: Annotated[
        str | list[str],
        "Registers to symbolize for Triton (comma-separated or JSON array). "
        "Pass empty string to skip symbolization.",
    ] = "",
    deobfuscate: Annotated[
        bool,
        "Apply Miasm constant-folding and dead-code elimination before analysis.",
    ] = True,
    max_insns: Annotated[int, "Safety cap on Triton instruction count (default 500)."] = 500,
    timeout_ms: Annotated[int, "Z3 solver timeout in ms (default 10000)."] = 10000,
) -> HybridAnalysisResult:
    """Cross-engine analysis: Miasm IR lifting/deobfuscation + Triton symbolic execution + Z3 solving.

    This is the most powerful single-function analysis tool in the fork.
    Miasm simplifies obfuscated control flow and constant expressions first;
    Triton then symbolically executes the result and asks Z3 for concrete
    inputs that drive each branch. Returns a unified report with both IR-level
    and symbolic-level findings.

    See also: analyze_function (IDA-only compact analysis),
    miasm_lift_function (IR lifting only), triton_init (symbolic execution only).
    """
    import idaapi
    import ida_funcs

    # Lazy imports to avoid circular dependencies (api_composite is loaded before
    # api_triton / api_miasm in __init__.py).
    try:
        from .api_triton import (
            TRITON_AVAILABLE,
            _detect_arch_from_ida,
            _build_ctx,
            _set_ctx,
            _CTX_KEY,
            _contexts,
            _symbolize_registers_internal,
            _process_function_instructions_linear,
            _try_solve_predicate,
        )
        from .api_miasm import (
            MIASM_AVAILABLE,
            _manager,
            _iter_ircfg_blocks,
            _ircfg_edges,
        )
    except ImportError as exc:
        return {"ok": False, "error": f"Import error: {exc}"}

    if not TRITON_AVAILABLE:
        return {"ok": False, "error": "Triton not available. Install: pip install triton-library"}
    if not MIASM_AVAILABLE:
        return {"ok": False, "error": "Miasm not available. Install: pip install miasm future"}

    try:
        ea = parse_address(address)
        func = ida_funcs.get_func(ea)
        if func is None:
            return {"ok": False, "error": f"No function at {hex(ea)}"}

        # ------------------------------------------------------------------
        # Miasm phase
        # ------------------------------------------------------------------
        miasm_result: dict = {}
        try:
            data = _manager.get_bytes(func.start_ea, func.end_ea)
            mdis, loc_db = _manager.get_mdis(data, func.start_ea)
            asmcfg = mdis.dis_multiblock(func.start_ea)
            lifter = _manager.machine.lifter_model_call(loc_db)
            ircfg = lifter.new_ircfg_from_asmcfg(asmcfg)

            block_count_before = len(list(_iter_ircfg_blocks(ircfg)))
            edge_count_before = len(_ircfg_edges(ircfg))

            if deobfuscate:
                from miasm.analysis.data_flow import DeadRemoval
                dead_rm = DeadRemoval(lifter)
                dead_rm(ircfg)

            block_count_after = len(list(_iter_ircfg_blocks(ircfg)))
            edge_count_after = len(_ircfg_edges(ircfg))

            miasm_result = {
                "block_count": block_count_after,
                "edge_count": edge_count_after,
                "block_reduction": block_count_before - block_count_after,
                "edge_reduction": edge_count_before - edge_count_after,
                "deobfuscation_applied": deobfuscate,
            }
        except Exception as exc:
            miasm_result = {"error": str(exc)}

        # ------------------------------------------------------------------
        # Triton phase
        # ------------------------------------------------------------------
        if _contexts.get(_CTX_KEY) is None:
            arch = _detect_arch_from_ida()
            ctx = _build_ctx(arch)
            _set_ctx(_CTX_KEY, ctx)
        else:
            ctx = _contexts.get(_CTX_KEY)
            if ctx is None:
                return {"ok": False, "error": "Triton context unavailable"}

        if isinstance(symbolize_args, str):
            reg_list = [r.strip() for r in symbolize_args.split(",") if r.strip()]
        else:
            reg_list = [str(r).strip() for r in symbolize_args if str(r).strip()]

        symbolized = _symbolize_registers_internal(ctx, reg_list) if reg_list else []

        sym_start = len(ctx.getSymbolicExpressions())
        pc_start = len(ctx.getPathConstraints())
        tainted_reg_start = len(ctx.getTaintedRegisters())
        tainted_mem_start = len(ctx.getTaintedMemory())

        processed, truncated = _process_function_instructions_linear(
            ctx, func.start_ea, func.end_ea, max_insns
        )

        sym_end = len(ctx.getSymbolicExpressions())
        pc_end = len(ctx.getPathConstraints())

        sym_vars_info = []
        try:
            from triton import SYMBOLIC
            for vid, sv in ctx.getSymbolicVariables().items():
                sym_vars_info.append({
                    "id": vid,
                    "name": sv.getName(),
                    "alias": sv.getAlias(),
                    "bitsize": sv.getBitSize(),
                    "kind": "register" if sv.getType() == SYMBOLIC.REGISTER_VARIABLE else "memory",
                })
        except Exception:
            pass

        pc_records = []
        try:
            for pc in ctx.getPathConstraints():
                branches_info = []
                for br in pc.getBranchConstraints():
                    branches_info.append({
                        "is_taken": br["isTaken"],
                        "src": hex(br["srcAddr"]),
                        "dst": hex(br["dstAddr"]),
                    })
                pc_records.append({
                    "multiple_branches": pc.isMultipleBranches(),
                    "branches": branches_info,
                })
        except Exception:
            pass

        tainted_outputs = {
            "registers": [r.getName() for r in ctx.getTaintedRegisters()],
            "memory_addrs": [hex(a) for a in ctx.getTaintedMemory()],
        }

        solve_result = _try_solve_predicate(ctx, timeout_ms)

        triton_result = {
            "symbolized_args": symbolized,
            "instructions_processed": len(processed),
            "instructions_truncated": truncated,
            "new_symbolic_expressions": sym_end - sym_start,
            "new_path_constraints": pc_end - pc_start,
            "symbolic_variables": sym_vars_info,
            "path_constraints": pc_records,
            "tainted_outputs": tainted_outputs,
            "tainted_register_delta": len(ctx.getTaintedRegisters()) - tainted_reg_start,
            "tainted_memory_delta": len(ctx.getTaintedMemory()) - tainted_mem_start,
            "solver": solve_result,
        }

        return {
            "ok": True,
            "function_ea": hex(func.start_ea),
            "miasm": miasm_result,
            "triton": triton_result,
            "solver": solve_result,
        }

    except IDAError as exc:
        return {"ok": False, "error": exc.message}
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


@unsafe
@tool
@idasync
@tool_timeout(180.0)
def hybrid_deobfuscate_and_patch(
    address: Annotated[str, "Function address (hex or symbol name)."],
    dry_run: Annotated[
        bool,
        "When True (default), only report proposed patches without modifying the database.",
    ] = True,
    confirm: Annotated[
        bool,
        "Must be set to True when dry_run=False to confirm destructive patching.",
    ] = False,
) -> HybridPatchResult:
    """Miasm deobfuscation + IDA patching workflow.

    1. Lifts the function to Miasm IR and applies dead-code elimination.
    2. Identifies basic blocks that became empty (all assignments dead).
    3. Maps empty blocks back to original instruction addresses.
    4. Reports patch candidates (address ranges that can be NOPed out).
    5. If dry_run=False AND confirm=True, patches the identified bytes with NOPs.

    This tool is marked @unsafe because it modifies the IDA database.
    Always run with dry_run=True first to review proposed patches.
    """
    import idaapi
    import ida_funcs
    import idc
    import ida_bytes

    try:
        from .api_miasm import (
            MIASM_AVAILABLE,
            _manager,
            _iter_ircfg_blocks,
        )
    except ImportError as exc:
        return {"ok": False, "error": f"Import error: {exc}"}

    if not MIASM_AVAILABLE:
        return {"ok": False, "error": "Miasm not available. Install: pip install miasm future"}

    if not dry_run and not confirm:
        return {
            "ok": False,
            "error": "confirm=True is required when dry_run=False. Set dry_run=True to preview patches.",
        }

    try:
        ea = parse_address(address)
        func = ida_funcs.get_func(ea)
        if func is None:
            return {"ok": False, "error": f"No function at {hex(ea)}"}

        data = _manager.get_bytes(func.start_ea, func.end_ea)
        mdis, loc_db = _manager.get_mdis(data, func.start_ea)
        asmcfg = mdis.dis_multiblock(func.start_ea)
        lifter = _manager.machine.lifter_model_call(loc_db)
        ircfg = lifter.new_ircfg_from_asmcfg(asmcfg)

        # Record block addresses before deobfuscation
        block_ranges: dict = {}
        for block in asmcfg.blocks:
            if not block.lines:
                continue
            start = block.lines[0].offset
            end = block.lines[-1].offset
            # Include instruction size for end
            last_len = block.lines[-1].l
            block_ranges[block.loc_key] = (start, end + last_len)

        # Apply dead-code elimination
        from miasm.analysis.data_flow import DeadRemoval
        dead_rm = DeadRemoval(lifter)
        dead_rm(ircfg)

        # Find empty IR blocks (all assignments dead)
        candidates: list[HybridPatchCandidate] = []
        for loc_key, irblock in _iter_ircfg_blocks(ircfg):
            if len(irblock) == 0:
                rng = block_ranges.get(loc_key)
                if rng:
                    candidates.append({
                        "address": hex(rng[0]),
                        "size": rng[1] - rng[0],
                        "reason": "Block empty after dead-code elimination",
                    })

        # Generate NOP bytes for the current architecture
        machine = _manager.machine
        bits = _manager.bitness
        loc_db_nop = None
        try:
            from miasm.core.locationdb import LocationDB
            loc_db_nop = LocationDB()
            mn = machine.mn
            nop_instr = mn.fromstring("NOP", loc_db_nop, bits)
            nop_encodings = mn.asm(nop_instr)
            nop_byte = nop_encodings[0] if nop_encodings else b"\x90"
        except Exception:
            nop_byte = b"\x90"  # Fallback to x86 NOP

        patches_applied = 0
        if not dry_run:
            for cand in candidates:
                try:
                    addr = int(cand["address"], 16)
                    size = cand["size"]
                    if size <= 0:
                        continue
                    # Build NOP sled: repeat shortest NOP encoding
                    nop_sled = (nop_byte * (size // len(nop_byte) + 1))[:size]
                    if ida_bytes.patch_bytes(addr, nop_sled):
                        patches_applied += 1
                except Exception:
                    pass

        return {
            "ok": True,
            "function_ea": hex(func.start_ea),
            "dry_run": dry_run,
            "candidates": candidates,
            "patches_applied": patches_applied,
        }

    except IDAError as exc:
        return {"ok": False, "error": exc.message}
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


# ============================================================================
# hybrid_iterative_deobfuscate
# ============================================================================

class IterativeDeobfuscateIteration(TypedDict, total=False):
    iteration: int
    block_count_before: int
    block_count_after: int
    edge_count_before: int
    edge_count_after: int
    ir_statements_before: int
    ir_statements_after: int
    ir_reduction_pct: float
    candidates: list[HybridPatchCandidate]
    blocks_removed: int
    patches_applied: int
    bytes_nopped: int
    proposed_patches: int
    proposed_bytes_nopped: int
    patch_errors: list[str]
    verified: bool | None
    verification_mismatches: list[str]
    converged: bool
    note: str


class IterativeDeobfuscateResult(TypedDict, total=False):
    ok: bool
    function_ea: str
    iterations: list[IterativeDeobfuscateIteration]
    total_patches: int
    total_blocks_removed: int
    total_bytes_nopped: int
    total_proposed_patches: int
    total_proposed_bytes_nopped: int
    converged: bool
    final_state: str
    aborted_reason: str | None
    dry_run: bool
    error: str


class DeobfuscateSegmentCandidate(TypedDict):
    addr: str
    name: str
    size: int
    block_count: int
    edge_count: int
    cyclomatic_complexity: int
    obfuscation_score: float


class DeobfuscateSegmentFunctionResult(TypedDict, total=False):
    addr: str
    name: str
    obfuscation_score: float
    iterations: list[IterativeDeobfuscateIteration]
    total_patches: int
    total_blocks_removed: int
    total_bytes_nopped: int
    converged: bool
    final_state: str
    error: str | None


class DeobfuscateSegmentResult(TypedDict, total=False):
    ok: bool
    segment: str
    segment_start: str
    segment_end: str
    scanned_functions: int
    candidate_count: int
    candidates: list[DeobfuscateSegmentCandidate]
    processed: int
    results: list[DeobfuscateSegmentFunctionResult]
    total_patches: int
    total_blocks_removed: int
    total_bytes_nopped: int
    errors: list[dict]
    dry_run: bool
    aborted_early: bool
    aborted_reason: str | None
    error: str | None


# Calling-convention registers per arch. Used by the Triton verification
# pass to seed random concrete inputs and to read output registers.
#
# For x86_64: caller-saved registers for both Windows (rcx/rdx/r8/r9 + rax/r10/r11)
# and SysV (rdi/rsi/rdx/rcx/r8/r9 + rax/r10/r11). r10/r11 are always available
# as scratch registers and are used as input parameters in the SysV ABI.
_ARCH_INPUT_REGS: dict[str, tuple[list[str], list[str]]] = {
    "x86_64": (
        ["rcx", "rdx", "r8", "r9", "rdi", "rsi", "r10", "r11"],
        ["rax", "rcx", "rdx", "rdi", "rsi", "r8", "r9", "r10", "r11"],
    ),
    "x86_32": (
        ["eax", "ecx", "edx"],
        ["eax", "ecx", "edx"],
    ),
    "aarch64": (
        ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"],
        ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"],
    ),
}


def _arch_input_regs(arch_str: str) -> tuple[list[str], list[str]]:
    if arch_str.startswith("x86_64"):
        return _ARCH_INPUT_REGS["x86_64"]
    if arch_str.startswith("aarch64"):
        return _ARCH_INPUT_REGS["aarch64"]
    if arch_str.startswith("x86"):
        return _ARCH_INPUT_REGS["x86_32"]
    return ([], [])


def _build_arch_nop(bits: int) -> bytes:
    """Return a single NOP encoding for the current Miasm machine. Raises
    RuntimeError if assembly fails — callers must handle this rather than
    silently fall back to a wrong-architecture NOP byte."""
    from .api_miasm import _manager
    from miasm.core.locationdb import LocationDB
    loc_db = LocationDB()
    mn = _manager.machine.mn
    nop_instr = mn.fromstring("NOP", loc_db, bits)
    encodings = mn.asm(nop_instr)
    if not encodings:
        raise RuntimeError(
            f"miasm assembler returned no encodings for NOP (bits={bits}, "
            f"mn={mn.__class__.__name__}). Cannot build NOP sled for this architecture."
        )
    return encodings[0]


def _nop_sled(nop_bytes: bytes, size: int) -> bytes:
    if size <= 0:
        return b""
    nlen = len(nop_bytes) or 1
    if nlen == 1:
        return nop_bytes * size
    full = size // nlen
    rem = size - full * nlen
    if rem:
        raise RuntimeError(
            f"NOP sled size {size} is not a multiple of the NOP encoding "
            f"length {nlen}. Cannot pad with x86 NOPs on a fixed-width architecture."
        )
    return nop_bytes * full


def _build_patched_bytes(orig_bytes: bytes, func_start: int,
                         candidates: list[HybridPatchCandidate],
                         nop_bytes: bytes) -> bytes:
    out = bytearray(orig_bytes)
    for cand in candidates:
        addr = int(cand["address"], 16)
        size = cand["size"]
        rel = addr - func_start
        if rel < 0 or rel + size > len(out) or size <= 0:
            continue
        out[rel:rel + size] = _nop_sled(nop_bytes, size)
    return bytes(out)


def _triton_concrete_run(arch, code_bytes: bytes, func_start: int,
                         input_regs: dict[str, int], read_regs: list[str],
                         max_insns: int) -> dict[str, int] | None:
    """Fresh Triton context, run code_bytes linearly, return {reg: value} or None.

    Uses Triton's own disassembly (ctx.disassembly) to decode instruction lengths
    from the loaded concrete memory — not IDA's decode_insn — so that patched
    NOP bytes are decoded correctly (1 byte each) rather than using the original
    instruction boundaries from the IDA database.
    """
    try:
        from .api_triton import _build_ctx

        ctx = _build_ctx(arch)
        ctx.setConcreteMemoryAreaValue(func_start, code_bytes)
        for reg_name, val in input_regs.items():
            try:
                reg = ctx.getRegister(reg_name)
                ctx.setConcreteRegisterValue(reg, val)
            except Exception:
                continue

        end_ea = func_start + len(code_bytes)
        curr = func_start
        count = 0
        while curr < end_ea and count < max_insns:
            try:
                # Decode from Triton's concrete memory view (correct for both
                # original and NOP-patched byte sequences).
                insns = ctx.disassembly(curr, 1)
                if not insns:
                    break
                insn = insns[0]
                ctx.processing(insn)
                size = insn.getSize()
                if size == 0:
                    break
                curr += size
                count += 1
            except Exception:
                break

        out: dict[str, int] = {}
        for reg_name in read_regs:
            try:
                reg = ctx.getRegister(reg_name)
                out[reg_name] = int(ctx.getConcreteRegisterValue(reg))
            except Exception:
                continue
        return out
    except Exception as exc:
        import sys
        print(f"[hybrid_iterative_deobfuscate] _triton_concrete_run failed: {exc}", file=sys.stderr)
        return None


def _verify_patches_with_triton(orig_bytes: bytes, func_start: int,
                                candidates: list[HybridPatchCandidate],
                                nop_bytes: bytes, samples: int,
                                max_insns: int) -> tuple[bool | None, list[str]]:
    """Compare concrete return-register values for original vs would-be-patched
    code across `samples` random inputs. Returns (verified, mismatched_regs).
    verified=None means the comparison was inconclusive (Triton unavailable,
    every run errored, or no candidates would alter the bytes)."""
    try:
        from .api_triton import TRITON_AVAILABLE, _detect_arch_from_ida, _arch_to_str
    except ImportError:
        return None, []
    if not TRITON_AVAILABLE:
        return None, []

    try:
        arch = _detect_arch_from_ida()
        arch_str = _arch_to_str(arch)
    except Exception:
        return None, []

    input_reg_names, output_regs = _arch_input_regs(arch_str)
    if not output_regs:
        return None, []
    read_regs = output_regs

    try:
        patched_bytes = _build_patched_bytes(orig_bytes, func_start, candidates, nop_bytes)
    except Exception:
        return None, []
    if patched_bytes == orig_bytes:
        return True, []

    import random
    rng = random.Random(0xC0FFEE)
    mismatches: set[str] = set()
    matched_samples = 0

    for _ in range(max(1, samples)):
        inputs = {name: rng.randrange(0, 1 << 32) for name in input_reg_names}
        out_orig = _triton_concrete_run(arch, orig_bytes, func_start, inputs, read_regs, max_insns)
        out_patched = _triton_concrete_run(arch, patched_bytes, func_start, inputs, read_regs, max_insns)
        if out_orig is None or out_patched is None:
            continue
        matched_samples += 1
        for reg in read_regs:
            if out_orig.get(reg) != out_patched.get(reg):
                mismatches.add(reg)

    if matched_samples == 0:
        return None, []
    return (len(mismatches) == 0), sorted(mismatches)


def _ir_statement_count(ircfg) -> int:
    from .api_miasm import _iter_ircfg_blocks
    total = 0
    for _, irblock in _iter_ircfg_blocks(ircfg):
        total += len(irblock)
    return total


def _ir_edge_count(ircfg) -> int:
    """Count directed CFG edges in the IRCFG by summing successors of each block."""
    from .api_miasm import _iter_ircfg_blocks
    total = 0
    for loc_key, _ in _iter_ircfg_blocks(ircfg):
        try:
            total += len(list(ircfg.successors(loc_key)))
        except Exception:
            pass
    return total


def _is_jmp_only_irblock(irblock, lifter) -> bool:
    """Return True if the irblock contains only a bare IRDst assignment with a
    constant target (a dead unconditional jump stub left by opaque predicate
    elimination).  This is distinct from live sequential blocks merged by
    merge_blocks, which produce IRBlocks with real assignments."""
    if len(irblock) != 1:
        return False
    assignblk = next(iter(irblock))  # single AssignBlk
    if len(assignblk) != 1:
        return False
    for lval, rval in assignblk.items():
        try:
            if lval != lifter.IRDst:
                return False
            # Target must be a constant loc_key expression — a compile-time
            # unconditional branch, not a symbolic/computed jump.
            return rval.is_loc()
        except Exception:
            return False
    return False


def _identify_dead_candidates(
    asmcfg, ircfg, lifter, func_start: int = 0
) -> list[HybridPatchCandidate]:
    """Return asmcfg blocks that are safe to NOP out after simplification.

    Three signals used (the Triton verification pass acts as the outer safety
    net for any false positives, especially for merged blocks):

    1. irblock is empty (len == 0) — all assignments dead, block is unreachable.
    2. irblock is a bare unconditional jump to a constant (jmp-only) — the sole
       remaining artifact of an opaque predicate that simplified to a constant
       branch; the original assembly for this block is dead.
    3. Block exists in asmcfg but was REMOVED from the IRCFG entirely — this
       happens when merge_blocks merges sequential blocks or when a block
       becomes unreachable after simplification. The original assembly bytes
       are no longer needed by the simplified IR.
    """
    from .api_miasm import _iter_ircfg_blocks

    ircfg_loc_keys: set = set()
    dead_loc_keys: set = set()
    for loc_key, irblock in _iter_ircfg_blocks(ircfg):
        ircfg_loc_keys.add(loc_key)
        if len(irblock) == 0 or _is_jmp_only_irblock(irblock, lifter):
            dead_loc_keys.add(loc_key)

    candidates: list[HybridPatchCandidate] = []
    for block in asmcfg.blocks:
        if not block.lines:
            continue

        start = block.lines[0].offset
        # Never patch the function entry block — it would destroy the function.
        if func_start and start == func_start:
            continue

        last = block.lines[-1]
        end = last.offset + last.l
        size = end - start
        if size <= 0:
            continue

        # Signal 3: block was removed from IRCFG (merged or unreachable)
        if block.loc_key not in ircfg_loc_keys:
            candidates.append({
                "address": hex(start),
                "size": size,
                "reason": "Block removed from IRCFG (merged or unreachable)",
            })
            continue

        # Signals 1 & 2: block is empty or jump-only in IRCFG
        if block.loc_key not in dead_loc_keys:
            continue
        candidates.append({
            "address": hex(start),
            "size": size,
            "reason": "Block dead/removed after iterative simplification",
        })
    return candidates


def _hybrid_iterative_deobfuscate_core(
    func_start: int,
    max_iterations: int,
    verify_with_triton: bool,
    verify_samples: int,
    dry_run: bool,
    confirm: bool,
    max_insns: int,
) -> dict:
    """Core iterative deobfuscation logic. Must be called on the IDA main thread."""
    import idaapi
    import ida_funcs
    import ida_bytes

    from .api_miasm import _manager, _iter_ircfg_blocks
    from miasm.analysis.simplifier import IRCFGSimplifierCommon

    nop_bytes = _build_arch_nop(_manager.bitness)

    iterations: list[IterativeDeobfuscateIteration] = []
    total_patches = 0
    total_blocks_removed = 0
    total_bytes_nopped = 0
    total_proposed_patches = 0
    total_proposed_bytes_nopped = 0
    converged = False
    aborted_reason: str | None = None
    func = ida_funcs.get_func(func_start)
    if func is None:
        return {"ok": False, "error": f"No function at {hex(func_start)}"}

    prev_signature: tuple[int, int, int] | None = None
    _last_candidates_found: bool = False
    _prev_cand_sig: tuple | None = None
    _dup_iter_count: int = 0

    for iter_idx in range(1, max_iterations + 1):
        func = ida_funcs.get_func(func_start) or func
        if func is None:
            aborted_reason = f"function disappeared at {hex(func_start)}"
            break
        data = _manager.get_bytes(func.start_ea, func.end_ea)
        if data is None:
            aborted_reason = f"could not read bytes at {hex(func.start_ea)}"
            break

        mdis, loc_db = _manager.get_mdis(data, func.start_ea)
        asmcfg = mdis.dis_multiblock(func.start_ea)
        lifter = _manager.machine.lifter_model_call(loc_db)
        ircfg = lifter.new_ircfg_from_asmcfg(asmcfg)

        head = loc_db.get_offset_location(func.start_ea)
        if head is None:
            aborted_reason = "no head location key for function entry"
            break

        block_count_before = sum(1 for _ in _iter_ircfg_blocks(ircfg))
        edge_count_before = _ir_edge_count(ircfg)
        ir_stmt_before = _ir_statement_count(ircfg)

        try:
            simplifier = IRCFGSimplifierCommon(lifter)
            simplifier(ircfg, head)
        except Exception as exc:
            iterations.append({
                "iteration": iter_idx,
                "block_count_before": block_count_before,
                "block_count_after": block_count_before,
                "edge_count_before": edge_count_before,
                "edge_count_after": edge_count_before,
                "ir_statements_before": ir_stmt_before,
                "ir_statements_after": ir_stmt_before,
                "ir_reduction_pct": 0.0,
                "candidates": [],
                "blocks_removed": 0,
                "patches_applied": 0,
                "bytes_nopped": 0,
                "patch_errors": [],
                "verified": None,
                "verification_mismatches": [],
                "converged": False,
                "note": f"simplifier raised: {type(exc).__name__}: {exc}",
            })
            aborted_reason = "simplifier exception"
            break

        block_count_after = sum(1 for _ in _iter_ircfg_blocks(ircfg))
        edge_count_after = _ir_edge_count(ircfg)
        ir_stmt_after = _ir_statement_count(ircfg)
        ir_reduction_pct = round(
            (ir_stmt_before - ir_stmt_after) / ir_stmt_before * 100, 1
        ) if ir_stmt_before > 0 else 0.0

        signature = (block_count_after, ir_stmt_after, edge_count_after)

        candidates = _identify_dead_candidates(asmcfg, ircfg, lifter, func.start_ea)

        if (prev_signature is not None and signature == prev_signature):
            if not candidates or (verify_with_triton and verified is False):
                iterations.append({
                    "iteration": iter_idx,
                    "block_count_before": prev_signature[0],
                    "block_count_after": block_count_after,
                    "edge_count_before": prev_signature[2],
                    "edge_count_after": edge_count_after,
                    "ir_statements_before": prev_signature[1],
                    "ir_statements_after": ir_stmt_after,
                    "ir_reduction_pct": ir_reduction_pct,
                    "candidates": [],
                    "blocks_removed": 0,
                    "patches_applied": 0,
                    "bytes_nopped": 0,
                    "patch_errors": [],
                    "verified": None,
                    "verification_mismatches": [],
                    "converged": True,
                    "note": "signature unchanged — converged",
                })
                converged = True
                break
        prev_signature = signature

        verified: bool | None = None
        mismatches: list[str] = []
        if candidates and verify_with_triton:
            verified, mismatches = _verify_patches_with_triton(
                data, func.start_ea, candidates, nop_bytes,
                verify_samples, max_insns,
            )

        patches_applied = 0
        bytes_nopped_iter = 0
        patch_errors: list[str] = []
        note_parts: list[str] = []

        if verify_with_triton and verified is None and candidates:
            if dry_run:
                note_parts.append(
                    "Triton verification inconclusive (unavailable or all runs errored)"
                )
            else:
                note_parts.append(
                    "Triton verification inconclusive (unavailable or all runs errored); "
                    "patches applied without verification"
                )

        if candidates:
            if verify_with_triton and verified is False:
                note_parts.append("patches skipped: Triton verification mismatch")
            else:
                for cand in candidates:
                    try:
                        addr = int(cand["address"], 16)
                        size = cand["size"]
                        if size <= 0:
                            continue
                        sled = _nop_sled(nop_bytes, size)
                        if not dry_run:
                            if ida_bytes.patch_bytes(addr, sled):
                                patches_applied += 1
                                bytes_nopped_iter += size
                        # In dry_run mode, actual patches_applied stays 0;
                        # proposed counts are tracked separately below
                    except RuntimeError as exc:
                        patch_errors.append(
                            f"{cand['address']}: {exc}"
                        )
                    except Exception as exc:
                        patch_errors.append(
                            f"{cand['address']}: {type(exc).__name__}: {exc}"
                        )
                if patches_applied and not dry_run:
                    idaapi.auto_wait()
                total_patches += patches_applied
                total_bytes_nopped += bytes_nopped_iter

            # Proposed counts = what WOULD be applied (independent of dry_run)
            proposed_patches_iter = len(candidates)
            proposed_bytes_nopped_iter = sum(
                c.get("size", 0) for c in candidates if c.get("size", 0) > 0
            )
            total_proposed_patches += proposed_patches_iter
            total_proposed_bytes_nopped += proposed_bytes_nopped_iter

        blocks_removed_iter = patches_applied
        total_blocks_removed += blocks_removed_iter

        iterations.append({
            "iteration": iter_idx,
            "block_count_before": block_count_before,
            "block_count_after": block_count_after,
            "edge_count_before": edge_count_before,
            "edge_count_after": edge_count_after,
            "ir_statements_before": ir_stmt_before,
            "ir_statements_after": ir_stmt_after,
            "ir_reduction_pct": ir_reduction_pct,
            "candidates": candidates,
            "blocks_removed": blocks_removed_iter,
            "patches_applied": patches_applied,
            "bytes_nopped": bytes_nopped_iter,
            "proposed_patches": proposed_patches_iter,
            "proposed_bytes_nopped": proposed_bytes_nopped_iter,
            "patch_errors": patch_errors,
            "verified": verified,
            "verification_mismatches": mismatches,
            "converged": False,
            "note": "; ".join(note_parts),
        })

        prev_signature = (block_count_after, ir_stmt_after, edge_count_after)

        # In dry_run mode, IDA bytes never change, so candidates repeat
        # identically — this convergence check is meaningless. Skip it.
        if not dry_run:
            _cand_sig = tuple(sorted(c["address"] for c in candidates)) + (verified,)
            if _cand_sig == _prev_cand_sig:
                _dup_iter_count += 1
            else:
                _dup_iter_count = 0
            _prev_cand_sig = _cand_sig

            if _dup_iter_count >= 3:
                converged = True
                iterations[-1]["converged"] = True
                iterations[-1]["note"] = (
                    "converged after repeated identical candidate+verification signatures; "
                    "Triton mismatch all-or-nothing limitation may prevent deobfuscation"
                )
                break

        # Dry-run short-circuit: if signature is unchanged and no patches
        # were actually applied, further iterations are pure waste.
        if dry_run and prev_signature is not None and signature == prev_signature:
            converged = True
            iterations[-1]["converged"] = True
            iterations[-1]["note"] += (
                "; dry-run short-circuit — no patches applied so further iterations "
                "would produce identical results."
            )
            break

        if (not candidates
                and block_count_after == block_count_before
                and ir_stmt_after == ir_stmt_before
                and edge_count_after == edge_count_before):
            converged = True
            iterations[-1]["converged"] = True
            break

    if converged:
        final_state = "converged"
    elif aborted_reason:
        final_state = "aborted"
    else:
        final_state = "max_iterations"

    return {
        "ok": True,
        "function_ea": hex(func_start),
        "iterations": iterations,
        "total_patches": total_patches,
        "total_blocks_removed": total_blocks_removed,
        "total_bytes_nopped": total_bytes_nopped,
        "total_proposed_patches": total_proposed_patches,
        "total_proposed_bytes_nopped": total_proposed_bytes_nopped,
        "converged": converged,
        "final_state": final_state,
        "aborted_reason": aborted_reason,
        "dry_run": dry_run,
    }


@unsafe
@tool
@idasync
@tool_timeout(300.0)
def hybrid_iterative_deobfuscate(
    address: Annotated[str, "Function address (hex or symbol name)."],
    max_iterations: Annotated[int, "Maximum simplification passes (default 10)."] = 10,
    verify_with_triton: Annotated[
        bool,
        "When True (default), verify each iteration's proposed patches by running "
        "Triton concretely on the original and would-be-patched bytes and comparing "
        "return-register outputs across random inputs. Skip patching on mismatch.",
    ] = True,
    verify_samples: Annotated[int, "Random input samples for Triton verification (default 5)."] = 5,
    dry_run: Annotated[
        bool,
        "When True (default), only report proposed patches per iteration without "
        "writing to the IDB. The full Miasm + verification pipeline still runs.",
    ] = True,
    confirm: Annotated[
        bool,
        "Must be True when dry_run=False to confirm destructive patching.",
    ] = False,
    max_insns: Annotated[int, "Triton per-run instruction cap during verification (default 500)."] = 500,
) -> IterativeDeobfuscateResult:
    """Iteratively deobfuscate a function: Miasm IRCFGSimplifierCommon → optional
    Triton equivalence check → NOP patch → repeat until convergence.

    Each iteration re-lifts the (possibly patched) function bytes, runs Miasm's
    full common simplifier (expr_simp constant folding + dead-code elimination +
    merge_blocks to fix-point), and identifies basic blocks that became empty
    or were removed entirely. When `verify_with_triton=True`, the proposed
    patches are first validated by running Triton concretely on the original
    versus a hypothetically-NOP-patched version across random inputs; mismatches
    abort that iteration's patch (the simplifier may have over-eliminated for
    that particular control flow).

    Convergence is reached when block_count, IR statement count, and CFG edge
    count are all unchanged versus the previous iteration. Returns a per-iteration
    log plus aggregated stats.

    `dry_run=True` (default) makes this safe to call exploratorily — the full
    Miasm pipeline runs and reports proposed patches without modifying the IDB.

    **Dry-run semantics:**
    - ``patches_applied`` / ``bytes_nopped`` / ``blocks_removed`` report the
      *actual* changes made to the IDB (always zero when ``dry_run=True``).
    - ``proposed_patches`` / ``proposed_bytes_nopped`` report what *would* be
      applied if ``dry_run=False``.
    - In ``dry_run=True`` mode, iterations short-circuit after the first pass
      if the signature is unchanged (no actual patches → further passes are
      identical), avoiding the confusing 4-iteration convergence seen before.
    """
    import idaapi
    import ida_funcs
    import ida_bytes

    try:
        from .api_miasm import MIASM_AVAILABLE, _manager, _iter_ircfg_blocks
    except ImportError as exc:
        return {"ok": False, "error": f"Import error: {exc}"}

    if not MIASM_AVAILABLE:
        return {"ok": False, "error": "Miasm not available. Install: pip install miasm future"}

    if not dry_run and not confirm:
        return {
            "ok": False,
            "error": "confirm=True is required when dry_run=False. Set dry_run=True to preview patches.",
        }

    try:
        ea = parse_address(address)
        func = ida_funcs.get_func(ea)
        if func is None:
            return {"ok": False, "error": f"No function at {hex(ea)}"}
        return _hybrid_iterative_deobfuscate_core(
            func.start_ea,
            max_iterations,
            verify_with_triton,
            verify_samples,
            dry_run,
            confirm,
            max_insns,
        )
    except IDAError as exc:
        return {"ok": False, "error": exc.message}
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


@unsafe
@tool
@idasync
@tool_timeout(600.0)
def deobfuscate_segment(
    segment: Annotated[str, "Segment name (e.g. '.text') or hex address within the segment."] = ".text",
    max_functions: Annotated[int, "Maximum candidate functions to process (default 100, max 500)."] = 100,
    complexity_threshold: Annotated[float, "Minimum obfuscation score to qualify (default 1.5)."] = 1.5,
    min_function_size: Annotated[int, "Skip functions smaller than N bytes (default 16)."] = 16,
    exclude_libraries: Annotated[bool, "Skip IDA-identified library functions (default True)."] = True,
    dry_run: Annotated[bool, "Preview only; do not patch (default True)."] = True,
    confirm: Annotated[bool, "Required when dry_run=False for destructive patching."] = False,
    verify_with_triton: Annotated[bool, "Verify each patch with Triton equivalence checks."] = True,
    verify_samples: Annotated[int, "Random inputs per Triton verification (default 5)."] = 5,
    max_iterations: Annotated[int, "Max simplification passes per function (default 10)."] = 10,
    max_insns: Annotated[int, "Triton instruction cap per verification run (default 500)."] = 500,
) -> DeobfuscateSegmentResult:
    """Batch-deobfuscate likely-obfuscated functions across a segment.

    Scans every function in the target segment, ranks them by a composite
    obfuscation score (branch density, block size, cyclomatic complexity),
    and runs the iterative Miasm deobfuscation pipeline on the top candidates.

    `dry_run=True` (default) previews candidates and runs the full analysis
    pipeline without writing patches to the IDB.
    """
    import idaapi
    import ida_segment
    import idautils
    import ida_funcs

    try:
        from .api_miasm import MIASM_AVAILABLE
    except ImportError as exc:
        return {"ok": False, "error": f"Import error: {exc}"}

    if not MIASM_AVAILABLE:
        return {"ok": False, "error": "Miasm not available. Install: pip install miasm future"}

    if not dry_run and not confirm:
        return {
            "ok": False,
            "error": "confirm=True is required when dry_run=False. Set dry_run=True to preview patches.",
        }

    if not segment or not segment.strip():
        return {"ok": False, "error": "segment name or address is required"}
    segment = segment.strip()

    seg = None
    if segment.lower().startswith("0x"):
        try:
            ea = int(segment, 16)
            seg = ida_segment.getseg(ea)
        except ValueError:
            return {"ok": False, "error": f"Invalid segment address: {segment}"}
    else:
        seg = idaapi.get_segm_by_name(segment)
        if seg is None:
            seg_name_l = segment.lower()
            for seg_ea in idautils.Segments():
                s = ida_segment.getseg(seg_ea)
                if s is None:
                    continue
                name = ida_segment.get_segm_name(s) or ""
                if name.lower() == seg_name_l:
                    seg = s
                    break

    if seg is None:
        return {"ok": False, "error": f"Segment not found: {segment}"}

    seg_name = ida_segment.get_segm_name(seg) or segment
    scanned = 0
    candidates = []

    for func_ea in idautils.Functions(seg.start_ea, seg.end_ea):
        scanned += 1
        func = ida_funcs.get_func(func_ea)
        if func is None:
            continue
        size = func.end_ea - func.start_ea
        if size < min_function_size:
            continue
        if exclude_libraries and (func.flags & ida_funcs.FUNC_LIB):
            continue
        try:
            score_info = _compute_obfuscation_score(func_ea)
        except Exception:
            score_info = None
        if score_info is None:
            continue
        if score_info["obfuscation_score"] < complexity_threshold:
            continue
        name = ida_funcs.get_func_name(func_ea) or ""
        candidates.append({
            "addr": hex(func_ea),
            "name": name,
            "size": size,
            "block_count": score_info["block_count"],
            "edge_count": score_info["edge_count"],
            "cyclomatic_complexity": score_info["cyclomatic_complexity"],
            "obfuscation_score": score_info["obfuscation_score"],
        })

    candidates.sort(key=lambda c: c["obfuscation_score"], reverse=True)
    capped_max = max(1, min(max_functions, 500))
    selected = candidates[:capped_max]

    results = []
    errors = []
    total_patches = 0
    total_blocks_removed = 0
    total_bytes_nopped = 0
    aborted_early = False
    aborted_reason = None
    consecutive_failures = 0
    max_consecutive_failures = 10

    for cand in selected:
        func_ea = int(cand["addr"], 16)
        try:
            result = _hybrid_iterative_deobfuscate_core(
                func_ea,
                max_iterations,
                verify_with_triton,
                verify_samples,
                dry_run,
                confirm,
                max_insns,
            )
            consecutive_failures = 0
            total_patches += result.get("total_patches", 0)
            total_blocks_removed += result.get("total_blocks_removed", 0)
            total_bytes_nopped += result.get("total_bytes_nopped", 0)
            results.append({
                "addr": cand["addr"],
                "name": cand["name"],
                "obfuscation_score": cand["obfuscation_score"],
                "iterations": result.get("iterations", []),
                "total_patches": result.get("total_patches", 0),
                "total_blocks_removed": result.get("total_blocks_removed", 0),
                "total_bytes_nopped": result.get("total_bytes_nopped", 0),
                "converged": result.get("converged", False),
                "final_state": result.get("final_state", "unknown"),
                "error": None,
            })
        except Exception as exc:
            consecutive_failures += 1
            err_text = f"{type(exc).__name__}: {exc}"
            errors.append({
                "addr": cand["addr"],
                "name": cand["name"],
                "error": err_text,
            })
            results.append({
                "addr": cand["addr"],
                "name": cand["name"],
                "obfuscation_score": cand["obfuscation_score"],
                "iterations": [],
                "total_patches": 0,
                "total_blocks_removed": 0,
                "total_bytes_nopped": 0,
                "converged": False,
                "final_state": "error",
                "error": err_text,
            })
            if consecutive_failures >= max_consecutive_failures:
                aborted_early = True
                aborted_reason = (
                    f"Aborted after {max_consecutive_failures} consecutive failures — "
                    "likely systemic issue (Miasm crash, corrupted bytes, or architecture mismatch)."
                )
                break

    return {
        "ok": True,
        "segment": seg_name,
        "segment_start": hex(seg.start_ea),
        "segment_end": hex(seg.end_ea),
        "scanned_functions": scanned,
        "candidate_count": len(candidates),
        "candidates": selected,
        "processed": len(results),
        "results": results,
        "total_patches": total_patches,
        "total_blocks_removed": total_blocks_removed,
        "total_bytes_nopped": total_bytes_nopped,
        "errors": errors,
        "dry_run": dry_run,
        "aborted_early": aborted_early,
        "aborted_reason": aborted_reason,
    }
