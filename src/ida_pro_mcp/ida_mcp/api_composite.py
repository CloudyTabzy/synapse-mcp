"""Composite analysis tools that aggregate multiple data sources."""

from __future__ import annotations

from collections import defaultdict
from typing import Annotated, Any, TypedDict

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
)

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
    assembly: str | None
    strings: list[str]
    constants: list[dict[str, Any]]
    callees: list[str]
    callers: list[str]
    xrefs: dict[str, Any]
    comments: dict[str, Any]
    basic_blocks: BasicBlockSummary
    error: str | None


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
    """Compact single-function analysis: pseudocode, strings, constants, callers, callees, xrefs, blocks."""

    try:
        ea = _resolve_addr(addr)
    except IDAError as exc:
        return {"addr": addr, "error": str(exc)}

    return _analyze_function_internal(ea, include_asm=include_asm)


# ---------------------------------------------------------------------------
# Tool 2 — analyze_component
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
        return {"error": "Empty address list"}

    ea_map: dict[int, str] = {}
    for a in raw:
        try:
            ea_map[_resolve_addr(a)] = a
        except IDAError:
            return {"error": f"Cannot resolve address: {a!r}"}

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



@tool
@unsafe
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
        return {"error": f"Action {action!r} failed: {exc}"}

    # --- After (invalidate Hex-Rays cache so we see the change) ---
    ida_hexrays.mark_cfunc_dirty(ea)
    after = decompile_function_safe(ea)

    return {
        "before": before,
        "after": after,
        "action_applied": applied,
        "changes_detected": before != after,
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
    max_depth controls how many hops to follow (default 5, max 20)."""

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
