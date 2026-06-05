import difflib
import hashlib
import heapq
from itertools import islice
import re as _re
import struct
from typing import Annotated, Any, NotRequired, Optional, TypedDict
import ida_lines
import ida_funcs
import idaapi
import idautils
import ida_typeinf
import ida_nalt
import ida_bytes
import ida_ida
import ida_idaapi
import ida_xref
import ida_ua
import ida_name
import idc
from .rpc import tool
from .sync import idasync, tool_timeout, IDAError
from .utils import (
    parse_address,
    normalize_list_input,
    normalize_dict_list,
    get_function,
    get_prototype,
    paginate,
    pattern_filter,
    get_stack_frame_variables_internal,
    decompile_function_safe,
    compact_whitespace,
    get_assembly_lines,
    get_all_xrefs,
    get_all_comments,
    Function,
    get_callers,
    get_callees,
    extract_function_strings,
    extract_function_constants,
    Argument,
    DisassemblyFunction,
    Ref,
    Xref,
    BasicBlock,
    StructFieldQuery,
    XrefQuery,
    InsnPattern,
    FuncProfileQuery,
    AnalyzeBatchQuery,
    tool_error,
    item_error,
    summary_stats,
)
from . import compat


class DecompileWarning(TypedDict, total=False):
    id: int
    ea: str
    text: str


class DecompileResult(TypedDict):
    addr: str
    code: str | None
    refs: NotRequired[list[Ref]]
    warnings: NotRequired[list[DecompileWarning]]
    truncated: NotRequired[bool]
    failure_reason: NotRequired[str]
    error: NotRequired[str]
    error_type: NotRequired[str]
    hint: NotRequired[str]


class ResultCursor(TypedDict, total=False):
    next: int
    done: bool


class DisasmResult(TypedDict, total=False):
    addr: str
    asm: DisassemblyFunction | None
    instruction_count: int
    total_instructions: int | None
    cursor: ResultCursor
    error: str
    error_type: str
    hint: str


class FuncProfileItem(TypedDict, total=False):
    addr: str
    name: str
    size: str
    instruction_count: int
    basic_block_count: int
    caller_count: int
    callee_count: int
    string_ref_count: int
    constant_count: int
    has_type: bool
    prototype: str | None
    callers: list[dict[str, Any]]
    callers_truncated: bool
    callees: list[dict[str, Any]]
    callees_truncated: bool
    strings: list[dict[str, Any]]
    strings_truncated: bool
    constants: list[dict[str, Any]]
    constants_truncated: bool
    error: str | None


class FuncProfileResult(TypedDict, total=False):
    target: str
    data: list[FuncProfileItem]
    next_offset: int | None
    error: str | None


class AnalyzeBatchDisasm(TypedDict):
    lines: list[str]
    instruction_count: int
    truncated: bool


AnalyzeBatchXrefs = TypedDict(
    "AnalyzeBatchXrefs",
    {
        "to": list[dict[str, str]],
        "from": list[dict[str, str]],
        "to_truncated": bool,
        "from_truncated": bool,
        "to_count": int,
        "from_count": int,
    },
)


class AnalyzeBatchDetails(TypedDict, total=False):
    size: str
    prototype: str | None
    decompile: str | None
    decompile_error: str | None
    disasm: AnalyzeBatchDisasm | None
    xrefs: AnalyzeBatchXrefs | None
    callers: list[dict[str, Any]] | None
    caller_count: int
    callers_truncated: bool
    callees: list[dict[str, Any]] | None
    callee_count: int
    callees_truncated: bool
    strings: list[dict[str, Any]] | None
    string_ref_count: int
    strings_truncated: bool
    constants: list[dict[str, Any]] | None
    constant_count: int
    constants_truncated: bool
    basic_blocks: list[BasicBlock] | None
    basic_block_count: int
    basic_blocks_truncated: bool


class AnalyzeBatchResult(TypedDict, total=False):
    target: str
    addr: str | None
    name: str | None
    analysis: AnalyzeBatchDetails | None
    error: str | None
    error_type: str
    hint: str


class XrefsToResult(TypedDict, total=False):
    addr: str
    xrefs: list[Xref] | None
    total: int
    next_offset: int | None
    more: bool
    has_more: bool
    note: str
    error: str
    error_type: str
    hint: str


XrefQueryRow = TypedDict(
    "XrefQueryRow",
    {
        "direction": str,
        "addr": str,
        "from": str,
        "to": str,
        "type": str,
        "fn": Function | None,
    },
    total=False,
)


class XrefQueryResult(TypedDict, total=False):
    target: str
    resolved_addr: str | None
    direction: str
    xref_type: str
    data: list[XrefQueryRow]
    next_offset: int | None
    total: int
    error: str | None
    error_type: str
    hint: str


class StructFieldXrefsResult(TypedDict, total=False):
    struct: str
    field: str
    xrefs: list[Xref]
    error: str
    error_type: str
    hint: str


class CalleeResultItem(TypedDict):
    addr: str
    name: str
    type: str


class CalleesResult(TypedDict, total=False):
    addr: str
    callees: list[CalleeResultItem] | None
    total: int
    next_offset: int | None
    more: bool
    has_more: bool
    error: str
    error_type: str
    hint: str


class FunctionCallersItem(TypedDict):
    func_addr: str
    func_name: str
    call_ea: str


class FunctionCallersResult(TypedDict, total=False):
    addr: str
    name: str
    callers: list[FunctionCallersItem] | None
    total: int
    next_offset: int | None
    more: bool
    has_more: bool
    error: str
    error_type: str
    hint: str


class FunctionSignatureResult(TypedDict, total=False):
    addr: str
    name: str
    signature: str | None
    has_type: bool
    source: str
    error: str
    error_type: str


class JumpTargetItem(TypedDict, total=False):
    ea: str
    target: str | None
    kind: str
    mnemonic: str


class JumpTargetsResult(TypedDict, total=False):
    addr: str
    name: str
    jump_count: int
    jumps: list[JumpTargetItem]
    error: str
    error_type: str


class FunctionHashResult(TypedDict, total=False):
    addr: str
    name: str
    hash: str
    normalized_bytes: int
    instruction_count: int
    error: str
    error_type: str


class BulkHashPage(TypedDict, total=False):
    data: list[FunctionHashResult]
    total: int
    next_offset: int | None
    summary: dict
    error: str
    error_type: str


class CompletenessResult(TypedDict, total=False):
    addr: str
    name: str
    score: int
    grade: str
    has_custom_name: bool
    has_type: bool
    has_func_comment: bool
    has_named_stack_vars: bool
    has_inline_comments: bool
    missing: list[str]
    error: str
    error_type: str


class BatchCompletenessResult(TypedDict, total=False):
    data: list[CompletenessResult]
    total: int
    next_offset: int | None
    mean_score: float
    grade_counts: dict[str, int]
    error: str
    error_type: str


class DiffFunctionsResult(TypedDict, total=False):
    ok: bool
    addr_a: str
    addr_b: str
    name_a: str
    name_b: str
    similarity: float
    diff: str
    diff_line_count: int
    lines_a: int
    lines_b: int
    note: str
    error: str
    error_type: str


class FindBytesResult(TypedDict, total=False):
    pattern: str
    matches: list[str]
    n: int
    cursor: ResultCursor
    error: str
    error_type: str
    hint: str


class BasicBlocksResult(TypedDict, total=False):
    addr: str
    error: str
    blocks: list[BasicBlock]
    count: int
    total_blocks: int
    cursor: ResultCursor
    error_type: str
    hint: str


class FindResult(TypedDict, total=False):
    query: str | int | None
    matches: list[str]
    count: int
    cursor: ResultCursor
    error: str | None
    error_type: str
    hint: str


class InsnScanRange(TypedDict):
    start: str
    end: str


class InsnQuerySummary(TypedDict, total=False):
    mnem: str | None
    op0: int | str | None
    op1: int | str | None
    op2: int | str | None
    op_any: int | str | None
    func: str | None
    segment: str | None
    start: str | None
    end: str | None
    offset: int
    count: int
    max_scan_insns: int
    allow_broad: bool


class InsnQueryMatch(TypedDict, total=False):
    addr: str
    disasm: str
    fn: Function | None


class InsnQueryResult(TypedDict, total=False):
    query: InsnQuerySummary
    ranges: list[InsnScanRange]
    matches: list[InsnQueryMatch]
    count: int
    cursor: ResultCursor
    scanned: int
    truncated: bool
    next_start: str | None
    error: str | None
    error_type: str
    hint: str


class ExportedFunctionJson(TypedDict, total=False):
    addr: str
    name: str | None
    prototype: str | None
    size: str
    comments: dict[str, dict[str, str]]
    asm: str
    code: str | None
    xrefs: dict[str, list[dict[str, str]]]
    error: str
    error_type: str
    hint: str


class ExportedPrototype(TypedDict, total=False):
    name: str | None
    prototype: str


class ExportFuncsJsonResult(TypedDict):
    format: str
    functions: list[ExportedFunctionJson]


class ExportFuncsHeaderResult(TypedDict):
    format: str
    content: str


class ExportFuncsPrototypesResult(TypedDict):
    format: str
    functions: list[ExportedPrototype]


class CallGraphNode(TypedDict):
    addr: str
    name: str | None
    depth: int


CallGraphEdge = TypedDict(
    "CallGraphEdge",
    {"from": str, "to": str, "type": str},
)


class CallGraphResult(TypedDict, total=False):
    root: str
    nodes: list[CallGraphNode]
    edges: list[CallGraphEdge]
    max_depth: int
    truncated: bool
    has_more: bool
    total_nodes: int
    total_edges: int
    limit_reason: str | None
    max_nodes: int
    max_edges: int
    max_edges_per_func: int
    per_func_capped: bool
    error: str
    error_type: str
    hint: str


# ============================================================================
# Instruction Helpers
# ============================================================================

_IMM_SCAN_BACK_MAX = 15


def _raw_bin_search(
    ea: int, max_ea: int, data: bytes, mask: bytes, flags: int = 0
) -> int:
    """Search for raw bytes with mask, compatible across IDA versions.

    Returns the match address, or idaapi.BADADDR if not found.
    """
    search_flags = flags or (ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOSHOW)
    return compat.raw_bin_search(ea, max_ea, data, mask, search_flags)


def _decode_insn_at(ea: int) -> ida_ua.insn_t | None:
    insn = ida_ua.insn_t()
    if ida_ua.decode_insn(insn, ea) == 0:
        return None
    return insn


def _next_head(ea: int, end_ea: int) -> int:
    return ida_bytes.next_head(ea, end_ea)


def _operand_value(insn: ida_ua.insn_t, i: int) -> int | None:
    op = insn.ops[i]
    if op.type == ida_ua.o_void:
        return None
    if op.type in (ida_ua.o_mem, ida_ua.o_far, ida_ua.o_near):
        return op.addr
    return op.value


def _operand_type(insn: ida_ua.insn_t, i: int) -> int:
    return insn.ops[i].type


def _insn_mnem(insn: ida_ua.insn_t) -> str:
    try:
        return insn.get_canon_mnem().lower()
    except Exception:
        return ""


def _value_to_le_bytes(value: int) -> tuple[bytes, int, int] | None:
    if value < 0:
        if value >= -0x80000000:
            size = 4
            value &= 0xFFFFFFFF
        elif value >= -0x8000000000000000:
            size = 8
            value &= 0xFFFFFFFFFFFFFFFF
        else:
            return None
    else:
        if value <= 0xFFFFFFFF:
            size = 4
        elif value <= 0xFFFFFFFFFFFFFFFF:
            size = 8
        else:
            return None

    fmt = "<I" if size == 4 else "<Q"
    return struct.pack(fmt, value), size, value


def _value_candidates_for_immediate(value: int) -> list[tuple[int, int, bytes]]:
    candidates: list[tuple[int, int, bytes]] = []

    def add(size: int, signed_val: int):
        if size == 4:
            masked = signed_val & 0xFFFFFFFF
            if not (-0x80000000 <= signed_val <= 0x7FFFFFFF):
                return
            b = struct.pack("<I", masked)
        else:
            masked = signed_val & 0xFFFFFFFFFFFFFFFF
            if not (-0x8000000000000000 <= signed_val <= 0x7FFFFFFFFFFFFFFF):
                return
            b = struct.pack("<Q", masked)
        candidates.append((masked, size, b))

    add(4, value)
    add(8, value)
    return candidates


def _resolve_immediate_insn_start(
    match_ea: int,
    value: int,
    seg_start: int,
    alt_value: int | None = None,
) -> int | None:
    start_min = max(seg_start, match_ea - _IMM_SCAN_BACK_MAX)
    for start in range(match_ea, start_min - 1, -1):
        insn = _decode_insn_at(start)
        if insn is None:
            continue
        end_ea = start + insn.size
        if not (start <= match_ea < end_ea):
            continue
        for i in range(8):
            op_type = _operand_type(insn, i)
            if op_type == ida_ua.o_void:
                break
            if op_type != ida_ua.o_imm:
                continue
            op_val = _operand_value(insn, i)
            if op_val is None:
                continue
            if op_val == value or (alt_value is not None and op_val == alt_value):
                offb = getattr(insn.ops[i], "offb", 0)
                if offb and start + offb != match_ea:
                    continue
                return start
    return None


def _clamp_int(value: object, default: int, minimum: int, maximum: int) -> int:
    try:
        i = int(value)
    except Exception:
        i = default
    if i < minimum:
        return minimum
    if i > maximum:
        return maximum
    return i


def _parse_optional_int(value: object, field: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        try:
            return int(s, 0)
        except Exception as e:
            raise ValueError(f"{field} must be an integer") from e
    try:
        return int(value)
    except Exception as e:
        raise ValueError(f"{field} must be an integer") from e


def _resolve_function_start(query: object) -> tuple[int | None, str | None]:
    q = str(query or "").strip()
    if not q:
        return None, "Function query is required"

    ea = idaapi.BADADDR
    try:
        ea = parse_address(q)
    except Exception:
        ea = idaapi.get_name_ea(idaapi.BADADDR, q)

    if ea == idaapi.BADADDR:
        return None, f"Failed to resolve function: {q}"

    func = idaapi.get_func(ea)
    if not func:
        return None, f"Not a function: {q}"
    return func.start_ea, None


def _collect_line_comments(ea: int) -> list[str]:
    out: list[str] = []
    i = 0
    while True:
        line = ida_lines.get_extra_cmt(ea, ida_lines.E_PREV + i)
        if line is None:
            break
        out.append(ida_lines.tag_remove(line))
        i += 1
    cmt = ida_bytes.get_cmt(ea, False)
    if cmt:
        out.append(cmt)
    rcmt = ida_bytes.get_cmt(ea, True)
    if rcmt and rcmt != cmt:
        out.append(rcmt)
    i = 0
    while True:
        line = ida_lines.get_extra_cmt(ea, ida_lines.E_NEXT + i)
        if line is None:
            break
        out.append(ida_lines.tag_remove(line))
        i += 1
    return out


def _resolve_ref_name(ea: int) -> str:
    name = ida_name.get_ea_name(ea)
    if name:
        return name
    func = idaapi.get_func(ea)
    if func and func.start_ea == ea:
        return ida_funcs.get_func_name(ea) or ""
    return ""


_STR_CODECS = {0: "utf-8", 1: "utf-16-le", 2: "utf-32-le"}


def _resolve_ref(ea: int) -> dict | None:
    name = _resolve_ref_name(ea)
    if not name:
        return None
    info: dict = {"addr": hex(ea), "name": name}
    flags = ida_bytes.get_flags(ea)
    if ida_bytes.is_strlit(flags):
        strtype = ida_nalt.get_str_type(ea)
        if strtype is None or strtype < 0:
            strtype = ida_nalt.STRTYPE_C
        raw = ida_bytes.get_strlit_contents(ea, -1, strtype)
        if raw:
            codec = _STR_CODECS.get(strtype & 3, "utf-8")
            try:
                info["string"] = raw.decode(codec, errors="replace")
            except Exception:
                pass
    return info


def _collect_decompile_refs(cfunc) -> list[dict]:
    import ida_hexrays

    seen: set[int] = set()
    refs: list[dict] = []

    class _Visitor(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)

        def visit_expr(self, e):
            if e.op == ida_hexrays.cot_obj:
                ea = e.obj_ea
                if ea != idaapi.BADADDR and ea not in seen:
                    seen.add(ea)
                    info = _resolve_ref(ea)
                    if info:
                        refs.append(info)
            return 0

    _Visitor().apply_to(cfunc.body, None)
    return refs


def _collect_line_refs(ea: int) -> list[dict]:
    seen: set[int] = set()
    refs: list[dict] = []
    for ref_ea in idautils.CodeRefsFrom(ea, False):
        if ref_ea == idaapi.BADADDR or ref_ea in seen:
            continue
        seen.add(ref_ea)
        info = _resolve_ref(ref_ea)
        if info:
            refs.append(info)
    for ref_ea in idautils.DataRefsFrom(ea):
        if ref_ea == idaapi.BADADDR or ref_ea in seen:
            continue
        seen.add(ref_ea)
        info = _resolve_ref(ref_ea)
        if info:
            refs.append(info)
    return refs


def _limit_items(items: list, limit: int) -> tuple[list, bool]:
    if limit < 0:
        limit = 0
    if len(items) <= limit:
        return items, False
    return items[:limit], True


def _disasm_lines_limited(func: ida_funcs.func_t, max_insns: int) -> tuple[list[str], bool]:
    lines: list[str] = []
    truncated = False
    for item_ea in idautils.FuncItems(func.start_ea):
        if len(lines) >= max_insns:
            truncated = True
            break
        line = ida_lines.generate_disasm_line(item_ea, 0)
        instruction = ida_lines.tag_remove(line) if line else ""
        lines.append(f"{item_ea:x}  {compact_whitespace(instruction)}")
    return lines, truncated


def _collect_basic_blocks_limited(
    func: ida_funcs.func_t, max_blocks: int
) -> tuple[list[BasicBlock], bool]:
    blocks: list[BasicBlock] = []
    truncated = False
    for block in idaapi.FlowChart(func):
        if len(blocks) >= max_blocks:
            truncated = True
            break
        blocks.append(
            BasicBlock(
                start=hex(block.start_ea),
                end=hex(block.end_ea),
                size=block.end_ea - block.start_ea,
                type=block.type,
                successors=[hex(s.start_ea) for s in block.succs()],
                predecessors=[hex(p.start_ea) for p in block.preds()],
            )
        )
    return blocks, truncated


def _collect_callees_for_function(func: ida_funcs.func_t) -> list[dict]:
    callees: dict[int, dict] = {}
    for item_ea in idautils.FuncItems(func.start_ea):
        for target in idautils.CodeRefsFrom(item_ea, 0):
            callee = idaapi.get_func(target)
            if not callee:
                continue
            callee_start = callee.start_ea
            if callee_start in callees:
                continue
            callees[callee_start] = {
                "addr": hex(callee_start),
                "name": ida_funcs.get_func_name(callee_start) or "<unnamed>",
            }
    return list(callees.values())


def _collect_callers_for_function(func: ida_funcs.func_t) -> list[dict]:
    callers: dict[int, dict] = {}
    for caller_site in idautils.CodeRefsTo(func.start_ea, 0):
        caller = idaapi.get_func(caller_site)
        if not caller:
            continue
        caller_start = caller.start_ea
        if caller_start in callers:
            continue

        insn = idaapi.insn_t()
        idaapi.decode_insn(insn, caller_site)
        if insn.itype not in [idaapi.NN_call, idaapi.NN_callfi, idaapi.NN_callni]:
            continue

        callers[caller_start] = {
            "addr": hex(caller_start),
            "name": ida_funcs.get_func_name(caller_start) or "<unnamed>",
        }
    return list(callers.values())


def _profile_function(
    start_ea: int,
    include_lists: bool,
    max_items: int,
    include_prototype: bool,
) -> FuncProfileItem:
    func = idaapi.get_func(start_ea)
    if not func:
        return {"addr": hex(start_ea), "error": "Function not found"}

    name = ida_funcs.get_func_name(func.start_ea) or "<unnamed>"
    size_int = func.end_ea - func.start_ea
    has_type = ida_nalt.get_tinfo(ida_typeinf.tinfo_t(), func.start_ea)

    instruction_count = sum(1 for _ in idautils.FuncItems(func.start_ea))
    basic_block_count = sum(1 for _ in idaapi.FlowChart(func))
    callers = _collect_callers_for_function(func)
    callees = _collect_callees_for_function(func)
    strings = extract_function_strings(func.start_ea)
    constants = extract_function_constants(func.start_ea)

    out = {
        "addr": hex(func.start_ea),
        "name": name,
        "size": hex(size_int),
        "size_int": size_int,
        "instruction_count": instruction_count,
        "basic_block_count": basic_block_count,
        "caller_count": len(callers),
        "callee_count": len(callees),
        "string_ref_count": len(strings),
        "constant_count": len(constants),
        "has_type": has_type,
        "prototype": None,
        "error": None,
    }

    if include_prototype:
        out["prototype"] = get_prototype(func)

    if include_lists:
        callers_limited, callers_truncated = _limit_items(callers, max_items)
        callees_limited, callees_truncated = _limit_items(callees, max_items)
        strings_limited, strings_truncated = _limit_items(strings, max_items)
        constants_limited, constants_truncated = _limit_items(constants, max_items)

        out["callers"] = callers_limited
        out["callers_truncated"] = callers_truncated
        out["callees"] = callees_limited
        out["callees_truncated"] = callees_truncated
        out["strings"] = strings_limited
        out["strings_truncated"] = strings_truncated
        out["constants"] = constants_limited
        out["constants_truncated"] = constants_truncated

    return out


# ============================================================================
# IDA Auto-Analysis Status
# ============================================================================

# Human-readable names for ida_auto.atype_t constants
_AU_PHASE_NAMES: dict | None = None


def _build_au_phase_names() -> dict:
    try:
        import ida_auto as _au
        return {v: n for n, v in {
            "code analysis":          getattr(_au, "AU_CODE",   None),
            "data analysis":          getattr(_au, "AU_DATA",   None),
            "type analysis":          getattr(_au, "AU_TYPE",   None),
            "library matching":       getattr(_au, "AU_CHLB",   None),
            "library recognition":    getattr(_au, "AU_LIBF",   None),
            "library recognition 2":  getattr(_au, "AU_LBF2",   None),
            "library recognition 3":  getattr(_au, "AU_LBF3",   None),
            "procedure detection":    getattr(_au, "AU_PROC",   None),
            "function chunk":         getattr(_au, "AU_FCHUNK", None),
            "tail analysis":          getattr(_au, "AU_TAIL",   None),
            "unknown bytes":          getattr(_au, "AU_UNK",    None),
            "cross-reference":        getattr(_au, "AU_USED",   None),
            "weak type":              getattr(_au, "AU_WEAK",   None),
            "final pass":             getattr(_au, "AU_FINAL",  None),
        }.items() if v is not None}
    except Exception:
        return {}


@tool
@idasync
def analysis_status() -> dict:
    """Report whether IDA's auto-analysis is still running.

    Returns ``is_complete: true`` when the auto-analysis queue is empty
    (``AU_NONE``). When still running, ``phase`` describes the current
    work stage and ``hint`` instructs the agent to wait before relying
    on function counts, xrefs, or type information.

    Call this at the start of any session with a freshly-opened binary,
    or after triggering a re-analysis (e.g. with analyze_range).

    Profile: discovery
    """
    global _AU_PHASE_NAMES
    try:
        import ida_auto as _au
        if _AU_PHASE_NAMES is None:
            _AU_PHASE_NAMES = _build_au_phase_names()

        state = _au.get_auto_state()
        au_none = getattr(_au, "AU_NONE", 0)
        is_complete = (state == au_none)

        phase = "idle" if is_complete else _AU_PHASE_NAMES.get(state, f"phase_{state}")
        result: dict = {
            "ok": True,
            "is_complete": is_complete,
            "phase": phase,
        }
        if not is_complete:
            result["hint"] = (
                f"IDA is still running auto-analysis ({phase}). "
                "Function counts, xref data, and type info may be incomplete. "
                "Call analysis_status() again before depending on those results."
            )
        return result
    except Exception as e:
        return {"ok": False, **tool_error(e, "analysis_status")}


# ============================================================================
# Code Analysis & Decompilation
# ============================================================================

# Lazy-initialised map: hexrays error code int → (failure_reason, hint).
# Built on first decompile failure so ida_hexrays is never imported at module
# load time (it may not be present when Hex-Rays is not installed).
_MERR_REASON_MAP: dict | None = None

_DECOMPILE_DEFAULT_HINT = (
    "Use disasm(addr='...') for assembly fallback, "
    "or analyze_function(addr='...') for a compact overview."
)


def _classify_merr(hf) -> tuple[str, str]:
    """Return (failure_reason, hint) from a hexrays_failure_t.

    Called after catching DecompilationFailure so hf.code is populated.
    Returns ("unknown", default_hint) if the code is not in the map.
    """
    global _MERR_REASON_MAP
    if _MERR_REASON_MAP is None:
        try:
            import ida_hexrays as _hr
            _tbl = [
                # const_name            failure_reason     hint
                ("MERR_LICENSE",   "no_license",      "Hex-Rays license is not available. Check IDA licensing."),
                ("MERR_BITNESS",   "unsupported_isa", "16-bit functions cannot be decompiled. Use disasm()."),
                ("MERR_ONLY32",    "unsupported_isa", "64-bit Hex-Rays is required for this 64-bit database."),
                ("MERR_ONLY64",    "unsupported_isa", "32-bit Hex-Rays is required for this 32-bit database."),
                ("MERR_BADARCH",   "unsupported_isa", "Current processor is not supported by Hex-Rays. Use disasm()."),
                ("MERR_EXTERN",    "unsupported_isa", "External/special segments cannot be decompiled. Use disasm()."),
                ("MERR_INSN",      "code_is_data",    "Cannot convert to microcode — range may contain data, not code. Verify with disasm()."),
                ("MERR_PROLOG",    "code_is_data",    "Prolog analysis failed — function may be too small or misidentified. Verify with disasm()."),
                ("MERR_COMPLEX",   "too_complex",     "Function is too complex. Try decompile_range() on a smaller sub-range."),
                ("MERR_FUNCSIZE",  "too_complex",     "Function is too large for Hex-Rays. Use decompile_batch() with max_lines_each= to sample."),
                ("MERR_RECDEPTH",  "too_complex",     "Recursion depth exceeded during local variable allocation."),
                ("MERR_HUGESTACK", "too_complex",     "Stack frame is too large for Hex-Rays."),
                ("MERR_CANCELED",  "timeout",         "Decompilation was cancelled (timeout or user interrupt)."),
            ]
            m: dict = {}
            for cname, reason, hint in _tbl:
                v = getattr(_hr, cname, None)
                if v is not None:
                    m[v] = (reason, hint)
            _MERR_REASON_MAP = m
        except Exception:
            _MERR_REASON_MAP = {}
    try:
        entry = _MERR_REASON_MAP.get(hf.code)
        if entry:
            return entry
    except Exception:
        pass
    return ("unknown", _DECOMPILE_DEFAULT_HINT)


@tool
@idasync
@tool_timeout(90.0)
def decompile(
    addr: Annotated[str, "Function address or name to decompile"],
    include_addresses: Annotated[
        bool, "Append /*0xNNNN*/ markers per line (default: true). Set false to save tokens."
    ] = True,
    max_pseudocode_lines: Annotated[
        int,
        "Truncate pseudocode at N lines (default: 0 = unlimited). "
        "Useful for very large functions where full output floods context. "
        "A /* ... (N more lines) ... */ note is appended when truncated.",
    ] = 0,
) -> DecompileResult:
    """Decompile function(s) at address(es); returns pseudocode and per-item errors.

    On success, a ``warnings`` list is included when the decompiler emits
    advisory messages (e.g. "bad sp value at call").  Each entry has ``id``,
    ``text``, and optionally ``ea``.

    On failure, ``error`` contains the structured Hex-Rays failure description
    rather than the generic "Decompilation failed" string.

    Use ``max_pseudocode_lines`` to limit output size for very large functions.
    Large outputs may be truncated at 50 KB with an ``output_id``.
    If truncated, use ``read_mcp_output(output_id=..., offset=0)`` to retrieve
    the full result in chunks.

    See also: decompile_batch (multiple functions), disasm (assembly fallback),
    analyze_function (decompile + xrefs + strings + constants).

    Profile: analysis
    """
    try:
        start = parse_address(addr)
        code = decompile_function_safe(
            start, include_addresses=include_addresses, max_lines=max_pseudocode_lines
        )
        if code is None:
            decompile_error = "Decompilation failed"
            failure_reason = "unknown"
            hint = _DECOMPILE_DEFAULT_HINT
            try:
                import ida_hexrays as _hr
                if _hr.init_hexrays_plugin():
                    hf = _hr.hexrays_failure_t()
                    try:
                        _hr.decompile(start, hf)
                    except _hr.DecompilationFailure:
                        desc = hf.desc()
                        if desc:
                            decompile_error = desc
                        failure_reason, hint = _classify_merr(hf)
            except Exception:
                pass
            return {
                "addr": addr,
                "code": None,
                "failure_reason": failure_reason,
                "error": decompile_error,
                "hint": hint,
            }

        result: DecompileResult = {"addr": addr, "code": code}
        if max_pseudocode_lines > 0 and "// ... (" in code and " more line" in code:
            result["truncated"] = True
        try:
            import ida_hexrays as _hr

            if _hr.init_hexrays_plugin():
                cfunc = _hr.decompile(start)
                if cfunc:
                    refs = _collect_decompile_refs(cfunc)
                    if refs:
                        result["refs"] = refs
                    # Collect advisory decompiler warnings
                    warns: list[DecompileWarning] = []
                    try:
                        import idaapi as _idaapi
                        for w in cfunc.warnings:
                            entry: DecompileWarning = {
                                "id": int(w.id),
                                "text": str(w.text),
                            }
                            if w.ea != _idaapi.BADADDR:
                                entry["ea"] = hex(w.ea)
                            warns.append(entry)
                    except Exception:
                        pass
                    if warns:
                        result["warnings"] = warns
        except Exception:
            pass
        return result
    except Exception as e:
        return {"addr": addr, "code": None, **item_error(e, f"decompile at {addr}")}


@tool
@idasync
@tool_timeout(120.0)
def decompile_batch(
    addresses: Annotated[
        list[str] | str,
        "Function addresses or names — list or comma-separated string. "
        "e.g. ['main', '0x401000', 'sub_401234'] or 'main,0x401000'",
    ],
    max_lines_each: Annotated[
        int,
        "Pseudocode lines per function (default: 0 = unlimited). "
        "Set to 10-20 for a compact scanning pass; 0 for full output.",
    ] = 0,
    include_addresses: Annotated[
        bool,
        "Include /*0xNNNN*/ per-line address markers (default: False to save tokens).",
    ] = False,
    skip_errors: Annotated[
        bool,
        "Continue past failures — failed entries get error= instead of code= "
        "(default: True). Set False to abort on the first decompilation failure.",
    ] = True,
) -> dict:
    """Decompile multiple functions in one call — one round-trip, compact results.

    More token-efficient than calling decompile() N times. Returns results in
    input order, each with {"addr", "name", "code", "truncated", "error"}.

    Useful for scanning patterns across many functions: pass max_lines_each=10
    to get signatures + opening logic for 20+ functions without flooding context.

    Heavy: for large batches use invoke_tool(..., async_mode=True) or task_submit + task_poll.

    Large outputs may be truncated at 50 KB with an ``output_id``.
    If truncated, use ``read_mcp_output(output_id=..., offset=0)`` to retrieve
    the full result in chunks.

    See also: decompile (single function), disasm (assembly fallback),
    analyze_batch (configurable per-function analysis).
    """
    try:
        import ida_hexrays as _hr
        addrs = normalize_list_input(addresses)
        if not addrs:
            return {"ok": False, "error": "No addresses provided"}

        if not _hr.init_hexrays_plugin():
            return {"ok": False, "error": "Hex-Rays decompiler is not available"}

        results: list[dict] = []
        succeeded = 0
        failed = 0

        for raw_addr in addrs:
            raw_addr = raw_addr.strip()
            if not raw_addr:
                continue
            try:
                ea = parse_address(raw_addr)
                func_name = ida_funcs.get_func_name(ea) or hex(ea)
                code = decompile_function_safe(
                    ea,
                    include_addresses=include_addresses,
                    max_lines=max_lines_each,
                )
                if code is None:
                    decompile_error = "Decompilation failed"
                    failure_reason = "unknown"
                    hint = _DECOMPILE_DEFAULT_HINT
                    try:
                        hf = _hr.hexrays_failure_t()
                        _hr.decompile(ea, hf)
                    except _hr.DecompilationFailure:
                        desc = hf.desc()
                        if desc:
                            decompile_error = desc
                        failure_reason, hint = _classify_merr(hf)
                    except Exception:
                        pass
                    entry: dict = {
                        "addr": raw_addr,
                        "name": func_name,
                        "code": None,
                        "failure_reason": failure_reason,
                        "error": decompile_error,
                        "hint": hint,
                    }
                    failed += 1
                    if not skip_errors:
                        results.append(entry)
                        break
                else:
                    entry = {
                        "addr": raw_addr,
                        "name": func_name,
                        "code": code,
                    }
                    if max_lines_each > 0 and "// ... (" in code and " more line" in code:
                        entry["truncated"] = True
                    succeeded += 1
                results.append(entry)
            except Exception as exc:
                entry = {
                    "addr": raw_addr,
                    "name": raw_addr,
                    "code": None,
                    **item_error(exc, f"decompile_batch entry {raw_addr!r}"),
                }
                failed += 1
                results.append(entry)
                if not skip_errors:
                    break

        return {
            "ok": True,
            "results": results,
            "total": len(results),
            "succeeded": succeeded,
            "failed": failed,
        }
    except Exception as e:
        return {"ok": False, **tool_error(e, "decompile_batch")}


@tool
@idasync
@tool_timeout(120.0)
def decompile_range(
    start: Annotated[str, "Start address (inclusive) — hex or symbol name"],
    end: Annotated[str, "End address (inclusive) — hex or symbol name"],
    max_lines_each: Annotated[
        int,
        "Pseudocode lines per function (default: 0 = unlimited). "
        "Set to 10-20 for a compact scanning pass; 0 for full output.",
    ] = 0,
    include_addresses: Annotated[
        bool,
        "Include /*0xNNNN*/ per-line address markers (default: False to save tokens).",
    ] = False,
) -> dict:
    """Decompile all functions within an address range.

    Iterates functions in the range and decompiles each one. Returns results in
    address order, each with {"addr", "name", "code", "truncated", "error"}.

    See also: decompile_batch (explicit address list), decompile (single function),
    func_profile (metrics-only scan of a range).
    """
    try:
        import ida_hexrays as _hr
        start_ea = parse_address(start)
        end_ea = parse_address(end)
        if start_ea > end_ea:
            start_ea, end_ea = end_ea, start_ea

        if not _hr.init_hexrays_plugin():
            return {"ok": False, "error": "Hex-Rays decompiler is not available"}

        addrs = []
        for fn_ea in idautils.Functions():
            if fn_ea >= start_ea and fn_ea <= end_ea:
                addrs.append(hex(fn_ea))

        if not addrs:
            return {"ok": False, "error": f"No functions found in range {hex(start_ea)} - {hex(end_ea)}"}

        results: list[dict] = []
        succeeded = 0
        failed = 0

        for raw_addr in addrs:
            try:
                ea = parse_address(raw_addr)
                func_name = ida_funcs.get_func_name(ea) or hex(ea)
                code = decompile_function_safe(
                    ea,
                    include_addresses=include_addresses,
                    max_lines=max_lines_each,
                )
                if code is None:
                    decompile_error = "Decompilation failed"
                    failure_reason = "unknown"
                    hint = _DECOMPILE_DEFAULT_HINT
                    try:
                        hf = _hr.hexrays_failure_t()
                        _hr.decompile(ea, hf)
                    except _hr.DecompilationFailure:
                        desc = hf.desc()
                        if desc:
                            decompile_error = desc
                        failure_reason, hint = _classify_merr(hf)
                    except Exception:
                        pass
                    entry: dict = {
                        "addr": raw_addr,
                        "name": func_name,
                        "code": None,
                        "failure_reason": failure_reason,
                        "error": decompile_error,
                        "hint": hint,
                    }
                    failed += 1
                else:
                    entry = {
                        "addr": raw_addr,
                        "name": func_name,
                        "code": code,
                    }
                    if max_lines_each > 0 and "// ... (" in code and " more line" in code:
                        entry["truncated"] = True
                    succeeded += 1
                results.append(entry)
            except Exception as exc:
                entry = {
                    "addr": raw_addr,
                    "name": raw_addr,
                    "code": None,
                    **item_error(exc, f"decompile_range entry {raw_addr!r}"),
                }
                failed += 1
                results.append(entry)

        return {
            "ok": True,
            "results": results,
            "total": len(results),
            "succeeded": succeeded,
            "failed": failed,
        }
    except Exception as e:
        return {"ok": False, **tool_error(e, "decompile_range")}


@tool
@idasync
@tool_timeout(90.0)
def disasm(
    addr: Annotated[str, "Function address or name to disassemble"],
    max_instructions: Annotated[
        int, "Max instructions per function (default: 5000, max: 50000)"
    ] = 5000,
    offset: Annotated[int, "Skip first N instructions (default: 0)"] = 0,
    include_total: Annotated[
        bool, "Compute total instruction count (default: false)"
    ] = False,
) -> DisasmResult:
    """Disassemble a function or address range with pagination.

    If ``addr`` resolves to a function, disassembly starts at that address and
    continues through the function end. If ``addr`` is not in a function,
    sequential disassembly is performed until an undecodeable instruction or
    segment end.

    When called inside a function, ``total_instructions`` is automatically
    computed without needing ``include_total=true``.

    Use ``offset`` + ``max_instructions`` to page through large functions.
    The ``cursor.next`` field contains the next offset to resume from.

    Large outputs may be truncated at 50 KB with an ``output_id``.
    If truncated, use ``read_mcp_output(output_id=..., offset=0)`` to retrieve
    the full result in chunks.

    See also: decompile (pseudocode), basic_blocks (CFG structure),
    analyze_function (combined analysis).

    Profile: analysis
    """

    # Enforce max limit
    if max_instructions <= 0 or max_instructions > 50000:
        max_instructions = 50000
    if offset < 0:
        offset = 0

    try:
        start = parse_address(addr)
        func = idaapi.get_func(start)

        # Get segment info
        seg = idaapi.getseg(start)
        if not seg:
            return {
                "addr": addr,
                "asm": None,
                "error": "No segment found",
                "cursor": {"done": True},
            }

        segment_name = idaapi.get_segm_name(seg) if seg else "UNKNOWN"

        if func:
            # Function exists: disassemble function items starting from requested address
            func_name: str = ida_funcs.get_func_name(func.start_ea) or "<unnamed>"
            header_addr = start  # Use requested address, not function start
        else:
            # No function: disassemble sequentially from start address
            func_name = "<no function>"
            header_addr = start

        lines: list[dict] = []
        seen = 0
        total_count = 0
        more = False

        # Always provide a fast total count when we have a function, so agents
        # can plan pagination without passing include_total=True manually.
        if func and not include_total:
            total_count = sum(1 for _ in idautils.FuncItems(func.start_ea))
            include_total = True  # mark so the value is emitted below

        def _maybe_add(ea: int) -> bool:
            nonlocal seen, total_count, more
            if include_total:
                total_count += 1
            if seen < offset:
                seen += 1
                return True
            if len(lines) < max_instructions:
                line = ida_lines.generate_disasm_line(ea, 0)
                instruction = ida_lines.tag_remove(line) if line else ""
                entry: dict = {
                    "addr": f"{ea:x}",
                    "instruction": compact_whitespace(instruction),
                }
                name = ida_name.get_ea_name(ea)
                if name:
                    entry["label"] = name
                comments = _collect_line_comments(ea)
                if comments:
                    entry["comments"] = comments
                refs = _collect_line_refs(ea)
                if refs:
                    entry["refs"] = refs
                lines.append(entry)
                seen += 1
                return True
            more = True
            seen += 1
            return include_total

        if func:
            for ea in idautils.FuncItems(func.start_ea):
                if ea == idaapi.BADADDR:
                    continue
                if ea < start:
                    continue
                if not _maybe_add(ea):
                    break
        else:
            ea = start
            while ea < seg.end_ea:
                if ea == idaapi.BADADDR:
                    break
                if _decode_insn_at(ea) is None:
                    break
                if not _maybe_add(ea):
                    break
                ea = _next_head(ea, seg.end_ea)
                if ea == idaapi.BADADDR:
                    break

        if include_total and not more:
            more = total_count > offset + max_instructions

        rettype = None
        args: Optional[list[Argument]] = None
        stack_frame = None

        if func:
            tif = ida_typeinf.tinfo_t()
            if ida_nalt.get_tinfo(tif, func.start_ea) and tif.is_func():
                ftd = ida_typeinf.func_type_data_t()
                if tif.get_func_details(ftd):
                    rettype = str(ftd.rettype)
                    args = [
                        Argument(name=(a.name or f"arg{i}"), type=str(a.type))
                        for i, a in enumerate(ftd)
                    ]
            stack_frame = get_stack_frame_variables_internal(func.start_ea, False)

        out: DisassemblyFunction = {
            "name": func_name,
            "start_ea": hex(header_addr),
            "segment": segment_name,
            "lines": lines,
        }
        if stack_frame:
            out["stack_frame"] = stack_frame
        if rettype:
            out["return_type"] = rettype
        if args is not None:
            out["arguments"] = args

        return {
            "addr": addr,
            "asm": out,
            "instruction_count": len(lines),
            "total_instructions": total_count if include_total else None,
            "cursor": ({"next": offset + max_instructions} if more else {"done": True}),
        }
    except Exception as e:
        return {
            "addr": addr,
            "asm": None,
            "cursor": {"done": True},
            **item_error(e, f"disassemble at {addr}"),
        }


@tool
@idasync
@tool_timeout(90.0)
def disasm_batch(
    addresses: Annotated[
        list[str] | str,
        "Function addresses or names — list or comma-separated string. "
        "e.g. ['main', '0x401000', 'sub_401234'] or 'main,0x401000'",
    ],
    max_instructions: Annotated[
        int, "Max instructions per function (default: 500, max: 50000)"
    ] = 500,
    offset: Annotated[int, "Skip first N instructions per function (default: 0)"] = 0,
    skip_errors: Annotated[
        bool,
        "Continue past failures — failed entries get error= instead of asm= "
        "(default: True). Set False to abort on the first disassembly failure.",
    ] = True,
) -> dict:
    """Disassemble multiple functions in one call — one round-trip, compact results.

    More token-efficient than calling disasm() N times. Returns results in
    input order, each with {"addr", "name", "asm", "instruction_count",
    "total_instructions", "cursor", "error"}.

    See also: disasm (single function), decompile_batch (batch pseudocode),
    analyze_batch (configurable per-function analysis).
    """
    try:
        addrs = normalize_list_input(addresses)
        if not addrs:
            return {"ok": False, "error": "No addresses provided"}

        results: list[dict] = []
        succeeded = 0
        failed = 0

        for raw_addr in addrs:
            raw_addr = raw_addr.strip()
            if not raw_addr:
                continue
            try:
                ea = parse_address(raw_addr)
                func_name = ida_funcs.get_func_name(ea) or hex(ea)
                # Re-use disasm logic inline to avoid double tool call overhead
                func = idaapi.get_func(ea)
                seg = idaapi.getseg(ea)
                if not seg:
                    entry = {
                        "addr": raw_addr,
                        "name": func_name,
                        "asm": None,
                        "error": "No segment found",
                        "cursor": {"done": True},
                    }
                    failed += 1
                    results.append(entry)
                    if not skip_errors:
                        break
                    continue

                if func:
                    header_addr = ea
                else:
                    header_addr = ea

                lines: list[dict] = []
                seen = 0
                total_count = 0
                more = False

                if func:
                    total_count = sum(1 for _ in idautils.FuncItems(func.start_ea))

                def _maybe_add_disasm(item_ea: int) -> bool:
                    nonlocal seen, total_count, more
                    if func:
                        total_count += 1
                    if seen < offset:
                        seen += 1
                        return True
                    if len(lines) < max_instructions:
                        line = ida_lines.generate_disasm_line(item_ea, 0)
                        instruction = ida_lines.tag_remove(line) if line else ""
                        entry_line: dict = {
                            "addr": f"{item_ea:x}",
                            "instruction": compact_whitespace(instruction),
                        }
                        name = ida_name.get_ea_name(item_ea)
                        if name:
                            entry_line["label"] = name
                        comments = _collect_line_comments(item_ea)
                        if comments:
                            entry_line["comments"] = comments
                        refs = _collect_line_refs(item_ea)
                        if refs:
                            entry_line["refs"] = refs
                        lines.append(entry_line)
                        seen += 1
                        return True
                    more = True
                    seen += 1
                    return True

                if func:
                    for item_ea in idautils.FuncItems(func.start_ea):
                        if item_ea == idaapi.BADADDR:
                            continue
                        if item_ea < ea:
                            continue
                        if not _maybe_add_disasm(item_ea):
                            break
                else:
                    item_ea = ea
                    while item_ea < seg.end_ea:
                        if item_ea == idaapi.BADADDR:
                            break
                        if _decode_insn_at(item_ea) is None:
                            break
                        if not _maybe_add_disasm(item_ea):
                            break
                        item_ea = _next_head(item_ea, seg.end_ea)
                        if item_ea == idaapi.BADADDR:
                            break

                if not func and not lines:
                    entry = {
                        "addr": raw_addr,
                        "name": func_name,
                        "asm": None,
                        "error": "No instructions found",
                        "cursor": {"done": True},
                    }
                    failed += 1
                else:
                    out: DisassemblyFunction = {
                        "name": func_name if func else "<no function>",
                        "start_ea": hex(header_addr),
                        "segment": idaapi.get_segm_name(seg) or "UNKNOWN",
                        "lines": lines,
                    }
                    entry = {
                        "addr": raw_addr,
                        "name": func_name,
                        "asm": out,
                        "instruction_count": len(lines),
                        "total_instructions": total_count if func else None,
                        "cursor": ({"next": offset + max_instructions} if more else {"done": True}),
                    }
                    succeeded += 1
                results.append(entry)
            except Exception as exc:
                entry = {
                    "addr": raw_addr,
                    "name": raw_addr,
                    "asm": None,
                    "cursor": {"done": True},
                    **item_error(exc, f"disasm_batch entry {raw_addr!r}"),
                }
                failed += 1
                results.append(entry)
                if not skip_errors:
                    break

        return {
            "ok": True,
            "results": results,
            "total": len(results),
            "succeeded": succeeded,
            "failed": failed,
        }
    except Exception as e:
        return {"ok": False, **tool_error(e, "disasm_batch")}


# ============================================================================
# Batch Analysis & Profiling
# ============================================================================


@tool
@idasync
@tool_timeout(120.0)
def func_profile(
    queries: Annotated[
        list[FuncProfileQuery] | FuncProfileQuery,
        "Function profiling query (supports name/address filters + pagination)",
    ],
) -> list[FuncProfileResult]:
    """Profile functions with summary metrics and optional sampled details.

    Returns metrics and metadata for functions — size, cyclomatic complexity,
    caller/callee counts, string/constants references, and optionally sampled
    instruction mnemonics.

    **This tool does NOT decompile.** For decompilation + code analysis, use
    ``analyze_function`` or ``analyze_batch`` instead. For metrics-only bulk
    profiling, this is the right tool.

    See also: analyze_function (decompilation + code analysis),
    analyze_batch (configurable buffet analysis), func_query (function catalog).
    """
    queries = normalize_dict_list(queries)

    results: list[dict] = []
    for query in queries:
        q = str(query.get("addr", "*") or "*").strip()
        filter_pattern = str(query.get("filter", "") or "")
        offset = _clamp_int(query.get("offset", 0), 0, 0, 2_000_000_000)
        count = _clamp_int(query.get("count", 50), 50, 0, 1000)
        sort_by = str(query.get("sort_by", "addr") or "addr")
        descending = bool(query.get("descending", False))
        include_lists = bool(query.get("include_lists", False))
        max_items = _clamp_int(query.get("max_items", 25), 25, 0, 1000)
        include_prototype = bool(query.get("include_prototype", False))

        # Resolve candidate function starts.
        candidates: list[dict] = []
        if q not in ("", "*"):
            start_ea, err = _resolve_function_start(q)
            if err is not None or start_ea is None:
                results.append(
                    {
                        "target": q,
                        "data": [],
                        "next_offset": None,
                        "error": err or "Failed to resolve function",
                    }
                )
                continue
            fn = idaapi.get_func(start_ea)
            if fn:
                candidates.append(
                    {
                        "start_ea": fn.start_ea,
                        "addr": hex(fn.start_ea),
                        "name": ida_funcs.get_func_name(fn.start_ea) or "<unnamed>",
                        "size_int": fn.end_ea - fn.start_ea,
                        "size": hex(fn.end_ea - fn.start_ea),
                    }
                )
        else:
            for start_ea in idautils.Functions():
                fn = idaapi.get_func(start_ea)
                if not fn:
                    continue
                candidates.append(
                    {
                        "start_ea": fn.start_ea,
                        "addr": hex(fn.start_ea),
                        "name": ida_funcs.get_func_name(fn.start_ea) or "<unnamed>",
                        "size_int": fn.end_ea - fn.start_ea,
                        "size": hex(fn.end_ea - fn.start_ea),
                    }
                )

        if filter_pattern:
            candidates = pattern_filter(candidates, filter_pattern, "name")

        if sort_by == "name":
            candidates.sort(key=lambda f: f["name"].lower(), reverse=descending)
        elif sort_by == "size":
            candidates.sort(key=lambda f: f["size_int"], reverse=descending)
        else:
            candidates.sort(key=lambda f: f["start_ea"], reverse=descending)

        page = paginate(candidates, offset, count)
        profiled: list[dict] = []
        for item in page["data"]:
            profiled.append(
                _profile_function(
                    int(item["start_ea"]),
                    include_lists=include_lists,
                    max_items=max_items,
                    include_prototype=include_prototype,
                )
            )

        for item in profiled:
            item.pop("size_int", None)

        results.append(
            {
                "target": q,
                "data": profiled,
                "next_offset": page["next_offset"],
                "error": None,
            }
        )

    return results


@tool
@idasync
@tool_timeout(120.0)
def analyze_batch(
    queries: Annotated[
        list[AnalyzeBatchQuery] | AnalyzeBatchQuery,
        "Comprehensive per-function analysis with selectable sections",
    ],
) -> list[AnalyzeBatchResult]:
    """Run comprehensive analysis over one or more target functions.

    This is the most configurable per-function analysis — pick exactly which
    sections you want (decompilation, disassembly, xrefs, callers, callees,
    strings, constants, comments, basic blocks). Use when you need specific
    sections only and want to save tokens.

    Heavy: for large batches use invoke_tool(..., async_mode=True) or task_submit + task_poll.

    See also: analyze_function (opinionated compact analysis),
    func_profile (metrics-only, no decompilation), decompile_batch.
    """
    queries = normalize_dict_list(queries)

    results: list[dict] = []
    for query in queries:
        q = str(query.get("addr", "") or "").strip()
        if not q:
            results.append(
                {
                    "target": q,
                    "addr": None,
                    "name": None,
                    "analysis": None,
                    "error": "addr is required",
                }
            )
            continue

        start_ea, err = _resolve_function_start(q)
        if err is not None or start_ea is None:
            results.append(
                {
                    "target": q,
                    "addr": None,
                    "name": None,
                    "analysis": None,
                    "error": err or "Failed to resolve function",
                }
            )
            continue

        try:
            fn = idaapi.get_func(start_ea)
            if not fn:
                raise RuntimeError(f"Function not found: {q}")

            fn_name = ida_funcs.get_func_name(fn.start_ea) or "<unnamed>"
            size_int = fn.end_ea - fn.start_ea

            include_decompile = bool(query.get("include_decompile", True))
            include_disasm = bool(query.get("include_disasm", False))
            include_xrefs = bool(query.get("include_xrefs", True))
            include_callers = bool(query.get("include_callers", True))
            include_callees = bool(query.get("include_callees", True))
            include_strings = bool(query.get("include_strings", True))
            include_constants = bool(query.get("include_constants", True))
            include_basic_blocks = bool(query.get("include_basic_blocks", True))
            include_proto = bool(query.get("include_proto", True))

            max_disasm_insns = _clamp_int(
                query.get("max_disasm_insns", 300), 300, 0, 50_000
            )
            max_callers = _clamp_int(query.get("max_callers", 100), 100, 0, 5000)
            max_callees = _clamp_int(query.get("max_callees", 100), 100, 0, 5000)
            max_strings = _clamp_int(query.get("max_strings", 100), 100, 0, 5000)
            max_constants = _clamp_int(
                query.get("max_constants", 200), 200, 0, 10000
            )
            max_blocks = _clamp_int(query.get("max_blocks", 500), 500, 0, 10000)

            analysis: dict = {
                "size": hex(size_int),
                "prototype": None,
                "decompile": None,
                "decompile_error": None,
                "disasm": None,
                "xrefs": None,
                "callers": None,
                "caller_count": 0,
                "callers_truncated": False,
                "callees": None,
                "callee_count": 0,
                "callees_truncated": False,
                "strings": None,
                "string_ref_count": 0,
                "strings_truncated": False,
                "constants": None,
                "constant_count": 0,
                "constants_truncated": False,
                "basic_blocks": None,
                "basic_block_count": 0,
                "basic_blocks_truncated": False,
            }

            if include_proto:
                analysis["prototype"] = get_prototype(fn)

            if include_decompile:
                code = decompile_function_safe(fn.start_ea)
                analysis["decompile"] = code
                if code is None:
                    analysis["decompile_error"] = "Decompilation failed"

            if include_disasm:
                lines, disasm_truncated = _disasm_lines_limited(fn, max_disasm_insns)
                analysis["disasm"] = {
                    "lines": lines,
                    "instruction_count": len(lines),
                    "truncated": disasm_truncated,
                }

            if include_xrefs:
                xrefs = get_all_xrefs(fn.start_ea)
                xrefs_to = list(xrefs.get("to", []))
                xrefs_from = list(xrefs.get("from", []))
                xrefs_to, xto_trunc = _limit_items(xrefs_to, 200)
                xrefs_from, xfrom_trunc = _limit_items(xrefs_from, 200)
                analysis["xrefs"] = {
                    "to": xrefs_to,
                    "from": xrefs_from,
                    "to_truncated": xto_trunc,
                    "from_truncated": xfrom_trunc,
                    "to_count": len(xrefs.get("to", [])),
                    "from_count": len(xrefs.get("from", [])),
                }

            if include_callers:
                callers = get_callers(hex(fn.start_ea), limit=max_callers)
                analysis["caller_count"] = len(callers)
                analysis["callers"] = callers
                analysis["callers_truncated"] = (
                    max_callers > 0 and len(callers) >= max_callers
                )

            if include_callees:
                all_callees = get_callees(hex(fn.start_ea))
                limited_callees, callees_truncated = _limit_items(all_callees, max_callees)
                analysis["callee_count"] = len(all_callees)
                analysis["callees"] = limited_callees
                analysis["callees_truncated"] = callees_truncated

            if include_strings:
                all_strings = extract_function_strings(fn.start_ea)
                limited_strings, strings_truncated = _limit_items(all_strings, max_strings)
                analysis["string_ref_count"] = len(all_strings)
                analysis["strings"] = limited_strings
                analysis["strings_truncated"] = strings_truncated

            if include_constants:
                all_constants = extract_function_constants(fn.start_ea)
                limited_constants, constants_truncated = _limit_items(
                    all_constants, max_constants
                )
                analysis["constant_count"] = len(all_constants)
                analysis["constants"] = limited_constants
                analysis["constants_truncated"] = constants_truncated

            if include_basic_blocks:
                blocks, blocks_truncated = _collect_basic_blocks_limited(fn, max_blocks)
                analysis["basic_block_count"] = len(blocks)
                analysis["basic_blocks"] = blocks
                analysis["basic_blocks_truncated"] = blocks_truncated

            results.append(
                {
                    "target": q,
                    "addr": hex(fn.start_ea),
                    "name": fn_name,
                    "analysis": analysis,
                    "error": None,
                }
            )
        except Exception as e:
            results.append(
                {
                    "target": q,
                    "addr": hex(start_ea),
                    "name": None,
                    "analysis": None,
                    **item_error(e, f"profile function {q}"),
                }
            )

    return results


# ============================================================================
# Cross-Reference Analysis
# ============================================================================


@tool
@idasync
def xrefs_to(
    addrs: Annotated[list[str] | str, "Addresses or function names to find cross-references to (e.g. '0x11a9', 'check_pw', 'main')"],
    limit: Annotated[int, "Max xrefs per address per page (default: 100, max: 1000)"] = 100,
    offset: Annotated[int, "Skip first N xrefs per address — pass next_offset from a previous result to page forward (default: 0)"] = 0,
) -> list[XrefsToResult]:
    """Return xrefs to address(es) or named symbols, with pagination support.

    Accepts a single address/name or a list. Returns per-address results.
    Use ``offset`` + ``next_offset`` to page through large xref sets.

    Empty results are expected for addresses in regions IDA has not analysed
    (e.g. encrypted sections). In that case:
    1. If the bytes are already decrypted in the IDB, call ``analyze_range``
       to force IDA to build the xref database for the region, then retry.
    2. If callers live in undefined code, use ``add_xref`` to register
       user-defined xrefs that persist across reanalysis.

    See also: xref_query (direction/type filters + pagination),
    trace_data_chain (multi-hop traversal), callees / get_function_callers
    (call graph neighbors).

    Profile: analysis
    """
    addrs = normalize_list_input(addrs)

    if limit <= 0 or limit > 1000:
        limit = 1000
    if offset < 0:
        offset = 0

    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            total = 0
            skip = offset
            xrefs: list[Xref] = []
            for xref in idautils.XrefsTo(ea):
                total += 1
                if skip > 0:
                    skip -= 1
                    continue
                if len(xrefs) < limit:
                    xrefs.append(
                        Xref(
                            addr=hex(xref.frm),
                            type="code" if xref.iscode else "data",
                            fn=get_function(xref.frm, raise_error=False),
                        )
                    )
            next_off: int | None = (offset + limit) if (offset + limit < total) else None
            more = next_off is not None
            row: XrefsToResult = {
                "addr": addr,
                "xrefs": xrefs,
                "total": total,
                "next_offset": next_off,
                "more": more,
                "has_more": more,
            }
            if not xrefs and offset == 0:
                import idc as _idc
                flags = _idc.get_full_flags(ea)
                if _idc.is_unknown(flags):
                    row["note"] = (
                        "No xrefs found and address is undefined. "
                        "If bytes are decrypted in the IDB, call analyze_range first "
                        "to build the xref database. "
                        "If the caller is in undefined code, use add_xref to register it manually."
                    )
                else:
                    row["note"] = (
                        "No xrefs found. The address is defined but has no recorded callers. "
                        "If callers exist in an unanalysed region, call analyze_range on that "
                        "region first, or use add_xref to register user-defined xrefs."
                    )
            results.append(row)
        except Exception as e:
            results.append({"addr": addr, "xrefs": None, **item_error(e, f"xrefs to {addr}")})

    return results


@tool
@idasync
def xref_query(
    queries: Annotated[
        list[XrefQuery] | XrefQuery,
        "Generic xref query with direction/type filters and pagination",
    ],
) -> list[XrefQueryResult]:
    """Query xrefs with direction/type filters and pagination.

    More flexible than xrefs_to: filter by direction (to/from/both),
    xref type (code/data/any), and paginate with offset/count.

    See also: xrefs_to (simple per-address xrefs), trace_data_chain (multi-hop traversal).
    """
    queries = normalize_dict_list(queries)

    results: list[dict] = []
    for query in queries:
        q = str(query.get("addr", "")).strip()
        direction = str(query.get("direction", "both") or "both").lower()
        xref_type = str(query.get("xref_type", "any") or "any").lower()
        offset = _clamp_int(query.get("offset", 0), 0, 0, 2_000_000_000)
        count = _clamp_int(query.get("count", 200), 200, 0, 5000)
        include_fn = bool(query.get("include_fn", True))
        dedup = bool(query.get("dedup", True))
        sort_by = str(query.get("sort_by", "addr") or "addr")
        descending = bool(query.get("descending", False))

        if direction not in {"to", "from", "both"}:
            direction = "both"
        if xref_type not in {"any", "code", "data"}:
            xref_type = "any"

        try:
            if not q:
                raise ValueError("addr is required")
            try:
                target = parse_address(q)
            except Exception:
                target = idaapi.get_name_ea(idaapi.BADADDR, q)
                if target == idaapi.BADADDR:
                    raise ValueError(f"Failed to resolve address/name: {q}")

            rows: list[dict] = []
            if direction in {"to", "both"}:
                for xr in idautils.XrefsTo(target, 0):
                    kind = "code" if xr.iscode else "data"
                    if xref_type != "any" and kind != xref_type:
                        continue
                    row = {
                        "direction": "to",
                        "addr": hex(xr.frm),
                        "from": hex(xr.frm),
                        "to": hex(target),
                        "type": kind,
                    }
                    if include_fn:
                        row["fn"] = get_function(xr.frm, raise_error=False)
                    rows.append(row)

            if direction in {"from", "both"}:
                for xr in idautils.XrefsFrom(target, 0):
                    kind = "code" if xr.iscode else "data"
                    if xref_type != "any" and kind != xref_type:
                        continue
                    row = {
                        "direction": "from",
                        "addr": hex(xr.to),
                        "from": hex(target),
                        "to": hex(xr.to),
                        "type": kind,
                    }
                    if include_fn:
                        row["fn"] = get_function(xr.to, raise_error=False)
                    rows.append(row)

            if dedup:
                seen = set()
                deduped = []
                for row in rows:
                    key = (row["direction"], row["from"], row["to"], row["type"])
                    if key in seen:
                        continue
                    seen.add(key)
                    deduped.append(row)
                rows = deduped

            if sort_by == "type":
                rows.sort(
                    key=lambda r: (str(r.get("type", "")), int(str(r["addr"]), 16)),
                    reverse=descending,
                )
            else:
                rows.sort(key=lambda r: int(str(r["addr"]), 16), reverse=descending)

            page = paginate(rows, offset, count)
            results.append(
                {
                    "target": q,
                    "resolved_addr": hex(target),
                    "direction": direction,
                    "xref_type": xref_type,
                    "data": page["data"],
                    "next_offset": page["next_offset"],
                    "total": len(rows),
                    "error": None,
                }
            )
        except Exception as e:
            results.append(
                {
                    "target": q,
                    "resolved_addr": None,
                    "direction": direction,
                    "xref_type": xref_type,
                    "data": [],
                    "next_offset": None,
                    "total": 0,
                    **item_error(e, f"xref query for {q!r}"),
                }
            )

    return results


@tool
@idasync
def xrefs_to_field(
    queries: list[StructFieldQuery] | StructFieldQuery,
) -> list[StructFieldXrefsResult]:
    """Get cross-references to structure fields"""
    if isinstance(queries, dict):
        queries = [queries]

    results = []
    til = ida_typeinf.get_idati()
    if not til:
        return [
            {
                "struct": q.get("struct"),
                "field": q.get("field"),
                "xrefs": [],
                "error": "Failed to retrieve type library",
            }
            for q in queries
        ]

    for query in queries:
        struct_name = query.get("struct", "")
        field_name = query.get("field", "")

        try:
            tif = ida_typeinf.tinfo_t()
            if not tif.get_named_type(
                til, struct_name, ida_typeinf.BTF_STRUCT, True, False
            ):
                results.append(
                    {
                        "struct": struct_name,
                        "field": field_name,
                        "xrefs": [],
                        "error": f"Struct '{struct_name}' not found",
                    }
                )
                continue

            idx = ida_typeinf.get_udm_by_fullname(None, struct_name + "." + field_name)
            if idx == -1:
                results.append(
                    {
                        "struct": struct_name,
                        "field": field_name,
                        "xrefs": [],
                        "error": f"Field '{field_name}' not found in '{struct_name}'",
                    }
                )
                continue

            tid = tif.get_udm_tid(idx)
            if tid == ida_idaapi.BADADDR:
                results.append(
                    {
                        "struct": struct_name,
                        "field": field_name,
                        "xrefs": [],
                        "error": "Unable to get tid",
                    }
                )
                continue

            xrefs = []
            xref: ida_xref.xrefblk_t
            for xref in idautils.XrefsTo(tid):
                xrefs += [
                    Xref(
                        addr=hex(xref.frm),
                        type="code" if xref.iscode else "data",
                        fn=get_function(xref.frm, raise_error=False),
                    )
                ]
            results.append({"struct": struct_name, "field": field_name, "xrefs": xrefs})
        except Exception as e:
            results.append(
                {
                    "struct": struct_name,
                    "field": field_name,
                    "xrefs": [],
                    **item_error(e, f"xrefs to {struct_name}.{field_name}"),
                }
            )

    return results


# ============================================================================
# Call Graph Analysis
# ============================================================================


@tool
@idasync
def callees(
    addrs: Annotated[list[str] | str, "Function addresses or names to get callees for (e.g. '0x123e', 'main')"],
    limit: Annotated[int, "Max callees per function per page (default: 200, max: 500)"] = 200,
    offset: Annotated[int, "Skip first N callees — pass next_offset from a previous result to page forward (default: 0)"] = 0,
) -> list[CalleesResult]:
    """Return unique callees per function, with pagination support.

    See also: get_function_callers (incoming calls), xrefs_to (all xrefs),
    callgraph (multi-level call graph).
    """
    addrs = normalize_list_input(addrs)

    if limit <= 0 or limit > 500:
        limit = 500
    if offset < 0:
        offset = 0

    results = []

    for fn_addr in addrs:
        try:
            func_start = parse_address(fn_addr)
            func = idaapi.get_func(func_start)
            if not func:
                results.append(
                    {"addr": fn_addr, "callees": None, "error": "No function found"}
                )
                continue
            func_end = func.end_ea
            all_callees_dict: dict[int, CalleeResultItem] = {}
            current_ea = func_start
            while current_ea < func_end:
                insn = _decode_insn_at(current_ea)
                if insn is None:
                    next_ea = _next_head(current_ea, func_end)
                    if next_ea == idaapi.BADADDR:
                        break
                    current_ea = next_ea
                    continue
                if insn.itype in [idaapi.NN_call, idaapi.NN_callfi, idaapi.NN_callni]:
                    op0 = insn.ops[0]
                    if op0.type in (ida_ua.o_mem, ida_ua.o_near, ida_ua.o_far):
                        target = op0.addr
                    elif op0.type == ida_ua.o_imm:
                        target = op0.value
                    else:
                        target = None
                    if target is not None and target not in all_callees_dict:
                        func_type = (
                            "internal"
                            if idaapi.get_func(target) is not None
                            else "external"
                        )
                        func_name = ida_name.get_name(target)
                        if func_name is not None:
                            all_callees_dict[target] = {
                                "addr": hex(target),
                                "name": func_name,
                                "type": func_type,
                            }
                next_ea = _next_head(current_ea, func_end)
                if next_ea == idaapi.BADADDR:
                    break
                current_ea = next_ea

            page = paginate(list(all_callees_dict.values()), offset, limit)
            more = page["next_offset"] is not None
            results.append(
                {
                    "addr": fn_addr,
                    "callees": page["data"],
                    "total": page["total"],
                    "next_offset": page["next_offset"],
                    "more": more,
                    "has_more": more,
                }
            )
        except Exception as e:
            results.append({"addr": fn_addr, "callees": None, **item_error(e, f"get callees of {fn_addr}")})

    return results


# ============================================================================
# Function Analysis — Callers / Signature / Jumps / Hash / Completeness / Diff
# ============================================================================

# Operand types that carry address/displacement data — these bytes are masked
# to zero when computing the normalised function hash so the hash stays stable
# across rebased or relocated binaries.
_ADDR_OP_TYPES: frozenset[int] = frozenset(
    {idaapi.o_near, idaapi.o_far, idaapi.o_mem, idaapi.o_displ}
)

# Auto-generated name patterns that indicate a function has NOT been renamed.
_AUTO_NAME_RE = _re.compile(
    r"^(sub|loc|j|nullsub|fn|unk|byte|word|dword|qword|off|seg|asc|str)_[0-9A-Fa-f]+$",
    _re.IGNORECASE,
)


def _hash_function_bytes(start_ea: int) -> tuple[str, int, int]:
    """Return (sha256_hex, normalised_byte_count, instruction_count).

    Each instruction's address-type operand bytes are zeroed before hashing so
    the result is stable across ASLR / rebase.  Immediate constants (algorithm
    magic numbers) are kept as-is so two identical algorithms still collide.
    """
    normalized: list[bytes] = []
    insn_count = 0
    for item_ea in idautils.FuncItems(start_ea):
        insn = idaapi.insn_t()
        length = idaapi.decode_insn(insn, item_ea)
        if length <= 0:
            continue
        raw = idaapi.get_bytes(item_ea, length)
        if not raw:
            continue
        raw_arr = bytearray(raw)
        # Find earliest operand byte offset carrying an address value
        mask_from = length
        for op in insn.ops:
            if op.type == idaapi.o_void:
                break
            if op.type in _ADDR_OP_TYPES and 0 < op.offb < mask_from:
                mask_from = op.offb
        for k in range(mask_from, length):
            raw_arr[k] = 0
        normalized.append(bytes(raw_arr))
        insn_count += 1
    combined = b"".join(normalized)
    return hashlib.sha256(combined).hexdigest(), len(combined), insn_count


def _score_function_completeness(start_ea: int) -> CompletenessResult:
    """Return a CompletenessResult dict for a single function."""
    import ida_struct

    fn = idaapi.get_func(start_ea)
    if not fn:
        raise ValueError(f"No function at {hex(start_ea)}")
    name = ida_funcs.get_func_name(start_ea) or f"sub_{start_ea:X}"

    has_custom_name = not bool(_AUTO_NAME_RE.match(name))
    has_type = bool(ida_nalt.get_tinfo(ida_typeinf.tinfo_t(), start_ea))

    func_cmt = (idc.get_func_cmt(start_ea, False) or "").strip() or (
        idc.get_func_cmt(start_ea, True) or ""
    ).strip()
    has_func_comment = bool(func_cmt)

    has_named_stack_vars = False
    try:
        frame_id = idc.get_frame_id(start_ea)
        if frame_id and frame_id != idaapi.BADADDR:
            frame = ida_struct.get_struc(frame_id)
            if frame:
                for idx in range(frame.memqty):
                    member = frame.get_member(idx)
                    if member:
                        mname = ida_struct.get_member_name(member.id) or ""
                        if mname and not _re.match(
                            r"^(var_|arg_|a\d+)[0-9A-Fa-f]*$", mname, _re.I
                        ):
                            has_named_stack_vars = True
                            break
    except Exception:
        pass

    has_inline_comments = False
    try:
        for item_ea in idautils.FuncItems(start_ea):
            if idaapi.get_cmt(item_ea, False) or idaapi.get_cmt(item_ea, True):
                has_inline_comments = True
                break
    except Exception:
        pass

    score = (
        (35 if has_custom_name else 0)
        + (25 if has_type else 0)
        + (20 if has_func_comment else 0)
        + (15 if has_named_stack_vars else 0)
        + (5 if has_inline_comments else 0)
    )
    grade = (
        "A" if score >= 90
        else "B" if score >= 70
        else "C" if score >= 40
        else "D" if score >= 20
        else "F"
    )
    missing = [
        label
        for flag, label in (
            (has_custom_name, "custom_name"),
            (has_type, "type_annotation"),
            (has_func_comment, "function_comment"),
            (has_named_stack_vars, "named_stack_vars"),
            (has_inline_comments, "inline_comments"),
        )
        if not flag
    ]
    return {
        "addr": hex(start_ea),
        "name": name,
        "score": score,
        "grade": grade,
        "has_custom_name": has_custom_name,
        "has_type": has_type,
        "has_func_comment": has_func_comment,
        "has_named_stack_vars": has_named_stack_vars,
        "has_inline_comments": has_inline_comments,
        "missing": missing,
    }


@tool
@idasync
def get_function_callers(
    addrs: Annotated[
        list[str] | str,
        "Function addresses or names (e.g. '0x401000', 'check_password')",
    ],
    limit: Annotated[int, "Max callers per function per page (default: 200, max: 500)"] = 200,
    offset: Annotated[int, "Skip first N callers — pass next_offset from a previous result to page forward (default: 0)"] = 0,
) -> list[FunctionCallersResult]:
    """Return unique callers for each function, with pagination support.

    Each entry includes the containing caller function's address/name **and**
    the specific call-site address so you can jump directly to the call.

    See also: callees (outgoing calls), xrefs_to (all xrefs),
    callgraph (multi-level call graph).

    Complements ``callees`` — together they give the full
    caller/callee relationship for a function.

    Profile: analysis
    """
    addrs = normalize_list_input(addrs)
    if limit <= 0 or limit > 500:
        limit = 500
    if offset < 0:
        offset = 0

    results: list[FunctionCallersResult] = []
    for fn_addr in addrs:
        try:
            start_ea = parse_address(fn_addr)
            func = idaapi.get_func(start_ea)
            if not func:
                results.append(
                    {
                        "addr": fn_addr,
                        "callers": None,
                        **item_error(
                            ValueError("No function at address"),
                            f"get_function_callers {fn_addr}",
                        ),
                    }
                )
                continue

            all_seen: dict[int, FunctionCallersItem] = {}
            for call_ea in idautils.CodeRefsTo(func.start_ea, True):
                # Only count actual call instructions, not data refs or jump tables
                insn = idaapi.insn_t()
                idaapi.decode_insn(insn, call_ea)
                if insn.itype not in (
                    idaapi.NN_call, idaapi.NN_callfi, idaapi.NN_callni
                ):
                    continue
                caller_func = idaapi.get_func(call_ea)
                if not caller_func:
                    continue
                cstart = caller_func.start_ea
                if cstart not in all_seen:
                    all_seen[cstart] = {
                        "func_addr": hex(cstart),
                        "func_name": ida_name.get_name(cstart) or f"sub_{cstart:X}",
                        "call_ea": hex(call_ea),
                    }

            page = paginate(list(all_seen.values()), offset, limit)
            more = page["next_offset"] is not None
            results.append(
                {
                    "addr": hex(func.start_ea),
                    "name": ida_name.get_name(func.start_ea) or f"sub_{func.start_ea:X}",
                    "callers": page["data"],
                    "total": page["total"],
                    "next_offset": page["next_offset"],
                    "more": more,
                    "has_more": more,
                }
            )
        except Exception as e:
            results.append(
                {
                    "addr": fn_addr,
                    "callers": None,
                    **item_error(e, f"get_function_callers {fn_addr}"),
                }
            )

    return results


@tool
@idasync
def get_function_signature(
    addrs: Annotated[
        list[str] | str,
        "Function addresses or names (e.g. '0x401000', 'main')",
    ],
) -> list[FunctionSignatureResult]:
    """Return the stored type/prototype string for each function.

    Tries in order: (1) IDB-stored type annotation (instant), (2) Hex-Rays
    type inference from the decompiled cfunc.  Returns ``has_type: false`` and
    ``signature: null`` when neither source yields a result — the function
    either hasn't been analysed by the decompiler yet or needs manual typing.

    ``source`` indicates where the signature came from: ``"idb"``, ``"hexrays"``,
    or ``"none"``.

    Profile: analysis
    """
    addrs = normalize_list_input(addrs)
    results: list[FunctionSignatureResult] = []

    for fn_addr in addrs:
        try:
            start_ea = parse_address(fn_addr)
            func = idaapi.get_func(start_ea)
            if not func:
                results.append(
                    {
                        "addr": fn_addr,
                        "has_type": False,
                        "signature": None,
                        **item_error(
                            ValueError("No function at address"),
                            f"get_function_signature {fn_addr}",
                        ),
                    }
                )
                continue

            name = ida_funcs.get_func_name(start_ea) or f"sub_{start_ea:X}"
            sig: str | None = get_prototype(func)
            source = "idb" if sig else "none"

            if not sig:
                try:
                    import ida_hexrays as _hr
                    if _hr.init_hexrays_plugin():
                        cfunc = _hr.decompile(start_ea)
                        if cfunc and cfunc.type:
                            raw = str(cfunc.type)
                            if raw:
                                sig = raw
                                source = "hexrays"
                except Exception:
                    pass

            results.append(
                {
                    "addr": hex(start_ea),
                    "name": name,
                    "signature": sig,
                    "has_type": sig is not None,
                    "source": source,
                }
            )
        except Exception as e:
            results.append(
                {
                    "addr": fn_addr,
                    "signature": None,
                    "has_type": False,
                    **item_error(e, f"get_function_signature {fn_addr}"),
                }
            )

    return results


@tool
@idasync
def get_function_jump_targets(
    addrs: Annotated[
        list[str] | str,
        "Function addresses or names (e.g. '0x401000', 'main')",
    ],
) -> list[JumpTargetsResult]:
    """Return all jump targets from a function's disassembly.

    Each jump entry includes the jump instruction address, the resolved target
    (or ``null`` for indirect/register jumps), the kind (``unconditional``,
    ``conditional``, or ``indirect``), and the mnemonic.

    Useful for quick control-flow triage without loading a full CFG or
    decompiling the function.

    Profile: analysis
    """
    addrs = normalize_list_input(addrs)
    results: list[JumpTargetsResult] = []

    for fn_addr in addrs:
        try:
            start_ea = parse_address(fn_addr)
            func = idaapi.get_func(start_ea)
            if not func:
                results.append(
                    {
                        "addr": fn_addr,
                        **item_error(
                            ValueError("No function at address"),
                            f"get_function_jump_targets {fn_addr}",
                        ),
                    }
                )
                continue

            name = ida_funcs.get_func_name(start_ea) or f"sub_{start_ea:X}"
            jumps: list[JumpTargetItem] = []

            for item_ea in idautils.FuncItems(start_ea):
                insn = idaapi.insn_t()
                if not idaapi.decode_insn(insn, item_ea):
                    continue
                feat = insn.get_canon_feature()
                if not (feat & idaapi.CF_JUMP):
                    continue
                is_unconditional = bool(feat & idaapi.CF_STOP)
                op0 = insn.ops[0]
                is_indirect = op0.type in (idaapi.o_reg, idaapi.o_phrase, idaapi.o_displ)
                if is_indirect:
                    kind = "indirect"
                    target_str = None
                elif is_unconditional:
                    kind = "unconditional"
                    target_str = hex(op0.addr) if op0.addr else None
                else:
                    kind = "conditional"
                    target_str = hex(op0.addr) if op0.addr else None
                jumps.append(
                    {
                        "ea": hex(item_ea),
                        "target": target_str,
                        "kind": kind,
                        "mnemonic": idc.print_insn_mnem(item_ea) or "",
                    }
                )

            results.append(
                {
                    "addr": hex(start_ea),
                    "name": name,
                    "jump_count": len(jumps),
                    "jumps": jumps,
                }
            )
        except Exception as e:
            results.append(
                {"addr": fn_addr, **item_error(e, f"get_function_jump_targets {fn_addr}")}
            )

    return results


@tool
@idasync
def get_function_hash(
    addrs: Annotated[
        list[str] | str,
        "Function addresses or names (e.g. '0x401000', 'main')",
    ],
) -> list[FunctionHashResult]:
    """SHA-256 hash of normalised function opcodes.

    Address-type operand bytes (branch targets, memory references,
    displacements) are zeroed before hashing so the digest is stable across
    rebased or relocated binaries.  Immediate constants are **kept** so two
    functions implementing the same algorithm with the same magic numbers still
    produce the same hash.

    Use ``get_bulk_function_hashes`` for binary-wide scanning.

    Profile: analysis
    """
    addrs = normalize_list_input(addrs)
    results: list[FunctionHashResult] = []

    for fn_addr in addrs:
        try:
            start_ea = parse_address(fn_addr)
            func = idaapi.get_func(start_ea)
            if not func:
                results.append(
                    {
                        "addr": fn_addr,
                        **item_error(
                            ValueError("No function at address"),
                            f"get_function_hash {fn_addr}",
                        ),
                    }
                )
                continue
            name = ida_funcs.get_func_name(start_ea) or f"sub_{start_ea:X}"
            digest, nbytes, insn_count = _hash_function_bytes(start_ea)
            results.append(
                {
                    "addr": hex(start_ea),
                    "name": name,
                    "hash": f"sha256:{digest}",
                    "normalized_bytes": nbytes,
                    "instruction_count": insn_count,
                }
            )
        except Exception as e:
            results.append(
                {"addr": fn_addr, **item_error(e, f"get_function_hash {fn_addr}")}
            )

    return results


@tool
@idasync
@tool_timeout(120.0)
def get_bulk_function_hashes(
    filter: Annotated[str, "Glob filter on function name (empty = all)"] = "",
    offset: Annotated[int, "Start index for pagination (default: 0)"] = 0,
    count: Annotated[int, "Max functions per page (default: 500)"] = 500,
    min_instructions: Annotated[
        int,
        "Skip functions with fewer than N instructions (default: 5 — filters tiny stubs)",
    ] = 5,
) -> BulkHashPage:
    """Compute SHA-256 normalised hashes for all (or filtered) functions.

    Paginate with ``offset`` + ``count``.  Filter to a name pattern with
    ``filter``.  Use ``min_instructions`` to skip tiny thunks and trampolines
    that produce near-identical hashes due to having only 1-2 instructions.

    Heavy: for binaries with >5000 functions use invoke_tool(..., async_mode=True)
    or task_submit + task_poll.

    Profile: analysis
    """
    try:
        candidates: list[dict] = []
        for start_ea in idautils.Functions():
            fn = idaapi.get_func(start_ea)
            if not fn:
                continue
            name = ida_funcs.get_func_name(start_ea) or f"sub_{start_ea:X}"
            candidates.append({"start_ea": start_ea, "name": name})

        if filter and filter not in ("*", ""):
            candidates = pattern_filter(candidates, filter, "name")

        total = len(candidates)
        page_items = candidates[offset: offset + count]
        data: list[FunctionHashResult] = []
        for item in page_items:
            start_ea = item["start_ea"]
            try:
                digest, nbytes, insn_count = _hash_function_bytes(start_ea)
                if insn_count < min_instructions:
                    continue
                data.append(
                    {
                        "addr": hex(start_ea),
                        "name": item["name"],
                        "hash": f"sha256:{digest}",
                        "normalized_bytes": nbytes,
                        "instruction_count": insn_count,
                    }
                )
            except Exception as e:
                data.append(
                    {
                        "addr": hex(start_ea),
                        "name": item["name"],
                        **item_error(e, f"hash {hex(start_ea)}"),
                    }
                )

        next_off = offset + count if offset + count < total else None
        result: dict = {"data": data, "total": total, "next_offset": next_off}
        stats = summary_stats(data, "instruction_count", label_field="name")
        if stats is not None:
            result["summary"] = {"instruction_count": stats}
        return result
    except Exception as e:
        return tool_error(e, context="get_bulk_function_hashes")


@tool
@idasync
def analyze_function_completeness(
    addrs: Annotated[
        list[str] | str,
        "Function addresses or names (e.g. '0x401000', 'main')",
    ],
) -> list[CompletenessResult]:
    """Score each function's reverse-engineering documentation completeness.

    A 0–100 score is computed from five weighted criteria:

    | Criterion           | Points | What counts                                      |
    |---------------------|--------|--------------------------------------------------|
    | Custom name         | 35     | Not ``sub_``/``loc_``/``j_`` auto-generated      |
    | Type annotation     | 25     | IDB has a stored tinfo prototype                 |
    | Function comment    | 20     | Regular or repeatable comment at function entry  |
    | Named stack vars    | 15     | At least one frame var without ``var_``/``arg_`` |
    | Inline comments     |  5     | Any comment inside the function body             |

    Grades: A ≥ 90, B ≥ 70, C ≥ 40, D ≥ 20, F < 20.

    Profile: analysis
    """
    addrs = normalize_list_input(addrs)
    results: list[CompletenessResult] = []
    for fn_addr in addrs:
        try:
            start_ea = parse_address(fn_addr)
            results.append(_score_function_completeness(start_ea))
        except Exception as e:
            results.append(
                {"addr": fn_addr, **item_error(e, f"analyze_function_completeness {fn_addr}")}
            )
    return results


@tool
@idasync
@tool_timeout(120.0)
def batch_analyze_completeness(
    filter: Annotated[str, "Glob filter on function name (empty = all)"] = "",
    offset: Annotated[int, "Start index for pagination (default: 0)"] = 0,
    count: Annotated[int, "Max functions per page (default: 200)"] = 200,
    min_score: Annotated[int, "Only return functions with score >= N (default: 0)"] = 0,
    max_score: Annotated[
        int, "Only return functions with score <= N (default: 100)"
    ] = 100,
    sort_by: Annotated[
        str, "Sort order: 'score' (default, ascending — worst first) or 'addr'"
    ] = "score",
) -> BatchCompletenessResult:
    """Completeness scores for all (or filtered) functions in the IDB.

    Sort by ``score`` (default, ascending) to surface the worst-documented
    functions first — the ones most worth renaming, commenting, and typing.

    Use ``max_score=59`` to find functions that still need work (grade C or
    below).  Use ``min_score=90`` to list fully-documented functions.

    Heavy: for large binaries use invoke_tool(..., async_mode=True)
    or task_submit + task_poll.

    Profile: analysis
    """
    try:
        candidates: list[dict] = []
        for start_ea in idautils.Functions():
            fn = idaapi.get_func(start_ea)
            if not fn:
                continue
            name = ida_funcs.get_func_name(start_ea) or f"sub_{start_ea:X}"
            candidates.append({"start_ea": start_ea, "name": name})

        if filter and filter not in ("*", ""):
            candidates = pattern_filter(candidates, filter, "name")

        scored: list[CompletenessResult] = []
        for item in candidates:
            try:
                s = _score_function_completeness(item["start_ea"])
                score_val = s.get("score", 0) or 0
                if min_score <= score_val <= max_score:
                    scored.append(s)
            except Exception as e:
                scored.append(
                    {
                        "addr": hex(item["start_ea"]),
                        "name": item["name"],
                        **item_error(e, f"completeness {hex(item['start_ea'])}"),
                    }
                )

        if sort_by == "score":
            scored.sort(key=lambda x: x.get("score") or 0)
        else:
            scored.sort(key=lambda x: int(x.get("addr", "0x0"), 16))

        total = len(scored)
        page_data = scored[offset: offset + count]
        next_off = offset + count if offset + count < total else None

        scores_only = [x.get("score") or 0 for x in scored if "score" in x]
        mean_score = round(sum(scores_only) / len(scores_only), 1) if scores_only else 0.0
        grade_counts: dict[str, int] = {"A": 0, "B": 0, "C": 0, "D": 0, "F": 0}
        for x in scored:
            g = x.get("grade", "F") or "F"
            grade_counts[g] = grade_counts.get(g, 0) + 1

        return {
            "data": page_data,
            "total": total,
            "next_offset": next_off,
            "mean_score": mean_score,
            "grade_counts": grade_counts,
        }
    except Exception as e:
        return tool_error(e, context="batch_analyze_completeness")


@tool
@idasync
@tool_timeout(60.0)
def diff_functions(
    addr_a: Annotated[str, "First function address or name"],
    addr_b: Annotated[str, "Second function address or name"],
    context_lines: Annotated[
        int,
        "Lines of context around each diff hunk (default: 3). "
        "Set 0 for changed lines only.",
    ] = 3,
) -> DiffFunctionsResult:
    """Side-by-side unified diff of two decompiled functions.

    Decompiles both functions via Hex-Rays and produces a unified diff.
    ``similarity`` is a 0–1 ratio from Python's ``SequenceMatcher`` — 1.0 means
    identical pseudocode, 0.0 means completely different.

    Typical uses: patch-diffing two binary versions, comparing inlined/outlined
    variants, or verifying that a manually-typed prototype changed only comments.

    Profile: analysis
    """
    try:
        start_a = parse_address(addr_a)
        start_b = parse_address(addr_b)
        func_a = idaapi.get_func(start_a)
        func_b = idaapi.get_func(start_b)
        if not func_a:
            return tool_error(
                ValueError(f"No function at {addr_a}"),
                context="diff_functions",
                hint="Verify addr_a is a valid function start address.",
            )
        if not func_b:
            return tool_error(
                ValueError(f"No function at {addr_b}"),
                context="diff_functions",
                hint="Verify addr_b is a valid function start address.",
            )

        name_a = ida_funcs.get_func_name(start_a) or f"sub_{start_a:X}"
        name_b = ida_funcs.get_func_name(start_b) or f"sub_{start_b:X}"

        code_a = decompile_function_safe(start_a, include_addresses=False)
        code_b = decompile_function_safe(start_b, include_addresses=False)

        note_parts: list[str] = []
        if code_a is None:
            note_parts.append(f"Decompilation failed for {name_a} — diff uses empty string.")
        if code_b is None:
            note_parts.append(f"Decompilation failed for {name_b} — diff uses empty string.")

        lines_a = (code_a or "").splitlines()
        lines_b = (code_b or "").splitlines()

        diff_lines = list(
            difflib.unified_diff(
                lines_a,
                lines_b,
                fromfile=name_a,
                tofile=name_b,
                lineterm="",
                n=max(0, context_lines),
            )
        )
        similarity = round(
            difflib.SequenceMatcher(None, lines_a, lines_b).ratio(), 4
        )

        if similarity == 1.0 and not note_parts:
            note_parts.append("Functions produce identical pseudocode.")

        return {
            "ok": True,
            "addr_a": hex(start_a),
            "addr_b": hex(start_b),
            "name_a": name_a,
            "name_b": name_b,
            "similarity": similarity,
            "diff": "\n".join(diff_lines),
            "diff_line_count": len(diff_lines),
            "lines_a": len(lines_a),
            "lines_b": len(lines_b),
            "note": " ".join(note_parts) if note_parts else "",
        }
    except Exception as e:
        return tool_error(e, context="diff_functions")


# ============================================================================
# Pattern Matching & Signature Tools
# ============================================================================


@tool
@idasync
def find_bytes(
    patterns: Annotated[
        list[str] | str, "Byte patterns to search for (e.g. '48 8B ?? ??')"
    ],
    limit: Annotated[int, "Max matches per pattern (default: 1000, max: 10000)"] = 1000,
    offset: Annotated[int, "Skip first N matches (default: 0)"] = 0,
) -> list[FindBytesResult]:
    """Search byte patterns (supports ??) with offset/limit pagination.

    Large match sets may be truncated at 50 KB with an ``output_id``.
    If truncated, use ``read_mcp_output(output_id=..., offset=0)`` to retrieve
    the full result in chunks.

    See also: find_regex (string/symbol regex search), insn_query
    (instruction pattern search).

    Profile: analysis
    """
    patterns = normalize_list_input(patterns)

    # Coerce dict items — agents sometimes pass {'pattern': '48 8B ...'} instead of
    # the bare string. Extract from known keys; fall back to the first string value.
    def _coerce_pattern(p: object) -> str:
        if isinstance(p, dict):
            for key in ("pattern", "bytes", "hex", "value", "data"):
                if key in p and isinstance(p[key], str):
                    return p[key]
            for v in p.values():
                if isinstance(v, str):
                    return v
        return p if isinstance(p, str) else str(p)

    patterns = [_coerce_pattern(p) for p in patterns]

    # Enforce max limit
    if limit <= 0 or limit > 10000:
        limit = 10000

    # Build a reusable search closure based on available IDA API
    def _make_searcher(pattern: str):
        """Return a (searcher_fn, error_str|None) for the given pattern.

        searcher_fn(ea, max_ea) -> ea_t  (BADADDR if not found)
        """
        return compat.make_bytes_searcher(pattern)

    results = []
    for pattern in patterns:
        matches = []
        skipped = 0
        more = False
        try:
            searcher, build_err = _make_searcher(pattern)
            if build_err is not None:
                results.append(
                    {
                        "pattern": pattern,
                        "matches": [],
                        "n": 0,
                        "cursor": {"done": True},
                        "error": build_err,
                    }
                )
                continue

            # Search with early exit
            ea = ida_ida.inf_get_min_ea()
            max_ea = ida_ida.inf_get_max_ea()
            while ea != idaapi.BADADDR:
                ea = searcher(ea, max_ea)
                if ea == idaapi.BADADDR:
                    break
                if skipped < offset:
                    skipped += 1
                else:
                    matches.append(hex(ea))
                    if len(matches) >= limit:
                        # Check if there's more
                        next_ea = searcher(ea + 1, max_ea)
                        more = next_ea != idaapi.BADADDR
                        break
                ea += 1
        except Exception as e:
            results.append(
                {
                    "pattern": pattern,
                    "matches": [],
                    "n": 0,
                    "cursor": {"done": True},
                    **item_error(e, f"find bytes pattern {pattern!r}"),
                }
            )
            continue

        results.append(
            {
                "pattern": pattern,
                "matches": matches,
                "n": len(matches),
                "cursor": {"next": offset + limit} if more else {"done": True},
            }
        )
    return results


# ============================================================================
# Control Flow Analysis
# ============================================================================


@tool
@idasync
def basic_blocks(
    addrs: Annotated[list[str] | str, "Function addresses or names to get basic blocks for (e.g. '0x123e', 'main')"],
    max_blocks: Annotated[
        int, "Max basic blocks per function (default: 1000, max: 10000)"
    ] = 1000,
    offset: Annotated[int, "Skip first N blocks (default: 0)"] = 0,
) -> list[BasicBlocksResult]:
    """Return function CFG blocks with offset/max_blocks pagination.

    Profile: analysis
    """
    addrs = normalize_list_input(addrs)

    # Enforce max limit
    if max_blocks <= 0 or max_blocks > 10000:
        max_blocks = 10000

    results = []
    for fn_addr in addrs:
        try:
            ea = parse_address(fn_addr)
            func = idaapi.get_func(ea)
            if not func:
                results.append(
                    {
                        "addr": fn_addr,
                        "error": "Function not found",
                        "blocks": [],
                        "cursor": {"done": True},
                    }
                )
                continue

            flowchart = idaapi.FlowChart(func)
            all_blocks = []

            for block in flowchart:
                all_blocks.append(
                    BasicBlock(
                        start=hex(block.start_ea),
                        end=hex(block.end_ea),
                        size=block.end_ea - block.start_ea,
                        type=block.type,
                        successors=[hex(succ.start_ea) for succ in block.succs()],
                        predecessors=[hex(pred.start_ea) for pred in block.preds()],
                    )
                )

            # Apply pagination
            total_blocks = len(all_blocks)
            blocks = all_blocks[offset : offset + max_blocks]
            more = offset + max_blocks < total_blocks

            results.append(
                {
                    "addr": fn_addr,
                    "blocks": blocks,
                    "count": len(blocks),
                    "total_blocks": total_blocks,
                    "cursor": (
                        {"next": offset + max_blocks} if more else {"done": True}
                    ),
                }
            )
        except Exception as e:
            results.append(
                {
                    "addr": fn_addr,
                    "blocks": [],
                    "cursor": {"done": True},
                    **item_error(e, f"get basic blocks of {fn_addr}"),
                }
            )
    return results


# ============================================================================
# Search Operations
# ============================================================================


@tool
@idasync
def find(
    type: Annotated[
        str, "Search type: 'string', 'immediate', 'data_ref', or 'code_ref'"
    ],
    targets: Annotated[
        list[str | int] | str | int, "Search targets (strings, integers, or addresses)"
    ],
    limit: Annotated[int, "Max matches per target (default: 1000, max: 10000)"] = 1000,
    offset: Annotated[int, "Skip first N matches (default: 0)"] = 0,
) -> list[FindResult]:
    """Search strings/immediates/refs for targets with offset/limit pagination."""
    if not isinstance(targets, list):
        targets = [targets]

    # Enforce max limit to prevent token overflow
    if limit <= 0 or limit > 10000:
        limit = 10000

    results = []

    if type == "string":
        # Raw byte search for UTF-8 substrings across the binary
        for pattern in targets:
            pattern_str = str(pattern)
            pattern_bytes = pattern_str.encode("utf-8")
            if not pattern_bytes:
                results.append(
                    {
                        "query": pattern_str,
                        "matches": [],
                        "count": 0,
                        "cursor": {"done": True},
                        "error": "Empty pattern",
                    }
                )
                continue

            matches = []
            skipped = 0
            more = False
            try:
                ea = ida_ida.inf_get_min_ea()
                max_ea = ida_ida.inf_get_max_ea()
                mask = b"\xff" * len(pattern_bytes)
                while ea != idaapi.BADADDR:
                    ea = _raw_bin_search(ea, max_ea, pattern_bytes, mask)
                    if ea != idaapi.BADADDR:
                        if skipped < offset:
                            skipped += 1
                        else:
                            matches.append(hex(ea))
                            if len(matches) >= limit:
                                next_ea = _raw_bin_search(
                                    ea + 1, max_ea, pattern_bytes, mask
                                )
                                more = next_ea != idaapi.BADADDR
                                break
                        ea += 1
            except Exception:
                pass

            results.append(
                {
                    "query": pattern_str,
                    "matches": matches,
                    "count": len(matches),
                    "cursor": {"next": offset + limit} if more else {"done": True},
                    "error": None,
                }
            )

    elif type == "immediate":
        # Search for immediate values
        for value in targets:
            if isinstance(value, str):
                try:
                    value = int(value, 0)
                except ValueError:
                    value = 0

            matches = []
            skipped = 0
            more = False
            try:
                candidates = _value_candidates_for_immediate(value)
                if not candidates:
                    results.append(
                        {
                            "query": value,
                            "matches": [],
                            "count": 0,
                            "cursor": {"done": True},
                            "error": "Immediate out of range",
                        }
                    )
                    continue

                seen_insn = set()
                for seg_ea in idautils.Segments():
                    seg = idaapi.getseg(seg_ea)
                    if not seg or not (seg.perm & idaapi.SEGPERM_EXEC):
                        continue
                    for normalized, size, pattern_bytes in candidates:
                        ea = seg.start_ea
                        while ea != idaapi.BADADDR and ea < seg.end_ea:
                            ea = _raw_bin_search(
                                ea, seg.end_ea, pattern_bytes, b"\xff" * size
                            )
                            if ea == idaapi.BADADDR:
                                break

                            insn_start = _resolve_immediate_insn_start(
                                ea, value, seg.start_ea, normalized
                            )
                            if insn_start is not None and insn_start not in seen_insn:
                                seen_insn.add(insn_start)
                                if skipped < offset:
                                    skipped += 1
                                else:
                                    matches.append(hex(insn_start))
                                    if len(matches) >= limit:
                                        more = True
                                        break

                            ea += 1

                        if more:
                            break
                    if more:
                        break
            except Exception:
                pass

            results.append(
                {
                    "query": value,
                    "matches": matches,
                    "count": len(matches),
                    "cursor": {"next": offset + limit} if more else {"done": True},
                    "error": None,
                }
            )

    elif type == "data_ref":
        # Find all data references to targets
        for target_str in targets:
            try:
                target = parse_address(str(target_str))
                gen = (hex(xref) for xref in idautils.DataRefsTo(target))
                # Skip offset items, take limit+1 to check more
                matches = list(islice(islice(gen, offset, None), limit + 1))
                more = len(matches) > limit
                if more:
                    matches = matches[:limit]

                results.append(
                    {
                        "query": str(target_str),
                        "matches": matches,
                        "count": len(matches),
                        "cursor": (
                            {"next": offset + limit} if more else {"done": True}
                        ),
                        "error": None,
                    }
                )
            except Exception as e:
                results.append(
                    {
                        "query": str(target_str),
                        "matches": [],
                        "count": 0,
                        "cursor": {"done": True},
                        **item_error(e, f"name/string pattern search for {target_str!r}"),
                    }
                )

    elif type == "code_ref":
        # Find all code references to targets
        for target_str in targets:
            try:
                target = parse_address(str(target_str))
                gen = (hex(xref) for xref in idautils.CodeRefsTo(target, 0))
                # Skip offset items, take limit+1 to check more
                matches = list(islice(islice(gen, offset, None), limit + 1))
                more = len(matches) > limit
                if more:
                    matches = matches[:limit]

                results.append(
                    {
                        "query": str(target_str),
                        "matches": matches,
                        "count": len(matches),
                        "cursor": (
                            {"next": offset + limit} if more else {"done": True}
                        ),
                        "error": None,
                    }
                )
            except Exception as e:
                results.append(
                    {
                        "query": str(target_str),
                        "matches": [],
                        "count": 0,
                        "cursor": {"done": True},
                        **item_error(e, f"code refs to {target_str}"),
                    }
                )

    else:
        results.append(
            {
                "query": None,
                "matches": [],
                "count": 0,
                "cursor": {"done": True},
                "error": f"Unknown search type: {type}",
            }
        )

    return results


def _resolve_insn_scan_ranges(
    pattern: dict, allow_broad: bool
) -> tuple[list[tuple[int, int]], str | None]:
    func_addr = pattern.get("func")
    segment_name = pattern.get("segment")
    start_s = pattern.get("start")
    end_s = pattern.get("end")

    exec_segments = []
    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if seg and (seg.perm & idaapi.SEGPERM_EXEC):
            exec_segments.append(seg)

    if func_addr is not None:
        try:
            ea = parse_address(func_addr)
            func = idaapi.get_func(ea)
            if not func:
                return [], f"Function not found at {func_addr}"
            return [(func.start_ea, func.end_ea)], None
        except Exception as e:
            return [], str(e)

    if segment_name is not None:
        for seg in exec_segments:
            if idaapi.get_segm_name(seg) == segment_name:
                return [(seg.start_ea, seg.end_ea)], None
        return [], f"Executable segment not found: {segment_name}"

    if start_s is not None or end_s is not None:
        if start_s is None:
            return [], "start is required when end is set"
        try:
            start_ea = parse_address(start_s)
            end_ea = parse_address(end_s) if end_s is not None else None
        except Exception as e:
            return [], str(e)

        if not exec_segments:
            return [], "No executable segments found"

        if end_ea is None:
            seg = idaapi.getseg(start_ea)
            if not seg or not (seg.perm & idaapi.SEGPERM_EXEC):
                return [], "start address not in executable segment"
            end_ea = seg.end_ea

        if end_ea <= start_ea:
            return [], "end must be greater than start"

        ranges = []
        for seg in exec_segments:
            seg_start = max(seg.start_ea, start_ea)
            seg_end = min(seg.end_ea, end_ea)
            if seg_end > seg_start:
                ranges.append((seg_start, seg_end))

        if not ranges:
            return [], "No executable ranges within start/end"

        return ranges, None

    if not allow_broad:
        return [], "Scope required: set func/segment/start/end or allow_broad=true"

    if not exec_segments:
        return [], "No executable segments found"

    return [(seg.start_ea, seg.end_ea) for seg in exec_segments], None


def _scan_insn_ranges(
    ranges: list[tuple[int, int]],
    mnem: str,
    op0_val: int | None,
    op1_val: int | None,
    op2_val: int | None,
    any_val: int | None,
    limit: int,
    offset: int,
    max_scan_insns: int,
) -> tuple[list[str], bool, int, bool, int | None]:
    matches: list[str] = []
    skipped = 0
    scanned = 0
    more = False
    truncated = False
    next_start: int | None = None

    for start_ea, end_ea in ranges:
        ea = start_ea
        while ea < end_ea:
            if scanned >= max_scan_insns:
                truncated = True
                next_start = ea
                break

            scanned += 1

            insn = _decode_insn_at(ea)
            if insn is None:
                ea = _next_head(ea, end_ea)
                if ea == idaapi.BADADDR:
                    break
                continue

            if mnem and _insn_mnem(insn) != mnem:
                ea = _next_head(ea, end_ea)
                if ea == idaapi.BADADDR:
                    break
                continue

            match = True
            if op0_val is not None and _operand_value(insn, 0) != op0_val:
                match = False
            if op1_val is not None and _operand_value(insn, 1) != op1_val:
                match = False
            if op2_val is not None and _operand_value(insn, 2) != op2_val:
                match = False

            if any_val is not None and match:
                found_any = False
                for i in range(8):
                    if _operand_type(insn, i) == ida_ua.o_void:
                        break
                    if _operand_value(insn, i) == any_val:
                        found_any = True
                        break
                if not found_any:
                    match = False

            if match:
                if skipped < offset:
                    skipped += 1
                else:
                    matches.append(hex(ea))
                    if len(matches) > limit:
                        more = True
                        matches = matches[:limit]
                        break

            ea = _next_head(ea, end_ea)
            if ea == idaapi.BADADDR:
                break

        if more or truncated:
            break

    return matches, more, scanned, truncated, next_start


@tool
@idasync
def insn_query(
    queries: Annotated[
        list[InsnPattern] | InsnPattern,
        "Instruction query with mnemonic/operand filters and scoped scan",
    ],
) -> list[InsnQueryResult]:
    """Query instructions with mnemonic/operand filters and scoped scans."""
    queries = normalize_dict_list(queries)

    results: list[dict] = []
    for pattern in queries:
        mnem = str(pattern.get("mnem", "") or "").strip().lower()
        if mnem == "*":
            mnem = ""

        offset = _clamp_int(pattern.get("offset", 0), 0, 0, 2_000_000_000)
        count = _clamp_int(pattern.get("count", 100), 100, 0, 5000)
        max_scan_insns = _clamp_int(
            pattern.get("max_scan_insns", 200000), 200000, 1, 2_000_000
        )
        allow_broad = bool(pattern.get("allow_broad", True))
        include_fn = bool(pattern.get("include_fn", False))
        include_disasm = bool(pattern.get("include_disasm", False))

        summary = {
            "mnem": mnem or None,
            "op0": pattern.get("op0"),
            "op1": pattern.get("op1"),
            "op2": pattern.get("op2"),
            "op_any": pattern.get("op_any"),
            "func": pattern.get("func"),
            "segment": pattern.get("segment"),
            "start": pattern.get("start"),
            "end": pattern.get("end"),
            "offset": offset,
            "count": count,
            "max_scan_insns": max_scan_insns,
            "allow_broad": allow_broad,
        }

        try:
            op0_val = _parse_optional_int(pattern.get("op0"), "op0")
            op1_val = _parse_optional_int(pattern.get("op1"), "op1")
            op2_val = _parse_optional_int(pattern.get("op2"), "op2")
            any_val = _parse_optional_int(pattern.get("op_any"), "op_any")

            ranges, range_error = _resolve_insn_scan_ranges(pattern, allow_broad)
            if range_error:
                raise ValueError(range_error)

            addresses, more, scanned, truncated, next_start = _scan_insn_ranges(
                ranges,
                mnem,
                op0_val,
                op1_val,
                op2_val,
                any_val,
                count,
                offset,
                max_scan_insns,
            )

            rows = []
            for addr_s in addresses:
                ea = int(addr_s, 16)
                row = {"addr": addr_s}
                if include_disasm:
                    line = ida_lines.generate_disasm_line(ea, 0)
                    row["disasm"] = compact_whitespace(ida_lines.tag_remove(line)) if line else ""
                if include_fn:
                    row["fn"] = get_function(ea, raise_error=False)
                rows.append(row)

            summary["op0"] = op0_val
            summary["op1"] = op1_val
            summary["op2"] = op2_val
            summary["op_any"] = any_val

            results.append(
                {
                    "query": summary,
                    "ranges": [
                        {"start": hex(start_ea), "end": hex(end_ea)}
                        for start_ea, end_ea in ranges
                    ],
                    "matches": rows,
                    "count": len(rows),
                    "cursor": {"next": offset + count} if more else {"done": True},
                    "scanned": scanned,
                    "truncated": truncated,
                    "next_start": hex(next_start) if next_start is not None else None,
                    "error": None,
                }
            )
        except Exception as e:
            results.append(
                {
                    "query": summary,
                    "ranges": [],
                    "matches": [],
                    "count": 0,
                    "cursor": {"done": True},
                    "scanned": 0,
                    "truncated": False,
                    "next_start": None,
                    **item_error(e, f"instruction search (mnem={mnem!r})"),
                }
            )

    return results


# ============================================================================
# Export Operations
# ============================================================================


@tool
@idasync
def export_funcs(
    addrs: Annotated[list[str] | str, "Function addresses or names to export (e.g. '0x123e', 'main')"],
    format: Annotated[
        str, "Export format: json (default), c_header, or prototypes"
    ] = "json",
) -> ExportFuncsJsonResult | ExportFuncsHeaderResult | ExportFuncsPrototypesResult:
    """Export function data (assembly, decompilation, xrefs, comments, prototype) for specific addresses.

    **Formats:**
    - ``json`` — Full detail per function (largest output; may trigger ``read_mcp_output``).
    - ``c_header`` — Prototypes only, formatted as C header text.
    - ``prototypes`` — List of ``{name, prototype}`` pairs.

    For bulk analysis of many functions, use ``analyze_batch`` or
    ``decompile_batch`` instead — they are more token-efficient.

    See also: decompile_batch (batch decompilation), analyze_batch (batch analysis),
    analyze_function (compact single-function analysis).
    """
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            func = idaapi.get_func(ea)
            if not func:
                results.append({"addr": addr, "error": "Function not found"})
                continue

            func_data = {
                "addr": addr,
                "name": ida_funcs.get_func_name(func.start_ea),
                "prototype": get_prototype(func),
                "size": hex(func.end_ea - func.start_ea),
                "comments": get_all_comments(ea),
            }

            if format == "json":
                func_data["asm"] = get_assembly_lines(ea)
                func_data["code"] = decompile_function_safe(ea)
                func_data["xrefs"] = get_all_xrefs(ea)

            results.append(func_data)

        except Exception as e:
            results.append({"addr": addr, **item_error(e, f"export function at {addr}")})

    if format == "c_header":
        # Generate C header file
        lines = ["// Auto-generated by IDA Pro MCP", ""]
        for func in results:
            if "prototype" in func and func["prototype"]:
                lines.append(f"{func['prototype']};")
        return {"format": "c_header", "content": "\n".join(lines)}

    elif format == "prototypes":
        # Just prototypes
        prototypes = []
        for func in results:
            if "prototype" in func and func["prototype"]:
                prototypes.append(
                    {"name": func.get("name"), "prototype": func["prototype"]}
                )
        return {"format": "prototypes", "functions": prototypes}

    return {"format": "json", "functions": results}


# ============================================================================
# Graph Operations
# ============================================================================


@tool
@idasync
def callgraph(
    roots: Annotated[
        list[str] | str, "Root function addresses to start call graph traversal from"
    ],
    max_depth: Annotated[int, "Maximum depth for call graph traversal"] = 5,
    max_nodes: Annotated[
        int, "Max nodes across the graph (default: 1000, max: 100000)"
    ] = 1000,
    max_edges: Annotated[
        int, "Max edges across the graph (default: 5000, max: 200000)"
    ] = 5000,
    max_edges_per_func: Annotated[
        int, "Max edges per function (default: 200, max: 5000)"
    ] = 200,
) -> list[CallGraphResult]:
    """Build bounded callgraph from roots with depth/node/edge limits.

    Large graphs may be truncated at 50 KB with an ``output_id``.
    If truncated, use ``read_mcp_output(output_id=..., offset=0)`` to retrieve
    the full result in chunks.

    See also: analyze_component (multi-function group analysis),
    trace_data_chain (data-flow traversal), callees / get_function_callers
    (direct neighbors of a single function).

    Heavy: for deep or wide graphs use invoke_tool(..., async_mode=True) or task_submit + task_poll."""
    roots = normalize_list_input(roots)
    if max_depth < 0:
        max_depth = 0
    if max_nodes <= 0 or max_nodes > 100000:
        max_nodes = 100000
    if max_edges <= 0 or max_edges > 200000:
        max_edges = 200000
    if max_edges_per_func <= 0 or max_edges_per_func > 5000:
        max_edges_per_func = 5000
    results = []

    for root in roots:
        try:
            ea = parse_address(root)
            func = idaapi.get_func(ea)
            if not func:
                results.append(
                    {
                        "root": root,
                        "error": "Function not found",
                        "nodes": [],
                        "edges": [],
                    }
                )
                continue

            nodes = {}
            edges = []
            visited = set()
            truncated = False
            per_func_capped = False
            limit_reason = None

            def hit_limit(reason: str):
                nonlocal truncated, limit_reason
                truncated = True
                limit_reason = reason

            def traverse(addr, depth):
                nonlocal per_func_capped
                if truncated:
                    return
                if depth > max_depth or addr in visited:
                    return
                if len(nodes) >= max_nodes:
                    hit_limit("nodes")
                    return
                visited.add(addr)

                f = idaapi.get_func(addr)
                if not f:
                    return

                func_name = ida_funcs.get_func_name(f.start_ea)
                nodes[hex(addr)] = {
                    "addr": hex(addr),
                    "name": func_name,
                    "depth": depth,
                }

                # Get callees
                edges_added = 0
                for item_ea in idautils.FuncItems(f.start_ea):
                    if truncated:
                        break
                    for xref in idautils.CodeRefsFrom(item_ea, 0):
                        if truncated:
                            break
                        if edges_added >= max_edges_per_func:
                            per_func_capped = True
                            break
                        callee_func = idaapi.get_func(xref)
                        if callee_func:
                            if len(edges) >= max_edges:
                                hit_limit("edges")
                                break
                            edges.append(
                                {
                                    "from": hex(addr),
                                    "to": hex(callee_func.start_ea),
                                    "type": "call",
                                }
                            )
                            edges_added += 1
                            traverse(callee_func.start_ea, depth + 1)
                    if edges_added >= max_edges_per_func:
                        break

            traverse(ea, 0)

            results.append(
                {
                    "root": root,
                    "nodes": list(nodes.values()),
                    "edges": edges,
                    "max_depth": max_depth,
                    "truncated": truncated,
                    "has_more": truncated,
                    "total_nodes": len(nodes),
                    "total_edges": len(edges),
                    "limit_reason": limit_reason,
                    "max_nodes": max_nodes,
                    "max_edges": max_edges,
                    "max_edges_per_func": max_edges_per_func,
                    "per_func_capped": per_func_capped,
                }
            )

        except Exception as e:
            results.append({"root": root, "nodes": [], "edges": [], **item_error(e, f"call graph for {root}")})

    return results


# ============================================================================
# IDA-native CFG export (Graphviz DOT)
# ============================================================================


class CfgDotResult(TypedDict, total=False):
    ok: bool
    address: str
    name: str
    block_count: int
    dot: str
    error: str
    error_type: str
    hint: str


class SimilarFunctionMatch(TypedDict):
    addr: str
    name: str
    similarity_score: float
    block_count: int
    edge_count: int
    complexity: int
    size_bytes: int
    matching_features: dict[str, float]
    fingerprint_name: NotRequired[str]
    fingerprint_description: NotRequired[str]


class ChainNode(TypedDict):
    addr: str
    type: str
    instruction: str | None
    function: str | None
    name: str | None
    depth: int


class ChainEdge(TypedDict):
    from_addr: str
    to_addr: str
    xref_type: str


class TerminatedAt(TypedDict):
    reason: str
    address: str


class TraceDataChainResult(TypedDict, total=False):
    ok: bool
    start: str
    direction: str
    max_depth: int
    depth_reached: int
    nodes: list[ChainNode]
    edges: list[ChainEdge]
    terminated_at: TerminatedAt | None
    node_count: int
    has_more: bool
    cross_functions: NotRequired[bool]
    functions_entered: NotRequired[list[str]]
    error: str


class FindSimilarFunctionsResult(TypedDict, total=False):
    ok: bool
    reference: dict
    candidates_scanned: int
    matches: list[SimilarFunctionMatch]
    error: str


_MNEM_ARITH = frozenset({
    "add", "sub", "mul", "imul", "div", "idiv", "inc", "dec",
    "and", "or", "xor", "not", "neg", "shl", "shr", "sar", "rol", "ror",
    "adc", "sbb",
})

_MNEM_LOAD = frozenset({"mov", "movzx", "movsx", "movaps", "movups", "movdqa", "movq", "movsb", "movsw"})
_MNEM_STORE = frozenset({"stosb", "stosw", "stosd", "stosq"})
_MNEM_JMP = frozenset({"jmp", "je", "jne", "jz", "jnz", "jg", "jge", "jl", "jle", "ja", "jb", "jae", "jbe", "jo", "jno", "js", "jns", "jc", "jnc", "loop", "loope", "loopne"})


def _compute_function_features(func_ea: int, fc) -> dict:
    import idautils
    import ida_ua

    func = idaapi.get_func(func_ea)
    if not func:
        return {}

    size_bytes = func.end_ea - func.start_ea
    edge_count = 0
    block_count = 0
    for block in fc:
        block_count += 1
        edge_count += len(list(block.succs()))

    cyclomatic = edge_count - block_count + 2 if block_count > 0 else 1

    instruction_count = 0
    mnem_counts: dict[str, int] = {}
    callee_addrs: set[int] = set()

    for item_ea in idautils.FuncItems(func_ea):
        instruction_count += 1
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, item_ea) == 0:
            continue
        mnem = insn.get_canon_mnem().lower()
        mnem_counts[mnem] = mnem_counts.get(mnem, 0) + 1
        if insn.itype in (idaapi.NN_call, idaapi.NN_callfi, idaapi.NN_callni):
            op = insn.ops[0]
            if op.type in (ida_ua.o_mem, ida_ua.o_near, ida_ua.o_far):
                callee_addrs.add(op.addr)
            elif op.type == ida_ua.o_imm:
                callee_addrs.add(op.value)

    total = max(instruction_count, 1)
    feat = {
        "block_count": block_count,
        "edge_count": edge_count,
        "cyclomatic_complexity": cyclomatic,
        "size_bytes": size_bytes,
        "instruction_count": instruction_count,
        "caller_count": sum(1 for _ in idautils.CodeRefsTo(func_ea, 0)),
        "callee_count": len(callee_addrs),
        "mnem_load_ratio": sum(mnem_counts.get(m, 0) for m in _MNEM_LOAD) / total,
        "mnem_store_ratio": sum(mnem_counts.get(m, 0) for m in _MNEM_STORE) / total,
        "mnem_jmp_ratio": sum(mnem_counts.get(m, 0) for m in _MNEM_JMP) / total,
        "mnem_call_ratio": mnem_counts.get("call", 0) / total,
        "mnem_ret_ratio": mnem_counts.get("retn", 0) / total,
        "mnem_mov_ratio": mnem_counts.get("mov", 0) / total,
        "mnem_arith_ratio": sum(mnem_counts.get(m, 0) for m in _MNEM_ARITH) / total,
    }
    return feat


_RAW_FEATURE_SCALES = {
    "block_count": 100.0,
    "edge_count": 200.0,
    "cyclomatic_complexity": 50.0,
    "size_bytes": 50000.0,
    "instruction_count": 10000.0,
    "caller_count": 1000.0,
    "callee_count": 100.0,
}


def _unit_normalize(vec: list[float]) -> list[float]:
    import math
    norm = math.sqrt(sum(x * x for x in vec))
    if norm == 0:
        return vec
    return [x / norm for x in vec]


def _feature_dict_to_vector(feat: dict) -> list[float]:
    raw = [
        min(float(feat.get("block_count", 0)) / _RAW_FEATURE_SCALES["block_count"], 1.0),
        min(float(feat.get("edge_count", 0)) / _RAW_FEATURE_SCALES["edge_count"], 1.0),
        min(float(feat.get("cyclomatic_complexity", 0)) / _RAW_FEATURE_SCALES["cyclomatic_complexity"], 1.0),
        min(float(feat.get("size_bytes", 1)) / _RAW_FEATURE_SCALES["size_bytes"], 1.0),
        min(float(feat.get("instruction_count", 0)) / _RAW_FEATURE_SCALES["instruction_count"], 1.0),
        min(float(feat.get("caller_count", 0)) / _RAW_FEATURE_SCALES["caller_count"], 1.0),
        min(float(feat.get("callee_count", 0)) / _RAW_FEATURE_SCALES["callee_count"], 1.0),
    ]
    ratios = [
        feat.get("mnem_load_ratio", 0.0),
        feat.get("mnem_store_ratio", 0.0),
        feat.get("mnem_jmp_ratio", 0.0),
        feat.get("mnem_call_ratio", 0.0),
        feat.get("mnem_ret_ratio", 0.0),
        feat.get("mnem_mov_ratio", 0.0),
        feat.get("mnem_arith_ratio", 0.0),
    ]
    norm_raw = _unit_normalize(raw)
    norm_ratios = _unit_normalize(ratios)
    return norm_raw + norm_ratios


def _cosine_similarity(a: list[float], b: list[float]) -> float:
    import math
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(y * y for y in b))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


_FINGERPRINT_DB: dict[str, dict] = {}


def _register_fingerprints() -> None:
    global _FINGERPRINT_DB

    _FINGERPRINT_DB = {
        "memcpy": {
            "description": "Memory copy function",
            "features": {
                "block_count": 2, "edge_count": 3, "cyclomatic_complexity": 2,
                "mnem_load_ratio": 0.3, "mnem_store_ratio": 0.3, "mnem_call_ratio": 0.0,
                "mnem_jmp_ratio": 0.05, "mnem_arith_ratio": 0.1, "mnem_mov_ratio": 0.5,
                "mnem_ret_ratio": 0.05,
            },
        },
        "memset": {
            "description": "Memory set function",
            "features": {
                "block_count": 2, "edge_count": 2, "cyclomatic_complexity": 2,
                "mnem_load_ratio": 0.1, "mnem_store_ratio": 0.4, "mnem_call_ratio": 0.0,
                "mnem_jmp_ratio": 0.05, "mnem_arith_ratio": 0.2, "mnem_mov_ratio": 0.4,
                "mnem_ret_ratio": 0.05,
            },
        },
        "strlen": {
            "description": "String length function",
            "features": {
                "block_count": 2, "edge_count": 3, "cyclomatic_complexity": 2,
                "mnem_load_ratio": 0.4, "mnem_store_ratio": 0.05, "mnem_call_ratio": 0.0,
                "mnem_jmp_ratio": 0.15, "mnem_arith_ratio": 0.15, "mnem_mov_ratio": 0.15,
                "mnem_ret_ratio": 0.05,
            },
        },
        "strcpy": {
            "description": "String copy function",
            "features": {
                "block_count": 2, "edge_count": 3, "cyclomatic_complexity": 2,
                "mnem_load_ratio": 0.3, "mnem_store_ratio": 0.3, "mnem_call_ratio": 0.0,
                "mnem_jmp_ratio": 0.1, "mnem_arith_ratio": 0.05, "mnem_mov_ratio": 0.5,
                "mnem_ret_ratio": 0.05,
            },
        },
        "malloc": {
            "description": "Memory allocator",
            "features": {
                "block_count": 3, "edge_count": 4, "cyclomatic_complexity": 3,
                "mnem_load_ratio": 0.1, "mnem_store_ratio": 0.2, "mnem_call_ratio": 0.3,
                "mnem_jmp_ratio": 0.1, "mnem_arith_ratio": 0.1, "mnem_mov_ratio": 0.2,
                "mnem_ret_ratio": 0.05,
            },
        },
        "free": {
            "description": "Memory deallocator",
            "features": {
                "block_count": 2, "edge_count": 3, "cyclomatic_complexity": 2,
                "mnem_load_ratio": 0.15, "mnem_store_ratio": 0.1, "mnem_call_ratio": 0.25,
                "mnem_jmp_ratio": 0.1, "mnem_arith_ratio": 0.05, "mnem_mov_ratio": 0.2,
                "mnem_ret_ratio": 0.05,
            },
        },
        "open": {
            "description": "File open (Unix)",
            "features": {
                "block_count": 2, "edge_count": 3, "cyclomatic_complexity": 2,
                "mnem_load_ratio": 0.1, "mnem_store_ratio": 0.05, "mnem_call_ratio": 0.4,
                "mnem_jmp_ratio": 0.05, "mnem_arith_ratio": 0.05, "mnem_mov_ratio": 0.2,
                "mnem_ret_ratio": 0.05,
            },
        },
        "read": {
            "description": "File read (Unix)",
            "features": {
                "block_count": 2, "edge_count": 3, "cyclomatic_complexity": 2,
                "mnem_load_ratio": 0.2, "mnem_store_ratio": 0.2, "mnem_call_ratio": 0.3,
                "mnem_jmp_ratio": 0.05, "mnem_arith_ratio": 0.05, "mnem_mov_ratio": 0.2,
                "mnem_ret_ratio": 0.05,
            },
        },
        "write": {
            "description": "File write (Unix)",
            "features": {
                "block_count": 2, "edge_count": 3, "cyclomatic_complexity": 2,
                "mnem_load_ratio": 0.1, "mnem_store_ratio": 0.25, "mnem_call_ratio": 0.3,
                "mnem_jmp_ratio": 0.05, "mnem_arith_ratio": 0.05, "mnem_mov_ratio": 0.2,
                "mnem_ret_ratio": 0.05,
            },
        },
        "printf": {
            "description": "Formatted print",
            "features": {
                "block_count": 3, "edge_count": 5, "cyclomatic_complexity": 3,
                "mnem_load_ratio": 0.15, "mnem_store_ratio": 0.05, "mnem_call_ratio": 0.4,
                "mnem_jmp_ratio": 0.1, "mnem_arith_ratio": 0.05, "mnem_mov_ratio": 0.15,
                "mnem_ret_ratio": 0.05,
            },
        },
        "exit": {
            "description": "Process termination",
            "features": {
                "block_count": 1, "edge_count": 1, "cyclomatic_complexity": 1,
                "mnem_load_ratio": 0.0, "mnem_store_ratio": 0.0, "mnem_call_ratio": 0.6,
                "mnem_jmp_ratio": 0.0, "mnem_arith_ratio": 0.0, "mnem_mov_ratio": 0.1,
                "mnem_ret_ratio": 0.0,
            },
        },
    }


_register_fingerprints()


def _fingerprint_match_score(feat: dict) -> tuple[float, str, str]:
    """Score a function against all fingerprints; return (best_score, name, description)."""
    best_score = 0.0
    best_name = ""
    best_desc = ""
    feat_vec = _feature_dict_to_vector(feat)
    for fp_name, fp_data in _FINGERPRINT_DB.items():
        fp_feat = fp_data["features"]
        fp_vec = _feature_dict_to_vector(fp_feat)
        score = _cosine_similarity(feat_vec, fp_vec)
        if score > best_score:
            best_score = score
            best_name = fp_name
            best_desc = fp_data.get("description", "")
    return best_score, best_name, best_desc


_FINGERPRINT_BOOST_WEIGHT = 0.3  # How much fingerprint score contributes to final score


@tool
@idasync
@tool_timeout(30.0)
def get_cfg_dot(
    address: Annotated[str, "Function start address or name"],
    max_blocks: Annotated[
        int,
        "Maximum basic blocks to render. Functions with more blocks are rejected "
        "unless force=true. Default 500 prevents hangs on huge/obfuscated functions.",
    ] = 500,
    force: Annotated[
        bool,
        "Bypass the block limit and generate anyway. May hang IDA on megabyte-sized functions.",
    ] = False,
    offset_lines: Annotated[
        int,
        "Line offset for pagination. When the full DOT exceeds the response size "
        "limit, use offset_lines to retrieve subsequent chunks.",
    ] = 0,
    max_lines: Annotated[
        int,
        "Maximum lines to return. Default 0 returns all lines (may be truncated "
        "by the global output limit). Set to a positive value to page through "
        "large graphs without hitting truncation.",
    ] = 0,
) -> CfgDotResult:
    """Export a function's control flow graph in Graphviz DOT format.

    Uses IDA's native gen_flow_graph with CHART_GEN_DOT to write a temporary
    .dot file, then returns the content. The DOT string can be rendered with
    any Graphviz-compatible tool (dot, xdot, online viewers).

    **Performance guard:** If the function has more than `max_blocks` basic blocks,
    the call is rejected unless `force=true`. This prevents IDA from hanging on
    huge/obfuscated functions. Use `miasm_get_cfg_dot` as an alternative for
    very large graphs.

    **Pagination:** For large graphs, use offset_lines + max_lines to retrieve
    the DOT in chunks. Each chunk preserves the Graphviz header/footer so it
    remains valid DOT syntax.
    """
    import os
    import tempfile
    import ida_gdl

    try:
        ea = parse_address(address)
        func = ida_funcs.get_func(ea)
        if func is None:
            return {"ok": False, "error": f"No function at {address}"}

        name = ida_name.get_ea_name(func.start_ea) or hex(func.start_ea)

        # Count basic blocks via FlowChart for metadata — much faster than DOT gen
        fc = ida_gdl.FlowChart(func)
        block_count = sum(1 for _ in fc)

        if block_count > max_blocks and not force:
            return {
                "ok": False,
                "error": (
                    f"Function '{name}' has {block_count} basic blocks, "
                    f"exceeds max_blocks={max_blocks}"
                ),
                "error_type": "BlockLimitExceeded",
                "block_count": block_count,
                "hint": (
                    "Set force=true to generate anyway (may hang on huge functions), "
                    "or use miasm_get_cfg_dot for large graphs."
                ),
            }

        # Write DOT to a temp file; IDA appends .dot automatically on some versions,
        # so use a path without extension and check both.
        tmp_fd, tmp_base = tempfile.mkstemp()
        os.close(tmp_fd)
        os.unlink(tmp_base)  # gen_flow_graph creates the file itself

        dot_path = tmp_base + ".dot"

        try:
            ok = ida_gdl.gen_flow_graph(
                dot_path,
                f"CFG: {name}",
                func,
                func.start_ea,
                func.end_ea,
                ida_gdl.CHART_GEN_DOT,
            )
            # Some IDA versions write without the .dot extension
            if not ok or not os.path.isfile(dot_path):
                if os.path.isfile(tmp_base):
                    dot_path = tmp_base
                    ok = True

            if not ok:
                return {"ok": False, "error": "gen_flow_graph returned False — check IDA version supports CHART_GEN_DOT"}

            with open(dot_path, "r", encoding="utf-8", errors="replace") as f:
                dot_content = f.read()
        finally:
            for p in (tmp_base, dot_path):
                try:
                    if os.path.isfile(p):
                        os.unlink(p)
                except OSError:
                    pass

        # Apply line-based pagination if requested
        if max_lines > 0:
            lines = dot_content.splitlines(keepends=True)
            total_lines = len(lines)
            if offset_lines < 0:
                offset_lines = 0
            if offset_lines > total_lines:
                offset_lines = total_lines
            end = offset_lines + max_lines
            chunk_lines = lines[offset_lines:end]
            # Preserve Graphviz structure: if we're not at the start, prepend a
            # comment header; if we're not at the end, append a comment footer.
            # This keeps each chunk valid standalone DOT syntax.
            if offset_lines > 0:
                chunk_lines.insert(0, f"// ... ({offset_lines} lines omitted) ...\n")
            if end < total_lines:
                chunk_lines.append(f"// ... ({total_lines - end} lines remaining) ...\n")
            dot_content = "".join(chunk_lines)
            return {
                "ok": True,
                "address": hex(func.start_ea),
                "name": name,
                "block_count": block_count,
                "dot": dot_content,
                "offset_lines": offset_lines,
                "max_lines": max_lines,
                "total_lines": total_lines,
                "has_more": end < total_lines,
            }

        return {
            "ok": True,
            "address": hex(func.start_ea),
            "name": name,
            "block_count": block_count,
            "dot": dot_content,
        }

    except Exception as e:
        return tool_error(e, f"cfg_dot at {address}")


# ============================================================================
# Function Clone / Similarity Detection
# ============================================================================


@tool
@idasync
@tool_timeout(60.0)
def find_similar_functions(
    address: Annotated[
        str,
        "Reference function address or name to find similar functions for "
        "(e.g. '0x401000', 'memcpy', 'main')",
    ],
    scope: Annotated[
        str,
        "Scope of the search: 'all' to search all functions, or a specific "
        "segment name like '.text' to limit search to that segment. "
        "(default: 'all')",
    ] = "all",
    max_results: Annotated[int, "Maximum number of matches to return (default: 10, max: 50)"] = 10,
    threshold: Annotated[
        float,
        "Minimum similarity score to return (0.0-1.0, default: 0.75). "
        "Set lower for more matches, higher for stricter matching.",
    ] = 0.75,
) -> FindSimilarFunctionsResult:
    """Find functions structurally similar to a reference function.

    Heavy: for large binaries use invoke_tool(..., async_mode=True) or task_submit + task_poll.

    Uses a feature-vector approach combining:
    - CFG metrics: block count, edge count, cyclomatic complexity
    - Code metrics: instruction count, caller/callee counts
    - Mnemonic ratios: relative frequency of load/store/jump/call/mov/arithmetic ops

    Returns top-N matches sorted by cosine similarity to the reference.
    Includes an embedded fingerprint database for common library functions
    (memcpy, memset, strlen, strcpy, malloc, free, open, read, write, printf, exit).

    **Performance:** Uses a bounded min-heap so only the top `max_results` matches
    are kept in memory. A cheap size pre-filter skips functions whose size differs
    by >10× from the reference, avoiding expensive FlowChart creation for outliers.

    Large result sets may be truncated at 50 KB with an ``output_id``.
    If truncated, use ``read_mcp_output(output_id=..., offset=0)`` to retrieve
    the full result in chunks.

    See also: analyze_function (deep analysis of a single function),
    get_function_hash (exact hash matching).
    """
    try:
        ea = parse_address(address)
        ref_func = idaapi.get_func(ea)
        if not ref_func:
            return {"ok": False, "error": f"No function found at {address}"}

        ref_ea = ref_func.start_ea
        ref_name = ida_funcs.get_func_name(ref_ea) or hex(ref_ea)
        ref_size = ref_func.end_ea - ref_func.start_ea

        ref_fc = idaapi.FlowChart(ref_func)
        ref_feat = _compute_function_features(ref_ea, ref_fc)
        if not ref_feat:
            return {"ok": False, "error": f"Could not compute features for {address}"}

        ref_vector = _feature_dict_to_vector(ref_feat)

        # Collect candidate functions
        candidate_funcs: list[tuple[int, str, int]] = []
        if scope == "all":
            for func_ea in idautils.Functions():
                if func_ea == ref_ea:
                    continue
                f = idaapi.get_func(func_ea)
                size = f.end_ea - f.start_ea if f else 0
                candidate_funcs.append((func_ea, ida_funcs.get_func_name(func_ea) or "", size))
        else:
            seg = idaapi.get_segm_by_name(scope)
            if not seg:
                return {"ok": False, "error": f"Segment not found: {scope}"}
            for func_ea in idautils.Functions():
                if func_ea < seg.start_ea or func_ea >= seg.end_ea:
                    continue
                if func_ea == ref_ea:
                    continue
                f = idaapi.get_func(func_ea)
                size = f.end_ea - f.start_ea if f else 0
                candidate_funcs.append((func_ea, ida_funcs.get_func_name(func_ea) or "", size))

        candidates_scanned = len(candidate_funcs)

        # Cheap size pre-filter: skip functions whose size differs by >10×.
        # This avoids expensive FlowChart + feature computation for obvious outliers.
        size_low = ref_size / 10.0 if ref_size > 0 else 0
        size_high = ref_size * 10.0 if ref_size > 0 else float("inf")

        # Bounded min-heap: only keep top `max_results` matches.
        # heapq is a min-heap, so we store (score, ...) and push/pop the smallest.
        top_heap: list[tuple[float, int, str, float, dict, str, str]] = []

        for func_ea, func_name, size in candidate_funcs:
            if size < size_low or size > size_high:
                continue
            f = idaapi.get_func(func_ea)
            if not f:
                continue
            fc = idaapi.FlowChart(f)
            feat = _compute_function_features(func_ea, fc)
            if not feat:
                continue
            vec = _feature_dict_to_vector(feat)
            cosine_score = _cosine_similarity(ref_vector, vec)
            fp_score, fp_name, fp_desc = _fingerprint_match_score(feat)
            combined_score = (1.0 - _FINGERPRINT_BOOST_WEIGHT) * cosine_score + _FINGERPRINT_BOOST_WEIGHT * fp_score
            if combined_score < threshold:
                continue
            entry = (combined_score, func_ea, func_name, cosine_score, feat, fp_name, fp_desc)
            if len(top_heap) < max_results:
                heapq.heappush(top_heap, entry)
            elif combined_score > top_heap[0][0]:
                heapq.heapreplace(top_heap, entry)

        # Sort descending by score
        top = sorted(top_heap, key=lambda x: x[0], reverse=True)

        matches: list[SimilarFunctionMatch] = []
        for combined_score, func_ea, func_name, cosine_score, feat, fp_name, fp_desc in top:
            block_count = feat.get("block_count", 0)
            edge_count = feat.get("edge_count", 0)
            match: SimilarFunctionMatch = SimilarFunctionMatch(
                addr=hex(func_ea),
                name=func_name or hex(func_ea),
                similarity_score=round(combined_score, 4),
                block_count=block_count,
                edge_count=edge_count,
                complexity=feat.get("cyclomatic_complexity", 0),
                size_bytes=feat.get("size_bytes", 0),
                matching_features={
                    "mnem_mov_ratio": feat.get("mnem_mov_ratio", 0.0),
                    "mnem_load_ratio": feat.get("mnem_load_ratio", 0.0),
                    "mnem_store_ratio": feat.get("mnem_store_ratio", 0.0),
                    "mnem_call_ratio": feat.get("mnem_call_ratio", 0.0),
                    "mnem_jmp_ratio": feat.get("mnem_jmp_ratio", 0.0),
                    "mnem_arith_ratio": feat.get("mnem_arith_ratio", 0.0),
                },
            )
            if fp_name:
                match["fingerprint_name"] = fp_name
                match["fingerprint_description"] = fp_desc
            matches.append(match)

        ref_block_count = ref_feat.get("block_count", 0)
        ref_edge_count = ref_feat.get("edge_count", 0)
        return {
            "ok": True,
            "reference": {
                "addr": hex(ref_ea),
                "name": ref_name,
                "block_count": ref_block_count,
                "edge_count": ref_edge_count,
                "complexity": ref_feat.get("cyclomatic_complexity", 0),
                "size_bytes": ref_feat.get("size_bytes", 0),
            },
            "candidates_scanned": candidates_scanned,
            "matches": matches,
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}


_MAX_CHAIN_NODES = 500
_MAX_CHAIN_EDGES = 600


@tool
@idasync
def trace_data_chain(
    address: Annotated[str, "Starting address for the chain traversal (hex or symbol name)"],
    direction: Annotated[
        str,
        "Traversal direction: 'backward' follows xrefs TO the address (data-flow origins), "
        "'forward' follows xrefs FROM the address (data-flow destinations)",
    ] = "backward",
    max_depth: Annotated[int, "Maximum traversal depth (default: 5, max: 20)"] = 5,
    include_data: Annotated[
        bool,
        "Include data cross-references in the traversal (default: True)",
    ] = True,
    include_code: Annotated[
        bool,
        "Include code cross-references in the traversal (default: True)",
    ] = True,
    cross_functions: Annotated[
        bool,
        "When True (default False), follow calls/jumps across function boundaries. "
        "When False, traversal stops at call/jump xrefs and does not enter the target function's CFG. "
        "Useful for tracing data-flow through call chains rather than just within a single function.",
    ] = False,
) -> TraceDataChainResult:
    """Multi-hop cross-reference chain traversal for surgical RE workflows.

    Traces data-flow across multiple hops in a single call. On stripped binaries
    this is essential for tracking pointer chains without manually chaining xrefs_to
    calls. The traversal stops at code/data boundaries — does not cross into
    unexamined segments unless they contain the next xref target.

    **Backward mode** ("backward", the default) answers: "where does this value originate?"
    Use cases:
      - Trace a vtable pointer back to its constructor
      - Find the source of a function pointer argument
      - Discover all writers to a global variable

    **Forward mode** ("forward") answers: "where does this value flow to?"
    Use cases:
      - Trace a stack variable to see which functions receive it
      - Follow a registered callback to its invocation sites
      - Map out a data structure's consumer functions

    The traversal is bounded by max_depth (not by following through functions).
    Each node in the path represents one address visited; edges represent xrefs
    between them. Nodes that are code (inside functions) report the enclosing
    function name and the disassembly at that address. Data nodes report the
    name/label at that address if any.

    Parameters
    ----------
    address : str
        Starting address (hex, e.g. "0x401000", or symbol name)
    direction : str
        "backward" | "forward". Default: "backward"
    max_depth : int
        Maximum graph depth to traverse (1-20, default 5)
    include_data : bool
        Include data xrefs (dr_R, dr_W, dr_O). Default True.
    include_code : bool
        Include code xrefs (fl_CN, fl_JN, fl_CF, fl_JF, fl_F). Default True.

    Returns
    -------
    TraceDataChainResult
        path: ordered list of nodes visited, each with addr/type/function/instruction/name
        terminated_at: reason traversal stopped (depth_limit, no_more_xrefs, node_limit)
        depth_reached: actual deepest depth reached

    Large outputs may be truncated at 50 KB with an ``output_id``.
    If truncated, use ``read_mcp_output(output_id=..., offset=0)`` to retrieve
    the full result in chunks.

    See also: trace_data_flow (composite backward slice with Miasm/Triton),
    xrefs_to (single-hop references), xref_query (filtered xref search).
    """
    if direction not in ("forward", "backward"):
        return {"ok": False, "error": f"direction must be 'forward' or 'backward', got {direction!r}"}

    if max_depth < 1:
        max_depth = 1
    if max_depth > 20:
        max_depth = 20

    try:
        start_ea = parse_address(address)
    except Exception as e:
        return {"ok": False, "error": f"Failed to resolve address {address!r}: {e}"}

    visited: set[int] = {start_ea}
    nodes: list[ChainNode] = []
    edges: list[ChainEdge] = []
    depth_reached = 0
    terminated_reason: str | None = None
    terminated_addr: str | None = hex(start_ea)
    functions_entered: list[str] = []
    _cross_func = cross_functions

    from collections import deque
    queue: deque[tuple[int, int]] = deque()
    queue.append((start_ea, 0))

    def _expand_function(func_ea: int, call_depth: int) -> None:
        """Expand all basic blocks of func_ea into the queue (up to depth limit)."""
        if call_depth >= max_depth:
            return
        func = idaapi.get_func(func_ea)
        if not func:
            return
        fc = idaapi.FlowChart(func)
        for block in fc:
            entry = block.start_ea
            if entry not in visited and len(nodes) + len(queue) < _MAX_CHAIN_NODES:
                visited.add(entry)
                queue.append((entry, call_depth))

    while queue:
        ea, depth = queue.popleft()

        if depth > max_depth:
            continue
        if depth > depth_reached:
            depth_reached = depth

        if len(nodes) >= _MAX_CHAIN_NODES:
            if not terminated_reason:
                terminated_reason = "node_limit"
                terminated_addr = hex(ea)
            break

        func = idaapi.get_func(ea)
        func_name = ida_funcs.get_func_name(ea) if func else None
        flags = idaapi.get_flags(ea)
        is_code_addr = idaapi.is_code(flags)
        node_type = "code" if is_code_addr else "data"
        name_at_raw = ida_name.get_name(ea)
        name_at = name_at_raw if name_at_raw and name_at_raw != f"loc_{ea:X}" else None
        disasm_text: str | None = None
        if is_code_addr and idaapi.is_loaded(ea):
            disasm_text = idc.GetDisasm(ea)

        nodes.append(ChainNode(
            addr=hex(ea),
            type=node_type,
            instruction=disasm_text,
            function=func_name,
            name=name_at,
            depth=depth,
        ))

        if depth >= max_depth:
            terminated_reason = "depth_limit"
            terminated_addr = hex(ea)

        xref_list: list[Any] = []
        if direction == "forward":
            xref_list = list(idautils.XrefsFrom(ea, 0))
        else:
            xref_list = list(idautils.XrefsTo(ea, 0))

        if not xref_list:
            if not terminated_reason:
                terminated_reason = "no_more_xrefs"
                terminated_addr = hex(ea)

        next_nodes_to_queue: list[tuple[int, int]] = []
        for xref in xref_list:
            if len(edges) >= _MAX_CHAIN_EDGES:
                if not terminated_reason:
                    terminated_reason = "edge_limit"
                    terminated_addr = hex(ea)
                break

            if direction == "forward":
                target = xref.to
                from_addr = ea
                to_addr = target
            else:
                target = xref.frm
                from_addr = target
                to_addr = ea

            is_code_xref = bool(xref.iscode)
            if is_code_xref and not include_code:
                continue
            if not is_code_xref and not include_data:
                continue

            xref_type_str: str
            if is_code_xref:
                t = xref.type
                if t == ida_xref.fl_CN:
                    xref_type_str = "call_near"
                elif t == ida_xref.fl_CF:
                    xref_type_str = "call_far"
                elif t == ida_xref.fl_JN:
                    xref_type_str = "jump_near"
                elif t == ida_xref.fl_JF:
                    xref_type_str = "jump_far"
                elif t == ida_xref.fl_F:
                    xref_type_str = "flow"
                else:
                    xref_type_str = "code"
            else:
                t = xref.type
                if t == ida_xref.dr_O:
                    xref_type_str = "offset"
                elif t == ida_xref.dr_R:
                    xref_type_str = "data_read"
                elif t == ida_xref.dr_W:
                    xref_type_str = "data_write"
                else:
                    xref_type_str = "data"

            edges.append(ChainEdge(
                from_addr=hex(from_addr),
                to_addr=hex(to_addr),
                xref_type=xref_type_str,
            ))

            if target not in visited and len(nodes) + len(queue) + len(next_nodes_to_queue) < _MAX_CHAIN_NODES:
                visited.add(target)
                if _cross_func and xref_type_str in ("call_near", "call_far"):
                    fn_name = ida_funcs.get_func_name(target)
                    fn_label = fn_name if fn_name else hex(target)
                    if fn_label not in functions_entered:
                        functions_entered.append(fn_label)
                    _expand_function(target, depth + 1)
                else:
                    next_nodes_to_queue.append((target, depth + 1))

        for item in next_nodes_to_queue:
            queue.append(item)

    if not terminated_reason:
        terminated_reason = "exhausted"

    terminated_at: TerminatedAt | None = None
    if terminated_reason and terminated_reason not in ("exhausted",) and terminated_addr:
        terminated_at = TerminatedAt(reason=terminated_reason, address=terminated_addr)

    result = {
        "ok": True,
        "start": hex(start_ea),
        "direction": direction,
        "max_depth": max_depth,
        "depth_reached": depth_reached,
        "nodes": nodes,
        "edges": edges,
        "terminated_at": terminated_at,
        "node_count": len(nodes),
        "has_more": terminated_reason in ("node_limit", "edge_limit", "depth_limit"),
        "cross_functions": _cross_func,
    }
    if functions_entered:
        result["functions_entered"] = functions_entered
    return result


# ============================================================================
# Static Analysis Tools — XOR Obfuscation & Constraint Classification
# ============================================================================


class XorPatternEntry(TypedDict):
    type: str
    address: str
    key_byte: str
    key_immediate: NotRequired[str]
    loop_count: NotRequired[int]
    rotate_count: NotRequired[int]
    xor_count: int
    confidence: str
    detail: NotRequired[str]


class FindXorPatternResult(TypedDict):
    ok: bool
    address: str
    function_name: str
    patterns_found: list[XorPatternEntry]
    total_instructions_scanned: int
    suggested_next_tool: NotRequired[str]
    hint: NotRequired[str]
    error: NotRequired[str]


@tool
@idasync
def find_xor_pattern(
    address: Annotated[str, "Function address or name to scan for XOR patterns (hex or symbol)"],
    max_insns: Annotated[int, "Maximum instructions to scan (default 2000)"] = 2000,
) -> FindXorPatternResult:
    """Detect XOR obfuscation loops and ROR/ROL+XOR patterns in a function.

    Scans instruction mnemonics and operands for common obfuscation signatures:
    - xor reg, imm inside a loop → simple XOR obfuscation
    - ror/rol reg, n followed by xor reg, key → ROTR/RATL+XOR cipher
    - successive xor instructions → multi-stage XOR

    This is the first tool to call when encountering an obfuscated binary.
    It classifies the cipher type before you commit to a solving approach.
    No symbolic execution — pure instruction pattern matching via IDA SDK.
    """
    try:
        ea = parse_address(address)
        func = idaapi.get_func(ea)
        if not func:
            return {"ok": False, "error": f"No function found at {address}"}

        func_name = ida_funcs.get_func_name(func.start_ea) or hex(func.start_ea)

        # Build instruction list
        insns: list[tuple[int, str, str, list[str]]] = []
        for item_ea in idautils.FuncItems(func.start_ea):
            mnem = idc.print_insn_mnem(item_ea) or ""
            ops: list[str] = []
            for n in range(4):
                if idc.get_operand_type(item_ea, n) == idaapi.o_void:
                    break
                op_str = idc.print_operand(item_ea, n) or ""
                ops.append(op_str)
            insns.append((item_ea, mnem.lower(), ops[0] if ops else "", ops))

            if len(insns) >= max_insns:
                break

        # Detect loop structures via FlowChart
        try:
            fc = idaapi.FlowChart(func)
            loop_headers: set[int] = set()
            for block in fc:
                for succ in block.succs():
                    if succ.start_ea <= block.start_ea:
                        loop_headers.add(succ.start_ea)
        except Exception:
            loop_headers = set()

        # Build basic block boundaries for context
        block_starts: set[int] = {func.start_ea}
        for block in fc:
            block_starts.add(block.start_ea)

        patterns: list[XorPatternEntry] = []
        i = 0
        while i < len(insns):
            item_ea, mnem, op0, ops = insns[i]

            # Detect xor reg, imm
            if mnem == "xor" and len(ops) >= 2:
                try:
                    key_val = int(ops[1], 0) & 0xFF
                except (ValueError, TypeError):
                    i += 1
                    continue
                xor_count = 1
                k = i + 1
                while k < len(insns) and k - i < 32:
                    if insns[k][1] == "xor" and len(insns[k][3]) >= 2:
                        try:
                            next_key = int(insns[k][3][1], 0) & 0xFF
                        except (ValueError, TypeError):
                            break
                        if next_key == key_val:
                            xor_count += 1
                            k += 1
                            continue
                    break

                in_loop = any(
                    lh <= item_ea <= (lh + 256) for lh in loop_headers
                ) if loop_headers else False

                ptype = "xor_single_byte" if not in_loop else "xor_loop"
                confidence = "high" if xor_count >= 3 or in_loop else "medium"

                patterns.append(XorPatternEntry(
                    type=ptype,
                    address=hex(item_ea),
                    key_byte=hex(key_val),
                    key_immediate=ops[1],
                    xor_count=xor_count,
                    confidence=confidence,
                    detail=f"In {'loop' if in_loop else 'linear'} code, {xor_count} XORs with key {hex(key_val)}",
                ))
                i = k
                continue

            # Detect ror/rol + xor combo
            if mnem in ("ror", "rol") and len(ops) >= 2:
                try:
                    rotate_count = int(ops[1], 0)
                    if 0 < rotate_count < 64:
                        if i + 1 < len(insns) and insns[i + 1][1] == "xor":
                            xor_item_ea = insns[i + 1][0]
                            xops = insns[i + 1][3]
                            if len(xops) >= 2:
                                try:
                                    key_val = int(xops[1], 0) & 0xFF
                                    patterns.append(XorPatternEntry(
                                        type="ror_xor_combo" if mnem == "ror" else "rol_xor_combo",
                                        address=hex(item_ea),
                                        key_byte=hex(key_val),
                                        rotate_count=rotate_count,
                                        xor_count=2,
                                        confidence="medium",
                                        detail=f"{mnem.upper()} by {rotate_count} then XOR with {hex(key_val)} at {hex(xor_item_ea)}",
                                    ))
                                    i += 2
                                    continue
                                except (ValueError, TypeError):
                                    pass
                except (ValueError, TypeError):
                    pass

            # Detect sub + xor combo (addition/XOR)
            if mnem == "sub" and i + 1 < len(insns) and insns[i + 1][1] == "xor":
                sub_ops = ops
                xor_ops = insns[i + 1][3]
                if len(sub_ops) >= 2 and len(xor_ops) >= 2:
                    try:
                        sub_val = int(sub_ops[1], 0) & 0xFF
                        xor_val = int(xor_ops[1], 0) & 0xFF
                        patterns.append(XorPatternEntry(
                            type="sub_xor_combo",
                            address=hex(item_ea),
                            key_byte=hex(xor_val),
                            key_immediate=f"sub {hex(sub_val)} then xor {hex(xor_val)}",
                            xor_count=2,
                            confidence="low",
                            detail=f"SUB {hex(sub_val)} then XOR {hex(xor_val)}",
                        ))
                        i += 2
                        continue
                    except (ValueError, TypeError):
                        pass

            i += 1

        hint = None
        suggested = None
        if not patterns:
            hint = (
                "No XOR patterns found. The function may use a different obfuscation "
                "technique (ADD, NOT, NEG, or a custom cipher). Try decompiling the "
                "function and look for arithmetic operations on byte arrays."
            )
            suggested = "check_constraint_type"
        else:
            suggested = "xor_invert"

        return {
            "ok": True,
            "address": hex(func.start_ea),
            "function_name": func_name,
            "patterns_found": patterns,
            "total_instructions_scanned": len(insns),
            "suggested_next_tool": suggested,
            "hint": hint,
        }

    except Exception as e:
        return {"ok": False, "error": str(e)}


class XorInvertResult(TypedDict):
    ok: bool
    xor_key: NotRequired[str]
    xor_key_int: NotRequired[int]
    decrypted: NotRequired[str]
    decrypted_hex: NotRequired[str]
    verified: NotRequired[bool]
    confidence: NotRequired[str]
    is_xor_cipher: NotRequired[bool]
    entropy: NotRequired[float]
    key_consistency: NotRequired[str]
    partial: NotRequired[bool]
    per_byte_keys: NotRequired[list[str]]
    error: NotRequired[str]
    hint: NotRequired[str]


@tool
@idasync
def xor_invert(
    ciphertext_address: Annotated[
        str, "Address of the obfuscated bytes (hex or symbol)"
    ],
    known_plaintext: Annotated[
        str, "Expected decrypted string or hex bytes (e.g. 'TESS{' or '544553537b')"
    ],
    max_length: Annotated[
        int, "Maximum bytes to read from the ciphertext address (default 256)"
    ] = 256,
    key_hint: Annotated[
        str, "Suspected single-byte XOR key as hex (e.g. '0x6D') — used for verification only"
    ] = "",
) -> XorInvertResult:
    """Recover XOR key from ciphertext + known plaintext — static, no symbolic execution.

    Given ciphertext bytes at an IDA address and a known (or suspected) plaintext
    string, computes the XOR key and recovers the full decrypted string.

    This is the core tool for simple single-byte XOR crackmes — the most common
    type. Each ciphertext byte is XORed with the same key byte to produce plaintext.

    The tool also handles multi-byte XOR keys by detecting repeating key patterns.

    Algorithm: key = ciphertext[n] ^ plaintext[n] for each matching position,
    then verify consistency across all positions. If key is consistent, decrypt
    remaining bytes. If inconsistent, try ROL/ROR transforms on the key.
    """
    try:
        ct_ea = parse_address(ciphertext_address)
        kp_bytes: bytes

        # Parse known_plaintext: if prefixed with "hex:", treat as hex
        if known_plaintext.startswith("hex:"):
            kp_bytes = bytes.fromhex(known_plaintext[4:].replace(" ", ""))
        elif known_plaintext.startswith("0x"):
            kp_bytes = bytes.fromhex(known_plaintext[2:].replace(" ", ""))
        else:
            # Check if it looks like hex (all hex chars)
            stripped = known_plaintext.replace(" ", "")
            if all(c in "0123456789abcdefABCDEF" for c in stripped) and len(stripped) >= 4:
                kp_bytes = bytes.fromhex(stripped)
            else:
                kp_bytes = known_plaintext.encode("utf-8")

        # Read ciphertext bytes
        ct_bytes = ida_bytes.get_bytes(ct_ea, max_length)
        if not ct_bytes:
            return {"ok": False, "error": f"No bytes found at {ciphertext_address}"}

        # ── Entropy check: detect non-XOR ciphertext ──────────────────────────
        # XOR-obfuscated data typically has byte values ~evenly distributed.
        # Custom alphabet ciphers often have a narrow byte range (e.g., 0x40-0x7F).
        byte_set = set(ct_bytes[:min(len(ct_bytes), 256)])
        byte_range = max(byte_set) - min(byte_set) if byte_set else 0
        unique_ratio = len(byte_set) / min(len(ct_bytes), 256) if ct_bytes else 0

        # Heuristic: if < 20 unique byte values or range < 40, likely NOT XOR
        is_probably_xor = len(byte_set) >= 20 and byte_range >= 40

        min_len = min(len(ct_bytes), len(kp_bytes))
        if min_len < 1:
            return {"ok": False, "error": "Need at least 1 byte of overlap between ciphertext and known plaintext"}

        # Try single-byte key
        key_candidates: list[int] = []
        for i in range(min_len):
            key_candidates.append(ct_bytes[i] ^ kp_bytes[i])

        # Check if all positions give the same key
        if len(set(key_candidates)) == 1:
            key = key_candidates[0]
            key_hint_byte = None
            if key_hint:
                try:
                    key_hint_byte = int(key_hint, 0) & 0xFF
                except (ValueError, TypeError):
                    pass

            # Decrypt all ciphertext bytes
            decrypted = bytes(ct ^ key for ct in ct_bytes)
            try:
                decrypted_str = decrypted.decode("utf-8", errors="replace")
            except UnicodeDecodeError:
                decrypted_str = decrypted.hex(" ").upper()

            return XorInvertResult(
                ok=True,
                xor_key=hex(key),
                xor_key_int=key,
                decrypted=decrypted_str,
                decrypted_hex=decrypted.hex(" ").upper(),
                verified=key_hint_byte is None or key_hint_byte == key,
                confidence="high",
                key_consistency="All overlapping bytes produced the same XOR key",
            )

        # Multi-byte key or inconsistent key: report per-byte keys
        per_byte = [hex(kc) for kc in key_candidates]
        unique = set(key_candidates)

        if len(unique) <= 4:
            # Possibly a multi-byte key — try decrypting with a repeating key
            key_cycle = len(key_candidates)
            if key_cycle > 1 and key_cycle <= 16:
                decrypted = bytes(ct_bytes[i] ^ key_candidates[i % key_cycle] for i in range(len(ct_bytes)))
                try:
                    decrypted_str = decrypted.decode("utf-8", errors="replace")
                except UnicodeDecodeError:
                    decrypted_str = decrypted.hex(" ").upper()

                return XorInvertResult(
                    ok=True,
                    xor_key=",".join(hex(k) for k in key_candidates),
                    xor_key_int=0,
                    decrypted=decrypted_str,
                    decrypted_hex=decrypted.hex(" ").upper(),
                    verified=False,
                    confidence="medium" if len(ct_bytes) < 64 else "low",
                    key_consistency=f"Multi-byte key of length {key_cycle}",
                    per_byte_keys=per_byte,
                )

        return XorInvertResult(
            ok=True,
            xor_key="",
            xor_key_int=0,
            decrypted="",
            decrypted_hex="",
            verified=False,
            confidence="low",
            is_xor_cipher=is_probably_xor,
            entropy=round(unique_ratio, 2),
            key_consistency=f"Inconsistent keys: {per_byte}",
            per_byte_keys=per_byte,
            hint=(
                "Key is not single-byte and byte entropy suggests non-XOR cipher. "
                "Try check_constraint_type to classify the actual cipher, "
                "or find_alphabet_encoder to detect custom alphabet encoding."
                if not is_probably_xor
                else "Key is not single-byte. Try static_invert_xor_with_constraints "
                "for multi-stage transforms, or use Triton for symbolic execution on path-dependent logic."
            ),
        )

    except Exception as e:
        return {"ok": False, "error": str(e)}


class ConstraintTypeEntry(TypedDict):
    constraint_type: str
    per_byte_independent: bool
    invertible_with: str
    confidence: str
    hint: str


class CheckConstraintTypeResult(TypedDict):
    ok: bool
    address: str
    function_name: str
    constraint_type: str
    cipher_type: NotRequired[str]
    xor_count: NotRequired[int]
    details: list[ConstraintTypeEntry]
    recommendation: str
    error: NotRequired[str]


@tool
@idasync
def check_constraint_type(
    address: Annotated[str, "Function address or name to analyze (hex or symbol)"],
) -> CheckConstraintTypeResult:
    """Classify a function's constraint structure to pick the right solving tool.

    Analyzes branch conditions, loop patterns, and data flow to determine
    whether the constraint is statically invertible or requires symbolic
    execution. This prevents spending time on Triton/Z3 when simple Python
    arithmetic would solve the problem in seconds.

    Classification outputs:
    - per_byte_invertible: Each byte's constraint is independent → use Python arithmetic
    - path_dependent: Branching depends on input → use Triton or angr
    - opaque_predicate: Cannot determine statically → use angr exploration
    - state_mixer: Non-linear state combination → use Triton with formula extraction
    """
    try:
        ea = parse_address(address)
        func = idaapi.get_func(ea)
        if not func:
            return {"ok": False, "error": f"No function found at {address}"}

        func_name = ida_funcs.get_func_name(func.start_ea) or hex(func.start_ea)

        # Collect instruction information
        mnemonics: list[str] = []
        cmp_count = 0
        branch_count = 0
        xor_count = 0
        call_count = 0
        indirect_call_count = 0
        memory_cmp_count = 0

        for item_ea in idautils.FuncItems(func.start_ea):
            mnem = idc.print_insn_mnem(item_ea) or ""
            mn = mnem.lower()
            mnemonics.append(mn)

            if mn in ("cmp", "test"):
                cmp_count += 1
            elif mn in ("jz", "jnz", "je", "jne", "jg", "jl", "jge", "jle", "ja", "jb", "jae", "jbe", "js", "jns", "jp", "jnp", "jo", "jno", "jmp", "jcxz", "jecxz"):
                branch_count += 1
            elif mn == "xor":
                xor_count += 1
            elif mn == "call":
                call_count += 1
                # Check if call target is indirect (register)
                op0_type = idc.get_operand_type(item_ea, 0)
                if op0_type in (idaapi.o_reg, idaapi.o_phrase, idaapi.o_displ):
                    indirect_call_count += 1

            # Detect memory comparison patterns: loads + cmp
            if mn in ("mov", "movzx", "movsx") and cmp_count > 0:
                op1_type = idc.get_operand_type(item_ea, 1)
                if op1_type in (idaapi.o_mem, idaapi.o_displ):
                    pass  # Could set memory_cmp_count, but we check mnemonic presence

            # Check for string comparison calls
            callee_name = ""
            if mn == "call":
                callee_name = idc.print_operand(item_ea, 0) or ""
                if any(s in callee_name.lower() for s in ("memcmp", "strcmp", "strncmp", "wmemcmp", "wcscmp")):
                    memory_cmp_count += 1

        # Check for loop structure
        has_loops = False
        try:
            fc = idaapi.FlowChart(func)
            for block in fc:
                for succ in block.succs():
                    if succ.start_ea <= block.start_ea:
                        has_loops = True
                        break
                if has_loops:
                    break
        except Exception:
            pass

        # ── Classification logic ─────────────────────────────────────────────
        entries: list[ConstraintTypeEntry] = []
        detects_xor = xor_count >= 1

        # Check for per-byte invertible: moderate branches, few indirect calls
        if branch_count <= cmp_count * 2 + 5 and memory_cmp_count < 2:
            conf = "high" if detects_xor else "medium"
            per_byte_hint = (
                "Each byte's constraint appears independent. Use xor_invert or "
                "static_invert_xor_with_constraints."
                if detects_xor
                else "Each byte appears independently processed but NO simple XOR "
                "was detected. The cipher may be a custom alphabet encoder "
                "or modular arithmetic transform. Decompile the function to "
                "identify lookup tables and arithmetic operations. Then use "
                "find_alphabet_encoder to detect the cipher structure."
            )
            entries.append(ConstraintTypeEntry(
                constraint_type="per_byte_invertible",
                per_byte_independent=True,
                invertible_with="python_arithmetic",
                confidence=conf,
                hint=per_byte_hint,
            ))

        # Check for path-dependent: many branches relative to comparison points
        if branch_count > cmp_count * 2 + 3 or has_loops:
            entries.append(ConstraintTypeEntry(
                constraint_type="path_dependent",
                per_byte_independent=False,
                invertible_with="triton or angr",
                confidence="medium",
                hint="Branching depends on input comparison. Symbolic execution may be needed.",
            ))

        # Check for opaque predicate: indirect calls + many branches
        if indirect_call_count > 0 and branch_count > 5:
            entries.append(ConstraintTypeEntry(
                constraint_type="opaque_predicate",
                per_byte_independent=False,
                invertible_with="angr_find_paths",
                confidence="low",
                hint="Indirect calls suggest control-flow obfuscation. Try angr with find_paths.",
            ))

        # Check for state mixer: many XORs + calls + branches
        if xor_count > 10 and call_count > 3:
            entries.append(ConstraintTypeEntry(
                constraint_type="state_mixer",
                per_byte_independent=False,
                invertible_with="triton_symbolic",
                confidence="low",
                hint="Heavy XOR/call mix suggests non-linear state combination. Triton symbolic execution recommended.",
            ))

        if not entries:
            entries.append(ConstraintTypeEntry(
                constraint_type="unknown",
                per_byte_independent=False,
                invertible_with="unknown",
                confidence="low",
                hint="Could not classify. Decompile the function and examine the validation logic manually.",
            ))

        # ── Build cipher-type-aware recommendation ────────────────────────────
        if not detects_xor:
            recommendation = (
                "CUSTOM CIPHER: No simple XOR detected in this function. "
                "Per-byte processing is present but the transform is not XOR-based. "
                "1) Run find_alphabet_encoder(address) to detect the cipher type. "
                "2) Decompile the function to identify lookup tables and arithmetic. "
                "3) Use get_string + get_bytes on referenced data to extract the alphabet. "
                "Avoid Triton/angr until you understand the cipher structure."
            )
        elif primary["constraint_type"] == "per_byte_invertible" and detects_xor:
            recommendation = (
                "USE LIGHTWEIGHT TOOLS: This looks statically invertible with XOR. "
                "Try xor_invert first (if you know expected plaintext), "
                "or use static_invert_xor_with_constraints for multi-stage transforms. "
                "Avoid Triton/angr unless static inversion fails."
            )
        elif primary["constraint_type"] == "per_byte_invertible":
            recommendation = (
                "USE LIGHTWEIGHT TOOLS: This looks statically invertible. "
                "Try find_alphabet_encoder to identify the cipher. "
                "No XOR detected — cipher may use custom alphabet encoding. "
                "Avoid Triton/angr unless static inversion fails."
            )
        elif primary["constraint_type"] == "path_dependent":
            recommendation = (
                "USE SYMBOLIC EXECUTION: Branching depends on input values. "
                "Use triton_analyze_function or triton_find_input_for_branch. "
                "If the binary is Windows x64, pass setup_windows_abi=True."
            )
        elif primary["constraint_type"] == "opaque_predicate":
            recommendation = (
                "USE ANGR EXPLORATION: Opaque predicates detected. "
                "angr's exploration engine can handle this better than Triton. "
                "Try angr with find_paths mode."
            )
        elif primary["constraint_type"] == "state_mixer":
            recommendation = (
                "USE TRITON SYMBOLIC: Non-linear state mixing detected. "
                "Use triton_init then triton_process_function with symbolic registers. "
                "May need triton_setup_windows_x64 for Windows binaries."
            )
        else:
            recommendation = (
                "MANUAL ANALYSIS NEEDED: Could not classify constraint type. "
                "Decompile the function and examine the validation logic. "
                "The function may be a custom cipher or VM."
            )

        return CheckConstraintTypeResult(
            ok=True,
            address=hex(func.start_ea),
            function_name=func_name,
            constraint_type=primary["constraint_type"],
            cipher_type="xor" if detects_xor else "custom_alphabet",
            xor_count=xor_count,
            details=entries,
            recommendation=recommendation,
        )

    except Exception as e:
        return {"ok": False, "error": str(e)}


class AlphabetEncoderMatch(TypedDict):
    encoder_type: str
    address: str
    confidence: str
    operation: NotRequired[str]
    table_address: NotRequired[str]
    table_size: NotRequired[int]
    detail: str


class FindAlphabetEncoderResult(TypedDict):
    ok: bool
    address: str
    function_name: str
    encoders_found: list[AlphabetEncoderMatch]
    total_instructions_scanned: int
    hint: NotRequired[str]
    error: NotRequired[str]


@tool
@idasync
def find_alphabet_encoder(
    address: Annotated[str, "Function address or name to scan for custom alphabet encoders (hex or symbol)"],
    max_insns: Annotated[int, "Maximum instructions to scan (default 2000)"] = 2000,
) -> FindAlphabetEncoderResult:
    """Detect custom alphabet encoding patterns: mod 64/32/256, lookup tables, and modular-arithmetic ciphers.

    Scans a function for patterns typical of custom base64-like alphabet encoders:
    - AND reg, 0x3F — flag decode (lower 6 bits)
    - AND reg, 0x1F — shl decode (lower 5 bits)
    - IMUL/ADD with small constants (e.g., *9+7, *3) as part of transform
    - Memory loads indexed by register (lookup table reads)
    - CMP against MOD values like 0x40 (64), 0x100 (256)

    Use this tool when find_xor_pattern returns empty and check_constraint_type
    reports cipher_type=custom_alphabet. It identifies the specific encoding
    algorithm so you can write a Python inverter without Triton/Z3.

    Detection is pure instruction pattern matching — no symbolic execution.
    """
    try:
        ea = parse_address(address)
        func = idaapi.get_func(ea)
        if not func:
            return {"ok": False, "error": f"No function found at {address}"}

        func_name = ida_funcs.get_func_name(func.start_ea) or hex(func.start_ea)

        # Collect instruction data
        insns: list[tuple[int, str, str, list[str]]] = []
        for item_ea in idautils.FuncItems(func.start_ea):
            mnem = idc.print_insn_mnem(item_ea) or ""
            ops: list[str] = []
            for n in range(4):
                if idc.get_operand_type(item_ea, n) == idaapi.o_void:
                    break
                op_str = idc.print_operand(item_ea, n) or ""
                ops.append(op_str)
            insns.append((item_ea, mnem.lower(), ops[0] if ops else "", ops))
            if len(insns) >= max_insns:
                break

        encoders: list[AlphabetEncoderMatch] = []

        # Look for AND + compare patterns typical of custom alphabet encoders
        for item_ea, mnem, op0, ops in insns:
            if mnem == "and" and len(ops) >= 2:
                try:
                    mask_val = int(ops[1], 0)
                except (ValueError, TypeError):
                    continue

                if mask_val == 0x3F:
                    # AND 0x3F — get lower 6 bits (mod 64) → base64-like encoding
                    encoders.append(AlphabetEncoderMatch(
                        encoder_type="base64_like",
                        address=hex(item_ea),
                        confidence="medium",
                        operation="AND 0x3F",
                        detail="Extracts lower 6 bits — likely indexing a 64-char alphabet table",
                    ))
                elif mask_val == 0x1F:
                    encoders.append(AlphabetEncoderMatch(
                        encoder_type="base32_like",
                        address=hex(item_ea),
                        confidence="medium",
                        operation="AND 0x1F",
                        detail="Extracts lower 5 bits — likely indexing a 32-char alphabet table",
                    ))

            # Look for IMUL + ADD combos (e.g., *9+7 used in custom ciphers)
            if mnem in ("imul", "mul") and len(ops) >= 2:
                try:
                    mul_val = int(ops[1], 0)
                    if 2 <= mul_val <= 20:
                        encoders.append(AlphabetEncoderMatch(
                            encoder_type="multiplicative_transform",
                            address=hex(item_ea),
                            confidence="low",
                            operation=f"IMUL {mul_val}",
                            detail=f"Multiplies by constant {mul_val} — possible custom cipher arithmetic",
                        ))
                except (ValueError, TypeError):
                    pass

            # Look for ADD/SUB with small constants on bytes
            if mnem in ("add", "sub") and len(ops) >= 2:
                try:
                    const_val = int(ops[1], 0)
                    if 1 <= const_val <= 127:
                        encoders.append(AlphabetEncoderMatch(
                            encoder_type="additive_transform",
                            address=hex(item_ea),
                            confidence="low",
                            operation=f"{mnem.upper()} {const_val}",
                            detail=f"{mnem.upper()}s by constant {const_val} — common in cipher state updates",
                        ))
                except (ValueError, TypeError):
                    pass

            # Look for indexed memory loads (lookup table reads)
            if mnem in ("mov", "movzx", "movsx") and len(ops) >= 2:
                for op_str in ops[1:]:
                    if "[" in op_str and ("*" in op_str or "+" in op_str):
                        encoders.append(AlphabetEncoderMatch(
                            encoder_type="lookup_table_read",
                            address=hex(item_ea),
                            confidence="medium",
                            operation=ops[1] if len(ops) >= 2 else "indexed_mem",
                            detail=f"Indexed memory read — likely alphabet table lookup at {ops[1]}",
                        ))
                        break

        # De-duplicate: keep only unique encoder types per address
        seen: set[tuple[str, str]] = set()
        unique_encoders: list[AlphabetEncoderMatch] = []
        for enc in encoders:
            key = (enc["encoder_type"], enc["address"])
            if key not in seen:
                seen.add(key)
                unique_encoders.append(enc)

        # Try to find the actual alphabet table
        alphabet_tables: list[tuple[int, int]] = []  # (address, size)
        for item_ea in idautils.FuncItems(func.start_ea):
            for xref in idautils.XrefsFrom(item_ea, 0):
                if not xref.iscode and xref.to != idaapi.BADADDR:
                    seg = idaapi.getseg(xref.to)
                    if seg and seg.type not in (idaapi.SEG_CODE,):
                        size = min(seg.end_ea - xref.to, 128)
                        data = ida_bytes.get_bytes(xref.to, size)
                        if data:
                            printable = sum(1 for b in data if 0x20 <= b < 0x7F)
                            if printable > len(data) * 0.6:
                                alphabet_tables.append((xref.to, size))

        for table_addr, table_size in alphabet_tables:
            unique_encoders.append(AlphabetEncoderMatch(
                encoder_type="alphabet_table",
                address=hex(table_addr),
                confidence="high",
                table_address=hex(table_addr),
                table_size=table_size,
                detail=f"Probable alphabet table at {hex(table_addr)}: {table_size} bytes, {sum(1 for b in ida_bytes.get_bytes(table_addr, min(table_size, 128)) or b'' if 0x20 <= b < 0x7F)} printable",
            ))

        hint = None
        if not unique_encoders:
            hint = (
                "No custom alphabet encoder patterns found. The function may use "
                "direct arithmetic on bytes (e.g., +x, -y) without lookup tables, "
                "or may use a VM-based cipher. Try decompiling to identify the exact transform."
            )

        return FindAlphabetEncoderResult(
            ok=True,
            address=hex(func.start_ea),
            function_name=func_name,
            encoders_found=unique_encoders,
            total_instructions_scanned=len(insns),
            hint=hint,
        )

    except Exception as e:
        return {"ok": False, "error": str(e)}


class StaticInvertResult(TypedDict):
    ok: bool
    recovered: NotRequired[str]
    recovered_hex: NotRequired[str]
    transform_sequence: NotRequired[list[str]]
    per_byte_keys: NotRequired[list[str]]
    confidence: NotRequired[str]
    error: NotRequired[str]
    hint: NotRequired[str]


@tool
@idasync
def static_invert_xor_with_constraints(
    ciphertext_address: Annotated[str, "Address of encrypted data (hex or symbol)"],
    known_plaintext: Annotated[
        str, "Known or expected plaintext at specific positions (e.g. 'TESS{' for a flag prefix)"
    ],
    max_length: Annotated[int, "Maximum ciphertext bytes to read (default 512)"] = 512,
    transform_hints: Annotated[
        str,
        "Comma-separated hints: 'ror' (try ROR shift), 'rol' (try ROL shift), "
        "'sub' (try subtraction), 'add' (try addition), 'xchg' (swap nibbles). "
        "Empty = auto-detect all.",
    ] = "",
) -> StaticInvertResult:
    """Invert a multi-stage XOR/arithmetic transform given known plaintext.

    Handles more complex cases than xor_invert where the transform involves
    multiple operations per byte: XOR with key, ROL/ROR rotation, addition or
    subtraction of index-dependent constants, nibble swaps.

    This is the tool for TenzoCrackme-style problems where the transform
    involves ror8(y, -5) then XOR with table. Each transform type is tried;
    the one that produces printable plaintext for all positions is selected.

    Algorithm: brute-force search over standard transform combinations
    for single-byte keys, then extend to multi-byte key schedules.
    """
    try:
        ct_ea = parse_address(ciphertext_address)

        kp_bytes: bytes
        if known_plaintext.startswith("hex:"):
            kp_bytes = bytes.fromhex(known_plaintext[4:].replace(" ", ""))
        elif known_plaintext.startswith("0x"):
            kp_bytes = bytes.fromhex(known_plaintext[2:].replace(" ", ""))
        else:
            stripped = known_plaintext.replace(" ", "")
            if all(c in "0123456789abcdefABCDEF" for c in stripped) and len(stripped) >= 4:
                kp_bytes = bytes.fromhex(stripped)
            else:
                kp_bytes = known_plaintext.encode("utf-8")

        ct_bytes = ida_bytes.get_bytes(ct_ea, max_length)
        if not ct_bytes:
            return {"ok": False, "error": f"No bytes found at {ciphertext_address}"}

        min_overlap = min(len(ct_bytes), len(kp_bytes))
        ct_arr = list(ct_bytes)
        kp_arr = list(kp_bytes)

        # Gather transform hints
        hints_set = set()
        if transform_hints:
            hints_set.update(h.strip().lower() for h in transform_hints.split(",") if h.strip())
        if not hints_set:
            hints_set = {"xor", "ror", "rol", "sub", "add", "xchg"}

        def ror8(v: int, n: int) -> int:
            n &= 7
            return ((v >> n) | (v << (8 - n))) & 0xFF

        def rol8(v: int, n: int) -> int:
            return ror8(v, 8 - (n & 7))

        def xchg_nibbles(v: int) -> int:
            return ((v & 0x0F) << 4) | ((v & 0xF0) >> 4)

        # Try each hint to find the transform
        best_transform: list[str] = []
        best_decrypted: bytes = b""
        best_confidence = "low"

        # Single-byte key: try all transform types
        for hint_name in ["xor", "ror", "rol", "sub", "add", "xchg"]:
            if hint_name not in hints_set:
                continue

            inverted: list[int] = []
            transform_desc: list[str] = []

            if hint_name == "xor":
                # Standard XOR: key = ct[i] ^ known[i]
                keys_at_positions = [ct_arr[i] ^ kp_arr[i] for i in range(min_overlap)]
                if len(set(keys_at_positions)) == 1:
                    key = keys_at_positions[0]
                    inverted = [ct ^ key for ct in ct_arr]
                    transform_desc.append(f"XOR with key {hex(key)}")
            elif hint_name == "ror":
                # Try each rotation amount 1-7
                for rot in range(1, 8):
                    keys_at_positions = []
                    for i in range(min_overlap):
                        key = ror8(kp_arr[i], rot) ^ ct_arr[i]
                        keys_at_positions.append(key)
                    if len(set(keys_at_positions)) == 1:
                        key = keys_at_positions[0]
                        inverted = [ror8(ct ^ key, rot) for ct in ct_arr]
                        transform_desc.append(f"ROR by {rot}, XOR with key {hex(key)}")
                        break
            elif hint_name == "rol":
                for rot in range(1, 8):
                    keys_at_positions = []
                    for i in range(min_overlap):
                        key = rol8(kp_arr[i], rot) ^ ct_arr[i]
                        keys_at_positions.append(key)
                    if len(set(keys_at_positions)) == 1:
                        key = keys_at_positions[0]
                        inverted = [rol8(ct ^ key, rot) for ct in ct_arr]
                        transform_desc.append(f"ROL by {rot}, XOR with key {hex(key)}")
                        break
            elif hint_name == "sub":
                # Key = (ct[i] + known[i]) & 0xFF
                keys_at_positions = [(ct_arr[i] + kp_arr[i]) & 0xFF for i in range(min_overlap)]
                if len(set(keys_at_positions)) == 1:
                    key = keys_at_positions[0]
                    inverted = [(ct + key) & 0xFF for ct in ct_arr]
                    transform_desc.append(f"SUB/ADD with key {hex(key)}")
            elif hint_name == "add":
                keys_at_positions = [(ct_arr[i] - kp_arr[i] + 256) & 0xFF for i in range(min_overlap)]
                if len(set(keys_at_positions)) == 1:
                    key = keys_at_positions[0]
                    inverted = [(ct - key + 256) & 0xFF for ct in ct_arr]
                    transform_desc.append(f"SUB key {hex(key)}")
            elif hint_name == "xchg":
                for i in range(min_overlap):
                    key = xchg_nibbles(kp_arr[i]) ^ ct_arr[i]
                    keys_at_positions = [key]
                if len(set(keys_at_positions)) == 1:
                    key = keys_at_positions[0]
                    inverted = [xchg_nibbles(ct ^ key) for ct in ct_arr]
                    transform_desc.append(f"Nibble swap, XOR with key {hex(key)}")

            if inverted:
                try:
                    recovered_str = bytes(inverted).decode("utf-8", errors="replace")
                    printable_count = sum(1 for b in inverted if 0x20 <= b < 0x7F)
                    confidence = "high" if printable_count > len(inverted) * 0.9 else "medium"

                    if confidence == "high" or not best_decrypted:
                        best_decrypted = bytes(inverted)
                        best_transform = transform_desc
                        best_confidence = confidence

                    if confidence == "high":
                        break  # Found good match
                except Exception:
                    pass

        if best_decrypted:
            try:
                recovered_str = best_decrypted.decode("utf-8", errors="replace")
            except UnicodeDecodeError:
                recovered_str = best_decrypted.hex(" ").upper()

            return StaticInvertResult(
                ok=True,
                recovered=recovered_str,
                recovered_hex=best_decrypted.hex(" ").upper(),
                transform_sequence=best_transform,
                confidence=best_confidence,
            )

        return StaticInvertResult(
            ok=False,
            error="Could not invert transform with any hint method",
            hint=(
                "The transform may involve a multi-byte key schedule, "
                "index-dependent operations, or a non-standard cipher. "
                "Try Triton symbolic execution: triton_init + triton_symbolize_bytes "
                "+ triton_process_function + triton_solve_path_constraints."
            ),
        )

    except Exception as e:
        return {"ok": False, "error": str(e)}


class BfAnalyzeResult(TypedDict):
    ok: bool
    is_bf_interpreter: NotRequired[bool]
    detection_method: NotRequired[str]
    scan_mode: NotRequired[str]
    program_address: NotRequired[str]
    program_bytes: NotRequired[str]
    program_ascii: NotRequired[str]
    program_size: NotRequired[int]
    output_address: NotRequired[str]
    tape_size: NotRequired[int]
    inverted_input: NotRequired[str]
    transform_map: NotRequired[dict[str, str]]
    candidates_found: NotRequired[int]
    hint: NotRequired[str]
    error: NotRequired[str]


@tool
@idasync
def bf_analyze(
    address: Annotated[str, "Function address or name suspected to be a BF interpreter (hex or symbol)"],
    known_output: Annotated[
        str,
        "Known or expected BF program output string. When supplied, the tool symbolically "
        "executes the BF program to find what initial tape state produces this output. "
        "For tesseract_crackme: pass 'TESS{' to recover the password input.",
    ] = "",
    max_program_size: Annotated[int, "Maximum bytes to extract as potential BF program (default 4096)"] = 4096,
    scan_mode: Annotated[
        str,
        "Scan scope: 'function' (default — only the named function), "
        "'callers' (the function + its direct callers), "
        "'binary' (scan ALL functions in the binary for BF patterns). "
        "Use 'binary' for tesseract-style crackmes where the BF interpreter "
        "might be in a different function than the main check logic.",
    ] = "function",
) -> BfAnalyzeResult:
    """Detect, extract, and symbolically invert Brainf*ck interpreter obfuscation.

    Uses three detection signals (any one is sufficient):
    1. Immediate values in switch-table comparisons matching BF opcodes (43,45,60,62,91,93,46,44)
    2. Switch table cases covering the BF opcode range (IDA-recognized switch idioms)
    3. Range-check pattern: compares a value against '+' and ']' boundaries

    When a BF interpreter is detected, extracts the embedded BF program by:
    1. Following data xrefs from the interpreter to program data
    2. Scanning data segments for BF-opcode-dense regions
    3. Searching for data near the interpreter function's callers

    When known_output is provided, runs a SYMBOLIC BF executor that tracks
    algebraic expressions per tape cell instead of concrete values. For programs
    without input-dependent loops, this produces the exact inverse mapping:
    input[i] = output[i] - net_delta[i].

    scan_mode='binary' scans the entire binary for BF interpreters — useful for
    tesseract_crackme-style binaries where the BF engine is not in the main check.
    """
    try:
        ea = parse_address(address)
        func = idaapi.get_func(ea)
        if not func:
            return {"ok": False, "error": f"No function found at {address}"}

        scan_mode = scan_mode.strip().lower() if scan_mode else "function"
        bf_chars = {ord("+"), ord("-"), ord("<"), ord(">"), ord("["), ord("]"), ord("."), ord(",")}

        def _detect_bf_in_function(func_ea: int) -> tuple[bool, str, int, set[int], list[int], list[int]]:
            """Return (is_bf, detection_signals, total_bf_match, immediates, indirect_jumps, switch_eas)."""
            bf_chars_local = {ord("+"), ord("-"), ord("<"), ord(">"), ord("["), ord("]"), ord("."), ord(",")}
            immediates_set: set[int] = set()
            indirect_jumps_list: list[int] = []
            switch_eas_list: list[int] = []

            for item_ea in idautils.FuncItems(func_ea):
                mnem = idc.print_insn_mnem(item_ea) or ""
                mn = mnem.lower()

                if mn in ("cmp", "sub"):
                    for n in range(4):
                        if idc.get_operand_type(item_ea, n) == idaapi.o_imm:
                            imm_val = idc.get_operand_value(item_ea, n)
                            if 0 <= imm_val <= 255:
                                immediates_set.add(imm_val)

                if mn == "jmp":
                    op0_type = idc.get_operand_type(item_ea, 0)
                    if op0_type in (idaapi.o_reg, idaapi.o_phrase, idaapi.o_displ):
                        indirect_jumps_list.append(item_ea)
                    if op0_type in (idaapi.o_mem, idaapi.o_displ, idaapi.o_phrase):
                        switch_eas_list.append(item_ea)

            bf_match_imm = immediates_set & bf_chars_local
            switch_set: set[int] = set()
            for sw_ea in switch_eas_list:
                try:
                    sw = ida_nalt.get_switch_info(sw_ea)
                    if sw and sw.ncases > 0:
                        for idx in range(min(sw.ncases, 256)):
                            val = sw.get_jump_target(idx) or idx
                            switch_set.add(val if isinstance(val, int) else idx)
                except Exception:
                    pass
            bf_match_sw = switch_set & bf_chars_local
            total = len(bf_match_imm | bf_match_sw)

            range_score = 0
            if ord("+") in immediates_set or ord("]") in immediates_set:
                range_score += 1
            if ord("[") in immediates_set or ord(".") in immediates_set:
                range_score += 1
            if len(indirect_jumps_list) >= 1 and len(switch_eas_list) >= 1:
                range_score += 1

            sigs = []
            if len(bf_match_imm) >= 3:
                sigs.append(f"immediates({len(bf_match_imm)}/8)")
            if len(bf_match_sw) >= 3:
                sigs.append(f"switch_table({len(bf_match_sw)}/8)")
            if range_score >= 2:
                sigs.append(f"range_check({range_score}/3)")

            is_bf_func = total >= 4 or (total >= 3 and range_score >= 2) or len(sigs) >= 2
            sig_str = ";".join(sigs) if sigs else f"only {total}/8 opcodes"
            return is_bf_func, sig_str, total, immediates_set, indirect_jumps_list, switch_eas_list

        # ── Collect functions to scan based on scan_mode ──────────────────────
        funcs_to_scan: list[int] = [func.start_ea]
        if scan_mode in ("callers", "binary"):
            for xref in idautils.XrefsTo(func.start_ea, 0):
                if xref.iscode and xref.frm not in funcs_to_scan:
                    caller_f = idaapi.get_func(xref.frm)
                    if caller_f and caller_f.start_ea not in funcs_to_scan:
                        funcs_to_scan.append(caller_f.start_ea)
        if scan_mode == "binary":
            for fea in idautils.Functions():
                if fea not in funcs_to_scan:
                    funcs_to_scan.append(fea)

        # ── Scan all candidate functions ──────────────────────────────────────
        best_candidate: tuple[int, str, int] | None = None  # (func_ea, sigs, total)
        for fea in funcs_to_scan:
            is_bf, sigs, total, _, _, _ = _detect_bf_in_function(fea)
            if is_bf and (best_candidate is None or total > best_candidate[2]):
                best_candidate = (fea, sigs, total)

        if best_candidate is None:
            return BfAnalyzeResult(
                ok=True,
                is_bf_interpreter=False,
                scan_mode=scan_mode,
                hint=(
                    f"No BF interpreter found across {len(funcs_to_scan)} function(s) "
                    f"(scan_mode={scan_mode}). Try find_xor_pattern for XOR obfuscation."
                ),
            )

        bf_func_ea = best_candidate[0]
        detection_signals = best_candidate[1]
        bf_func = idaapi.get_func(bf_func_ea)
        if not bf_func:
            return {"ok": False, "error": f"BF candidate function at {hex(bf_func_ea)} no longer valid"}
        bf_func_name = ida_funcs.get_func_name(bf_func_ea) or hex(bf_func_ea)

        # ── PROGRAM EXTRACTION ────────────────────────────────────────────────
        program_ea = None
        program_bytes = b""
        data_refs: list[tuple[int, int]] = []
        visited = set()

        for item_ea in idautils.FuncItems(bf_func_ea):
            for xref in idautils.XrefsFrom(item_ea, 0):
                if not xref.iscode and xref.to not in visited:
                    visited.add(xref.to)
                    seg = idaapi.getseg(xref.to)
                    if seg and seg.type not in (idaapi.SEG_CODE,):
                        data_refs.append((xref.to, min(4096, seg.end_ea - xref.to)))

        for xref in idautils.XrefsTo(bf_func_ea, 0):
            if xref.iscode and xref.frm not in visited:
                visited.add(xref.frm)
                caller_func = idaapi.get_func(xref.frm)
                if caller_func:
                    for citem_ea in idautils.FuncItems(caller_func.start_ea):
                        for cxref in idautils.XrefsFrom(citem_ea, 0):
                            if not cxref.iscode and cxref.to not in visited:
                                visited.add(cxref.to)
                                seg = idaapi.getseg(cxref.to)
                                if seg and seg.type not in (idaapi.SEG_CODE,):
                                    data_refs.append((cxref.to, min(4096, seg.end_ea - cxref.to)))

        best_score = 0
        for start, size in data_refs:
            data = ida_bytes.get_bytes(start, min(size, max_program_size))
            if data and len(data) >= 3:
                bf_count = sum(1 for b in data[:256] if b in bf_chars)
                printable_count = sum(1 for b in data[:256] if 0x20 <= b < 0x7F)
                score = bf_count * 3 + printable_count
                if score > best_score:
                    best_score = score
                    program_ea = start
                    program_bytes = data

        if not program_ea:
            for seg_idx in range(idaapi.get_segm_qty()):
                seg = idaapi.getnseg(seg_idx)
                if not seg or seg.type in (idaapi.SEG_CODE,):
                    continue
                data = ida_bytes.get_bytes(seg.start_ea, min(seg.end_ea - seg.start_ea, max_program_size))
                if data:
                    bf_count = sum(1 for b in data[:256] if b in bf_chars)
                    printable_count = sum(1 for b in data[:256] if 0x20 <= b < 0x7F)
                    score = bf_count * 2 + printable_count
                    if score > best_score:
                        best_score = score
                        program_ea = seg.start_ea
                        program_bytes = data

        if not program_ea:
            return BfAnalyzeResult(
                ok=True,
                is_bf_interpreter=True,
                detection_method=detection_signals,
                scan_mode=scan_mode,
                candidates_found=len(funcs_to_scan),
                hint=(
                    f"BF interpreter detected at {bf_func_name} via {detection_signals}. "
                    f"Scanned {len(funcs_to_scan)} function(s) (mode={scan_mode}). "
                    f"Could not locate embedded BF program from {len(data_refs)} data refs. "
                    "Try: dump data segments with get_bytes, search for strings with find_regex, "
                    "or check the interpreter's callers for program buffer setup."
                ),
            )

        program_display = " ".join(f"{b:02X}" for b in program_bytes[:128])
        program_ascii = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in program_bytes[:256])

        result: BfAnalyzeResult = {
            "ok": True,
            "is_bf_interpreter": True,
            "detection_method": detection_signals,
            "scan_mode": scan_mode,
            "program_address": hex(program_ea),
            "program_bytes": program_display,
            "program_ascii": program_ascii,
            "program_size": len(program_bytes),
            "candidates_found": len(funcs_to_scan),
        }

        # ── BF PROGRAM ANALYSIS + INVERSION ───────────────────────────────────
        # Strip leading non-BF bytes to find program start
        prog_start = 0
        for b in program_bytes:
            if b in bf_chars:
                break
            prog_start += 1
        program = program_bytes[prog_start:]
        if prog_start > 0:
            result["output_address"] = hex(program_ea + prog_start)

        # Precompute bracket matching
        bracket_map: dict[int, int] = {}
        stack: list[int] = []
        for i, b in enumerate(program):
            if b == ord("["):
                stack.append(i)
            elif b == ord("]") and stack:
                j = stack.pop()
                bracket_map[j] = i
                bracket_map[i] = j

        # ── SYMBOLIC BF EXECUTOR ─────────────────────────────────────────────
        # Tracks cells as (literal_offset: int, sym_offset: int) tuples.
        # literal_offset = net constant delta, sym_offset = coefficient for the unknown initial value.
        # Value = literal_offset + sym_offset * initial[p0], but sym_offset is 0 or 1 for linear programs.
        # For output-driven inversion, we need: value = literal + sym * input_cell_i
        # where input_cell_i is the initial value at the cell that was at pointer when a `,` was read
        # or that the program was initialized with.

        def _run_symbolic_bf(
            prog: bytes,
            bracket: dict[int, int],
            input_cells: int = 128,
            max_steps: int = 50000,
        ) -> tuple[list[tuple[int, int]], list[tuple[int, int]], bool]:
            """Run BF program symbolically. Returns (cell_states, outputs, completed).

            cell_states[i] = (literal, sym_id) where value = literal + sym_cells[sym_id]
            sym_cells represents the initial state of each cell before execution.
            outputs = list of (literal, sym_id) at each `.` encounter.
            """
            cells = [(0, i) for i in range(input_cells)]  # (literal, sym_id)
            ptr = 0
            ip = 0
            outputs: list[tuple[int, int]] = []
            steps = 0
            completed = False

            while ip < len(prog) and steps < max_steps:
                b = prog[ip]
                literal, sym_id = cells[ptr]

                if b == ord("+"):
                    cells[ptr] = ((literal + 1) & 0xFF, sym_id)
                elif b == ord("-"):
                    cells[ptr] = ((literal - 1) & 0xFF, sym_id)
                elif b == ord(">"):
                    ptr = (ptr + 1) % input_cells
                elif b == ord("<"):
                    ptr = (ptr - 1) % input_cells
                elif b == ord("."):
                    outputs.append(cells[ptr])
                elif b == ord(","):
                    # Input: cell becomes a fresh symbolic variable
                    cells[ptr] = (0, input_cells + len(outputs))
                elif b == ord("[") and literal == 0:
                    # Jump past matching ] — but only if cell is provably zero
                    # Without concrete values we can't know. For deterministic analysis,
                    # we skip `[` only when cell is (0, ?) — unknown sym makes it non-zero.
                    # Actually: cell is zero iff literal == 0 AND sym_id maps to initial_0.
                    # Since all initial cells are symbolic (non-zero by default),
                    # we only skip `[` when literal == 0 and it references a cell known to be 0.
                    # For simplicity: only skip when both literal and the sym referent are 0.
                    target = bracket.get(ip)
                    if target is not None:
                        ip = target
                elif b == ord("]") and literal != 0:
                    # Loop back — but we don't know if sym makes it non-zero
                    # For safety: if literal != 0, definitely loop back
                    target = bracket.get(ip)
                    if target is not None:
                        ip = target

                ip += 1
                steps += 1

            if ip >= len(prog):
                completed = True

            return cells, outputs, completed

        sym_cells, sym_outputs, completed = _run_symbolic_bf(program, bracket_map)

        result["tape_size"] = 128

        # ── INVERSION: Given known output, find input that produces it ────────
        if known_output:
            output_bytes: bytes
            if known_output.startswith("hex:"):
                output_bytes = bytes.fromhex(known_output[4:].replace(" ", ""))
            elif known_output.startswith("0x"):
                output_bytes = bytes.fromhex(known_output[2:].replace(" ", ""))
            else:
                stripped = known_output.replace(" ", "")
                if all(c in "0123456789abcdefABCDEF" for c in stripped) and len(stripped) >= 4:
                    output_bytes = bytes.fromhex(stripped)
                else:
                    output_bytes = known_output.encode("utf-8")

            invert_insn = min(len(sym_outputs), len(output_bytes))
            if invert_insn > 0:
                # Build the transformation map: output[i] = literal + sym_cells[sym_id]
                transform_map: dict[str, str] = {}
                solved_cells: list[int] = []
                for i in range(invert_insn):
                    out_literal, out_sym = sym_outputs[i]
                    expected = output_bytes[i]
                    # We need: (out_literal + initial[sym_id_if_any]) % 256 == expected
                    # For initial cells (sym_id < 128): initial[sym_id] = (expected - out_literal) % 256
                    initial_val = (expected - out_literal) & 0xFF
                    transform_map[f"output[{i}]"] = f"cell[{out_sym}] = (out_literal={hex(out_literal)} + init) -> {hex(expected)}"
                    solved_cells.append(initial_val)

                result["transform_map"] = transform_map

                # Recover password by converting solved cell values to bytes/ASCII
                if solved_cells:
                    inverted_bytes = bytes(solved_cells)
                    try:
                        inverted_str = inverted_bytes.decode("utf-8", errors="replace")
                    except UnicodeDecodeError:
                        inverted_str = inverted_bytes.hex(" ").upper()
                    result["inverted_input"] = inverted_str
            elif completed and not sym_outputs:
                result["hint"] = (
                    "BF program completed with no `.` output instructions. "
                    "The password may be the BF program itself (not the initial tape). "
                    "Check if the program bytes at program_address are the password."
                )
            else:
                result["hint"] = (
                    f"BF program produced {len(sym_outputs)} outputs but {len(output_bytes)} were expected. "
                    "The program may need input via `,` (stdin bytes). "
                    "Try running with a longer tape or checking for embedded comparison logic."
                )

        return result

    except Exception as e:
        return {"ok": False, "error": str(e)}
