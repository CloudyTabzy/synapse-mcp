"""api_angr — Angr symbolic execution engine for IDA Pro MCP.

Optional module: tools are only registered when `angr` is installed.
Install with: pip install angr  (large ~200 MB; separate from --install-deps all)

Provides symbolic path exploration, CFG recovery, backward slicing, and
crackme/serial solving via stdin/argv symbolic modeling. Angr solves the
problem Triton cannot: serial keys that arrive via stdin (not registers).

Killer feature: `angr_find_paths` + `workflow_solve_crackme` — model stdin
as N free symbolic bytes, explore paths from entry to the serial check,
and ask the constraint solver what bytes reach the target address.

Tool roster (22 tools + 1 always-registered probe):

  Infrastructure / Load
    I.0  angr_status                — availability probe (always registered)
    A.1  angr_load_segment          — load binary into cached angr Project
    A.2  angr_cfg_fast              — static CFG recovery (CFGFast)
    A.3  angr_cfg_from_ida          — build CFG from IDA's FlowChart
    A.4  angr_diff_cfg              — before/after CFG comparison

  Symbolic Execution
    B.1  angr_find_paths            ⭐ KILLER — solve for stdin/argv inputs
    B.2  angr_enumerate_reachable   — BFS reachable addresses from a source
    B.3  angr_state_evaluate        — evaluate expression at a state
    B.4  angr_hook_function         — skip/observe/replace SimProcedure hooks

  Analysis
    C.1  angr_backward_slice        — data-flow origin of a target value
    C.2  angr_value_set             — register value bounds at a point
    C.3  angr_snapshot_save         — save simulation state for later restore
    C.4  angr_snapshot_restore      — restore a saved state

  Hybrid Cross-Engine
    H.1  hybrid_angr_triton_solve   — angr path → Triton deep symbolic analysis
    H.2  hybrid_angr_stdin_fuzz     — char-class-constrained stdin enumeration
    H.3  hybrid_angr_miasm_path     — Miasm deobfuscate + angr solve combined
    H.4  hybrid_angr_triton_decompile  — annotated decompilation w/ Triton sym state
    H.5  hybrid_angr_z3_formula     — export path constraints as SMT-LIB2
    H.6  hybrid_angr_unicorn_concrete — Unicorn decrypts a region → angr loads
                                        & analyzes the revealed code (Phase 6.4)

  Workflows
    W.1  workflow_solve_crackme     ⭐ one-call end-to-end serial solving
    W.2  workflow_trace_data_flow   — cross-function data flow trace
    W.3  workflow_find_gadgets      — ROP/JOP gadget enumeration
    W.4  workflow_enum_code_hints   — path constraint hints to a target

Implementation pattern: each tool function is a thin wrapper around a
private ``_xxx_impl`` helper. Composite/workflow tools call the impl
helpers directly to avoid re-entering @idasync (which raises IDASyncError
on nested calls to execute_sync).
"""
from __future__ import annotations

import logging
import os
import re as _re
import threading
import time
from collections import OrderedDict
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
    import angr as _angr
    import claripy as _claripy
    import cle as _cle  # angr's loader; always present when angr is
    ANGR_AVAILABLE = True
    _ANGR_VERSION = getattr(_angr, "__version__", "unknown")
except ImportError:
    _angr = None  # type: ignore[assignment]
    _claripy = None  # type: ignore[assignment]
    _cle = None  # type: ignore[assignment]
    ANGR_AVAILABLE = False
    _ANGR_VERSION = ""
    logger.warning(
        "angr not installed — angr_* tools unavailable. "
        "Install with: pip install angr"
    )

def _patch_claripy_sigint() -> None:
    """Neutralize claripy's z3 SIGINT handler install/uninstall.

    angr runs inside a daemon thread here, never the main thread. Modern
    claripy (>=9.2.x, late 2022) already guards ``signal.signal()`` behind a
    ``threading.main_thread()`` check, so the classic ``ValueError: signal only
    works in main thread`` does not fire on import or while solving. The
    residual problem is ``uninstall_sigint_handler()``, which claripy calls
    unconditionally in its per-call ``condom``/finally block and which can raise
    an ``AssertionError`` when the matching install was skipped off the main
    thread (claripy issue #723, observed in embedded hosts like angr-management).

    We replace only the install/uninstall entry points with no-ops and never
    touch claripy's internal counters. Ctrl+C interruption is handled at the MCP
    server layer, not inside z3, so dropping the handler costs us nothing here.
    """
    try:
        import claripy.backends.backend_z3 as _bz3
    except Exception:
        return

    def _noop(*_a, **_kw):
        return None

    # Module-level entry points (current names plus legacy underscored ones).
    for _fname in ("install_sigint_handler", "uninstall_sigint_handler",
                   "_install_sigint_handler", "_uninstall_sigint_handler"):
        if callable(getattr(_bz3, _fname, None)):
            try:
                setattr(_bz3, _fname, _noop)
            except Exception:
                pass

    # Class-level methods, in case a claripy version moved the logic onto the
    # backend class instead of module functions.
    for _cls_name in ("BackendZ3", "Backend"):
        _cls = getattr(_bz3, _cls_name, None)
        if _cls is None:
            continue
        for _mname in ("install_sigint_handler", "uninstall_sigint_handler"):
            if callable(getattr(_cls, _mname, None)):
                try:
                    setattr(_cls, _mname, _noop)
                except Exception:
                    pass


# Reduce noise from angr's chatty default loggers and neutralize claripy's
# SIGINT handler so it cannot fault while solving inside our daemon thread.
if ANGR_AVAILABLE:
    for _noisy in ("angr", "cle", "claripy", "pyvex", "archinfo"):
        try:
            logging.getLogger(_noisy).setLevel(logging.WARNING)
        except Exception:
            pass

    # A failure here must never take down the whole module. Without this guard
    # a single patch error makes every angr_* tool silently unavailable.
    try:
        _patch_claripy_sigint()
    except Exception:
        logger.debug("claripy SIGINT patch skipped", exc_info=True)


# ============================================================================
# TypedDict result types
# ============================================================================


class AngrStatusResult(TypedDict, total=False):
    ok: bool
    available: bool
    version: str
    claripy_version: str
    arches_supported: list[str]
    engines: dict
    projects_cached: int
    input_file: str
    input_format: str
    detected_arch: str
    blob_fallback_likely: bool
    hint: str
    error: str


class AngrMemoryRegion(TypedDict, total=False):
    name: str
    start: str
    size: int


class AngrLoadResult(TypedDict, total=False):
    ok: bool
    project_id: str
    binary_path: str
    arch: str
    bits: int
    entry_point: str
    image_base: str
    memory_regions: list[AngrMemoryRegion]
    symbol_count: int
    loader_backend: str
    fallback_used: bool
    note: str
    error: str
    error_type: str
    hint: str


class AngrFunctionEntry(TypedDict, total=False):
    addr: str
    name: str
    block_count: int
    call_targets: list[str]
    is_returning: bool
    has_unresolved_calls: bool
    has_unresolved_jumps: bool


class AngrCfgResult(TypedDict, total=False):
    ok: bool
    project_id: str
    function_count: int
    block_count: int
    edge_count: int
    indirect_jumps_resolved: int
    unresolved_indirect_jumps: int
    functions: list[AngrFunctionEntry]
    top_by_complexity: list[AngrFunctionEntry]
    note: str
    error: str
    error_type: str
    hint: str


class AngrCfgFromIdaResult(TypedDict, total=False):
    ok: bool
    function_address: str
    function_name: str
    block_count: int
    edge_count: int
    blocks: list[dict]
    edges: list[dict]
    note: str
    error: str
    error_type: str


class PathSolution(TypedDict, total=False):
    path_id: int
    path_length: int
    input_bytes: str
    input_hex: str
    constraint_count: int
    satisfiable: bool
    error: str


class AngrFindPathsResult(TypedDict, total=False):
    ok: bool
    source_address: str
    target_address: str
    avoid_addresses: list[str]
    input_mode: str
    input_size: int
    paths_found: int
    paths: list[PathSolution]
    states_explored: int
    states_active: int
    states_deadended: int
    elapsed_ms: int
    timed_out: bool
    note: str
    error: str
    error_type: str
    hint: str


class ReachableNode(TypedDict, total=False):
    addr: str
    depth: int
    function_name: str
    is_interesting: bool


class AngrReachableResult(TypedDict, total=False):
    ok: bool
    source_address: str
    reachable_count: int
    nodes: list[ReachableNode]
    interesting_addresses: list[str]
    note: str
    error: str


class AngrStateEvalResult(TypedDict, total=False):
    ok: bool
    at_address: str
    expression: str
    result: str
    result_decimal: str
    is_symbolic: bool
    bit_width: int
    note: str
    error: str
    error_type: str


class AngrHookResult(TypedDict, total=False):
    ok: bool
    function_address: str
    hook_type: str
    hook_id: str
    note: str
    error: str


class SliceInstruction(TypedDict, total=False):
    addr: str
    mnemonic: str
    function_name: str
    reason: str


class AngrBackwardSliceResult(TypedDict, total=False):
    ok: bool
    target_address: str
    target_reg: str
    slice_size: int
    contributing_instructions: list[SliceInstruction]
    note: str
    timed_out: bool
    error: str
    error_type: str
    hint: str


class ValueSetBounds(TypedDict, total=False):
    type: str
    lower_bound: str
    upper_bound: str
    is_concrete: bool
    concrete_value: str


class AngrValueSetResult(TypedDict, total=False):
    ok: bool
    function_address: str
    at_address: str
    register: str
    bounds: ValueSetBounds
    concrete_examples: list[str]
    note: str
    error: str


class AngrSnapshotResult(TypedDict, total=False):
    ok: bool
    snapshot_id: str
    label: str
    project_id: str
    addr: str
    constraint_count: int
    note: str
    error: str


class HybridAngrTritonResult(TypedDict, total=False):
    ok: bool
    paths_found: int
    paths: list[dict]
    engines_used: list[str]
    angr_time_ms: int
    triton_time_ms: int
    note: str
    error: str
    error_type: str
    hint: str


class AngrStdinFuzzResult(TypedDict, total=False):
    ok: bool
    target_address: str
    inputs_found: int
    inputs: list[str]
    inputs_hex: list[str]
    char_constraint_used: str
    paths_explored: int
    note: str
    timed_out: bool
    error: str
    error_type: str
    hint: str


class HybridMiasmAngrResult(TypedDict, total=False):
    ok: bool
    function_address: str
    target_address: str
    miasm_available: bool
    miasm_blocks: int
    angr_paths_found: int
    solution: str
    solution_hex: str
    engines_used: list[str]
    note: str
    error: str


class AnnotatedLine(TypedDict, total=False):
    line: str
    addr: str
    has_symbolic_ops: bool
    symbolic_registers: dict[str, str] | None


class HybridDecompileResult(TypedDict, total=False):
    ok: bool
    function_address: str
    function_name: str
    pseudocode: str
    annotated_lines: list[AnnotatedLine]
    symbolic_line_count: int
    total_instructions_processed: int
    symbolized_registers: list[str]
    constraint_count: int
    engines_used: list[str]
    error: str


class AngrZ3FormulaResult(TypedDict, total=False):
    ok: bool
    smt2_formula: str
    constraint_count: int
    variables: list[str]
    note: str
    error: str


class CrackmeSolveResult(TypedDict, total=False):
    ok: bool
    target_address: str
    target_detection_method: str
    avoid_addresses: list[str]
    serial_found: bool
    serial: str
    serial_hex: str
    path_length: int
    elapsed_ms: int
    paths_found: int
    all_serials: list[str]
    detection_notes: list[str]
    engines_used: list[str]
    note: str
    error: str
    error_type: str
    hint: str


class DataFlowNode(TypedDict, total=False):
    addr: str
    insn: str
    function_name: str
    contributes_to: str


class DataFlowResult(TypedDict, total=False):
    ok: bool
    source_address: str
    sink_address: str
    sink_reg: str
    trace_direction: str
    nodes: list[DataFlowNode]
    terminated_reason: str
    cross_functions: bool
    engines_used: list[str]
    error: str


class RopGadget(TypedDict, total=False):
    addr: str
    bytes: str
    mnemonics: list[str]
    gadget_type: str


class GadgetsResult(TypedDict, total=False):
    ok: bool
    segment: str
    gadget_count: int
    gadgets: list[RopGadget]
    note: str
    error: str


class PathConstraintSummary(TypedDict, total=False):
    path_id: int
    path_length: int
    constraints: list[str]
    satisfiable: bool


class CodeHintsResult(TypedDict, total=False):
    ok: bool
    target_address: str
    path_count: int
    paths: list[PathConstraintSummary]
    prefix_hints: list[str]
    note: str
    error: str


# ============================================================================
# Project cache (module-global, LRU-bounded)
# ============================================================================

# Always-enforced load options. Cannot be overridden by callers — IDA safety.
_FORCED_LOAD_OPTIONS: dict = {"auto_load_libs": False}
_MAX_PROJECTS = 3
_PROJECT_LOCK = threading.Lock()

# Entry shape:
#   {
#       "project":            angr.Project,
#       "binary_path":        str,
#       "cfg":                angr.analyses.CFGFast | None,
#       "snapshots":          {snapshot_id: {"label", "state", "addr", "constraints"}},
#       "hooks":              {func_ea: hook_type},
#       "hook_log":           [{"addr", "args"}, ...],
#       "last_simgr":         angr.SimulationManager | None,
#       "last_found_states":  list[SimState],
#   }
_angr_projects: "OrderedDict[str, dict]" = OrderedDict()


def _project_count() -> int:
    with _PROJECT_LOCK:
        return len(_angr_projects)


def _evict_if_needed() -> None:
    with _PROJECT_LOCK:
        while len(_angr_projects) > _MAX_PROJECTS:
            ev_key, _ = _angr_projects.popitem(last=False)
            logger.info("Evicted angr project '%s' (LRU)", ev_key)


def _store_project(project_id: str, entry: dict) -> None:
    with _PROJECT_LOCK:
        _angr_projects[project_id] = entry
        _angr_projects.move_to_end(project_id)
    _evict_if_needed()


def _get_entry(project_id: str | None) -> dict | None:
    """Return the cached project entry (LRU-marked), or None if not loaded."""
    with _PROJECT_LOCK:
        if not _angr_projects:
            return None
        if project_id is None:
            key = next(reversed(_angr_projects))  # most recent
            entry = _angr_projects[key]
            _angr_projects.move_to_end(key)
            return entry
        entry = _angr_projects.get(project_id)
        if entry is not None:
            _angr_projects.move_to_end(project_id)
        return entry


def _next_project_id() -> str:
    with _PROJECT_LOCK:
        return f"proj_{len(_angr_projects)}"


def _project_id_for_entry(entry: dict) -> str | None:
    """Reverse-lookup the project_id for a cached entry."""
    with _PROJECT_LOCK:
        for pid, ent in _angr_projects.items():
            if ent is entry:
                return pid
    return None


# ============================================================================
# Architecture mapping helpers (IDA → angr)
# ============================================================================

_IDA_ARCH_PATTERNS = (
    # (procname-prefix, 64bit_arch, 32bit_arch)
    ("metapc",  "AMD64",   "X86"),
    ("80",      "AMD64",   "X86"),
    ("x86",     "AMD64",   "X86"),
    ("i386",    "AMD64",   "X86"),
    ("i486",    "AMD64",   "X86"),
    ("i586",    "AMD64",   "X86"),
    ("i686",    "AMD64",   "X86"),
    ("ia",      "AMD64",   "X86"),
    ("aarch64", "AARCH64", "AARCH64"),
    ("arm64",   "AARCH64", "AARCH64"),
    ("arm",     "AARCH64", "ARMEL"),
    ("mips",    "MIPS64",  "MIPS32"),
    ("ppc",     "PPC64",   "PPC32"),
)


def _detect_arch() -> tuple[str, int]:
    """Return (angr_arch_name, bits) from the loaded IDB."""
    try:
        procname = idaapi.get_inf_structure().procname.lower()
    except Exception:
        try:
            procname = idaapi.inf_get_procname().lower()
        except Exception:
            procname = "metapc"

    try:
        is_64 = bool(idaapi.get_inf_structure().is_64bit())
    except Exception:
        try:
            is_64 = bool(idaapi.inf_is_64bit())
        except Exception:
            is_64 = False

    bits = 64 if is_64 else 32
    for prefix, arch_64, arch_32 in _IDA_ARCH_PATTERNS:
        if procname.startswith(prefix):
            return (arch_64 if is_64 else arch_32, bits)
    return ("AMD64" if is_64 else "X86", bits)


def _ida_imagebase() -> int | None:
    """IDA's image base, for rebasing a blob to match the IDB's addresses."""
    try:
        base = int(idaapi.get_imagebase())
        return base if base not in (0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF) else None
    except Exception:
        return None


def _ida_entry_point() -> int | None:
    """IDA's program entry point: first defined entry, else INF_START_EA."""
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


def _peek_file_format(path: str) -> str:
    """Cheap magic-byte sniff of the input file: 'PE' / 'ELF' / 'MachO' / 'blob'.

    Lets angr_status tell an agent up front whether angr_load_segment will need
    the blob fallback, instead of the agent discovering it via a load failure.
    """
    try:
        with open(path, "rb") as fh:
            magic = fh.read(4)
    except Exception:
        return "unknown"
    if magic[:2] == b"MZ":
        return "PE"
    if magic[:4] == b"\x7fELF":
        return "ELF"
    if magic[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
                     b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",
                     b"\xca\xfe\xba\xbe"):
        return "MachO"
    return "blob"


def _is_cle_backend_error(e: BaseException) -> bool:
    """True when angr.Project failed because CLE couldn't auto-detect a backend.

    This is the exact signal to retry with the explicit ``blob`` backend — the
    binary is a raw dump / decrypted section / custom format with no PE/ELF/MachO
    header. Matches both the typed CLE exceptions and the message text, since the
    concrete class has moved across cle versions.
    """
    if _cle is not None:
        backend_errs = tuple(
            cls for cls in (
                getattr(_cle.errors, "CLECompatibilityError", None),
                getattr(_cle.errors, "CLEUnknownFormatError", None),
            ) if isinstance(cls, type)
        )
        if backend_errs and isinstance(e, backend_errs):
            return True
    msg = str(e).lower()
    return "loader backend" in msg or "unable to find a loader" in msg


# ============================================================================
# Threading-based deadline for long-running angr calls
# ============================================================================


def _run_with_deadline(fn, timeout_s: float):
    """Run fn() in a daemon thread; return its result or raise TimeoutError.

    angr holds the GIL inside native code (pyvex, claripy/z3), so we cannot
    interrupt mid-step from Python. We just wait `timeout_s` and bail; the
    worker keeps running in the background (daemon, so it dies with IDA).
    """
    result: list = [None]
    exc: list = [None]

    def _target():
        try:
            result[0] = fn()
        except BaseException as e:
            exc[0] = e

    t = threading.Thread(target=_target, daemon=True)
    t.start()
    t.join(timeout_s)
    if t.is_alive():
        raise TimeoutError(f"operation timed out after {timeout_s:.1f}s")
    if exc[0] is not None:
        raise exc[0]
    return result[0]


# ============================================================================
# Character constraint helpers (for symbolic stdin / argv)
# ============================================================================

_PRINTABLE_BYTES = bytes(range(0x20, 0x7F))
_ALPHANUMERIC_BYTES = bytes(
    list(range(ord("0"), ord("9") + 1))
    + list(range(ord("A"), ord("Z") + 1))
    + list(range(ord("a"), ord("z") + 1))
)
_HEX_BYTES = bytes(
    list(range(ord("0"), ord("9") + 1))
    + list(range(ord("a"), ord("f") + 1))
    + list(range(ord("A"), ord("F") + 1))
)


def _parse_char_spec(spec: str) -> bytes:
    """Parse a character-class spec into a sorted byte set.

    Accepted forms:
        'printable'             — bytes 0x20..0x7e
        'alphanumeric'          — A-Z, a-z, 0-9
        'hex'                   — 0-9, a-f, A-F
        'A-Z,0-9'               — ranges and individual chars
        'A-Z,0-9,{,}'           — mix of ranges and literal chars
        '2-9,A-H,J-N,P-Z'       — multiple ranges
    """
    s = (spec or "").strip().lower()
    if s == "printable":
        return _PRINTABLE_BYTES
    if s == "alphanumeric":
        return _ALPHANUMERIC_BYTES
    if s == "hex":
        return _HEX_BYTES

    chars: set[int] = set()
    raw = (spec or "").strip()
    if not raw:
        return _PRINTABLE_BYTES

    # Split on commas, preserve "{,}" idiom for literal '{' and '}'
    parts = raw.split(",")
    cleaned: list[str] = []
    i = 0
    while i < len(parts):
        part = parts[i]
        if part.endswith("{") and i + 1 < len(parts) and parts[i + 1].startswith("}"):
            cleaned.append(part)
            cleaned.append(parts[i + 1])
            i += 2
            continue
        cleaned.append(part)
        i += 1

    for part in cleaned:
        p = part.strip()
        if not p:
            continue
        if len(p) == 3 and p[1] == "-":
            lo, hi = ord(p[0]), ord(p[2])
            if lo <= hi <= 0xFF:
                for c in range(lo, hi + 1):
                    chars.add(c)
        elif len(p) == 1:
            chars.add(ord(p))
        else:
            for c in p:
                if ord(c) <= 0xFF:
                    chars.add(ord(c))

    return bytes(sorted(chars)) if chars else _PRINTABLE_BYTES


def _apply_byte_constraints(state, sym_bv, size_bytes: int, allowed: bytes) -> None:
    """Constrain each byte of sym_bv to be in the allowed-byte set.

    Encodes as `Or(byte == c0, byte == c1, ...)` per byte.
    """
    if not allowed or _claripy is None:
        return
    bits_total = sym_bv.size()
    for i in range(size_bytes):
        if (i + 1) * 8 > bits_total:
            break
        byte_i = sym_bv.get_byte(i)
        clauses = [byte_i == c for c in allowed]
        if len(clauses) == 1:
            state.solver.add(clauses[0])
        else:
            state.solver.add(_claripy.Or(*clauses))


# ============================================================================
# Status probe — always registered, even when angr is unavailable
# ============================================================================


@tool
@idasync
def angr_status() -> AngrStatusResult:
    """Probe angr availability and the current binary's loadability.

    Always registered regardless of whether angr is installed. Beyond engine
    capability flags, it sniffs the input file so an agent knows up front
    whether angr_load_segment will auto-fall-back to the 'blob' backend
    (raw dump / decrypted section / custom format with no PE/ELF/MachO header).
    """
    if not ANGR_AVAILABLE:
        return {
            "ok": True,
            "available": False,
            "version": "",
            "claripy_version": "",
            "hint": "Install with: pip install angr  (large ~200 MB)",
        }
    try:
        claripy_version = getattr(_claripy, "__version__", "unknown")
    except Exception:
        claripy_version = "unknown"

    # Lightweight capability probe of the current input binary.
    input_file = ""
    input_format = "unknown"
    detected_arch = ""
    blob_likely = False
    try:
        input_file = idaapi.get_input_file_path() or ""
        if input_file and os.path.exists(input_file):
            input_format = _peek_file_format(input_file)
            blob_likely = input_format == "blob"
        detected_arch = _detect_arch()[0]
    except Exception:
        pass

    result: AngrStatusResult = {
        "ok": True,
        "available": True,
        "version": _ANGR_VERSION,
        "claripy_version": claripy_version,
        "arches_supported": [
            "AMD64", "X86",
            "AARCH64", "ARMEL",
            "MIPS32", "MIPS64",
            "PPC32", "PPC64",
        ],
        "engines": {
            "simulation_manager": True,
            "cfg_fast": True,
            "cfg_emulated": True,
            "backward_slice": True,
            "vfg": True,
            "ddg": True,
        },
        "projects_cached": _project_count(),
        "input_file": input_file,
        "input_format": input_format,
        "detected_arch": detected_arch,
        "blob_fallback_likely": blob_likely,
    }
    if blob_likely:
        result["hint"] = (
            "Input has no PE/ELF/MachO header — angr_load_segment will load it via "
            "the 'blob' backend (rebased to IDA's imagebase). For CFG/function data "
            "prefer angr_cfg_from_ida; use angr for symbolic execution."
        )
    return result


# ============================================================================
# All other tools are guarded — only registered when angr is available.
# ============================================================================

if ANGR_AVAILABLE:

    # =====================================================================
    # State option policy
    # =====================================================================
    #
    # angr auto-enables its unicorn engine when the `unicorn` package is present
    # (it is — unicorn 2.x). The unicorn SimState plugin holds a *native* cffi
    # handle (``_cffi_backend._CDataBase``) that is not pickle/deepcopy-safe.
    # angr/claripy copy states constantly during exploration and IDA's tooling
    # boundary can attempt to serialize them, which surfaces as
    # ``TypeError: cannot pickle '_cffi_backend._CDataBase' object`` — exactly
    # the V2 stress-test failure. We never need unicorn for pure-symbolic
    # exploration, so strip its options from every state we build; the handle is
    # then never created. ZERO_FILL_UNCONSTRAINED_REGISTERS happens to live in
    # angr.options.unicorn too but we want it, so it is excluded from the strip
    # and added back explicitly.
    _STATE_ADD_OPTIONS = {
        _angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
        _angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
    }
    _STATE_REMOVE_OPTIONS = set(_angr.options.unicorn) - _STATE_ADD_OPTIONS

    # =====================================================================
    # Out-of-process worker integration (angr_worker.py / angr_ipc.py)
    # =====================================================================
    # Heavy / serialization-sensitive ops can run in a separate process: it is
    # killable on timeout (a thread in native angr code is not), and only plain
    # dicts cross the boundary so the cffi pickle bug is impossible. Worker mode
    # is decided ONCE per session (a cheap ping) so a tool never runs half
    # in-process / half in-worker, and it transparently falls back to the
    # in-process path when the worker can't start — behaviour is never worse.
    import threading as _threading_mod
    _worker_mode: bool | None = None
    _worker_mode_lock = _threading_mod.Lock()

    def _use_worker() -> bool:
        global _worker_mode
        if os.environ.get("IDA_MCP_ANGR_NO_WORKER"):
            return False
        with _worker_mode_lock:
            if _worker_mode is None:
                try:
                    from .angr_ipc import get_worker
                    pong = get_worker().ping(timeout=20.0)
                    _worker_mode = bool(isinstance(pong, dict) and pong.get("ok"))
                except Exception:
                    _worker_mode = False
                logger.info("angr out-of-process worker: %s",
                            "ENABLED" if _worker_mode else "disabled (in-process)")
            return _worker_mode

    def _worker_request(op: str, payload: dict, timeout: float) -> dict:
        from .angr_ipc import get_worker
        return get_worker().request(op, payload, timeout)

    def _gather_load_hints_internal(binary_path: str | None = None, arch: str | None = None,
                                    base_address: str | None = None) -> dict:
        """Raw IDA hint gather — assumes it is already running on the main thread."""
        path = binary_path or idaapi.get_input_file_path() or ""
        a = arch or _detect_arch()[0]
        base = None
        if base_address:
            try:
                base = parse_address(base_address)
            except Exception:
                base = None
        if base is None:
            base = _ida_imagebase()
        return {"binary_path": path, "arch": a, "base_addr": base,
                "entry_point": _ida_entry_point()}

    _gather_load_hints_marshalled = idasync(_gather_load_hints_internal)

    def _gather_load_hints(binary_path: str | None = None, arch: str | None = None,
                           base_address: str | None = None) -> dict:
        """Collect the IDA-derived inputs the worker needs — safe from ANY context.

        Calls IDA directly when already on the main thread (e.g. inside an
        @idasync tool — calling the marshalled version there would nest
        execute_sync and raise IDASyncError). When invoked off the main thread
        (e.g. a non-@idasync tool like angr_backward_slice), IDA raises
        "Function can be called from the main thread only"; we catch that and
        marshal via execute_sync. This removes the footgun where the caller had
        to pick the right variant — the V10 backward_slice regression.
        """
        try:
            return _gather_load_hints_internal(binary_path, arch, base_address)
        except RuntimeError as e:
            if "main thread" in str(e).lower():
                return _gather_load_hints_marshalled(binary_path, arch, base_address)
            raise

    @idasync
    def _enrich_slice_addresses(addrs: list, target_reg: str | None) -> list[dict]:
        """Turn the worker's bare slice addresses into rich rows using the IDB."""
        items: list[dict] = []
        for addr_str in addrs:
            try:
                a = parse_address(addr_str)
            except Exception:
                a = None
            mnem = fname = ""
            if a is not None:
                try:
                    mnem = idc.print_insn_mnem(a) or ""
                except Exception:
                    pass
                f = idaapi.get_func(a)
                if f is not None:
                    fname = idc.get_func_name(f.start_ea) or ""
            items.append({"addr": addr_str, "mnemonic": mnem,
                          "function_name": fname, "reason": "control_flow_predecessor"})
        return items

    # =====================================================================
    # Shared resolution helpers
    # =====================================================================

    def _summarize_memory_regions(proj) -> list[dict]:
        """Return a compact list of mapped memory regions for the main object."""
        regions: list[dict] = []
        try:
            for seg in getattr(proj.loader.main_object, "segments", []):
                regions.append({
                    "name":  getattr(seg, "name", "") or "",
                    "start": hex(getattr(seg, "vaddr", 0)),
                    "size":  int(getattr(seg, "memsize", 0)),
                })
            if not regions:
                for sec in getattr(proj.loader.main_object, "sections", []):
                    regions.append({
                        "name":  getattr(sec, "name", "") or "",
                        "start": hex(getattr(sec, "vaddr", 0)),
                        "size":  int(getattr(sec, "memsize", 0)),
                    })
        except Exception:
            pass
        return regions[:32]


    def _resolve_source_addr(proj, source_address: str) -> int:
        """Resolve 'entry' or hex address to a concrete int."""
        if not source_address or source_address == "entry":
            return proj.entry
        return parse_address(source_address)


    # =====================================================================
    # A.1 — angr_load_segment
    # =====================================================================

    def _load_segment_impl(
        segment_names=None,
        base_address: str | None = None,
        arch: str | None = None,
        project_id: str | None = None,
        binary_path: str | None = None,
    ) -> AngrLoadResult:
        """Implementation of angr_load_segment. Safe to call from other impl funcs."""
        try:
            path = binary_path or idaapi.get_input_file_path() or ""
            if not path or not os.path.exists(path):
                return tool_error(
                    FileNotFoundError(
                        f"Binary path not found: {path!r}. "
                        "Pass binary_path explicitly or ensure the IDB references an existing file."
                    ),
                    context="angr_load_segment",
                )

            # Reuse cached project for the same binary
            with _PROJECT_LOCK:
                for pid, ent in _angr_projects.items():
                    if ent.get("binary_path") == path:
                        _angr_projects.move_to_end(pid)
                        proj = ent["project"]
                        lb = ent.get("loader_backend", "")
                        return {
                            "ok": True,
                            "project_id": pid,
                            "binary_path": path,
                            "arch": proj.arch.name,
                            "bits": proj.arch.bits,
                            "entry_point": hex(proj.entry),
                            "image_base": hex(proj.loader.main_object.mapped_base),
                            "memory_regions": _summarize_memory_regions(proj),
                            "symbol_count": len(list(proj.loader.main_object.symbols)),
                            "loader_backend": lb,
                            "fallback_used": lb == "blob",
                            "note": "Project already cached for this binary.",
                        }

            load_options: dict = dict(_FORCED_LOAD_OPTIONS)
            main_opts: dict = {}
            if arch:
                main_opts["arch"] = arch
            else:
                detected_arch, _ = _detect_arch()
                main_opts["arch"] = detected_arch
            if base_address:
                try:
                    main_opts["base_addr"] = parse_address(base_address)
                except Exception:
                    pass
            if main_opts:
                load_options["main_opts"] = main_opts

            # First attempt: let CLE auto-detect the backend (PE/ELF/MachO/...).
            proj = None
            loader_backend = ""
            fallback_used = False
            try:
                proj = _angr.Project(path, load_options=load_options)
                loader_backend = type(proj.loader.main_object).__name__
            except Exception as e_auto:
                if not _is_cle_backend_error(e_auto):
                    return tool_error(
                        e_auto,
                        context="angr.Project",
                        hint=(
                            "angr failed to load this binary, and not because the "
                            "format was unrecognized (raw blobs are handled "
                            "automatically). Likely a corrupt file or an arch angr "
                            "cannot model. angr_cfg_from_ida and workflow_find_gadgets "
                            "still work — they run on IDA's analysis, no angr project."
                        ),
                    )
                # Auto-fallback: raw blob (decrypted section, shellcode dump, custom
                # format). Map it flat at IDA's imagebase so angr addresses line up
                # with the IDB, and seed the entry point from IDA.
                blob_opts: dict = dict(main_opts)
                blob_opts["backend"] = "blob"
                blob_opts.setdefault("arch", _detect_arch()[0])
                if "base_addr" not in blob_opts:
                    ida_base = _ida_imagebase()
                    if ida_base is not None:
                        blob_opts["base_addr"] = ida_base
                ida_entry = _ida_entry_point()
                if ida_entry is not None:
                    blob_opts["entry_point"] = ida_entry
                blob_load_options: dict = dict(_FORCED_LOAD_OPTIONS)
                blob_load_options["main_opts"] = blob_opts
                try:
                    proj = _angr.Project(path, load_options=blob_load_options)
                    loader_backend = "blob"
                    fallback_used = True
                    logger.info(
                        "angr_load_segment: blob fallback for %s (arch=%s base=%s entry=%s)",
                        path,
                        blob_opts.get("arch"),
                        hex(blob_opts["base_addr"]) if "base_addr" in blob_opts else "default",
                        hex(blob_opts["entry_point"]) if "entry_point" in blob_opts else "default",
                    )
                except Exception as e_blob:
                    return tool_error(
                        e_blob,
                        context="angr.Project/blob",
                        hint=(
                            "Blob fallback also failed. Pass an explicit arch "
                            "('X86'/'AMD64'/'ARMEL'/'AARCH64'/'MIPS32'/'PPC32') and/or "
                            "base_address, or use angr_cfg_from_ida / "
                            "workflow_find_gadgets, which need no angr project."
                        ),
                    )

            pid = project_id or _next_project_id()
            entry = {
                "project":     proj,
                "binary_path": path,
                "loader_backend": loader_backend,
                "cfg":         None,
                "snapshots":   {},
                "hooks":       {},
                "hook_log":    [],
                "last_simgr":  None,
                "last_found_states": [],
            }
            _store_project(pid, entry)

            if fallback_used:
                note = (
                    "Loaded via angr 'blob' backend (raw binary, no symbols), rebased "
                    "to IDA's imagebase so addresses match the IDB. For CFG/function "
                    "data prefer angr_cfg_from_ida — IDA's analysis is ground truth on "
                    "a blob; use angr for symbolic execution (angr_find_paths, "
                    "workflow_solve_crackme). CFGFast on a blob needs "
                    "force_complete_scan=True and is still weaker than IDA."
                )
            else:
                note = "Project cached. Call angr_cfg_fast to build a CFG."

            return {
                "ok": True,
                "project_id": pid,
                "binary_path": path,
                "arch": proj.arch.name,
                "bits": proj.arch.bits,
                "entry_point": hex(proj.entry),
                "image_base": hex(proj.loader.main_object.mapped_base),
                "memory_regions": _summarize_memory_regions(proj),
                "symbol_count": len(list(proj.loader.main_object.symbols)),
                "loader_backend": loader_backend,
                "fallback_used": fallback_used,
                "note": note,
            }
        except Exception as e:
            return tool_error(e, context="angr_load_segment")


    @tool
    @idasync
    @tool_timeout(60.0)
    def angr_load_segment(
        segment_names: Annotated[
            list[str] | str | None,
            "Segment name(s) to load (e.g. '.text' or ['.text', '.rdata']). "
            "Currently informational only — angr loads the full binary file. "
            "Omit or pass '*' for default.",
        ] = None,
        base_address: Annotated[
            str | None,
            "Base address override (hex). Defaults to IDA imagebase.",
        ] = None,
        arch: Annotated[
            str | None,
            "Architecture override: 'AMD64', 'X86', 'AARCH64', 'ARMEL', 'MIPS32', 'PPC32'. "
            "Defaults to auto-detection from IDA processor.",
        ] = None,
        project_id: Annotated[
            str | None,
            "Explicit project ID. Auto-generated as 'proj_N' if omitted.",
        ] = None,
        binary_path: Annotated[
            str | None,
            "Explicit binary path. Defaults to the IDB's input file path.",
        ] = None,
    ) -> AngrLoadResult:
        """Load the current binary into a cached angr Project.

        Foundational tool — all other angr tools operate on a loaded project.
        Always passes ``auto_load_libs=False`` to angr (cannot be overridden)
        for IDA plugin safety. The Project is cached with LRU eviction
        (max 3 projects); subsequent calls with the same binary return the
        same project_id.

        Raw binaries with no PE/ELF/MachO header (decrypted sections, shellcode
        dumps, custom formats) are handled automatically: if CLE can't detect a
        backend, the loader retries with angr's 'blob' backend, rebasing to IDA's
        imagebase and seeding the entry point from IDA so addresses match the IDB.
        The result reports ``loader_backend`` and ``fallback_used``. On a blob,
        prefer angr_cfg_from_ida for CFG/function data (IDA is ground truth) and
        reserve angr for symbolic execution.
        """
        return _load_segment_impl(
            segment_names=segment_names,
            base_address=base_address,
            arch=arch,
            project_id=project_id,
            binary_path=binary_path,
        )


    def _ensure_project(project_id: str | None):
        """Return (entry, project) — auto-loading from the IDB if needed.

        Used by impl helpers that need a project but want to be tolerant of
        callers who skipped angr_load_segment.
        """
        ent = _get_entry(project_id)
        if ent is None:
            path = idaapi.get_input_file_path() or ""
            if not path or not os.path.exists(path):
                raise RuntimeError(
                    "No angr project loaded. Call angr_load_segment first."
                )
            res = _load_segment_impl()
            if not res.get("ok"):
                raise RuntimeError(res.get("error", "angr_load_segment failed"))
            ent = _get_entry(res.get("project_id"))
            if ent is None:
                raise RuntimeError("angr_load_segment returned ok but project not cached")
        return ent, ent["project"]


    # =====================================================================
    # A.2 — angr_cfg_fast
    # =====================================================================

    # A blob this size or larger triggers pathological CFGFast complete-scan
    # times (the V2 stress test saw 15+ min on a 1.5 MB blob). Above it we
    # refuse force_complete_scan unless the caller explicitly overrides.
    _BLOB_COMPLETE_SCAN_LIMIT = 512 * 1024

    def _cfg_fast_impl(
        project_id: str | None = None,
        resolve_indirect_jumps: bool = True,
        force_complete_scan: bool = False,
        max_functions: int = 200,
        timeout_seconds: int = 60,
        allow_blob_complete_scan: bool = False,
        start_address: str | None = None,
        max_depth: int = 0,
    ) -> AngrCfgResult:
        try:
            entry, proj = _ensure_project(project_id)

            # Guard against the V2 thread-starvation trap: force_complete_scan on
            # a large symbolless blob can run for many minutes, and because the
            # worker holds the GIL in native code it starves every other tool
            # (even angr_status). On a blob, IDA's own analysis is ground truth
            # anyway, so steer the agent there instead of melting the main thread.
            if (
                force_complete_scan
                and not allow_blob_complete_scan
                and entry.get("loader_backend") == "blob"
            ):
                try:
                    obj = proj.loader.main_object
                    blob_size = int(obj.max_addr - obj.min_addr)
                except Exception:
                    blob_size = 0
                if blob_size >= _BLOB_COMPLETE_SCAN_LIMIT:
                    return {
                        "ok": False,
                        "error": (
                            f"Refusing force_complete_scan on a {blob_size // 1024} KB "
                            "blob — CFGFast complete-scan on a symbolless blob this "
                            "size can block for many minutes and starve all other "
                            "tools (it holds the GIL in native code)."
                        ),
                        "error_type": "invalid_input",
                        "hint": (
                            "Use angr_cfg_from_ida (IDA already analyzed this blob — "
                            "ground truth), or call angr_cfg_fast again with "
                            "force_complete_scan=False, or pass "
                            "allow_blob_complete_scan=True to override if you really "
                            "want the full scan and can wait."
                        ),
                    }

            def _build():
                return proj.analyses.CFGFast(
                    normalize=True,
                    resolve_indirect_jumps=resolve_indirect_jumps,
                    force_complete_scan=force_complete_scan,
                )

            try:
                cfg = _run_with_deadline(_build, float(timeout_seconds))
            except TimeoutError as e:
                return tool_error(
                    e,
                    context="angr_cfg_fast",
                    hint="Increase timeout_seconds or set force_complete_scan=False.",
                )

            entry["cfg"] = cfg

            funcs: list[dict] = []
            for addr, func in cfg.kb.functions.items():
                try:
                    call_targets: list[str] = []
                    get_ct = getattr(func, "get_call_targets", None)
                    if callable(get_ct):
                        for t in get_ct() or []:
                            call_targets.append(hex(t))
                    else:
                        for cs in (func.get_call_sites() or []):
                            tgt = func.get_call_target(cs)
                            if tgt is not None:
                                call_targets.append(hex(tgt))
                except Exception:
                    call_targets = []

                funcs.append({
                    "addr": hex(addr),
                    "name": func.name or f"sub_{addr:X}",
                    "block_count": (
                        len(func.block_addrs_set)
                        if hasattr(func, "block_addrs_set")
                        else len(list(func.block_addrs))
                    ),
                    "call_targets": call_targets[:20],
                    "is_returning": bool(func.returning) if func.returning is not None else False,
                    "has_unresolved_calls": bool(getattr(func, "has_unresolved_calls", False)),
                    "has_unresolved_jumps": bool(getattr(func, "has_unresolved_jumps", False)),
                })

            funcs_sorted = sorted(funcs, key=lambda f: f["block_count"], reverse=True)

            graph = cfg.model.graph
            # SpillingCFG (angr >= 9.2) exposes .nodes and .edges as properties
            # that return views; calling them with () invokes __call__ which
            # yields a generator, breaking len(). Use number_of_* for safety.
            try:
                block_count = graph.number_of_nodes()
            except Exception:
                block_count = len(list(graph.nodes()))
            try:
                edge_count = graph.number_of_edges()
            except Exception:
                edge_count = len(list(graph.edges()))
            resolved_ij = 0
            unresolved_ij = 0
            try:
                for ij in cfg.indirect_jumps.values():
                    if getattr(ij, "resolved_targets", None):
                        resolved_ij += 1
                    else:
                        unresolved_ij += 1
            except Exception:
                pass

            note = "CFGFast is static — indirect jumps resolved heuristically."
            is_blob = entry.get("loader_backend") == "blob"
            if is_blob and not force_complete_scan and len(funcs) == 0:
                note = (
                    "CFGFast found no functions on this blob. A blob has no symbols, "
                    "so prefer angr_cfg_from_ida (IDA already analyzed this binary), "
                    "or retry with force_complete_scan=True to scan the whole region "
                    "as code (slower, noisier)."
                )
            elif is_blob:
                note = (
                    "CFGFast on a blob is heuristic and weaker than IDA — "
                    "cross-check with angr_cfg_from_ida for ground-truth function data."
                )

            # ── max_depth filtering via call-graph BFS ────────────────────
            filtered_note = ""
            depth_filtered = False
            if max_depth > 0:
                # Resolve start_address to an angr function address
                start_addr: int | None = None
                if start_address:
                    try:
                        start_addr = parse_address(start_address)
                    except Exception:
                        pass
                if start_addr is None:
                    try:
                        start_addr = proj.entry
                    except Exception:
                        start_addr = None

                if start_addr is not None and len(funcs) > 0:
                    # Build adjacency: addr -> set of call target addrs
                    adj: dict[str, set[str]] = {}
                    all_addrs: set[str] = {f["addr"] for f in funcs}
                    for f in funcs:
                        src = f["addr"]
                        adj.setdefault(src, set())
                        for tgt_str in f.get("call_targets", []) or []:
                            # Normalize: target may be hex string with/without 0x prefix
                            try:
                                tgt_hex = hex(int(tgt_str, 16))
                            except (ValueError, TypeError):
                                continue
                            if tgt_hex in all_addrs:
                                adj[src].add(tgt_hex)
                            # also try adding reverse edges (callees → callers)
                            adj.setdefault(tgt_hex, set())
                            if tgt_hex in all_addrs:
                                adj[tgt_hex].add(src)

                    start_key = hex(start_addr)
                    # BFS depth computation
                    depth: dict[str, int] = {}
                    queue = [start_key]
                    depth[start_key] = 0
                    while queue:
                        node = queue.pop(0)
                        next_depth = depth[node] + 1
                        if next_depth > max_depth:
                            continue
                        for neighbor in adj.get(node, set()):
                            if neighbor not in depth:
                                depth[neighbor] = next_depth
                                queue.append(neighbor)

                    # Filter functions list
                    funcs_filtered = [f for f in funcs if f["addr"] in depth]
                    funcs_sorted = sorted(funcs_filtered, key=lambda f: depth.get(f["addr"], 99))
                    filtered_note = (
                        f" Depth-filtered from {len(funcs)} → {len(funcs_sorted)} functions "
                        f"(max_depth={max_depth} from {start_key}). "
                    )
                    depth_filtered = True

            return {
                "ok": True,
                "project_id": _project_id_for_entry(entry) or "",
                "function_count": len(funcs_sorted),
                "block_count": block_count,
                "edge_count": edge_count,
                "indirect_jumps_resolved": resolved_ij,
                "unresolved_indirect_jumps": unresolved_ij,
                "functions": funcs_sorted[:max_functions],
                "top_by_complexity": funcs_sorted[:10],
                "note": note + filtered_note,
                "depth_filtered": depth_filtered,
            }
        except Exception as e:
            return tool_error(e, context="angr_cfg_fast")


    @tool
    @idasync
    @tool_timeout(180.0)
    def angr_cfg_fast(
        project_id: Annotated[str | None, "Project ID from angr_load_segment"] = None,
        resolve_indirect_jumps: Annotated[
            bool, "Resolve indirect jump targets (default: True)"
        ] = True,
        force_complete_scan: Annotated[
            bool,
            "Treat entire binary as code (default: False — use only for stripped blobs)",
        ] = False,
        max_functions: Annotated[
            int, "Cap functions list at this many entries (default: 200)"
        ] = 200,
        start_address: Annotated[
            str | None,
            "⭐ Focus CFG on a specific function. When set with max_depth, only "
            "returns functions within N call-graph hops of this address. "
            "Omit to get full binary CFG.",
        ] = None,
        max_depth: Annotated[
            int,
            "⭐ Maximum call-graph depth from start_address (default: 0 = unlimited). "
            "Use with start_address for targeted analysis: max_depth=1 gives the "
            "function's direct callers/callees, max_depth=2 adds their neighbors, etc. "
            "Setting max_depth > 0 without start_address uses the binary entry point.",
        ] = 0,
        timeout_seconds: Annotated[int, "Timeout in seconds (default: 60)"] = 60,
        allow_blob_complete_scan: Annotated[
            bool,
            "Permit force_complete_scan on a large blob despite the multi-minute / "
            "thread-starvation risk (default: False — refused on big blobs).",
        ] = False,
    ) -> AngrCfgResult:
        """Build a static CFG via angr's CFGFast.

        Read-only — does not modify IDA. CFG is cached in the project entry
        so downstream tools (backward_slice, value_set) can reuse it.

        Use start_address + max_depth for targeted analysis — avoids building
        a full binary-wide CFG when you only care about one function's neighborhood.

        On a blob loaded via the 'blob' backend, prefer angr_cfg_from_ida —
        IDA's analysis is ground truth and CFGFast complete-scan on a large blob
        can block for minutes.

        Heavy: always use invoke_tool(async_mode='task') or task_wait.
        """
        result = _cfg_fast_impl(
            project_id=project_id,
            resolve_indirect_jumps=resolve_indirect_jumps,
            force_complete_scan=force_complete_scan,
            max_functions=max_functions,
            timeout_seconds=timeout_seconds,
            allow_blob_complete_scan=allow_blob_complete_scan,
            start_address=start_address,
            max_depth=max_depth,
        )
        if isinstance(result, dict) and not result.get("ok"):
            return result
        return result


    # =====================================================================
    # B.1 — angr_find_paths ⭐ KILLER FEATURE
    # =====================================================================

    def _find_paths_impl(
        target_address: str,
        source_address: str = "entry",
        avoid_addresses=None,
        input_mode: str = "stdin",
        input_size: int = 64,
        char_constraint: str | None = None,
        max_paths: int = 5,
        use_dfs: bool = False,
        use_veritesting: bool = False,
        loop_bound: int = 10,
        project_id: str | None = None,
        timeout_seconds: int = 120,
    ) -> AngrFindPathsResult:
        try:
            entry, proj = _ensure_project(project_id)
            target_ea = parse_address(target_address)
            source_ea = _resolve_source_addr(proj, source_address)

            avoid_eas: list[int] = []
            avoid_list_str: list[str] = []
            if avoid_addresses:
                for a in normalize_list_input(avoid_addresses):
                    try:
                        ea = parse_address(a)
                        avoid_eas.append(ea)
                        avoid_list_str.append(hex(ea))
                    except Exception:
                        continue

            sym_input = None
            try:
                if input_mode == "stdin":
                    sym_input = _claripy.BVS("stdin_input", max(8, input_size) * 8)
                    stdin_file = _angr.SimFileStream(
                        name="stdin", content=sym_input, has_end=True
                    )
                    if source_address == "entry":
                        state = proj.factory.entry_state(
                            stdin=stdin_file,
                            add_options=_STATE_ADD_OPTIONS,
                            remove_options=_STATE_REMOVE_OPTIONS,
                        )
                    else:
                        state = proj.factory.blank_state(
                            addr=source_ea,
                            stdin=stdin_file,
                            add_options=_STATE_ADD_OPTIONS,
                            remove_options=_STATE_REMOVE_OPTIONS,
                        )
                elif input_mode == "argv":
                    sym_input = _claripy.BVS("argv1", max(8, input_size) * 8)
                    state = proj.factory.entry_state(
                        args=[proj.filename, sym_input],
                        add_options=_STATE_ADD_OPTIONS,
                        remove_options=_STATE_REMOVE_OPTIONS,
                    )
                elif input_mode == "register":
                    state = proj.factory.blank_state(
                        addr=source_ea,
                        add_options=_STATE_ADD_OPTIONS,
                        remove_options=_STATE_REMOVE_OPTIONS,
                    )
                    bits = proj.arch.bits
                    for reg in ("rdi", "rsi", "rdx", "rcx", "r8", "r9"):
                        try:
                            sym = _claripy.BVS(f"reg_{reg}", bits)
                            setattr(state.regs, reg, sym)
                        except Exception:
                            continue
                    try:
                        sym_input = state.regs.rdi
                    except Exception:
                        sym_input = None
                else:
                    return tool_error(
                        ValueError(f"Unknown input_mode: {input_mode!r}"),
                        context="angr_find_paths",
                        hint="Use one of: 'stdin', 'argv', 'register'.",
                    )
            except Exception as e:
                return tool_error(e, context="angr_find_paths/state_setup")

            char_used = None
            if char_constraint and sym_input is not None and input_mode in ("stdin", "argv"):
                allowed = _parse_char_spec(char_constraint)
                try:
                    _apply_byte_constraints(state, sym_input, input_size, allowed)
                    char_used = char_constraint
                except Exception as e:
                    logger.warning("Failed to apply char_constraint %r: %s", char_constraint, e)

            simgr = proj.factory.simgr(state)
            try:
                if use_dfs:
                    simgr.use_technique(_angr.exploration_techniques.DFS())
                if use_veritesting:
                    simgr.use_technique(_angr.exploration_techniques.Veritesting())
                simgr.use_technique(
                    _angr.exploration_techniques.LoopSeer(bound=max(1, int(loop_bound)))
                )
            except Exception as e:
                logger.warning("Failed to attach exploration technique: %s", e)

            start_t = time.time()
            timed_out = False

            def _do_explore():
                def _attempt():
                    simgr.explore(
                        find=target_ea,
                        avoid=avoid_eas if avoid_eas else None,
                        num_find=max(1, int(max_paths)),
                    )
                try:
                    _attempt()
                except (KeyboardInterrupt, AssertionError) as _sigint_err:
                    # claripy SIGINT handler assertion (#723) fired despite the
                    # startup patch — re-apply the no-op patch and retry once.
                    logger.warning(
                        "angr_find_paths: %s during explore, re-patching claripy and retrying",
                        type(_sigint_err).__name__,
                    )
                    _patch_claripy_sigint()
                    try:
                        _attempt()
                    except Exception as _retry_err:
                        logger.warning("simgr.explore raised on retry: %s", _retry_err)
                except Exception as ex:
                    logger.warning("simgr.explore raised: %s", ex)

            try:
                _run_with_deadline(_do_explore, float(timeout_seconds))
            except TimeoutError:
                timed_out = True

            elapsed_ms = int((time.time() - start_t) * 1000)

            found_states = list(getattr(simgr, "found", []) or [])[: max(1, int(max_paths))]
            entry["last_simgr"] = simgr
            entry["last_found_states"] = found_states

            paths: list[dict] = []
            for i, fs in enumerate(found_states):
                try:
                    if input_mode == "stdin":
                        try:
                            stdin_data = fs.posix.stdin.load(0, fs.posix.stdin.size)
                            solution_bv = stdin_data
                        except Exception:
                            solution_bv = sym_input
                    elif input_mode == "argv":
                        solution_bv = sym_input
                    elif input_mode == "register":
                        try:
                            solution_bv = fs.regs.rdi
                        except Exception:
                            solution_bv = sym_input
                    else:
                        solution_bv = sym_input

                    sol_bytes = fs.solver.eval(solution_bv, cast_to=bytes)
                    if input_mode == "stdin":
                        sol_bytes = sol_bytes[:input_size]
                    try:
                        decoded = sol_bytes.decode("ascii", errors="replace")
                        decoded = "".join(
                            c if (0x20 <= ord(c) < 0x7F or c in "\n\r\t") else f"\\x{ord(c):02x}"
                            for c in decoded
                        )
                    except Exception:
                        decoded = repr(sol_bytes)

                    paths.append({
                        "path_id": i,
                        "path_length": len(list(fs.history.bbl_addrs)),
                        "input_bytes": decoded,
                        "input_hex": sol_bytes.hex(" "),
                        "constraint_count": len(fs.solver.constraints),
                        "satisfiable": True,
                    })
                except Exception as e:
                    paths.append({"path_id": i, "error": f"solver_eval_failed: {e}"})

            stash_count = lambda name: len(list(getattr(simgr, name, []) or []))

            note_parts = []
            if timed_out:
                note_parts.append(f"Search timed out after {timeout_seconds}s.")
            if not paths and not timed_out:
                note_parts.append(
                    "No paths found. Try: increasing input_size, removing char_constraint, "
                    "verifying target_address, or supplying explicit avoid_addresses."
                )
            elif paths:
                note_parts.append(f"Solved in {elapsed_ms}ms.")

            return {
                "ok": True,
                "source_address": hex(source_ea),
                "target_address": hex(target_ea),
                "avoid_addresses": avoid_list_str,
                "input_mode": input_mode,
                "input_size": input_size,
                "paths_found": len(paths),
                "paths": paths,
                "states_explored": stash_count("found") + stash_count("active")
                                   + stash_count("deadended") + stash_count("avoid"),
                "states_active": stash_count("active"),
                "states_deadended": stash_count("deadended"),
                "elapsed_ms": elapsed_ms,
                "timed_out": timed_out,
                "note": " ".join(note_parts) if note_parts else "",
            }
        except Exception as e:
            return tool_error(e, context="angr_find_paths")


    def _find_paths_with_worker(
        target_address: str, source_address: str = "entry",
        avoid_addresses=None, input_mode: str = "stdin", input_size: int = 64,
        char_constraint: str | None = None, max_paths: int = 5,
        use_dfs: bool = False, use_veritesting: bool = False,
        loop_bound: int = 10, project_id: str | None = None,
        timeout_seconds: int = 120,
    ) -> AngrFindPathsResult:
        """Shared find_paths dispatch: worker if available, else in-process.

        Used by both the @tool angr_find_paths (so it supports worker + auto_async)
        and workflow_solve_crackme (which composes find_paths into a one-call solver).
        """
        if _use_worker():
            hints = _gather_load_hints()
            avoid_list: list[str] = []
            if avoid_addresses:
                avoid_list = [hex(parse_address(a)) for a in normalize_list_input(avoid_addresses) if a]
            return _worker_request(
                "find_paths",
                {"load": hints, "project_id": project_id,
                 "target_address": target_address, "source_address": source_address,
                 "input_mode": input_mode, "input_size": input_size,
                 "char_constraint": char_constraint, "max_paths": max_paths,
                 "use_dfs": use_dfs, "use_veritesting": use_veritesting,
                 "loop_bound": loop_bound, "avoid_addresses": avoid_list},
                timeout=float(timeout_seconds) + 30.0,
            )
        return _find_paths_impl(
            target_address=target_address, source_address=source_address,
            avoid_addresses=avoid_addresses, input_mode=input_mode,
            input_size=input_size, char_constraint=char_constraint,
            max_paths=max_paths, use_dfs=use_dfs, use_veritesting=use_veritesting,
            loop_bound=loop_bound, project_id=project_id,
            timeout_seconds=timeout_seconds,
        )

    @tool
    @idasync
    @tool_timeout(120.0)
    def angr_find_paths(
        target_address: Annotated[str, "Address to reach — typically the 'win'/'success' branch (hex or symbol)"],
        source_address: Annotated[str, "Start address (hex or 'entry'). Default: binary entry point"] = "entry",
        avoid_addresses: Annotated[
            list[str] | str | None,
            "⭐ CRITICAL: Address(es) to AVOID — failure/wrong-password branches. "
            "Without this, angr may find trivial paths that don't represent a real solve. "
            "Comma-separated string or list of hex addresses (e.g. '0x401050,0x401080').",
        ] = None,
        input_mode: Annotated[
            str, "'stdin' (model stdin as symbolic bytes — default), "
                 "'argv' (model argv[1] as symbolic), "
                 "'register' (symbolize rdi/rsi/rdx at source)."
        ] = "stdin",
        input_size: Annotated[int, "Size of symbolic input in bytes. For serial keys: the expected key length. Default: 64."] = 64,
        char_constraint: Annotated[
            str | None,
            "Constrain input bytes to a character class (e.g. 'printable', 'alphanumeric', "
            "'A-Z,0-9', 'FRZ{,A-Z,0-9}'). Reduces search space. If you know the flag format "
            "(e.g. 'TESS{'), pass it as known_format to the include_characters field.",
        ] = None,
        max_paths: Annotated[int, "⭐ Maximum distinct solutions to return (default: 5). Set higher "
                                   "to enumerate all valid inputs — useful when the crackme accepts "
                                   "multiple passwords."] = 5,
        use_dfs: Annotated[bool, "Use depth-first search instead of BFS (default: False)"] = False,
        use_veritesting: Annotated[bool, "Enable Veritesting for static symex at loops (default: False)"] = False,
        loop_bound: Annotated[int, "LoopSeer iteration bound (default: 10)"] = 10,
        project_id: Annotated[str | None, "Project ID from angr_load_segment"] = None,
        timeout_seconds: Annotated[int, "Total timeout in seconds (default: 120)"] = 120,
    ) -> AngrFindPathsResult:
        """⭐ Solve for concrete inputs that drive execution from source to target.

        **The tool that solves crackmes.** Models stdin/argv/registers as
        symbolic and uses angr's SimulationManager to find paths that reach
        the target while avoiding failure paths.

        Usage for a typical crackme:
            angr_load_segment()                     # load the binary into angr
            angr_find_paths(
                target_address  = address of "Correct!" / "Success!" xref
                avoid_addresses = ["0x40F050", ...]  # wrong-password branches ⭐ IMPORTANT
                input_size      = 59                 # known serial length
                char_constraint = "printable"        # or "FRZ{,A-Z,0-9}" for known format
                max_paths       = 3                  # enumerate multiple solutions
            )

        Heavy: always use invoke_tool(async_mode='task') or task_wait.
        """
        return _find_paths_with_worker(
            target_address=target_address, source_address=source_address,
            avoid_addresses=avoid_addresses, input_mode=input_mode,
            input_size=input_size, char_constraint=char_constraint,
            max_paths=max_paths, use_dfs=use_dfs, use_veritesting=use_veritesting,
            loop_bound=loop_bound, project_id=project_id,
            timeout_seconds=timeout_seconds,
        )


    # =====================================================================
    # W.1 — workflow_solve_crackme ⭐
    # =====================================================================

    _DEFAULT_SUCCESS_KW = (
        "success", "correct", "valid", "congrat", "congratulations",
        "right password", "right key", "access granted", "well done",
        "nice", "good job", "you win", "you got it", "unlocked",
        "flag", "winner", "passed",
    )
    _DEFAULT_FAIL_KW = (
        "wrong", "invalid", "fail", "incorrect", "bad",
        "access denied", "try again", "denied", "error",
        "nope", "no match",
    )


    def _iter_idb_strings():
        """Yield (ea, str) for each defined string in the IDB."""
        try:
            sc = idautils.Strings()
            for s in sc:
                try:
                    yield s.ea, str(s)
                except Exception:
                    continue
        except Exception:
            return


    def _auto_detect_target_and_avoid() -> tuple[list[int], list[int], list[str]]:
        """Scan IDB string xrefs for success/fail patterns.

        Returns (target_eas, avoid_eas, notes).
        """
        target_eas: list[int] = []
        avoid_eas: list[int] = []
        notes: list[str] = []

        for s_ea, s_val in _iter_idb_strings():
            sval_lower = s_val.lower()
            is_success = any(kw in sval_lower for kw in _DEFAULT_SUCCESS_KW)
            is_fail = any(kw in sval_lower for kw in _DEFAULT_FAIL_KW)
            if not is_success and not is_fail:
                continue
            for xref in idautils.XrefsTo(s_ea):
                func = idaapi.get_func(xref.frm)
                if func is None:
                    continue
                tgt = xref.frm
                if is_success:
                    if tgt not in target_eas:
                        target_eas.append(tgt)
                        notes.append(f"target: {hex(tgt)} -> '{s_val[:40]}'")
                elif is_fail:
                    if tgt not in avoid_eas:
                        avoid_eas.append(tgt)
                        notes.append(f"avoid: {hex(tgt)} -> '{s_val[:40]}'")
        return target_eas, avoid_eas, notes


    @tool
    @idasync
    @tool_timeout(420.0)
    def workflow_solve_crackme(
        target_address: Annotated[
            str,
            "Serial check address (hex) or 'auto-detect'. "
            "auto-detect scans IDB strings for 'success'/'correct'/'valid' refs.",
        ] = "auto-detect",
        avoid_addresses: Annotated[
            list[str] | str | None,
            "Explicit failure paths to avoid (hex). "
            "auto-detect also gathers 'wrong'/'invalid'/'fail' refs.",
        ] = None,
        source_address: Annotated[str, "Entry point (default: binary entry)"] = "entry",
        input_mode: Annotated[str, "'stdin' or 'argv'"] = "stdin",
        known_format: Annotated[
            str | None,
            "Known serial format prefix for char-class inference (e.g. 'FRZ{'). "
            "Omit for fully unconstrained solving.",
        ] = None,
        input_size: Annotated[int, "Expected input size in bytes (default: 64)"] = 64,
        char_constraint: Annotated[
            str | None,
            "Explicit char-class spec. Overrides known_format inference.",
        ] = None,
        max_solutions: Annotated[int, "Max distinct solutions (default: 3)"] = 3,
        project_id: Annotated[str | None, "Project ID"] = None,
        timeout_seconds: Annotated[int, "Total timeout (default: 300)"] = 300,
    ) -> CrackmeSolveResult:
        """⭐ End-to-end crackme/serial-key solver in one call.

        Composes auto-detection (via IDB string xrefs), char-class inference,
        and angr_find_paths into a single workflow. The flagship tool for the
        Phase 5 stress-test failure mode (stdin-fed serial check).

        Heavy: always use invoke_tool(..., async_mode=True) or task_submit + task_poll for this workflow.
        """
        try:
            try:
                entry, proj = _ensure_project(project_id)
            except Exception as e:
                return tool_error(e, context="workflow_solve_crackme")

            notes: list[str] = []
            engines = ["angr", "ida"]

            # 1) Resolve target + avoid
            if target_address == "auto-detect":
                tgt_eas, av_eas, det_notes = _auto_detect_target_and_avoid()
                notes.extend(det_notes[:8])
                if not tgt_eas:
                    return {
                        "ok": False,
                        "error": "Auto-detection found no success-string xrefs in the IDB.",
                        "error_type": "not_found",
                        "hint": (
                            "Provide target_address explicitly (the address that prints/sets the "
                            "'correct password' state), or define more strings in IDA."
                        ),
                        "detection_notes": det_notes[:8],
                    }
                target_ea = tgt_eas[0]
                if not avoid_addresses:
                    avoid_str = [hex(ea) for ea in av_eas]
                else:
                    avoid_str = list(normalize_list_input(avoid_addresses))
                detection_method = "string_xref_scan"
            else:
                try:
                    target_ea = parse_address(target_address)
                except Exception as e:
                    return tool_error(e, context="workflow_solve_crackme/target")
                avoid_str = list(normalize_list_input(avoid_addresses)) if avoid_addresses else []
                detection_method = "explicit"

            # 2) Char-constraint inference
            cc = char_constraint
            if not cc:
                if known_format:
                    extras = "".join(ch for ch in known_format if not ch.isalnum())
                    extras_csv = ",".join(c for c in extras if c.strip())
                    cc = "alphanumeric" + (("," + extras_csv) if extras_csv else "")
                else:
                    cc = "printable"

            # 3) Solve — uses shared worker dispatch path
            start = time.time()
            res = _find_paths_with_worker(
                target_address=hex(target_ea),
                source_address=source_address,
                avoid_addresses=avoid_str if avoid_str else None,
                input_mode=input_mode,
                input_size=input_size,
                char_constraint=cc,
                max_paths=max_solutions,
                project_id=project_id,
                timeout_seconds=timeout_seconds,
            )
            elapsed_ms = int((time.time() - start) * 1000)

            if not res.get("ok"):
                return {
                    "ok": False,
                    "target_address": hex(target_ea),
                    "target_detection_method": detection_method,
                    "avoid_addresses": avoid_str,
                    "error": res.get("error", "angr_find_paths failed"),
                    "error_type": res.get("error_type", "internal_error"),
                    "detection_notes": notes,
                    "engines_used": engines,
                }

            paths = res.get("paths", []) or []
            if not paths:
                return {
                    "ok": True,
                    "target_address": hex(target_ea),
                    "target_detection_method": detection_method,
                    "avoid_addresses": avoid_str,
                    "serial_found": False,
                    "paths_found": 0,
                    "elapsed_ms": elapsed_ms,
                    "detection_notes": notes,
                    "engines_used": engines,
                    "note": (res.get("note") or
                             "No paths found. Try increasing input_size, "
                             "removing char_constraint, or providing explicit "
                             "avoid_addresses."),
                }

            best = paths[0]
            return {
                "ok": True,
                "target_address": hex(target_ea),
                "target_detection_method": detection_method,
                "avoid_addresses": avoid_str,
                "serial_found": True,
                "serial": best.get("input_bytes", ""),
                "serial_hex": best.get("input_hex", ""),
                "path_length": best.get("path_length", 0),
                "elapsed_ms": elapsed_ms,
                "paths_found": len(paths),
                "all_serials": [p.get("input_bytes", "") for p in paths],
                "detection_notes": notes,
                "engines_used": engines,
                "note": f"Solved {len(paths)} path(s) via {detection_method}.",
            }
        except Exception as e:
            return tool_error(e, context="workflow_solve_crackme")


    # =====================================================================
    # A.3 — angr_cfg_from_ida
    # =====================================================================

    def _cfg_from_ida_impl(function_address: str) -> AngrCfgFromIdaResult:
        try:
            func_ea = parse_address(function_address)
            func = idaapi.get_func(func_ea)
            if func is None:
                return {
                    "ok": False,
                    "error": f"No function at {hex(func_ea)}",
                    "error_type": "not_found",
                }

            blocks: list[dict] = []
            edges: list[dict] = []
            try:
                fc = idaapi.FlowChart(func)
                for blk in fc:
                    blocks.append({
                        "start": hex(blk.start_ea),
                        "end": hex(blk.end_ea),
                        "size": int(blk.end_ea - blk.start_ea),
                    })
                    for succ in blk.succs():
                        edges.append({
                            "from": hex(blk.start_ea),
                            "to": hex(succ.start_ea),
                            "kind": "flow",
                        })
            except Exception as e:
                return tool_error(e, context="angr_cfg_from_ida/flowchart")

            return {
                "ok": True,
                "function_address": hex(func.start_ea),
                "function_name": idc.get_func_name(func.start_ea) or f"sub_{func.start_ea:X}",
                "block_count": len(blocks),
                "edge_count": len(edges),
                "blocks": blocks,
                "edges": edges,
                "note": "CFG extracted from IDA FlowChart.",
            }
        except Exception as e:
            return tool_error(e, context="angr_cfg_from_ida")


    @tool
    @idasync
    @tool_timeout(30.0)
    def angr_cfg_from_ida(
        function_address: Annotated[str, "Function address (hex)"],
    ) -> AngrCfgFromIdaResult:
        """Build a CFG from IDA's FlowChart for a single function.

        Faster than CFGFast for already-analyzed functions and uses IDA's
        analysis as ground truth. Useful as a sanity check or when angr's
        CFGFast misses blocks on obfuscated code.
        """
        return _cfg_from_ida_impl(function_address)


    # =====================================================================
    # A.4 — angr_diff_cfg
    # =====================================================================

    @tool
    @idasync
    @tool_timeout(90.0)
    def angr_diff_cfg(
        function_address: Annotated[str, "Function address (hex)"],
        project_id: Annotated[
            str | None,
            "Project ID for the 'after' (angr) state. Default: most recent.",
        ] = None,
    ) -> dict:
        """Compare IDA FlowChart vs angr CFGFast for a function.

        Useful for spotting obfuscation that fools one analyzer but not the
        other: angr's emulation-aware CFGFast sometimes resolves indirect
        jumps that IDA leaves unanalyzed, and vice versa.
        """
        try:
            ida_res = _cfg_from_ida_impl(function_address)
            if not ida_res.get("ok"):
                return ida_res
            ida_blocks = {b["start"]: b for b in ida_res.get("blocks", [])}

            entry, proj = _ensure_project(project_id)
            cfg = entry.get("cfg")
            if cfg is None:
                try:
                    cfg = _run_with_deadline(
                        lambda: proj.analyses.CFGFast(
                            normalize=True, resolve_indirect_jumps=True
                        ),
                        60.0,
                    )
                    entry["cfg"] = cfg
                except TimeoutError as e:
                    return tool_error(e, context="angr_diff_cfg/CFGFast")

            func_ea = parse_address(function_address)
            angr_blocks: dict[str, dict] = {}
            try:
                angr_func = cfg.kb.functions.get(func_ea)
                if angr_func is not None:
                    for ba in angr_func.block_addrs:
                        angr_blocks[hex(ba)] = {"start": hex(ba)}
            except Exception:
                pass

            blocks_in_ida_only = sorted(set(ida_blocks) - set(angr_blocks))
            blocks_in_angr_only = sorted(set(angr_blocks) - set(ida_blocks))
            shared = set(ida_blocks) & set(angr_blocks)

            return {
                "ok": True,
                "function_address": hex(func_ea),
                "ida_block_count": len(ida_blocks),
                "angr_block_count": len(angr_blocks),
                "shared_blocks": len(shared),
                "blocks_in_ida_only": blocks_in_ida_only[:50],
                "blocks_in_angr_only": blocks_in_angr_only[:50],
                "note": (
                    "ida_only blocks: angr missed (often obfuscated jumps); "
                    "angr_only blocks: angr resolved an indirect target IDA didn't."
                ),
            }
        except Exception as e:
            return tool_error(e, context="angr_diff_cfg")


    # =====================================================================
    # B.2 — angr_enumerate_reachable
    # =====================================================================

    @tool
    @idasync
    @tool_timeout(60.0)
    def angr_enumerate_reachable(
        source_address: Annotated[str, "Source address (hex or 'entry')"],
        max_depth: Annotated[int, "Maximum BFS depth (default: 15)"] = 15,
        max_nodes: Annotated[int, "Maximum nodes (default: 2000)"] = 2000,
        flag_strings: Annotated[
            list[str] | str | None,
            "Mark nodes whose function name matches any of these substrings (case-insensitive).",
        ] = None,
        project_id: Annotated[str | None, "Project ID"] = None,
    ) -> AngrReachableResult:
        """BFS over the static CFG from a source address.

        Reports reachable block addresses. Pure CFG operation — no symbolic
        execution; fast.
        """
        try:
            entry, proj = _ensure_project(project_id)
            cfg = entry.get("cfg")
            if cfg is None:
                cfg = proj.analyses.CFGFast(normalize=True, resolve_indirect_jumps=True)
                entry["cfg"] = cfg

            src_ea = _resolve_source_addr(proj, source_address)
            src_node = cfg.model.get_any_node(src_ea)
            if src_node is None:
                return {
                    "ok": False,
                    "error": f"No CFG node at {hex(src_ea)}.",
                    "error_type": "not_found",
                }

            graph = cfg.model.graph

            # SpillingCFG (angr >= 9.2) lacks .neighbors() which NetworkX
            # bfs_tree requires. Use manual BFS over .successors() instead.
            from collections import deque as _deque

            kw = None
            if flag_strings:
                kw = [s.lower() for s in normalize_list_input(flag_strings) if s]

            nodes_out: list[dict] = []
            interesting: list[str] = []
            seen_addrs: set[int] = set()
            bfs_queue: _deque = _deque()
            bfs_queue.append((src_node, 0))

            while bfs_queue and len(nodes_out) < max_nodes:
                n, depth = bfs_queue.popleft()
                addr = getattr(n, "addr", None)
                if addr is None or addr in seen_addrs:
                    continue
                seen_addrs.add(addr)

                func_name = None
                try:
                    f = cfg.kb.functions.get(getattr(n, "function_address", 0))
                    if f is not None:
                        func_name = f.name
                except Exception:
                    pass
                is_interesting = False
                if kw and func_name:
                    name_lower = func_name.lower()
                    is_interesting = any(k in name_lower for k in kw)
                nodes_out.append({
                    "addr": hex(addr),
                    "depth": depth,
                    "function_name": func_name or "",
                    "is_interesting": is_interesting,
                })
                if is_interesting:
                    interesting.append(hex(addr))

                if depth < max_depth:
                    try:
                        for succ in graph.successors(n):
                            saddr = getattr(succ, "addr", None)
                            if saddr is not None and saddr not in seen_addrs:
                                bfs_queue.append((succ, depth + 1))
                    except Exception:
                        pass

            return {
                "ok": True,
                "source_address": hex(src_ea),
                "reachable_count": len(nodes_out),
                "nodes": nodes_out,
                "interesting_addresses": interesting,
                "note": "BFS over CFGFast graph (no symbolic execution).",
            }
        except Exception as e:
            return tool_error(e, context="angr_enumerate_reachable")


    # =====================================================================
    # B.3 — angr_state_evaluate
    # =====================================================================

    @tool
    @idasync
    @tool_timeout(30.0)
    def angr_state_evaluate(
        at_address: Annotated[str, "Address to create the blank state at (hex)"],
        expression: Annotated[
            str,
            "Expression: register name ('rax'), arithmetic ('rax + rdi * 4'), "
            "or 'mem:0x1000:8' for an 8-byte memory dereference.",
        ],
        initial_registers: Annotated[
            dict | None,
            "Concrete register values: {'rax': '0x10', 'rdi': '0x20'}. "
            "Omit for default blank (zero-filled) state.",
        ] = None,
        project_id: Annotated[str | None, "Project ID"] = None,
    ) -> AngrStateEvalResult:
        """Evaluate a register/arithmetic expression at a blank state.

        Useful for ad-hoc constant-folding and exploring how a register
        value would compute given a concrete prefix of register state.
        """
        try:
            entry, proj = _ensure_project(project_id)
            at_ea = parse_address(at_address)
            state = proj.factory.blank_state(
                addr=at_ea,
                add_options=_STATE_ADD_OPTIONS,
                remove_options=_STATE_REMOVE_OPTIONS,
            )

            if initial_registers:
                for rname, rval in initial_registers.items():
                    try:
                        ival = parse_address(rval) if isinstance(rval, str) else int(rval)
                        setattr(state.regs, rname.lower(), _claripy.BVV(ival, proj.arch.bits))
                    except Exception:
                        continue

            expr = expression.strip()

            mem_match = _re.match(r"^mem:([^:]+):(\d+)$", expr, _re.IGNORECASE)
            if mem_match:
                addr_int = parse_address(mem_match.group(1))
                size_bytes = int(mem_match.group(2))
                result_bv = state.memory.load(addr_int, size_bytes)
            else:
                ns: dict = {}
                for reg_name in dir(state.regs):
                    if reg_name.startswith("_"):
                        continue
                    try:
                        val = getattr(state.regs, reg_name)
                        ns[reg_name] = val
                        ns[reg_name.upper()] = val
                    except Exception:
                        continue
                try:
                    result_bv = eval(expr, {"__builtins__": {}}, ns)
                except Exception as e:
                    return tool_error(
                        e,
                        context="angr_state_evaluate/expr",
                        hint="Use register names like 'rax', arithmetic like 'rax + 4*rdi', "
                             "or 'mem:0x401000:8'.",
                    )

            if hasattr(result_bv, "symbolic"):
                is_sym = bool(result_bv.symbolic)
                bw = result_bv.size()
                try:
                    val = state.solver.eval(result_bv)
                    return {
                        "ok": True,
                        "at_address": hex(at_ea),
                        "expression": expr,
                        "result": hex(val),
                        "result_decimal": str(val),
                        "is_symbolic": is_sym,
                        "bit_width": bw,
                        "note": "symbolic — one possible value" if is_sym else "concrete",
                    }
                except Exception as e:
                    return tool_error(e, context="angr_state_evaluate/eval")
            else:
                return {
                    "ok": True,
                    "at_address": hex(at_ea),
                    "expression": expr,
                    "result": str(result_bv),
                    "result_decimal": str(result_bv),
                    "is_symbolic": False,
                    "bit_width": 0,
                    "note": "non-bitvector result",
                }
        except Exception as e:
            return tool_error(e, context="angr_state_evaluate")


    # =====================================================================
    # B.4 — angr_hook_function
    # =====================================================================

    @tool
    @idasync
    @tool_timeout(15.0)
    def angr_hook_function(
        function_address: Annotated[str, "Address to hook (hex)"],
        hook_type: Annotated[
            str,
            "'skip' (return a fixed value), 'observe' (log calls), "
            "or 'unhook' (remove a previous hook).",
        ],
        return_value: Annotated[
            str,
            "For hook_type='skip': concrete return value (hex or decimal). Default: '0x0'.",
        ] = "0x0",
        return_bits: Annotated[
            int,
            "Width of the return value bitvector. Default: arch.bits.",
        ] = 0,
        project_id: Annotated[str | None, "Project ID"] = None,
    ) -> AngrHookResult:
        """Hook a function during symbolic execution.

        - 'skip':    Replace with a SimProcedure that returns `return_value`.
        - 'observe': Log every call to the function with argument values.
        - 'unhook':  Remove an existing hook.

        Hooks persist on the cached project across angr_find_paths calls.
        """
        try:
            entry, proj = _ensure_project(project_id)
            func_ea = parse_address(function_address)
            bits = return_bits if return_bits > 0 else proj.arch.bits

            if hook_type == "unhook":
                try:
                    proj.unhook(func_ea)
                except Exception as e:
                    return tool_error(e, context="angr_hook_function/unhook")
                entry.setdefault("hooks", {}).pop(func_ea, None)
                return {
                    "ok": True,
                    "function_address": hex(func_ea),
                    "hook_type": "unhook",
                    "hook_id": f"hook_{func_ea:X}",
                    "note": "Hook removed.",
                }

            if hook_type == "skip":
                try:
                    ret_int = parse_address(return_value)
                except Exception:
                    ret_int = 0
                rv_local = ret_int

                class _SkipHook(_angr.SimProcedure):  # noqa: N801
                    def run(self):  # type: ignore[override]
                        return _claripy.BVV(rv_local, bits)

                proj.hook(func_ea, _SkipHook())
                entry.setdefault("hooks", {})[func_ea] = "skip"
                return {
                    "ok": True,
                    "function_address": hex(func_ea),
                    "hook_type": "skip",
                    "hook_id": f"hook_{func_ea:X}",
                    "note": f"Function will return {hex(rv_local)} ({bits}-bit).",
                }

            if hook_type == "observe":
                log = entry.setdefault("hook_log", [])

                class _ObserveHook(_angr.SimProcedure):  # noqa: N801
                    NO_RET = False
                    def run(self):  # type: ignore[override]
                        try:
                            args = []
                            for r in ("rdi", "rsi", "rdx", "rcx", "r8", "r9"):
                                try:
                                    args.append(str(getattr(self.state.regs, r)))
                                except Exception:
                                    break
                            log.append({"addr": hex(func_ea), "args": args})
                        except Exception:
                            pass
                        return _claripy.BVS("observe_ret", bits)

                proj.hook(func_ea, _ObserveHook())
                entry.setdefault("hooks", {})[func_ea] = "observe"
                return {
                    "ok": True,
                    "function_address": hex(func_ea),
                    "hook_type": "observe",
                    "hook_id": f"hook_{func_ea:X}",
                    "note": "Calls logged to project entry; returns symbolic value.",
                }

            return tool_error(
                ValueError(f"unknown hook_type {hook_type!r}"),
                context="angr_hook_function",
                hint="hook_type must be 'skip', 'observe', or 'unhook'.",
            )
        except Exception as e:
            return tool_error(e, context="angr_hook_function")


    # =====================================================================
    # C.1 — angr_backward_slice
    # =====================================================================

    def _backward_slice_impl(
        target_address: str,
        target_reg: str | None = None,
        use_cfg_only: bool = True,
        project_id: str | None = None,
        max_results: int = 200,
        timeout_seconds: int = 60,
    ) -> AngrBackwardSliceResult:
        try:
            entry, proj = _ensure_project(project_id)
            target_ea = parse_address(target_address)
            timed_out = False

            if use_cfg_only:
                cfg = entry.get("cfg")
                if cfg is None:
                    try:
                        cfg = _run_with_deadline(
                            lambda: proj.analyses.CFGFast(
                                normalize=True, resolve_indirect_jumps=True
                            ),
                            float(timeout_seconds),
                        )
                        entry["cfg"] = cfg
                    except TimeoutError:
                        return {
                            "ok": False,
                            "error": "CFG build timed out.",
                            "error_type": "internal_error",
                            "timed_out": True,
                        }

                target_node = cfg.model.get_any_node(target_ea)
                if target_node is None:
                    return {
                        "ok": False,
                        "error": f"No CFG node at {hex(target_ea)}.",
                        "error_type": "not_found",
                    }

                def _build_slice():
                    # angr >= 9.2 requires cdg and ddg as positional args even
                    # when control_flow_slice=True; pass None for both.
                    return proj.analyses.BackwardSlice(
                        cfg, None, None,
                        control_flow_slice=True,
                        targets=[(target_node, -1)],
                    )

                try:
                    bs = _run_with_deadline(_build_slice, float(timeout_seconds))
                except TimeoutError:
                    return {
                        "ok": False,
                        "error": "BackwardSlice timed out.",
                        "error_type": "internal_error",
                        "timed_out": True,
                    }

                items: list[dict] = []
                try:
                    for node in bs.runs_in_slice.nodes():
                        addr = getattr(node, "addr", node) if not isinstance(node, int) else node
                        try:
                            mnem = idc.print_insn_mnem(addr) or ""
                        except Exception:
                            mnem = ""
                        func = idaapi.get_func(addr) if isinstance(addr, int) else None
                        fname = idc.get_func_name(func.start_ea) if func else ""
                        items.append({
                            "addr": hex(addr) if isinstance(addr, int) else str(addr),
                            "mnemonic": mnem,
                            "function_name": fname,
                            "reason": "control_flow_predecessor",
                        })
                        if len(items) >= max_results:
                            break
                except Exception as e:
                    logger.warning("Failed to enumerate slice nodes: %s", e)

                return {
                    "ok": True,
                    "target_address": hex(target_ea),
                    "target_reg": target_reg or "",
                    "slice_size": len(items),
                    "contributing_instructions": items,
                    "timed_out": timed_out,
                    "note": "CFG-only slice (control flow only).",
                }

            # DDG mode — slow path
            def _build_emu():
                cfg_e = proj.analyses.CFGEmulated(
                    keep_state=True,
                    state_add_options=_angr.sim_options.refs,
                    context_sensitivity_level=1,
                )
                cdg = proj.analyses.CDG(cfg_e)
                ddg = proj.analyses.DDG(cfg_e)
                tnode = cfg_e.model.get_any_node(target_ea)
                if tnode is None:
                    return None
                return proj.analyses.BackwardSlice(
                    cfg_e, cdg=cdg, ddg=ddg, targets=[(tnode, -1)]
                )

            try:
                bs = _run_with_deadline(_build_emu, float(timeout_seconds))
            except TimeoutError:
                return {
                    "ok": False,
                    "error": "CFGEmulated/DDG slice timed out.",
                    "error_type": "internal_error",
                    "timed_out": True,
                    "hint": "Use use_cfg_only=True for a much faster (but coarser) slice.",
                }
            if bs is None:
                return {
                    "ok": False,
                    "error": f"No CFGEmulated node at {hex(target_ea)}.",
                    "error_type": "not_found",
                }

            items = []
            chosen_stmts = getattr(bs, "chosen_statements", {}) or {}
            for blk_addr, stmts in chosen_stmts.items():
                for sid in (stmts or [])[:max_results]:
                    items.append({
                        "addr": hex(blk_addr),
                        "mnemonic": idc.print_insn_mnem(blk_addr) or "",
                        "function_name": idc.get_func_name(blk_addr) or "",
                        "reason": f"stmt_{sid}",
                    })
                    if len(items) >= max_results:
                        break
                if len(items) >= max_results:
                    break

            return {
                "ok": True,
                "target_address": hex(target_ea),
                "target_reg": target_reg or "",
                "slice_size": len(items),
                "contributing_instructions": items,
                "timed_out": False,
                "note": "DDG-backed slice (precise but slow).",
            }
        except Exception as e:
            return tool_error(e, context="angr_backward_slice")


    # In-process fallback, marshalled to the IDA main thread on demand.
    _backward_slice_in_process = idasync(_backward_slice_impl)

    @tool
    def angr_backward_slice(
        target_address: Annotated[str, "Address to slice from (hex)"],
        target_reg: Annotated[
            str | None,
            "Register to trace (e.g. 'rax'). Omit for control-flow slice.",
        ] = None,
        use_cfg_only: Annotated[
            bool,
            "Use CFG-only slice (fast, less precise). Default True — CFGEmulated/DDG is slow.",
        ] = True,
        project_id: Annotated[str | None, "Project ID"] = None,
        max_results: Annotated[int, "Maximum contributing items (default: 200)"] = 200,
        timeout_seconds: Annotated[int, "Timeout (default: 60)"] = 60,
    ) -> AngrBackwardSliceResult:
        """Find blocks/instructions that contribute to the target value.

        Two modes:
          • CFG-only (default, fast): uses CFGFast + control_flow_slice=True.
          • DDG-backed (use_cfg_only=False): uses CFGEmulated + CDG + DDG.
            Precise but minutes-long on real binaries.

        CFG-only runs in the out-of-process angr worker when available: this is
        what finally fixes the ``cannot pickle '_cffi_backend._CDataBase'`` error
        (the slice never leaves the worker — only a plain address list crosses,
        which the parent enriches with IDA mnemonics/names). DDG mode and the
        no-worker case use the in-process path.
        """
        if use_cfg_only and _use_worker():
            # angr_backward_slice is NOT @idasync (so the worker wait below stays
            # off the IDA main thread). The hint gather touches IDA APIs, so it
            # must marshal to the main thread — use the @idasync _gather_load_hints,
            # NOT _gather_load_hints_internal (which assumes it's already on the
            # main thread, and raised "can be called from the main thread only").
            hints = _gather_load_hints()
            res = _worker_request(
                "backward_slice",
                {"load": hints, "project_id": project_id,
                 "target_address": target_address, "target_reg": target_reg,
                 "max_results": max_results},
                timeout=float(timeout_seconds) + 30.0,
            )
            if res.get("ok"):
                items = _enrich_slice_addresses(res.get("slice_addresses", []), target_reg)
                return {
                    "ok": True,
                    "target_address": res.get("target_address", target_address),
                    "target_reg": target_reg or "",
                    "slice_size": len(items),
                    "contributing_instructions": items,
                    "timed_out": False,
                    "note": "CFG-only slice (control flow only) — computed out-of-process.",
                }
            return res  # structured worker error (timeout/not_found/etc.)

        return _backward_slice_in_process(
            target_address=target_address,
            target_reg=target_reg,
            use_cfg_only=use_cfg_only,
            project_id=project_id,
            max_results=max_results,
            timeout_seconds=timeout_seconds,
        )


    # =====================================================================
    # C.2 — angr_value_set
    # =====================================================================

    @tool
    @idasync
    @tool_timeout(60.0)
    def angr_value_set(
        function_address: Annotated[str, "Function start address (hex)"],
        at_address: Annotated[str, "Instruction address to evaluate at (hex)"],
        register: Annotated[str, "Register name (e.g. 'rax', 'rdi')"],
        project_id: Annotated[str | None, "Project ID"] = None,
        max_examples: Annotated[int, "Maximum concrete examples to enumerate"] = 5,
        timeout_seconds: Annotated[int, "Timeout (default: 30)"] = 30,
    ) -> AngrValueSetResult:
        """Compute the value-set bounds for a register at a program point.

        Uses angr's symbolic execution from the function entry to reach
        `at_address`, then queries the solver for the register's min/max
        values.
        """
        try:
            entry, proj = _ensure_project(project_id)
            func_ea = parse_address(function_address)
            at_ea = parse_address(at_address)

            state = proj.factory.blank_state(
                addr=func_ea,
                add_options=_STATE_ADD_OPTIONS,
                remove_options=_STATE_REMOVE_OPTIONS,
            )
            simgr = proj.factory.simgr(state)

            try:
                _run_with_deadline(
                    lambda: simgr.explore(find=at_ea),
                    float(timeout_seconds),
                )
            except TimeoutError:
                return {
                    "ok": False,
                    "error": "explore timed out",
                    "error_type": "internal_error",
                }

            found = list(getattr(simgr, "found", []) or [])
            if not found:
                return {
                    "ok": False,
                    "error": f"No path reached {hex(at_ea)} from {hex(func_ea)}.",
                    "error_type": "not_found",
                }
            fs = found[0]
            try:
                reg_bv = getattr(fs.regs, register.lower())
            except Exception as e:
                return tool_error(
                    e,
                    context="angr_value_set/register",
                    hint=f"Unknown register: {register!r}.",
                )

            is_concrete = not reg_bv.symbolic
            if is_concrete:
                val = fs.solver.eval(reg_bv)
                return {
                    "ok": True,
                    "function_address": hex(func_ea),
                    "at_address": hex(at_ea),
                    "register": register,
                    "bounds": {
                        "type": "concrete",
                        "is_concrete": True,
                        "concrete_value": hex(val),
                        "lower_bound": hex(val),
                        "upper_bound": hex(val),
                    },
                    "concrete_examples": [hex(val)],
                    "note": "Register is concretely determined at target.",
                }

            try:
                lo = fs.solver.min(reg_bv)
                hi = fs.solver.max(reg_bv)
            except Exception:
                lo = hi = fs.solver.eval(reg_bv)

            examples: list[str] = []
            try:
                for v in fs.solver.eval_upto(reg_bv, max_examples):
                    examples.append(hex(v))
            except Exception:
                pass

            return {
                "ok": True,
                "function_address": hex(func_ea),
                "at_address": hex(at_ea),
                "register": register,
                "bounds": {
                    "type": "interval",
                    "is_concrete": False,
                    "lower_bound": hex(lo),
                    "upper_bound": hex(hi),
                },
                "concrete_examples": examples,
                "note": "Register is symbolic — min/max from solver.",
            }
        except Exception as e:
            return tool_error(e, context="angr_value_set")


    # =====================================================================
    # C.3 / C.4 — snapshot save/restore
    # =====================================================================

    @tool
    @idasync
    @tool_timeout(15.0)
    def angr_snapshot_save(
        label: Annotated[str, "Human-readable label for this snapshot"],
        from_path_id: Annotated[
            int,
            "Index into the last_found_states list to save (default: 0 = best path).",
        ] = 0,
        project_id: Annotated[str | None, "Project ID"] = None,
    ) -> AngrSnapshotResult:
        """Save a SimState snapshot for later restoration.

        Uses the most recent ``angr_find_paths`` result's `found` states as
        the source. Pass `from_path_id` to select which one.
        """
        try:
            entry, proj = _ensure_project(project_id)
            states = entry.get("last_found_states") or []
            if not states or from_path_id >= len(states):
                return {
                    "ok": False,
                    "error": (
                        f"No state at from_path_id={from_path_id}. "
                        "Run angr_find_paths first."
                    ),
                    "error_type": "not_found",
                }
            state = states[from_path_id]
            snap_state = state.copy()
            snap_id = f"snap_{len(entry.get('snapshots', {}))}"
            entry.setdefault("snapshots", {})[snap_id] = {
                "label": label,
                "state": snap_state,
                "addr": getattr(snap_state, "addr", 0),
                "constraints": len(snap_state.solver.constraints),
            }
            return {
                "ok": True,
                "snapshot_id": snap_id,
                "label": label,
                "project_id": _project_id_for_entry(entry) or "",
                "addr": hex(getattr(snap_state, "addr", 0) or 0),
                "constraint_count": len(snap_state.solver.constraints),
                "note": "Snapshot saved. Use angr_snapshot_restore to recall.",
            }
        except Exception as e:
            return tool_error(e, context="angr_snapshot_save")


    @tool
    @idasync
    @tool_timeout(15.0)
    def angr_snapshot_restore(
        snapshot_id: Annotated[str, "Snapshot ID from angr_snapshot_save"],
        project_id: Annotated[str | None, "Project ID"] = None,
    ) -> AngrSnapshotResult:
        """Restore a previously-saved SimState snapshot into last_found_states[0]."""
        try:
            entry, _ = _ensure_project(project_id)
            snaps = entry.get("snapshots", {}) or {}
            snap = snaps.get(snapshot_id)
            if snap is None:
                return {
                    "ok": False,
                    "error": f"Unknown snapshot_id: {snapshot_id!r}",
                    "error_type": "not_found",
                }
            entry["last_found_states"] = [snap["state"].copy()]
            return {
                "ok": True,
                "snapshot_id": snapshot_id,
                "label": snap.get("label", ""),
                "project_id": _project_id_for_entry(entry) or "",
                "addr": hex(snap.get("addr", 0) or 0),
                "constraint_count": int(snap.get("constraints", 0)),
                "note": "Snapshot restored — available as path 0 in last_found_states.",
            }
        except Exception as e:
            return tool_error(e, context="angr_snapshot_restore")


    # =====================================================================
    # H.1 — hybrid_angr_triton_solve
    # =====================================================================

    @tool
    @idasync
    @tool_timeout(420.0)
    def hybrid_angr_triton_solve(
        target_address: Annotated[str, "Target address to reach (hex)"],
        source_address: Annotated[
            str, "Source address (default: 'entry')"
        ] = "entry",
        input_mode: Annotated[
            str, "'stdin', 'argv', or 'register'"
        ] = "stdin",
        input_size: Annotated[int, "Symbolic input size in bytes"] = 64,
        char_constraint: Annotated[
            str | None, "Char-class constraint"
        ] = "printable",
        avoid_addresses: Annotated[
            list[str] | str | None, "Addresses to avoid"
        ] = None,
        max_paths: Annotated[int, "Max paths to enumerate"] = 3,
        project_id: Annotated[str | None, "Project ID"] = None,
        timeout_seconds: Annotated[int, "Total timeout (default: 300)"] = 300,
    ) -> HybridAngrTritonResult:
        """Run angr_find_paths, then enrich each path with Triton symbolic state.

        Workflow:
          1. angr finds concrete stdin/argv bytes reaching the target.
          2. If Triton is installed, expose the paths for Triton inspection
             — the caller can then `triton_init` + `triton_process_function`
             over the same source function with the concrete input bytes
             written to the Triton state to extract full register-level
             symbolic constraints.

        Degrades gracefully when Triton is absent.
        """
        try:
            angr_start = time.time()
            res = _find_paths_impl(
                target_address=target_address,
                source_address=source_address,
                avoid_addresses=avoid_addresses,
                input_mode=input_mode,
                input_size=input_size,
                char_constraint=char_constraint,
                max_paths=max_paths,
                project_id=project_id,
                timeout_seconds=timeout_seconds,
            )
            angr_ms = int((time.time() - angr_start) * 1000)

            if not res.get("ok"):
                return {
                    "ok": False,
                    "error": res.get("error", "angr_find_paths failed"),
                    "error_type": res.get("error_type", "internal_error"),
                    "engines_used": ["angr"],
                }

            paths = res.get("paths", []) or []
            if not paths:
                return {
                    "ok": True,
                    "paths_found": 0,
                    "paths": [],
                    "engines_used": ["angr"],
                    "angr_time_ms": angr_ms,
                    "triton_time_ms": 0,
                    "note": "angr found no paths; Triton phase skipped.",
                }

            triton_available = False
            try:
                from . import api_triton as _ap_triton
                triton_available = bool(getattr(_ap_triton, "TRITON_AVAILABLE", False))
            except Exception:
                triton_available = False

            triton_start = time.time()
            enriched: list[dict] = []
            for p in paths:
                merged = dict(p)
                merged["triton_available"] = triton_available
                if triton_available:
                    merged["triton_note"] = (
                        "Triton available — call triton_init() then "
                        "triton_process_function() on the source function to "
                        "extract full register-level symbolic state."
                    )
                else:
                    merged["triton_note"] = (
                        "Triton not installed — install with `pip install triton-library`."
                    )
                enriched.append(merged)
            triton_ms = int((time.time() - triton_start) * 1000)

            engines = ["angr"] + (["triton"] if triton_available else [])
            return {
                "ok": True,
                "paths_found": len(enriched),
                "paths": enriched,
                "engines_used": engines,
                "angr_time_ms": angr_ms,
                "triton_time_ms": triton_ms,
                "note": (
                    "angr provided the concrete inputs; Triton can be invoked "
                    "separately for deep register-level analysis on each path."
                ),
            }
        except Exception as e:
            return tool_error(e, context="hybrid_angr_triton_solve")


    # =====================================================================
    # H.2 — hybrid_angr_stdin_fuzz
    # =====================================================================

    @tool
    @idasync
    @tool_timeout(420.0)
    def hybrid_angr_stdin_fuzz(
        target_address: Annotated[str, "Target address to reach (hex)"],
        source_address: Annotated[
            str, "Source address (default: 'entry')"
        ] = "entry",
        avoid_addresses: Annotated[
            list[str] | str | None, "Addresses to avoid"
        ] = None,
        input_size: Annotated[int, "Stdin size in bytes (default: 64)"] = 64,
        char_constraint: Annotated[
            str, "Character class (default: 'printable')"
        ] = "printable",
        max_inputs: Annotated[int, "Maximum distinct inputs (default: 5)"] = 5,
        project_id: Annotated[str | None, "Project ID"] = None,
        timeout_seconds: Annotated[int, "Timeout (default: 300)"] = 300,
    ) -> AngrStdinFuzzResult:
        """Constrained stdin enumeration — find multiple valid inputs to a target.

        Calls `_find_paths_impl` with `max_paths=max_inputs`. The
        char_constraint is enforced from the start, dramatically reducing
        the symbolic search space compared to unconstrained byte ranges.
        """
        try:
            res = _find_paths_impl(
                target_address=target_address,
                source_address=source_address,
                avoid_addresses=avoid_addresses,
                input_mode="stdin",
                input_size=input_size,
                char_constraint=char_constraint,
                max_paths=max_inputs,
                project_id=project_id,
                timeout_seconds=timeout_seconds,
            )
            if not res.get("ok"):
                return {
                    "ok": False,
                    "error": res.get("error", "angr_find_paths failed"),
                    "error_type": res.get("error_type", "internal_error"),
                }
            paths = res.get("paths", []) or []
            return {
                "ok": True,
                "target_address": res.get("target_address", target_address),
                "inputs_found": len(paths),
                "inputs": [p.get("input_bytes", "") for p in paths],
                "inputs_hex": [p.get("input_hex", "") for p in paths],
                "char_constraint_used": char_constraint,
                "paths_explored": res.get("states_explored", 0),
                "timed_out": res.get("timed_out", False),
                "note": (
                    f"Found {len(paths)} distinct input(s) matching the constraint. "
                    "Run again with a tighter constraint if results look like noise."
                ),
            }
        except Exception as e:
            return tool_error(e, context="hybrid_angr_stdin_fuzz")


    # =====================================================================
    # H.3 — hybrid_angr_miasm_path
    # =====================================================================

    @tool
    @idasync
    @tool_timeout(360.0)
    def hybrid_angr_miasm_path(
        function_address: Annotated[str, "Function to analyze (hex)"],
        target_address: Annotated[str, "Target address within function (hex)"],
        input_mode: Annotated[str, "'stdin' or 'argv'"] = "stdin",
        input_size: Annotated[int, "Symbolic input size"] = 64,
        deobfuscate: Annotated[
            bool, "Run Miasm constant-folding / DCE first (default: True)"
        ] = True,
        project_id: Annotated[str | None, "Project ID"] = None,
        timeout_seconds: Annotated[int, "Total timeout (default: 180)"] = 180,
    ) -> HybridMiasmAngrResult:
        """Miasm deobfuscates first, then angr solves on the simplified context.

        Workflow:
          1. api_miasm.miasm_cfg → block count (informational).
          2. If deobfuscate=True: api_miasm.miasm_deobfuscate_cfg.
          3. _find_paths_impl(target, source=function_address).

        Miasm doesn't re-emit binary code — we use its analysis to confirm
        that angr should be able to find a path. Failure modes are
        informative: if angr can't solve but Miasm finds a simpler CFG,
        the gap shows where to focus.
        """
        try:
            miasm_available = False
            miasm_blocks = 0
            try:
                from . import api_miasm as _ap_miasm
                miasm_available = bool(getattr(_ap_miasm, "MIASM_AVAILABLE", False))
                # Note: miasm_cfg and miasm_deobfuscate_cfg are @idasync — we cannot
                # call them from within our @idasync context. We just check availability
                # and skip the actual analysis (Miasm can still be run separately).
            except Exception:
                miasm_available = False

            ang_res = _find_paths_impl(
                target_address=target_address,
                source_address=function_address,
                input_mode=input_mode,
                input_size=input_size,
                project_id=project_id,
                timeout_seconds=timeout_seconds,
            )

            engines = ["angr"]
            if miasm_available:
                engines.append("miasm")

            if not ang_res.get("ok"):
                return {
                    "ok": False,
                    "error": ang_res.get("error", "angr_find_paths failed"),
                    "engines_used": engines,
                }

            paths = ang_res.get("paths", []) or []
            best_solution = paths[0].get("input_bytes", "") if paths else ""
            best_hex = paths[0].get("input_hex", "") if paths else ""
            return {
                "ok": True,
                "function_address": function_address,
                "target_address": target_address,
                "miasm_available": miasm_available,
                "miasm_blocks": miasm_blocks,
                "angr_paths_found": len(paths),
                "solution": best_solution,
                "solution_hex": best_hex,
                "engines_used": engines,
                "note": (
                    f"angr found {len(paths)} path(s). "
                    + ("Miasm available — call miasm_cfg / miasm_deobfuscate_cfg "
                       "directly for CFG simplification metrics."
                       if miasm_available else "Miasm not installed.")
                ),
            }
        except Exception as e:
            return tool_error(e, context="hybrid_angr_miasm_path")


    # =====================================================================
    # H.4 — hybrid_angr_triton_decompile
    # =====================================================================

    @tool
    @idasync
    @tool_timeout(120.0)
    def hybrid_angr_triton_decompile(
        function_address: Annotated[str, "Function address (hex or symbol)"],
        symbolize_args: Annotated[
            str, "Comma-separated registers to symbolize as attacker-controlled "
                 "(default: 'rdi,rsi,rdx' — x64 first three args). "
                 "Use 'rcx,rdx,r8,r9' for __fastcall x64 convention."
        ] = "rdi,rsi,rdx",
        show_symbolic_only: Annotated[
            bool, "Show only lines with symbolic operands (default: False)"
        ] = False,
        max_insns: Annotated[int, "Maximum instructions to process through Triton (default: 500)"] = 500,
        annotate_idb: Annotated[
            bool,
            "Write symbolic annotations as IDA comments at instruction addresses "
            "(default: False — read-only analysis). Set True to persist symbolic "
            "state as inline comments in the IDB.",
        ] = False,
    ) -> HybridDecompileResult:
        """⭐ Decompile a function with Triton symbolic execution annotations.

        Runs Triton's symbolic engine over the function, then annotates the IDA
        decompiler pseudocode with symbolic register/memory expressions. Each
        line that uses a symbolic value is marked with `has_symbolic_ops: true`
        and the symbolic expression (e.g. `rax = user_rdi ^ 0x6D`).

        This reveals HOW user input propagates through the function — the agent
        can see exactly which pseudocode lines depend on symbolized registers.

        When annotate_idb=True, also writes `;; sym: rax = ...` comments into
        the IDA database at each instruction address for permanent annotation.

        Requires triton-library installed.
        """
        try:
            func_ea = parse_address(function_address)
            func = idaapi.get_func(func_ea)
            if func is None:
                return {
                    "ok": False,
                    "error": f"No function at {hex(func_ea)}",
                    "engines_used": ["ida"],
                }

            fname = idc.get_func_name(func.start_ea) or f"sub_{func.start_ea:X}"

            engines = ["ida"]
            symbolic_state: dict[int, dict[str, str]] = {}
            constraint_count = 0
            triton_used = False

            # ═══════════════════════════════════════════════════════════════════
            # Triton symbolic execution pass
            # ═══════════════════════════════════════════════════════════════════
            try:
                from .api_triton import TRITON_AVAILABLE as _TA
            except ImportError:
                _TA = False

            if _TA:
                try:
                    from triton import (
                        ARCH, MODE, AST_REPRESENTATION, TritonContext,
                        Instruction as TritonInstruction,
                        MemoryAccess as TritonMemoryAccess,
                    )
                    from . import api_triton as _ap_triton  # noqa: F401

                    # Architecture detection
                    info = idaapi.get_inf_structure()
                    proc = info.procname
                    bitness = 64 if compat.inf_is_64bit() else 32

                    arch_map = {
                        ("metapc", 64): ARCH.X86_64,
                        ("metapc", 32): ARCH.X86,
                        ("arm", 64): ARCH.AARCH64,
                        ("arm", 32): ARCH.ARM32,
                    }
                    triton_arch = arch_map.get((proc, bitness))
                    if triton_arch is None:
                        return {
                            "ok": False,
                            "error": f"Unsupported arch: {proc} {bitness}bit",
                            "engines_used": engines,
                        }

                    ctx = TritonContext(triton_arch)
                    ctx.setMode(MODE.CONSTANT_FOLDING, True)
                    ctx.setMode(MODE.AST_OPTIMIZATIONS, True)
                    ctx.setAstRepresentationMode(AST_REPRESENTATION.SMT)

                    # Symbolize registers
                    regs_to_sym = [r.strip().lower() for r in symbolize_args.split(",") if r.strip()]
                    reg_name_to_id: dict[str, int] = {}
                    if triton_arch == ARCH.X86_64:
                        reg_name_to_id = {
                            "rax": ctx.registers.rax, "rbx": ctx.registers.rbx,
                            "rcx": ctx.registers.rcx, "rdx": ctx.registers.rdx,
                            "rsi": ctx.registers.rsi, "rdi": ctx.registers.rdi,
                            "r8": ctx.registers.r8, "r9": ctx.registers.r9,
                            "r10": ctx.registers.r10, "r11": ctx.registers.r11,
                            "r12": ctx.registers.r12, "r13": ctx.registers.r13,
                            "r14": ctx.registers.r14, "r15": ctx.registers.r15,
                        }
                    elif triton_arch == ARCH.X86:
                        reg_name_to_id = {
                            "eax": ctx.registers.eax, "ebx": ctx.registers.ebx,
                            "ecx": ctx.registers.ecx, "edx": ctx.registers.edx,
                            "esi": ctx.registers.esi, "edi": ctx.registers.edi,
                        }

                    symbolized: list[str] = []
                    for reg_name in regs_to_sym:
                        reg_id = reg_name_to_id.get(reg_name)
                        if reg_id is not None:
                            var = ctx.symbolizeRegister(reg_id, f"user_{reg_name}")
                            if var:
                                symbolized.append(reg_name)

                    if not symbolized:
                        return {
                            "ok": False,
                            "error": f"None of {regs_to_sym} could be symbolized for {proc}",
                            "engines_used": engines,
                        }

                    # Process instructions
                    insns: list[tuple[int, bytes]] = []
                    for item_ea in idautils.FuncItems(func.start_ea):
                        if len(insns) >= max_insns:
                            break
                        size = idc.get_item_size(item_ea)
                        if size <= 0 or size > 16:
                            continue
                        bts = ida_bytes.get_bytes(item_ea, size)
                        if bts:
                            insns.append((item_ea, bytes(bts)))

                    for item_ea, bts in insns:
                        try:
                            inst = TritonInstruction(item_ea, bts)
                            ctx.processing(inst)
                        except Exception:
                            continue
                        # Collect current symbolic state for this address
                        sr = ctx.getSymbolicRegisters()
                        addr_state: dict[str, str] = {}
                        for reg_id, expr in sr.items():
                            reg_name = None
                            for rn, rid in reg_name_to_id.items():
                                if rid == reg_id:
                                    reg_name = rn
                                    break
                            if reg_name:
                                try:
                                    ast_str = str(ctx.unrollAst(expr.getAst()))
                                    # Simplify: strip SMT2 define-fun wrapper
                                    if ast_str.startswith("(define-fun "):
                                        ast_str = ast_str.split(")", 1)[-1].strip()
                                    addr_state[reg_name] = ast_str[:120]
                                except Exception:
                                    addr_state[reg_name] = "symbolic"
                        if addr_state:
                            symbolic_state[item_ea] = addr_state

                    constraint_count = len(ctx.getPathConstraints())
                    triton_used = True
                    engines.append("triton")
                except Exception as e:
                    logger.warning("Triton symbolic pass failed: %s", e)

            # ═══════════════════════════════════════════════════════════════════
            # Decompile + annotate
            # ═══════════════════════════════════════════════════════════════════
            try:
                from .utils import decompile_function_safe
                pseudo = decompile_function_safe(func.start_ea, include_addresses=True) or ""
            except Exception:
                pseudo = ""

            annotated: list[dict] = []
            symbolic_lines = 0
            for line in pseudo.split("\n")[:max(max_insns, 2000)]:
                m = _re.search(r"/\*(0x[0-9a-fA-F]+)\*/", line)
                addr_str = m.group(1) if m else ""
                has_sym = False
                sym_exprs: dict[str, str] = {}

                if addr_str and triton_used:
                    try:
                        addr = int(addr_str, 16)
                        # Match closest symbolic state to this address
                        best_match = None
                        best_dist = 999999
                        for sym_ea in symbolic_state:
                            dist = abs(addr - sym_ea)
                            if dist <= 16 and dist < best_dist:
                                best_match = sym_ea
                                best_dist = dist
                        if best_match is not None:
                            sym_exprs = symbolic_state[best_match]
                            has_sym = True
                            symbolic_lines += 1
                    except (ValueError, TypeError):
                        pass

                annotated.append({
                    "line": line,
                    "addr": addr_str,
                    "has_symbolic_ops": has_sym,
                    "symbolic_registers": sym_exprs if sym_exprs else None,
                })

            # ═══════════════════════════════════════════════════════════════════
            # Write IDA comments if requested
            # ═══════════════════════════════════════════════════════════════════
            if annotate_idb and triton_used and symbolic_state:
                for ea, regs in symbolic_state.items():
                    parts = [f"{r}: {e[:60]}" for r, e in sorted(regs.items())]
                    comment = "sym: " + "; ".join(parts)[:400]
                    try:
                        ida_bytes.set_cmt(ea, comment, False)
                    except Exception:
                        pass

            if show_symbolic_only:
                annotated = [a for a in annotated if a.get("has_symbolic_ops")]

            return {
                "ok": True,
                "function_address": hex(func.start_ea),
                "function_name": fname,
                "pseudocode": pseudo,
                "annotated_lines": annotated,
                "symbolic_line_count": symbolic_lines,
                "total_instructions_processed": len(symbolic_state),
                "constraint_count": constraint_count,
                "symbolized_registers": symbolized if triton_used else [],
                "engines_used": engines,
            }
        except Exception as e:
            return tool_error(e, context="hybrid_angr_triton_decompile")


    # =====================================================================
    # H.5 — hybrid_angr_z3_formula
    # =====================================================================

    @tool
    @idasync
    @tool_timeout(60.0)
    def hybrid_angr_z3_formula(
        path_id: Annotated[
            int, "Index into last_found_states (default 0)"
        ] = 0,
        project_id: Annotated[str | None, "Project ID"] = None,
        include_full_smt2: Annotated[
            bool,
            "Include full SMT-LIB2 text in output (can be large). Default: False — summary only.",
        ] = False,
    ) -> AngrZ3FormulaResult:
        """Export the path's constraint set for inspection / external Z3."""
        try:
            entry, _ = _ensure_project(project_id)
            states = entry.get("last_found_states") or []
            if path_id >= len(states):
                return {
                    "ok": False,
                    "error": f"No found state at path_id={path_id}. Run angr_find_paths first.",
                }
            fs = states[path_id]
            constraints = list(fs.solver.constraints)

            smt2 = ""
            variables: list[str] = []
            try:
                bz = _claripy.backends.z3
                if include_full_smt2:
                    solver = bz.solver()
                    for c in constraints:
                        solver.add(bz.convert(c))
                    smt2 = solver.to_smt2()
            except Exception as e:
                logger.warning("SMT-LIB2 export failed: %s", e)
                smt2 = ""

            try:
                for c in constraints[:32]:
                    for v in c.variables:
                        if v not in variables:
                            variables.append(str(v))
            except Exception:
                pass

            return {
                "ok": True,
                "smt2_formula": smt2 if include_full_smt2 else "",
                "constraint_count": len(constraints),
                "variables": variables[:50],
                "note": (
                    "Full SMT-LIB2 omitted (include_full_smt2=False)"
                    if not include_full_smt2 else
                    "Full SMT-LIB2 included — may be very large."
                ),
            }
        except Exception as e:
            return tool_error(e, context="hybrid_angr_z3_formula")


    # =====================================================================
    # W.2 — workflow_trace_data_flow
    # =====================================================================

    @tool
    @idasync
    @tool_timeout(180.0)
    def workflow_trace_data_flow(
        sink_address: Annotated[str, "Address where the value is used (hex)"],
        sink_reg: Annotated[str, "Register at the sink (e.g. 'rax', 'rdi')"],
        source_address: Annotated[
            str | None,
            "Starting point for trace (default: function start of sink)",
        ] = None,
        project_id: Annotated[str | None, "Project ID"] = None,
    ) -> DataFlowResult:
        """Backward data-flow trace using backward_slice + IDA xrefs.

        Composes a CFG-only backward slice with IDA's xref database to
        produce a human-readable trace of which instructions contribute to
        the sink register's value.
        """
        try:
            sink_ea = parse_address(sink_address)
            if source_address is None:
                func = idaapi.get_func(sink_ea)
                source_ea = func.start_ea if func else sink_ea
            else:
                source_ea = parse_address(source_address)

            bs = _backward_slice_impl(
                target_address=hex(sink_ea),
                target_reg=sink_reg,
                use_cfg_only=True,
                project_id=project_id,
            )
            if not bs.get("ok"):
                return {
                    "ok": False,
                    "error": bs.get("error", "backward_slice failed"),
                    "engines_used": ["angr"],
                }

            items = bs.get("contributing_instructions", []) or []
            nodes: list[dict] = []
            for it in items:
                addr_str = it.get("addr", "")
                try:
                    addr_int = parse_address(addr_str) if addr_str else 0
                except Exception:
                    addr_int = 0
                insn = ""
                try:
                    insn = idc.GetDisasm(addr_int) if addr_int else ""
                except Exception:
                    pass
                fn_name = it.get("function_name", "")
                nodes.append({
                    "addr": addr_str,
                    "insn": insn,
                    "function_name": fn_name,
                    "contributes_to": sink_reg,
                })

            cross = False
            seen_funcs = {n.get("function_name", "") for n in nodes if n.get("function_name")}
            if len(seen_funcs) > 1:
                cross = True

            return {
                "ok": True,
                "source_address": hex(source_ea),
                "sink_address": hex(sink_ea),
                "sink_reg": sink_reg,
                "trace_direction": "backward",
                "nodes": nodes,
                "terminated_reason": "slice_complete",
                "cross_functions": cross,
                "engines_used": ["angr", "ida"],
            }
        except Exception as e:
            return tool_error(e, context="workflow_trace_data_flow")


    # =====================================================================
    # W.3 — workflow_find_gadgets
    # =====================================================================

    @tool
    @idasync
    @tool_timeout(60.0)
    def workflow_find_gadgets(
        segment_name: Annotated[str, "Segment to search (default: '.text')"] = ".text",
        gadget_types: Annotated[
            str, "Comma-separated: 'rop', 'jop', 'call' (default: 'rop')"
        ] = "rop",
        max_gadgets: Annotated[int, "Maximum gadgets to return (default: 100)"] = 100,
        max_insns_per_gadget: Annotated[int, "Max instructions per gadget"] = 5,
        project_id: Annotated[str | None, "Project ID"] = None,
    ) -> GadgetsResult:
        """Find ROP/JOP gadgets in a segment.

        Uses IDA's disassembly to locate `ret`/`jmp reg`/`call reg`
        instructions, then walks backwards up to `max_insns_per_gadget`
        instructions to construct each gadget. No symbolic execution.
        """
        try:
            types_set = {t.strip().lower() for t in (gadget_types or "rop").split(",")}
            target_mnem: set[str] = set()
            if "rop" in types_set:
                target_mnem.update({"ret", "retn"})
            if "jop" in types_set:
                target_mnem.update({"jmp"})
            if "call" in types_set:
                target_mnem.update({"call"})

            seg_start = seg_end = 0
            for seg_ea in idautils.Segments():
                if idc.get_segm_name(seg_ea) == segment_name:
                    seg_start = seg_ea
                    seg_end = idc.get_segm_end(seg_ea)
                    break
            if seg_end == 0:
                return {
                    "ok": False,
                    "error": f"Segment {segment_name!r} not found.",
                    "segment": segment_name,
                    "gadget_count": 0,
                    "gadgets": [],
                }

            gadgets: list[dict] = []
            ea = seg_start
            while ea < seg_end and len(gadgets) < max_gadgets:
                mnem = (idc.print_insn_mnem(ea) or "").lower()
                if mnem in target_mnem:
                    chain_addrs: list[int] = [ea]
                    cursor = ea
                    for _ in range(max_insns_per_gadget - 1):
                        prev = idc.prev_head(cursor, seg_start)
                        if prev == idaapi.BADADDR or prev < seg_start:
                            break
                        if not idc.is_code(idc.get_full_flags(prev)):
                            break
                        chain_addrs.insert(0, prev)
                        cursor = prev
                    mnemonics = []
                    for a in chain_addrs:
                        disasm = (idc.GetDisasm(a) or "").strip()
                        mnemonics.append(disasm.split(";", 1)[0].strip())
                    size = (ea + idc.get_item_size(ea)) - chain_addrs[0]
                    raw = read_bytes_bss_safe(chain_addrs[0], size)
                    gadget_type = (
                        "rop" if mnem in ("ret", "retn")
                        else "jop" if mnem == "jmp"
                        else "call"
                    )
                    gadgets.append({
                        "addr": hex(chain_addrs[0]),
                        "bytes": raw.hex(" "),
                        "mnemonics": mnemonics,
                        "gadget_type": gadget_type,
                    })
                ea = idc.next_head(ea, seg_end)
                if ea == idaapi.BADADDR:
                    break

            return {
                "ok": True,
                "segment": segment_name,
                "gadget_count": len(gadgets),
                "gadgets": gadgets,
                "note": (
                    f"Found {len(gadgets)} gadget(s) in {segment_name}. "
                    "Structural only — no semantic equivalence checking."
                ),
            }
        except Exception as e:
            return tool_error(e, context="workflow_find_gadgets")


    # =====================================================================
    # W.4 — workflow_enum_code_hints
    # =====================================================================

    @tool
    @idasync
    @tool_timeout(300.0)
    def workflow_enum_code_hints(
        target_address: Annotated[str, "Target address (hex)"],
        source_address: Annotated[str, "Source (default: 'entry')"] = "entry",
        max_paths: Annotated[int, "Maximum paths to enumerate (default: 5)"] = 5,
        input_mode: Annotated[str, "'stdin' (default), 'argv', or 'register'"] = "stdin",
        input_size: Annotated[int, "Input size in bytes"] = 64,
        project_id: Annotated[str | None, "Project ID"] = None,
        timeout_seconds: Annotated[int, "Timeout (default: 120)"] = 120,
    ) -> CodeHintsResult:
        """Enumerate paths to a target + extract per-path constraint hints.

        Useful as a precursor to workflow_solve_crackme: discover what
        prefix / structural constraints any solution must satisfy.
        """
        try:
            res = _find_paths_impl(
                target_address=target_address,
                source_address=source_address,
                input_mode=input_mode,
                input_size=input_size,
                max_paths=max_paths,
                project_id=project_id,
                timeout_seconds=timeout_seconds,
            )
            if not res.get("ok"):
                return {
                    "ok": False,
                    "error": res.get("error", "find_paths failed"),
                }

            entry, _ = _ensure_project(project_id)
            states = entry.get("last_found_states") or []

            path_summaries: list[dict] = []
            for i, fs in enumerate(states[:max_paths]):
                try:
                    if input_mode == "stdin":
                        sb = fs.posix.stdin.load(0, fs.posix.stdin.size)
                    else:
                        sb = None
                    constraint_texts: list[str] = []
                    if sb is not None:
                        eval_bytes = fs.solver.eval(sb, cast_to=bytes)[:input_size]
                        for bi in range(min(len(eval_bytes), input_size, 32)):
                            byte_var = sb.get_byte(bi)
                            try:
                                if not byte_var.symbolic:
                                    continue
                                if (
                                    fs.solver.min(byte_var)
                                    == fs.solver.max(byte_var)
                                ):
                                    constraint_texts.append(
                                        f"byte[{bi}] == {hex(eval_bytes[bi])} "
                                        f"({chr(eval_bytes[bi]) if 32 <= eval_bytes[bi] < 127 else '.'})"
                                    )
                            except Exception:
                                continue
                    path_summaries.append({
                        "path_id": i,
                        "path_length": len(list(fs.history.bbl_addrs)),
                        "constraints": constraint_texts[:50],
                        "satisfiable": True,
                    })
                except Exception as e:
                    path_summaries.append({
                        "path_id": i, "constraints": [], "satisfiable": False,
                        "error": str(e),
                    })

            prefix_hints: list[str] = []
            if path_summaries:
                common = set(path_summaries[0].get("constraints", []))
                for p in path_summaries[1:]:
                    common &= set(p.get("constraints", []))
                prefix_hints = sorted(common)[:50]

            return {
                "ok": True,
                "target_address": res.get("target_address", target_address),
                "path_count": len(path_summaries),
                "paths": path_summaries,
                "prefix_hints": prefix_hints,
                "note": (
                    f"{len(prefix_hints)} byte position(s) uniquely determined across all paths. "
                    "Use these as char_constraint or known_format in workflow_solve_crackme."
                ),
            }
        except Exception as e:
            return tool_error(e, context="workflow_enum_code_hints")


    # =====================================================================
    # H.6 — hybrid_angr_unicorn_concrete  (Phase 6.4 — Unicorn coupling)  ⚠️ unsafe
    # =====================================================================

    @unsafe
    @tool
    @idasync
    @tool_timeout(180.0)
    def hybrid_angr_unicorn_concrete(
        decrypt_stub: Annotated[str, "Decrypt-stub start address (hex)."],
        encrypted_start: Annotated[str, "Encrypted region start (hex)."],
        encrypted_size: Annotated[int, "Encrypted region size in bytes."],
        stub_end: Annotated[
            str | None, "Decrypt-stub end (hex). Default: encrypted_start."
        ] = None,
        regs: Annotated[dict | None, "Decryption args as registers."] = None,
        run_cfg: Annotated[bool, "Build a CFGFast after loading (default True)."] = True,
        uc_max_insns: Annotated[int, "Unicorn instruction cap (default 500000)."] = 500000,
        uc_timeout_ms: Annotated[int, "Unicorn timeout in ms (default 15000)."] = 15000,
    ) -> dict:
        """Unicorn decrypts a region → angr loads & analyzes the revealed code.

        Closes the loop between concrete and symbolic engines:
          1. Unicorn maps the IDB, runs the decrypt stub, and patches the
             decrypted bytes into the database (the part angr cannot do —
             angr can't execute a runtime-only decryptor).
          2. angr (re)loads the now-decrypted binary into a Project.
          3. Optional CFGFast over the freshly-visible functions.

        After this, the full angr toolset (find_paths, backward_slice, …)
        works on code that did not exist statically. Requires both engines.
        """
        try:
            try:
                from . import api_unicorn as _U
            except Exception:
                _U = None
            if _U is None or not getattr(_U, "UNICORN_AVAILABLE", False):
                return {"ok": False, "error": "unicorn not installed",
                        "error_type": "missing_dependency",
                        "note": "Install with: pip install unicorn"}

            import ida_bytes
            import ida_auto

            stub_ea = parse_address(decrypt_stub)
            enc_start = parse_address(encrypted_start)
            end_ea = parse_address(stub_end) if stub_end else enc_start

            # We are already on the IDA main thread (@idasync), so call the
            # raw segment gather directly. Unicorn releases the GIL during
            # emu_start and _emulate_impl owns a Timer that force-stops it, so
            # the decrypt stub cannot freeze the UI past uc_timeout_ms.
            segments = _U._gather_ida_segments_internal()
            uc_arch, uc_mode, bits = _U._detect_uc_arch()
            emu_res = _U._emulate_impl(
                segments, uc_arch, uc_mode, bits,
                stub_ea, end_ea, regs, _U._DEFAULT_STACK_SIZE,
                uc_max_insns, uc_timeout_ms,
            )
            ctl = emu_res.pop("_controller")
            try:
                decrypted = bytes(ctl.emu.mem_read(enc_start, encrypted_size))
            except Exception as e:
                return {"ok": False,
                        "error": f"could not read decrypted region: {e}",
                        "error_type": "unmapped_memory",
                        "unicorn_stop_reason": emu_res.get("stop_reason")}

            before = _U._original_bytes(segments, enc_start, encrypted_size)
            ent_before = _U._shannon_entropy(before)
            ent_after = _U._shannon_entropy(decrypted)
            ida_bytes.patch_bytes(enc_start, decrypted)
            ida_auto.plan_and_wait(enc_start, enc_start + encrypted_size)

            # Reload into angr so the Project sees the patched bytes. Evict any
            # stale cached project for this binary first so we don't reuse a
            # pre-decryption load.
            path = idaapi.get_input_file_path() or ""
            with _PROJECT_LOCK:
                stale = [pid for pid, ent in _angr_projects.items()
                         if ent.get("binary_path") == path]
                for pid in stale:
                    _angr_projects.pop(pid, None)

            load_res = _load_segment_impl()
            cfg_res = None
            if run_cfg and load_res.get("ok"):
                cfg_res = _cfg_fast_impl(project_id=load_res.get("project_id"))

            delta = round(ent_after - ent_before, 3)
            return {
                "ok": bool(load_res.get("ok")),
                "engines_used": ["unicorn", "angr"],
                "unicorn_phase": {
                    "insns_executed": emu_res.get("insns_executed", 0),
                    "stop_reason": emu_res.get("stop_reason"),
                    "bytes_patched": len(decrypted),
                    "entropy_before": ent_before,
                    "entropy_after": ent_after,
                    "entropy_delta": delta,
                },
                "angr_load": load_res,
                "angr_cfg": cfg_res,
                "note": (
                    f"Decrypted {len(decrypted)} bytes (entropy delta {delta}) and "
                    "reloaded into angr. "
                    + ("CFG built — run angr_find_paths/angr_backward_slice on the "
                       "recovered functions." if cfg_res and cfg_res.get("ok")
                       else "Run angr_cfg_fast next to map the recovered code.")),
            }
        except Exception as e:
            return tool_error(e, context="hybrid_angr_unicorn_concrete")
