"""Triton symbolic execution, taint analysis, and SMT solving.

Optional module: tools are only registered when triton-library is installed.
Install with: pip install triton-library

All tools run on the IDA main thread via @idasync and read bytes directly
from the open IDA database — no file path or manual byte feeding required.
"""

import logging
import sys
import time
import threading
import collections
from collections import OrderedDict
from typing import Annotated, NotRequired, TypedDict

logger = logging.getLogger(__name__)

# ============================================================================
# Optional import guard
# ============================================================================

# Python 313 path fallback: if running under a different Python (e.g. the
# hermes-agent venv), prepend Python 313's site-packages so triton-library
# can be found even when IDA loads the plugin from its own embedded Python.
_PY313_SITE_PACKAGES = r"C:\Users\User\AppData\Local\Programs\Python\Python313\Lib\site-packages"
if _PY313_SITE_PACKAGES not in sys.path:
    sys.path.insert(0, _PY313_SITE_PACKAGES)

try:
    import triton as _triton_lib
    from triton import (
        ARCH,
        MODE,
        SOLVER,
        AST_REPRESENTATION,
        TritonContext,
        Instruction as TritonInstruction,
        MemoryAccess as TritonMemoryAccess,
    )
    TRITON_AVAILABLE = True
except ImportError:
    _triton_lib = None
    TRITON_AVAILABLE = False
    logger.warning(
        "triton-library not installed — Triton tools unavailable. "
        "Run: ida-pro-mcp --install-deps triton"
    )

from .rpc import tool, unsafe
from .sync import idasync, IDAError, tool_timeout
from . import compat

# ============================================================================
# Context store
# Single context per IDA plugin instance.
# Keys are kept in an OrderedDict for potential future per-session isolation.
# ============================================================================

_CTX_KEY = "__default__"
_MAX_CONTEXTS = 8
_contexts: "OrderedDict[str, TritonContext]" = OrderedDict()
_contexts_lock = threading.Lock()

# Snapshot store: key -> {id, label, timestamp, arch, sym_vars, registers,
#                          tainted_registers, tainted_memory, path_predicate}
_snapshots: "dict[int, dict]" = {}
_next_snapshot_id = 0
_snapshots_lock = threading.Lock()

# Instruction trace for snapshot replay.
# Each entry maps session key -> deque of executed instruction addresses (ea int).
# Max trace length per session prevents unbounded memory growth.
_MAX_EXEC_TRACE_LEN = 10000
_exec_traces: "dict[str, collections.deque[int]]" = {}
_exec_traces_lock = threading.Lock()

# Extra constraints injected via triton_inject_comparison_constraint.
# These are ANDed with getPathPredicate() at solve time, allowing manual
# "memcmp equality" or arbitrary SMT constraints to influence the model
# without needing to appear in a branch path constraint.
_injected_constraints: "dict[str, list]" = {}  # key -> list of AST nodes
_injected_lock = threading.Lock()

# Pre-registered stdin buffer config set by triton_symbolize_stdin.
# Maps alias_prefix → {"size": int, "alias_prefix": str}
_STDIN_BUFFER: dict = {}


def _get_injected() -> "list":
    with _injected_lock:
        if _CTX_KEY not in _injected_constraints:
            _injected_constraints[_CTX_KEY] = []
        return _injected_constraints[_CTX_KEY]


def _clear_injected() -> None:
    with _injected_lock:
        _injected_constraints.pop(_CTX_KEY, None)


def _fmt_triton_version() -> str:
    """Return a human-readable Triton version string (e.g. '1.0.1597+z3')."""
    if not TRITON_AVAILABLE:
        return "unavailable"
    try:
        v = getattr(_triton_lib, "VERSION", None)
        if v is None:
            return "unknown"
        major = getattr(v, "MAJOR", "?")
        minor = getattr(v, "MINOR", "?")
        build = getattr(v, "BUILD", "?")
        backends = []
        if getattr(v, "Z3_INTERFACE", False):
            backends.append("z3")
        if getattr(v, "BITWUZLA_INTERFACE", False):
            backends.append("bitwuzla")
        if getattr(v, "LLVM_INTERFACE", False):
            backends.append("llvm")
        suffix = "+" + "+".join(backends) if backends else ""
        return f"{major}.{minor}.{build}{suffix}"
    except Exception:
        return "installed"


def _get_trace() -> "collections.deque[int]":
    with _exec_traces_lock:
        if _CTX_KEY not in _exec_traces:
            _exec_traces[_CTX_KEY] = collections.deque(maxlen=_MAX_EXEC_TRACE_LEN)
        return _exec_traces[_CTX_KEY]


def _clear_trace() -> None:
    with _exec_traces_lock:
        _exec_traces.pop(_CTX_KEY, None)


def _get_ctx(key: str = _CTX_KEY) -> "TritonContext":
    """Return the context for *key*, raising IDAError if uninitialised."""
    with _contexts_lock:
        ctx = _contexts.get(key)
    if ctx is None:
        raise IDAError(
            "Triton context not initialised. Call triton_init first."
        )
    return ctx


def _set_ctx(key: str, ctx: "TritonContext") -> None:
    with _contexts_lock:
        if key in _contexts:
            _contexts.move_to_end(key)
        _contexts[key] = ctx
        while len(_contexts) > _MAX_CONTEXTS:
            _contexts.popitem(last=False)


# ============================================================================
# Architecture detection
# ============================================================================

_ARCH_MAP_IDA_TO_TRITON: "dict[str, dict[bool, ARCH]]" = {}  # populated lazily


def _build_arch_map() -> "dict[str, dict[bool, ARCH]]":
    return {
        # IDA procname prefix  ->  {is_64bit: ARCH enum}
        "metapc": {True: ARCH.X86_64, False: ARCH.X86},
        "80386r":  {True: ARCH.X86_64, False: ARCH.X86},
        "80386p":  {True: ARCH.X86_64, False: ARCH.X86},
        "arm":     {True: ARCH.AARCH64, False: ARCH.ARM32},
        "aarch64": {True: ARCH.AARCH64, False: ARCH.AARCH64},
    }


def _detect_arch_from_ida() -> "ARCH":
    """Map current IDA database architecture to a Triton ARCH enum value."""
    arch_map = _build_arch_map()
    procname = compat.inf_get_procname().lower()
    is64 = compat.inf_is_64bit()

    for prefix, bit_map in arch_map.items():
        if procname.startswith(prefix):
            return bit_map[is64]

    raise IDAError(
        f"Unsupported architecture for Triton: procname={procname!r}. "
        f"Supported: x86, x86_64, ARM32, AArch64."
    )


def _arch_to_str(arch: "ARCH") -> str:
    names = {
        ARCH.X86: "x86",
        ARCH.X86_64: "x86_64",
        ARCH.ARM32: "arm32",
        ARCH.AARCH64: "aarch64",
        ARCH.RV32: "rv32",
        ARCH.RV64: "rv64",
    }
    return names.get(arch, str(arch))


def _str_to_arch(name: str) -> "ARCH":
    overrides = {
        "x86": ARCH.X86,
        "x86_64": ARCH.X86_64,
        "x64": ARCH.X86_64,
        "arm32": ARCH.ARM32,
        "arm": ARCH.ARM32,
        "aarch64": ARCH.AARCH64,
        "arm64": ARCH.AARCH64,
        "rv32": ARCH.RV32,
        "rv64": ARCH.RV64,
    }
    arch = overrides.get(name.lower())
    if arch is None:
        raise IDAError(
            f"Unknown architecture override {name!r}. "
            f"Valid values: {', '.join(overrides)}"
        )
    return arch


# ============================================================================
# Context factory
# ============================================================================

def _build_ctx(arch: "ARCH", pc_tracking_symbolic: bool = False) -> "TritonContext":
    ctx = TritonContext()
    ctx.setArchitecture(arch)
    ctx.setAstRepresentationMode(AST_REPRESENTATION.PYTHON)
    ctx.setSolver(SOLVER.Z3)
    # Reduce AST size, fold constants, track aligned memory
    ctx.setMode(MODE.AST_OPTIMIZATIONS, True)
    ctx.setMode(MODE.CONSTANT_FOLDING, True)
    ctx.setMode(MODE.ALIGNED_MEMORY, True)
    # PC_TRACKING_SYMBOLIC=True: only add path constraints when the branch
    # condition involves at least one symbolic variable. This prevents constraint
    # bloat for concrete-only branches but means branches on un-symbolized memory
    # (e.g. PEB via gs:60h) produce zero constraints. Set False to track all
    # branches regardless, at the cost of larger (but trivially satisfied) predicates.
    ctx.setMode(MODE.PC_TRACKING_SYMBOLIC, pc_tracking_symbolic)
    return ctx


# ============================================================================
# TypedDicts
# ============================================================================

class TritonStatusResult(TypedDict):
    available: bool
    version: str
    initialised: bool
    architecture: NotRequired[str]
    symbolic_var_count: NotRequired[int]
    path_constraint_count: NotRequired[int]
    tainted_register_count: NotRequired[int]
    tainted_memory_cell_count: NotRequired[int]
    snapshot_count: NotRequired[int]


class TritonInitResult(TypedDict):
    ok: bool
    architecture: str
    version: str
    already_initialized: NotRequired[bool]
    error: NotRequired[str]


class TritonResetResult(TypedDict):
    ok: bool
    message: NotRequired[str]
    error: NotRequired[str]


class SymVarItem(TypedDict, total=False):
    id: int
    name: str
    alias: str
    bitsize: int
    kind: str
    origin: str


class SymExprItem(TypedDict, total=False):
    id: int
    kind: str
    is_symbolised: bool
    is_tainted: bool
    disasm: str
    ast: str


class PathConstraintItem(TypedDict, total=False):
    source_addr: str
    taken_addr: str
    is_multiple_branches: bool
    branches: list[dict]


class TaintResult(TypedDict, total=False):
    ok: bool
    target: str
    error: str


class TaintSummaryResult(TypedDict, total=False):
    ok: bool
    tainted_registers: list[str]
    tainted_memory_addrs: list[str]
    total_count: int
    error: str


class SolveResult(TypedDict, total=False):
    ok: bool
    sat: bool
    model: dict[str, str]
    error: str


class ProcessInsnResult(TypedDict, total=False):
    ok: bool
    address: str
    disasm: str
    size: int
    is_branch: bool
    is_symbolised: bool
    is_tainted: bool
    new_sym_expr_count: int
    path_constraint_added: bool
    error: str


class SnapshotResult(TypedDict, total=False):
    ok: bool
    snapshot_id: int
    label: str
    timestamp: float
    sym_var_count: int
    instruction_trace_count: NotRequired[int]
    error: str


# ============================================================================
# Always-available probe tool
# ============================================================================

class _StatusAlways(TypedDict):
    available: bool
    version: str
    install_hint: NotRequired[str]
    initialised: NotRequired[bool]
    architecture: NotRequired[str]
    symbolic_var_count: NotRequired[int]
    path_constraint_count: NotRequired[int]
    tainted_register_count: NotRequired[int]
    tainted_memory_cell_count: NotRequired[int]
    snapshot_count: NotRequired[int]


@tool
@idasync
def triton_status(
    probe: Annotated[
        bool,
        "When true, attempt to auto-detect architecture from IDA and build a "
        "TritonContext, surfacing any error via MCP.",
    ] = False,
) -> _StatusAlways:
    """Report whether triton-library is installed and the current context state.

    Always returns a result — safe to call before triton_init to check
    availability. When available=false, install triton-library and restart IDA.

    Set ``probe=true`` to force full context initialisation and diagnose
    architecture-detection or Z3-backend errors without needing the IDA console.
    """
    version = "unknown"
    if TRITON_AVAILABLE:
        version = _fmt_triton_version()

    if not TRITON_AVAILABLE:
        return {
            "available": False,
            "version": version,
            "install_hint": "pip install triton-library  (then restart IDA)",
        }

    if probe:
        probe_log: list[dict] = []
        try:
            probe_log.append({"step": "detect_arch", "status": "running"})
            arch = _detect_arch_from_ida()
            probe_log.append({"step": "detect_arch", "status": "ok", "arch": _arch_to_str(arch)})
        except Exception as e:
            probe_log.append({"step": "detect_arch", "status": "failed", "error": f"{type(e).__name__}: {e}"})
            return {
                "available": True,
                "version": version,
                "probe": True,
                "initialised": False,
                "probe_log": probe_log,
                "error": f"Architecture detection failed: {e}",
            }

        try:
            probe_log.append({"step": "build_ctx", "status": "running"})
            ctx = _build_ctx(arch)
            probe_log.append({"step": "build_ctx", "status": "ok"})
        except Exception as e:
            probe_log.append({"step": "build_ctx", "status": "failed", "error": f"{type(e).__name__}: {e}"})
            return {
                "available": True,
                "version": version,
                "probe": True,
                "initialised": False,
                "probe_log": probe_log,
                "error": f"TritonContext creation failed: {e}",
            }

        # Store the probed context so subsequent calls work
        _set_ctx(_CTX_KEY, ctx)

        return {
            "available": True,
            "version": version,
            "probe": True,
            "initialised": True,
            "architecture": _arch_to_str(arch),
            "symbolic_var_count": 0,
            "path_constraint_count": 0,
            "tainted_register_count": 0,
            "tainted_memory_cell_count": 0,
            "snapshot_count": 0,
            "probe_log": probe_log,
        }

    ctx = _contexts.get(_CTX_KEY)
    if ctx is None:
        return {
            "available": True,
            "version": version,
            "initialised": False,
        }

    sym_vars = ctx.getSymbolicVariables()
    pcs = ctx.getPathConstraints()
    tainted_regs = ctx.getTaintedRegisters()
    tainted_mem = ctx.getTaintedMemory()

    with _snapshots_lock:
        snap_count = len(_snapshots)

    return {
        "available": True,
        "version": version,
        "initialised": True,
        "architecture": _arch_to_str(ctx.getArchitecture()),
        "symbolic_var_count": len(sym_vars),
        "path_constraint_count": len(pcs),
        "tainted_register_count": len(tainted_regs),
        "tainted_memory_cell_count": len(tainted_mem),
        "snapshot_count": snap_count,
    }


# ============================================================================
# Context lifecycle
# ============================================================================

@tool
@idasync
def triton_init(
    architecture: Annotated[
        str,
        "Architecture override: x86, x86_64, arm32, aarch64, rv32, rv64. "
        "Leave blank to auto-detect from the open IDA database.",
    ] = "",
    skip_if_initialized: Annotated[
        bool,
        "When True, skip re-initialization if a context already exists and return "
        "its current state. Useful at the top of analysis scripts that may be "
        "called multiple times. Default False (always reinitialize).",
    ] = False,
    pc_tracking_symbolic: Annotated[
        bool,
        "When True, path constraints are only collected for branches whose condition "
        "involves at least one symbolic variable (low noise, but misses concrete branches). "
        "When False (default), ALL branches are tracked regardless of symbolization — "
        "this is the practical default because it ensures Windows PEB checks, length "
        "guards, and other concrete branches all appear in the path predicate. "
        "Use True only when the function has many irrelevant concrete branches you "
        "want to exclude from the constraint set.",
    ] = False,
) -> TritonInitResult:
    """Initialise (or re-initialise) a Triton context for the current binary.

    Automatically detects architecture from IDA unless overridden.
    Re-calling resets all symbolic state — use triton_snapshot_save first
    if you want to preserve the current context.

    Pass ``skip_if_initialized=True`` for idempotent calls: if a context is
    already active the tool returns immediately with ``already_initialized=true``
    rather than wiping existing symbolic state.

    **Windows binaries**: After init, call ``triton_setup_windows_x64`` to model
    the GS segment (TEB/PEB), stack, and shadow space so that anti-debug checks
    against ``gs:60h`` produce satisfiable concrete constraints rather than
    unresolved symbolic ones.
    """
    if not TRITON_AVAILABLE:
        return {"ok": False, "architecture": "", "version": "", "error": "triton-library not installed"}

    try:
        # Idempotent path: return current context info without reinitialising
        if skip_if_initialized:
            with _contexts_lock:
                existing = _contexts.get(_CTX_KEY)
            if existing is not None:
                version = _fmt_triton_version()
                arch_str = _arch_to_str(existing.getArchitecture())
                return {
                    "ok": True,
                    "architecture": arch_str,
                    "version": version,
                    "already_initialized": True,
                }

        if architecture:
            arch = _str_to_arch(architecture)
        else:
            arch = _detect_arch_from_ida()

        ctx = _build_ctx(arch, pc_tracking_symbolic=pc_tracking_symbolic)
        _set_ctx(_CTX_KEY, ctx)
        _clear_trace()
        _clear_injected()
        _STDIN_BUFFER.clear()

        version = _fmt_triton_version()
        arch_str = _arch_to_str(arch)
        logger.info("Triton context initialised for %s (pc_tracking_symbolic=%s)", arch_str, pc_tracking_symbolic)
        return {
            "ok": True,
            "architecture": arch_str,
            "version": version,
            "pc_tracking_symbolic": pc_tracking_symbolic,
        }

    except IDAError as e:
        return {"ok": False, "architecture": architecture, "version": "", "error": e.message}
    except Exception as e:
        logger.exception("triton_init failed")
        return {"ok": False, "architecture": architecture, "version": "", "error": str(e)}


@tool
@idasync
def triton_reset() -> TritonResetResult:
    """Reset all symbolic state in the current context (clears vars, taints, path constraints).

    The architecture is preserved. Equivalent to starting a new analysis
    on the same binary without reinitialising the context.
    """
    if not TRITON_AVAILABLE:
        return {"ok": False, "error": "triton-library not installed"}
    try:
        ctx = _get_ctx()
        ctx.reset()
        ctx.clearPathConstraints()
        _clear_injected()
        return {"ok": True, "message": "Triton context reset — symbolic state cleared, architecture preserved."}
    except IDAError as e:
        return {"ok": False, "error": e.message}
    except Exception as e:
        logger.exception("triton_reset failed")
        return {"ok": False, "error": str(e)}


@tool
@idasync
def triton_get_context_info() -> dict:
    """Return a detailed summary of the current Triton context.

    Includes architecture, enabled modes, symbolic variable count,
    path constraint count, and taint state.
    """
    if not TRITON_AVAILABLE:
        return {"ok": False, "error": "triton-library not installed"}
    try:
        ctx = _get_ctx()
        sym_vars = ctx.getSymbolicVariables()
        pcs = ctx.getPathConstraints()
        tainted_regs = ctx.getTaintedRegisters()
        tainted_mem = ctx.getTaintedMemory()

        with _snapshots_lock:
            snap_count = len(_snapshots)

        modes_enabled = []
        for mode in (
            MODE.ALIGNED_MEMORY,
            MODE.AST_OPTIMIZATIONS,
            MODE.CONSTANT_FOLDING,
            MODE.ONLY_ON_SYMBOLIZED,
            MODE.ONLY_ON_TAINTED,
            MODE.PC_TRACKING_SYMBOLIC,
            MODE.TAINT_THROUGH_POINTERS,
        ):
            if ctx.isModeEnabled(mode):
                modes_enabled.append(str(mode))

        return {
            "ok": True,
            "architecture": _arch_to_str(ctx.getArchitecture()),
            "gpr_bitsize": ctx.getGprBitSize(),
            "modes_enabled": modes_enabled,
            "symbolic_var_count": len(sym_vars),
            "path_constraint_count": len(pcs),
            "tainted_register_count": len(tainted_regs),
            "tainted_memory_cell_count": len(tainted_mem),
            "snapshot_count": snap_count,
        }
    except IDAError as e:
        return {"ok": False, "error": e.message}
    except Exception as e:
        logger.exception("triton_reset failed")
        return {"ok": False, "error": str(e)}


# ============================================================================
# Symbolisation
# ============================================================================

@tool
@idasync
def triton_symbolize_register(
    register: Annotated[str, "Register name (e.g. rdi, eax, r8)."],
    alias: Annotated[str, "Optional alias / label for this symbolic variable."] = "",
) -> dict:
    """Mark a CPU register as symbolic (attacker-controlled / unknown).

    Returns the symbolic variable ID that can later be used in constraint queries.
    """
    if not TRITON_AVAILABLE:
        return {"ok": False, "register": register, "error": "triton-library not installed"}
    try:
        ctx = _get_ctx()
        reg = ctx.getRegister(register.lower())
        sym_var = ctx.symbolizeRegister(reg, alias)
        return {
            "ok": True,
            "register": register,
            "sym_var_id": sym_var.getId(),
            "sym_var_name": sym_var.getName(),
            "bitsize": sym_var.getBitSize(),
        }
    except IDAError as e:
        return {"ok": False, "register": register, "error": e.message}
    except Exception as e:
        logger.exception("triton_symbolize_register failed")
        return {"ok": False, "register": register, "error": str(e)}


@tool
@idasync
def triton_symbolize_memory(
    address: Annotated[str, "Start address (hex, e.g. 0x401000, or decimal)."],
    size: Annotated[int, "Number of bytes to symbolise (1, 2, 4, or 8)."] = 1,
    alias: Annotated[str, "Optional alias / label for this symbolic variable."] = "",
) -> dict:
    """Mark a memory range as symbolic (attacker-controlled / unknown).

    This is the low-level primitive: ``size`` must be a power of two and
    ``address`` must be aligned to ``size``.  For arbitrary ranges (e.g.
    256-byte buffers, odd addresses) use ``triton_symbolize_bytes`` instead.
    """
    if not TRITON_AVAILABLE:
        return {"ok": False, "error": "triton-library not installed"}
    try:
        ctx = _get_ctx()
        addr = int(address, 16) if isinstance(address, str) and address.startswith("0x") else int(address, 0)
        mem = TritonMemoryAccess(addr, size)
        sym_var = ctx.symbolizeMemory(mem, alias)
        return {
            "ok": True,
            "address": hex(addr),
            "size": size,
            "sym_var_id": sym_var.getId(),
            "sym_var_name": sym_var.getName(),
        }
    except IDAError as e:
        return {"ok": False, "address": address, "error": e.message}
    except Exception as e:
        logger.exception("triton_symbolize_memory failed")
        return {"ok": False, "address": address, "error": str(e)}


@tool
@idasync
@tool_timeout(30.0)
def triton_symbolize_bytes(
    address: Annotated[str, "Start address (hex or decimal)."],
    size: Annotated[int, "Number of bytes to symbolise."],
    alias_prefix: Annotated[
        str,
        "Optional prefix for symbolic variable aliases (e.g. 'buf_' produces buf_0, buf_8, ...).",
    ] = "",
) -> dict:
    """Mark an arbitrary byte range as symbolic using architecture-aligned chunks.

    Unlike ``triton_symbolize_memory`` which requires size ∈ {1,2,4,8} and an
    aligned address, this tool accepts any positive size and automatically splits
    the range into the largest valid Triton chunks (e.g. 8-byte on x64, 4-byte on
    x86) with correct alignment, falling back to smaller chunks at boundaries.

    A 256-byte buffer on x64 becomes ~32 symbolic variables instead of 256,
    and unaligned addresses are handled gracefully.

    Ranges are capped at 4096 bytes by default to prevent accidental context
    bloat.  For larger aligned ranges call ``triton_symbolize_memory`` directly
    with word-sized chunks.
    """
    if not TRITON_AVAILABLE:
        return {"ok": False, "error": "triton-library not installed"}

    _MAX_BYTES = 4096
    if size <= 0:
        return {"ok": False, "error": "size must be positive"}
    if size > _MAX_BYTES:
        return {
            "ok": False,
            "error": (
                f"size {size} exceeds safety cap of {_MAX_BYTES} bytes. "
                f"Break the range into smaller pieces, or use triton_symbolize_memory "
                f"with aligned word-sized chunks (1/2/4/8 bytes)."
            ),
        }

    try:
        ctx = _get_ctx()
        addr = (
            int(address, 16)
            if isinstance(address, str) and address.startswith("0x")
            else int(address, 0)
        )
        arch = ctx.getArchitecture()

        # Map architecture to max natural chunk size (GPR width in bytes)
        _ARCH_MAX_CHUNK: "dict[ARCH, int]" = {
            ARCH.X86: 4,
            ARCH.X86_64: 8,
            ARCH.ARM32: 4,
            ARCH.AARCH64: 8,
            ARCH.RV32: 4,
            ARCH.RV64: 8,
        }
        max_chunk = _ARCH_MAX_CHUNK.get(arch, 8)

        def _pick_chunk(pos: int, rem: int) -> int:
            """Largest power-of-2 ≤ max_chunk that aligns at pos and fits in rem."""
            for test in (max_chunk, max_chunk // 2, max_chunk // 4, max_chunk // 8, 2):
                if test >= 1 and pos % test == 0 and test <= rem:
                    return test
            return 1

        sym_var_ids: list[int] = []
        pos = addr
        rem = size
        chunk_count = 0
        total_fallbacks = 0

        while rem > 0:
            cs = _pick_chunk(pos, rem)
            alias = f"{alias_prefix}{pos - addr}" if alias_prefix else ""
            try:
                mem = TritonMemoryAccess(pos, cs)
                sym_var = ctx.symbolizeMemory(mem, alias)
            except Exception:
                # The chosen chunk failed (rare — can happen on esoteric arch
                # limits).  Fall back to a single byte for this position and
                # continue; the next iteration will re-chunk from pos+1.
                cs = 1
                alias = f"{alias_prefix}{pos - addr}" if alias_prefix else ""
                mem = TritonMemoryAccess(pos, cs)
                sym_var = ctx.symbolizeMemory(mem, alias)
                total_fallbacks += 1

            sym_var_ids.append(sym_var.getId())
            pos += cs
            rem -= cs
            chunk_count += 1

        return {
            "ok": True,
            "address": hex(addr),
            "size": size,
            "sym_var_count": len(sym_var_ids),
            "chunk_count": chunk_count,
            "fallback_byte_chunks": total_fallbacks,
            "first_sym_var_id": sym_var_ids[0] if sym_var_ids else None,
            "last_sym_var_id": sym_var_ids[-1] if sym_var_ids else None,
            "alias_prefix": alias_prefix,
        }
    except IDAError as e:
        return {"ok": False, "address": address, "error": e.message}
    except Exception as e:
        logger.exception("triton_symbolize_bytes failed")
        return {"ok": False, "address": address, "error": str(e)}


@tool
@idasync
def triton_batch_symbolize_registers(
    registers: Annotated[
        str | list[str],
        "Register names — comma-separated string or JSON array. E.g. 'rdi,rsi,rdx'.",
    ],
) -> list[dict]:
    """Symbolise multiple registers in a single call."""
    if not TRITON_AVAILABLE:
        return [{"ok": False, "error": "triton-library not installed"}]
    if isinstance(registers, str):
        regs = [r.strip() for r in registers.split(",") if r.strip()]
    else:
        regs = list(registers)

    results = []
    try:
        ctx = _get_ctx()
        for name in regs:
            try:
                reg = ctx.getRegister(name.lower())
                sym_var = ctx.symbolizeRegister(reg)
                results.append({
                    "ok": True,
                    "register": name,
                    "sym_var_id": sym_var.getId(),
                    "sym_var_name": sym_var.getName(),
                })
            except Exception as e:
                results.append({"ok": False, "register": name, "error": str(e)})
    except IDAError as e:
        return [{"ok": False, "register": r, "error": e.message} for r in regs]
    return results


# ============================================================================
# Concrete value get / set
# ============================================================================

@tool
@idasync
def triton_set_concrete_register_value(
    register: Annotated[str, "Register name (e.g. rdi, eax)."],
    value: Annotated[str, "Value as decimal integer or 0x-prefixed hex string."],
) -> dict:
    """Set a concrete (known) value for a register before processing instructions."""
    if not TRITON_AVAILABLE:
        return {"ok": False, "error": "triton-library not installed"}
    try:
        ctx = _get_ctx()
        int_val = int(value, 16) if isinstance(value, str) and value.startswith("0x") else int(value, 0)
        reg = ctx.getRegister(register.lower())
        ctx.setConcreteRegisterValue(reg, int_val)
        return {"ok": True, "register": register, "value": hex(int_val)}
    except IDAError as e:
        return {"ok": False, "register": register, "error": e.message}
    except Exception as e:
        logger.exception("triton_set_concrete_register_value failed")
        return {"ok": False, "register": register, "error": str(e)}


@tool
@idasync
def triton_get_concrete_register_value(
    register: Annotated[str, "Register name (e.g. rdi, eax)."],
) -> dict:
    """Read back the current concrete value of a register from the Triton context."""
    if not TRITON_AVAILABLE:
        return {"ok": False, "error": "triton-library not installed"}
    try:
        ctx = _get_ctx()
        reg = ctx.getRegister(register.lower())
        val = ctx.getConcreteRegisterValue(reg)
        return {"ok": True, "register": register, "value": val, "value_hex": hex(val)}
    except IDAError as e:
        return {"ok": False, "register": register, "error": e.message}
    except Exception as e:
        logger.exception("triton_set_concrete_register_value failed")
        return {"ok": False, "register": register, "error": str(e)}


@tool
@idasync
def triton_set_concrete_memory_value(
    address: Annotated[str, "Address (hex or decimal)."],
    data_hex: Annotated[str, "Bytes to write as hex string, e.g. '41 42 43' or '414243'."],
) -> dict:
    """Write concrete bytes into the Triton context's memory model.

    This does NOT modify the IDA database — it only affects the Triton
    context's view of memory for symbolic execution purposes.
    """
    if not TRITON_AVAILABLE:
        return {"ok": False, "error": "triton-library not installed"}
    try:
        ctx = _get_ctx()
        addr = int(address, 16) if isinstance(address, str) and address.startswith("0x") else int(address, 0)
        raw = bytes.fromhex(data_hex.replace(" ", ""))
        ctx.setConcreteMemoryAreaValue(addr, raw)
        return {"ok": True, "address": hex(addr), "bytes_written": len(raw)}
    except IDAError as e:
        return {"ok": False, "address": address, "error": e.message}
    except Exception as e:
        logger.exception("triton_set_concrete_memory_value failed")
        return {"ok": False, "address": address, "error": str(e)}


@tool
@idasync
def triton_get_concrete_memory_value(
    address: Annotated[str, "Address (hex or decimal)."],
    size: Annotated[int, "Number of bytes to read."] = 8,
) -> dict:
    """Read concrete bytes from the Triton context's memory model."""
    if not TRITON_AVAILABLE:
        return {"ok": False, "error": "triton-library not installed"}
    try:
        ctx = _get_ctx()
        addr = int(address, 16) if isinstance(address, str) and address.startswith("0x") else int(address, 0)
        data: bytes = ctx.getConcreteMemoryAreaValue(addr, size)
        return {
            "ok": True,
            "address": hex(addr),
            "size": size,
            "data_hex": data.hex(),
        }
    except IDAError as e:
        return {"ok": False, "address": address, "error": e.message}
    except Exception as e:
        logger.exception("triton_get_concrete_memory_value failed")
        return {"ok": False, "address": address, "error": str(e)}


# ============================================================================
# Instruction processing
# ============================================================================

@tool
@idasync
def triton_process_instruction(
    address: Annotated[str, "Address of the instruction to process (hex or symbol name)."],
) -> ProcessInsnResult:
    """Process a single instruction at the given IDA address symbolically.

    Fetches bytes directly from IDA, feeds them to Triton, and returns
    a summary of what changed (new symbolic expressions, path constraints added).
    """
    if not TRITON_AVAILABLE:
        return {"ok": False, "error": "triton-library not installed"}
    import idaapi
    import idc
    import ida_lines

    try:
        ctx = _get_ctx()
        from .utils import parse_address
        ea = parse_address(address)

        insn_ida = idaapi.insn_t()
        length = idaapi.decode_insn(insn_ida, ea)
        if length == 0:
            return {"ok": False, "address": hex(ea), "error": f"No instruction at {hex(ea)}"}

        raw = idc.get_bytes(ea, length)
        if raw is None:
            return {"ok": False, "address": hex(ea), "error": f"Could not read {length} bytes at {hex(ea)}"}

        # Seed Triton's memory model with the instruction bytes
        ctx.setConcreteMemoryAreaValue(ea, raw)

        insn = TritonInstruction()
        insn.setAddress(ea)
        insn.setOpcode(raw)

        sym_before = len(ctx.getSymbolicExpressions())
        pc_before = len(ctx.getPathConstraints())

        ctx.processing(insn)

        sym_after = len(ctx.getSymbolicExpressions())
        pc_after = len(ctx.getPathConstraints())
        _get_trace().append(ea)

        disasm_raw = ida_lines.generate_disasm_line(ea, 0)
        disasm = ida_lines.tag_remove(disasm_raw) if disasm_raw else ""

        return {
            "ok": True,
            "address": hex(ea),
            "disasm": disasm,
            "size": length,
            "is_branch": insn.isBranch(),
            "is_symbolised": insn.isSymbolized(),
            "is_tainted": insn.isTainted(),
            "new_sym_expr_count": sym_after - sym_before,
            "path_constraint_added": pc_after > pc_before,
        }

    except IDAError as e:
        return {"ok": False, "address": address, "error": e.message}
    except Exception as e:
        logger.exception("triton_process_instruction failed at %s", address)
        return {"ok": False, "address": address, "error": str(e)}


@tool
@idasync
@tool_timeout(60.0)
def triton_process_function(
    address: Annotated[str, "Address within the function (hex or symbol name)."],
    max_insns: Annotated[int, "Safety cap on instruction count (default 500)."] = 500,
) -> dict:
    """Process every instruction in a function symbolically.

    Heavy: for large functions use invoke_tool(..., async_mode=True) or task_submit + task_poll.

    Iterates the function linearly (not following branches), feeds each
    instruction to Triton in order. Returns a summary of symbolic expressions
    and path constraints collected.

    Use triton_snapshot_save before calling if you want to restore state afterwards.
    """
    if not TRITON_AVAILABLE:
        return {"ok": False, "error": "triton-library not installed"}
    import idaapi
    import idc
    import ida_funcs
    import ida_lines

    try:
        ctx = _get_ctx()
        from .utils import parse_address
        ea = parse_address(address)

        func = ida_funcs.get_func(ea)
        if func is None:
            return {"ok": False, "address": hex(ea), "error": f"No function at {hex(ea)}"}

        # Preload function bytes into Triton memory in one shot
        func_size = func.end_ea - func.start_ea
        raw_func = idc.get_bytes(func.start_ea, func_size)
        if raw_func:
            ctx.setConcreteMemoryAreaValue(func.start_ea, raw_func)

        processed = []
        curr = func.start_ea
        count = 0
        sym_start = len(ctx.getSymbolicExpressions())
        pc_start = len(ctx.getPathConstraints())

        while curr < func.end_ea and count < max_insns:
            insn_ida = idaapi.insn_t()
            length = idaapi.decode_insn(insn_ida, curr)
            if length == 0:
                break

            raw = idc.get_bytes(curr, length)
            if not raw:
                curr += 1
                continue

            insn = TritonInstruction()
            insn.setAddress(curr)
            insn.setOpcode(raw)
            ctx.processing(insn)
            _get_trace().append(curr)

            disasm_raw = ida_lines.generate_disasm_line(curr, 0)
            disasm = ida_lines.tag_remove(disasm_raw) if disasm_raw else ""

            processed.append({
                "address": hex(curr),
                "disasm": disasm,
                "size": length,
                "is_branch": insn.isBranch(),
                "is_symbolised": insn.isSymbolized(),
            })

            curr += length
            count += 1

        sym_end = len(ctx.getSymbolicExpressions())
        pc_end = len(ctx.getPathConstraints())
        truncated = count >= max_insns and curr < func.end_ea

        return {
            "ok": True,
            "function": hex(func.start_ea),
            "instructions_processed": count,
            "truncated": truncated,
            "new_sym_exprs": sym_end - sym_start,
            "new_path_constraints": pc_end - pc_start,
            "instructions": processed,
        }

    except IDAError as e:
        return {"ok": False, "address": address, "error": e.message}
    except Exception as e:
        logger.exception("triton_process_function failed at %s", address)
        return {"ok": False, "address": address, "error": str(e)}


# ============================================================================
# Symbolic state queries
# ============================================================================

@tool
@idasync
def triton_get_symbolic_variables() -> dict:
    """List all symbolic variables in the current context.

    Each entry shows the variable's ID, name, alias, bitsize, and origin
    (the register name or memory address it was created from).
    """
    if not TRITON_AVAILABLE:
        return {"ok": False, "error": "triton-library not installed"}
    try:
        ctx = _get_ctx()
        from triton import SYMBOLIC
        items: list[SymVarItem] = []
        for vid, sv in ctx.getSymbolicVariables().items():
            stype = sv.getType()
            if stype == SYMBOLIC.REGISTER_VARIABLE:
                kind = "register"
                try:
                    origin = ctx.getRegister(sv.getOrigin()).getName()
                except Exception:
                    origin = str(sv.getOrigin())
            elif stype == SYMBOLIC.MEMORY_VARIABLE:
                kind = "memory"
                origin = hex(sv.getOrigin())
            else:
                kind = "undefined"
                origin = str(sv.getOrigin())

            items.append({
                "id": sv.getId(),
                "name": sv.getName(),
                "alias": sv.getAlias(),
                "bitsize": sv.getBitSize(),
                "kind": kind,
                "origin": origin,
            })

        return {"ok": True, "count": len(items), "variables": items}

    except IDAError as e:
        return {"ok": False, "error": e.message}
    except Exception as e:
        logger.exception("triton_reset failed")
        return {"ok": False, "error": str(e)}


@tool
@idasync
def triton_get_symbolic_expressions(
    limit: Annotated[int, "Maximum number of expressions to return (0 = all)."] = 50,
) -> dict:
    """List symbolic expressions generated so far.

    Symbolic expressions are the SSA nodes produced as each instruction
    is processed. Use limit=0 to retrieve all (can be very large).
    """
    if not TRITON_AVAILABLE:
        return {"ok": False, "error": "triton-library not installed"}
    try:
        ctx = _get_ctx()
        exprs = ctx.getSymbolicExpressions()
        items: list[SymExprItem] = []
        for eid, expr in exprs.items():
            if limit > 0 and len(items) >= limit:
                break
            items.append({
                "id": expr.getId(),
                "kind": "memory" if expr.isMemory() else ("register" if expr.isRegister() else "volatile"),
                "is_symbolised": expr.isSymbolized(),
                "is_tainted": expr.isTainted(),
                "disasm": expr.getDisassembly(),
                "ast": str(expr.getAst()),
            })

        return {
            "ok": True,
            "total_count": len(exprs),
            "returned_count": len(items),
            "expressions": items,
        }

    except IDAError as e:
        return {"ok": False, "error": e.message}
    except Exception as e:
        logger.exception("triton_reset failed")
        return {"ok": False, "error": str(e)}


@tool
@idasync
def triton_get_path_constraints() -> dict:
    """List all path constraints accumulated during symbolic execution.

    Each constraint corresponds to a conditional branch. Each branch entry now
    includes a constraint_type field:
    - "symbolic"       — condition involves at least one symbolic variable → solver can steer it
    - "concrete_true"  — condition is always True (never gates execution)
    - "concrete_false" — condition is always False (path is infeasible with current state)
    - "concrete"       — condition is concrete but not trivially true/false

    Use triton_check_input_reaches_branch to understand whether your symbolized input
    flows into any branch. Constraints with constraint_type="concrete" cannot be solved
    for inputs — only "symbolic" ones produce useful Z3 models.
    """
    if not TRITON_AVAILABLE:
        return {"ok": False, "error": "triton-library not installed"}
    try:
        ctx = _get_ctx()
        all_sym_var_names = {sv.getName() for sv in ctx.getSymbolicVariables().values()}
        pcs = ctx.getPathConstraints()
        items: list[PathConstraintItem] = []
        symbolic_count = 0
        concrete_count = 0

        for pc in pcs:
            branches = []
            pc_has_symbolic = False
            for branch in pc.getBranchConstraints():
                ast_str = str(branch["constraint"])
                has_sym = bool(all_sym_var_names & set(ast_str.split()))

                # Classify constraint type
                if has_sym:
                    ctype = "symbolic"
                    pc_has_symbolic = True
                else:
                    # Check for trivially concrete: try eval via str comparison
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
                    "has_symbolic": has_sym,
                    "constraint": ast_str,
                })

            if pc_has_symbolic:
                symbolic_count += 1
            else:
                concrete_count += 1

            items.append({
                "source_addr": hex(pc.getSourceAddress()),
                "taken_addr": hex(pc.getTakenAddress()),
                "is_multiple_branches": pc.isMultipleBranches(),
                "has_symbolic": pc_has_symbolic,
                "branches": branches,
            })

        advice = ""
        if items and symbolic_count == 0:
            advice = (
                "All constraints are concrete — the solver cannot produce useful input assignments. "
                "Ensure you symbolized the correct register or memory region BEFORE running "
                "the instructions that contain the branch. Use triton_check_input_reaches_branch "
                "or triton_scan_for_input_calls to diagnose."
            )

        return {
            "ok": True,
            "count": len(items),
            "symbolic_constraints": symbolic_count,
            "concrete_constraints": concrete_count,
            "advice": advice,
            "path_constraints": items,
        }

    except IDAError as e:
        return {"ok": False, "error": e.message}
    except Exception as e:
        logger.exception("triton_get_path_constraints failed")
        return {"ok": False, "error": str(e)}


# ============================================================================
# Taint analysis
# ============================================================================

@tool
@idasync
def triton_taint_register(
    register: Annotated[str, "Register name (e.g. rdi, rsi, eax)."],
) -> TaintResult:
    """Mark a register as tainted (attacker-influenced data)."""
    if not TRITON_AVAILABLE:
        return {"ok": False, "error": "triton-library not installed"}
    try:
        ctx = _get_ctx()
        reg = ctx.getRegister(register.lower())
        ctx.taintRegister(reg)
        return {"ok": True, "target": register}
    except IDAError as e:
        return {"ok": False, "target": register, "error": e.message}
    except Exception as e:
        logger.exception("triton_taint_register failed")
        return {"ok": False, "target": register, "error": str(e)}


@tool
@idasync
def triton_untaint_register(
    register: Annotated[str, "Register name (e.g. rdi, rsi, eax)."],
) -> TaintResult:
    """Remove taint from a register."""
    if not TRITON_AVAILABLE:
        return {"ok": False, "error": "triton-library not installed"}
    try:
        ctx = _get_ctx()
        reg = ctx.getRegister(register.lower())
        ctx.untaintRegister(reg)
        return {"ok": True, "target": register}
    except IDAError as e:
        return {"ok": False, "target": register, "error": e.message}
    except Exception as e:
        logger.exception("triton_untaint_register failed")
        return {"ok": False, "target": register, "error": str(e)}


@tool
@idasync
def triton_taint_memory(
    address: Annotated[str, "Start address (hex or decimal)."],
    size: Annotated[int, "Number of bytes to taint."] = 1,
) -> TaintResult:
    """Mark a memory range as tainted."""
    if not TRITON_AVAILABLE:
        return {"ok": False, "error": "triton-library not installed"}
    try:
        ctx = _get_ctx()
        addr = int(address, 16) if isinstance(address, str) and address.startswith("0x") else int(address, 0)
        mem = TritonMemoryAccess(addr, size)
        ctx.taintMemory(mem)
        return {"ok": True, "target": f"{hex(addr)}:{size}"}
    except IDAError as e:
        return {"ok": False, "target": address, "error": e.message}
    except Exception as e:
        logger.exception("triton_taint_memory failed")
        return {"ok": False, "target": address, "error": str(e)}


@tool
@idasync
def triton_untaint_memory(
    address: Annotated[str, "Start address (hex or decimal)."],
    size: Annotated[int, "Number of bytes to untaint."] = 1,
) -> TaintResult:
    """Remove taint from a memory range."""
    if not TRITON_AVAILABLE:
        return {"ok": False, "error": "triton-library not installed"}
    try:
        ctx = _get_ctx()
        addr = int(address, 16) if isinstance(address, str) and address.startswith("0x") else int(address, 0)
        mem = TritonMemoryAccess(addr, size)
        ctx.untaintMemory(mem)
        return {"ok": True, "target": f"{hex(addr)}:{size}"}
    except IDAError as e:
        return {"ok": False, "target": address, "error": e.message}
    except Exception as e:
        logger.exception("triton_untaint_memory failed")
        return {"ok": False, "target": address, "error": str(e)}


@tool
@idasync
def triton_batch_taint_registers(
    registers: Annotated[
        str | list[str],
        "Register names — comma-separated string or JSON array.",
    ],
) -> list[TaintResult]:
    """Taint multiple registers in one call."""
    if not TRITON_AVAILABLE:
        return [{"ok": False, "error": "triton-library not installed"}]
    if isinstance(registers, str):
        regs = [r.strip() for r in registers.split(",") if r.strip()]
    else:
        regs = list(registers)

    results: list[TaintResult] = []
    try:
        ctx = _get_ctx()
        for name in regs:
            try:
                ctx.taintRegister(ctx.getRegister(name.lower()))
                results.append({"ok": True, "target": name})
            except Exception as e:
                results.append({"ok": False, "target": name, "error": str(e)})
    except IDAError as e:
        return [{"ok": False, "target": r, "error": e.message} for r in regs]
    return results


@tool
@idasync
def triton_is_register_tainted(
    register: Annotated[str, "Register name."],
) -> dict:
    """Check whether a register is currently tainted."""
    if not TRITON_AVAILABLE:
        return {"ok": False, "error": "triton-library not installed"}
    try:
        ctx = _get_ctx()
        reg = ctx.getRegister(register.lower())
        return {"ok": True, "register": register, "is_tainted": ctx.isRegisterTainted(reg)}
    except IDAError as e:
        return {"ok": False, "register": register, "error": e.message}
    except Exception as e:
        logger.exception("triton_set_concrete_register_value failed")
        return {"ok": False, "register": register, "error": str(e)}


@tool
@idasync
def triton_is_memory_tainted(
    address: Annotated[str, "Address (hex or decimal)."],
    size: Annotated[int, "Number of bytes to check."] = 1,
) -> dict:
    """Check whether a memory range is currently tainted."""
    if not TRITON_AVAILABLE:
        return {"ok": False, "error": "triton-library not installed"}
    try:
        ctx = _get_ctx()
        addr = int(address, 16) if isinstance(address, str) and address.startswith("0x") else int(address, 0)
        mem = TritonMemoryAccess(addr, size)
        return {"ok": True, "address": hex(addr), "size": size, "is_tainted": ctx.isMemoryTainted(mem)}
    except IDAError as e:
        return {"ok": False, "address": address, "error": e.message}
    except Exception as e:
        logger.exception("triton_set_concrete_memory_value failed")
        return {"ok": False, "address": address, "error": str(e)}


@tool
@idasync
def triton_get_taint_summary() -> TaintSummaryResult:
    """Return all currently tainted registers and memory addresses."""
    if not TRITON_AVAILABLE:
        return {"ok": False, "error": "triton-library not installed"}
    try:
        ctx = _get_ctx()
        tainted_regs = [r.getName() for r in ctx.getTaintedRegisters()]
        # getTaintedMemory() returns a list of tainted byte addresses (integers)
        tainted_mem_addrs = [hex(addr) for addr in ctx.getTaintedMemory()]
        return {
            "ok": True,
            "tainted_registers": tainted_regs,
            "tainted_memory_addrs": tainted_mem_addrs,
            "total_count": len(tainted_regs) + len(tainted_mem_addrs),
        }
    except IDAError as e:
        return {"ok": False, "tainted_registers": [], "tainted_memory_addrs": [], "total_count": 0, "error": e.message}
    except Exception as e:
        logger.exception("triton_get_taint_summary failed")
        return {"ok": False, "tainted_registers": [], "tainted_memory_addrs": [], "total_count": 0, "error": str(e)}


# ============================================================================
# SMT / constraint solving
# ============================================================================

@tool
@idasync
@tool_timeout(30.0)
def triton_solve_path_constraints(
    negate_last: Annotated[
        bool,
        "When true, negate the last path constraint to find inputs that take "
        "the branch NOT taken during execution — the core of path exploration.",
    ] = False,
    timeout_ms: Annotated[int, "Solver timeout in milliseconds (0 = no limit)."] = 10000,
) -> SolveResult:
    """Ask Z3 to find concrete input values satisfying the accumulated path constraints.

    Returns a model mapping each symbolic variable name to its concrete value.
    Set negate_last=true to explore the opposite side of the most recent branch.

    When the result is sat=false, a 'diagnostics' field explains the likely cause:
    - no_path_constraints: PC_TRACKING_SYMBOLIC filtered all branches (see hint)
    - concrete_constraints_only: branches don't depend on your symbolic variables
    - unsat: the constraint set is genuinely unsatisfiable

    Typical workflow:
      1. triton_init()
      2. triton_setup_windows_x64()           # for Windows binaries (PEB/gs setup)
      3. triton_symbolize_register('rdi')     # mark argument as unknown
      4. triton_process_function('0x401000')  # execute symbolically
      5. triton_solve_path_constraints()      # find input reaching observed path
      6. triton_solve_path_constraints(negate_last=true)  # find input for other branch
    """
    if not TRITON_AVAILABLE:
        return {"ok": False, "error": "triton-library not installed"}
    try:
        ctx = _get_ctx()
        ast_ctx = ctx.getAstContext()
        pcs = ctx.getPathConstraints()

        if negate_last and pcs:
            # Build predicate: conjunction of all-but-last taken predicates
            # THEN add the NOT-taken alternative of the last branch.
            # This is the correct Triton pattern (from code_coverage_crackme_xor.py).
            prev = ast_ctx.equal(ast_ctx.bvtrue(), ast_ctx.bvtrue())
            for pc in pcs[:-1]:
                prev = ast_ctx.land([prev, pc.getTakenPredicate()])

            last = pcs[-1]
            not_taken_node = None
            for branch in last.getBranchConstraints():
                if not branch["isTaken"]:
                    not_taken_node = branch["constraint"]
                    break

            if not_taken_node is not None:
                predicate = ast_ctx.land([prev, not_taken_node])
            else:
                # Last branch has no not-taken alternative (e.g. unconditional jump)
                predicate = ctx.getPathPredicate()
        else:
            predicate = ctx.getPathPredicate()

        model = ctx.getModel(predicate, timeout=timeout_ms)

        if not model:
            diag = _constraint_diagnostics(ctx)
            return {"ok": True, "sat": False, "model": {}, "diagnostics": diag}

        result: dict[str, str] = {}
        for var_id, solver_model in model.items():
            sv = solver_model.getVariable()
            alias = sv.getAlias() or sv.getName()
            result[alias] = hex(solver_model.getValue())

        return {"ok": True, "sat": True, "model": result}

    except IDAError as e:
        return {"ok": False, "sat": False, "model": {}, "error": e.message}
    except Exception as e:
        logger.exception("triton_solve_path_constraints failed")
        return {"ok": False, "sat": False, "model": {}, "error": str(e)}


@tool
@idasync
def triton_setup_windows_x64(
    teb_address: Annotated[
        str,
        "Base address for the fake TEB (Thread Environment Block). "
        "Default 0x7ffa0000 — a safe region well below the typical stack.",
    ] = "0x7ffa0000",
    peb_address: Annotated[
        str,
        "Base address for the fake PEB (Process Environment Block). "
        "Default 0x7ff90000.",
    ] = "0x7ff90000",
    stack_top: Annotated[
        str,
        "Initial RSP value. Default 0x7fffffffe000 (typical Windows user-mode stack).",
    ] = "0x7fffffffe000",
    being_debugged: Annotated[
        int,
        "Value for PEB.BeingDebugged (offset 0x2). 0 = not debugged (default). "
        "Set 1 to simulate a debugger being present.",
    ] = 0,
    nt_global_flag: Annotated[
        int,
        "Value for PEB.NtGlobalFlag (offset 0x68 on x64). 0 = default user mode. "
        "Anti-debug checks look for 0x70 here when a debugger is attached.",
    ] = 0,
    heap_flags: Annotated[
        int,
        "Value for first heap's Flags field (at PEB.ProcessHeap+0x14 on x64). "
        "Normally 2 (HEAP_GROWABLE). Anti-debug checks look for non-2 values.",
    ] = 2,
    heap_force_flags: Annotated[
        int,
        "Value for first heap's ForceFlags field (at PEB.ProcessHeap+0x18 on x64). "
        "Normally 0. Anti-debug checks look for non-zero values.",
    ] = 0,
) -> dict:
    """Set up a realistic Windows x64 execution environment in the Triton context.

    Windows x64 binaries commonly access the TEB/PEB via the GS segment register
    (``mov rax, gs:[0x60]`` to get the PEB pointer). Without modeling these
    structures, Triton reads from virtual address 0x60 (unmapped → returns 0)
    which makes PEB-based anti-debug checks produce concrete-false branch
    conditions that the solver cannot satisfy.

    This tool:
      1. Sets gs_base to ``teb_address`` (so ``gs:[0x60]`` resolves to TEB+0x60)
      2. Writes a minimal fake TEB with the PEB pointer at offset 0x60
      3. Writes a minimal fake PEB with BeingDebugged, NtGlobalFlag, heap fields
      4. Sets RSP to ``stack_top`` with 32-byte shadow space allocated below
      5. Sets RBP to the same value

    After calling this tool, re-symbolize your argument registers (they are
    cleared by the TEB/PEB memory writes if they overlap — they don't with
    default addresses, but always symbolize AFTER this call to be safe).

    **Typical workflow for Windows crackmes:**

      1. triton_init(architecture="x86_64")
      2. triton_setup_windows_x64()
      3. triton_symbolize_register("rcx")   # first arg in Windows x64 ABI
      4. triton_process_function("0x401000")
      5. triton_solve_path_constraints()
    """
    if not TRITON_AVAILABLE:
        return {"ok": False, "error": "triton-library not installed"}
    try:
        ctx = _get_ctx()
        arch = ctx.getArchitecture()
        if arch != ARCH.X86_64:
            return {
                "ok": False,
                "error": f"triton_setup_windows_x64 requires x86_64 architecture, got {_arch_to_str(arch)}",
            }

        def _parse(s: str) -> int:
            return int(s, 16) if isinstance(s, str) and s.startswith("0x") else int(s, 0)

        teb = _parse(teb_address)
        peb = _parse(peb_address)
        stack = _parse(stack_top)

        # ── GS segment base ────────────────────────────────────────────────
        # On Windows x64, GS.base = TEB base. Setting gs_base register causes
        # Triton to resolve gs:[offset] as teb + offset.
        try:
            gs_reg = ctx.getRegister("gs_base")
            ctx.setConcreteRegisterValue(gs_reg, teb)
        except Exception:
            # Some Triton builds expose it as "gs" directly
            try:
                gs_reg = ctx.getRegister("gs")
                ctx.setConcreteRegisterValue(gs_reg, teb)
            except Exception as e:
                logger.warning("Could not set gs_base: %s", e)

        # ── Fake TEB (minimal) ──────────────────────────────────────────────
        # TEB layout (x64, relevant fields):
        #   +0x000  NtTib.StackBase (8 bytes)
        #   +0x008  NtTib.StackLimit (8 bytes)
        #   +0x030  ProcessEnvironmentBlock pointer (8 bytes) → PEB address
        #   +0x060  PEB pointer (alternative — some code reads TEB+0x60 directly
        #            as shorthand on older Windows; keep both)
        import struct
        teb_data = bytearray(0x200)
        struct.pack_into("<Q", teb_data, 0x000, stack)        # StackBase
        struct.pack_into("<Q", teb_data, 0x008, stack - 0x100000)  # StackLimit
        struct.pack_into("<Q", teb_data, 0x030, peb)          # PEB ptr (standard)
        struct.pack_into("<Q", teb_data, 0x060, peb)          # PEB ptr (gs:[0x60])
        ctx.setConcreteMemoryAreaValue(teb, bytes(teb_data))

        # ── Fake heap (referenced by PEB.ProcessHeap) ───────────────────────
        heap_addr = peb + 0x1000
        heap_data = bytearray(0x40)
        struct.pack_into("<I", heap_data, 0x14, heap_flags)       # Heap.Flags
        struct.pack_into("<I", heap_data, 0x18, heap_force_flags)  # Heap.ForceFlags
        ctx.setConcreteMemoryAreaValue(heap_addr, bytes(heap_data))

        # ── Fake PEB (minimal) ──────────────────────────────────────────────
        # PEB layout (x64, anti-debug relevant fields):
        #   +0x000  InheritedAddressSpace (1 byte)
        #   +0x001  ReadImageFileExecOptions (1 byte)
        #   +0x002  BeingDebugged (1 byte)  ← checked by IsDebuggerPresent
        #   +0x003  BitField (1 byte, NtGlobalFlag bits...)
        #   +0x010  ImageBaseAddress (8 bytes)
        #   +0x018  Ldr (8 bytes)
        #   +0x020  ProcessParameters (8 bytes)
        #   +0x058  NtGlobalFlag (was 0x68 on older Windows x64 PEB)
        #             Actually NtGlobalFlag is at:
        #             PEB+0x068 on Windows 8.1+ x64
        #             PEB+0x06C on older x86 PEB
        #   +0x010  — ProcessHeap ptr at PEB+0x30 on x64
        #
        # We zero out 0x200 bytes then set the specific fields.
        peb_data = bytearray(0x200)
        peb_data[0x002] = being_debugged & 0xFF
        # NtGlobalFlag: at PEB+0x68 on Windows x64 (confirmed by WinDbg dt _PEB)
        struct.pack_into("<I", peb_data, 0x068, nt_global_flag & 0xFFFFFFFF)
        # ProcessHeap pointer at PEB+0x30 (x64)
        struct.pack_into("<Q", peb_data, 0x030, heap_addr)
        ctx.setConcreteMemoryAreaValue(peb, bytes(peb_data))

        # ── Stack ────────────────────────────────────────────────────────────
        # Allocate 64 KB of zeroed stack memory below RSP
        stack_buf_size = 0x10000
        stack_buf_base = stack - stack_buf_size
        ctx.setConcreteMemoryAreaValue(stack_buf_base, b"\x00" * stack_buf_size)

        rsp_reg = ctx.getRegister("rsp")
        rbp_reg = ctx.getRegister("rbp")
        # Windows x64 ABI: caller allocates 32-byte shadow space; RSP must be
        # 16-byte aligned before the CALL. We set RSP to stack - 8 (simulating
        # the return address push) with shadow space already accounted for.
        ctx.setConcreteRegisterValue(rsp_reg, stack - 8)
        ctx.setConcreteRegisterValue(rbp_reg, stack)

        return {
            "ok": True,
            "teb_address": hex(teb),
            "peb_address": hex(peb),
            "gs_base_set": hex(teb),
            "stack_rsp": hex(stack - 8),
            "being_debugged": being_debugged,
            "nt_global_flag": nt_global_flag,
            "heap_addr": hex(heap_addr),
            "heap_flags": heap_flags,
            "heap_force_flags": heap_force_flags,
            "note": (
                "Windows memory model initialized. gs:[0x60] now resolves to the "
                f"fake PEB at {hex(peb)}. Symbolize argument registers AFTER this call."
            ),
        }

    except IDAError as e:
        return {"ok": False, "error": e.message}
    except Exception as e:
        logger.exception("triton_setup_windows_x64 failed")
        return {"ok": False, "error": str(e)}


@tool
@idasync
def triton_diagnose_constraints() -> dict:
    """Diagnose why triton_solve_path_constraints returned UNSAT or an empty model.

    Inspects the current path constraints and symbolic variables to explain
    the most likely cause of solver failure. Returns:

    - constraint_count: total path constraints accumulated
    - symbolic_var_count: symbolic variables in the context
    - constraints_with_symbolic: constraints that reference at least one symbolic var
    - constraints_all_concrete: constraints entirely on concrete values
    - per_constraint details: AST string, whether symbolic, whether taken
    - hint: human-readable explanation and suggested fix

    This is the first tool to call when you see sat=false.
    """
    if not TRITON_AVAILABLE:
        return {"ok": False, "error": "triton-library not installed"}
    try:
        ctx = _get_ctx()
        pcs = ctx.getPathConstraints()
        sym_vars = ctx.getSymbolicVariables()

        diag = _constraint_diagnostics(ctx)

        # Build per-constraint detail list
        constraint_details = []
        for i, pc in enumerate(pcs):
            branches = []
            for br in pc.getBranchConstraints():
                ast_str = str(br["constraint"])
                has_sym = _has_symbolic_in_ast(ast_str)
                branches.append({
                    "is_taken": br["isTaken"],
                    "src_addr": hex(br["srcAddr"]),
                    "dst_addr": hex(br["dstAddr"]),
                    "has_symbolic": has_sym,
                    "constraint": ast_str[:300] + ("..." if len(ast_str) > 300 else ""),
                })
            constraint_details.append({
                "index": i,
                "source_addr": hex(pc.getSourceAddress()),
                "taken_addr": hex(pc.getTakenAddress()),
                "is_multiple_branches": pc.isMultipleBranches(),
                "branches": branches,
            })

        # Symbolic variable summary
        sym_var_list = []
        try:
            from triton import SYMBOLIC
            for vid, sv in sym_vars.items():
                stype = sv.getType()
                kind = "register" if stype == SYMBOLIC.REGISTER_VARIABLE else "memory"
                sym_var_list.append({
                    "id": sv.getId(),
                    "name": sv.getName(),
                    "alias": sv.getAlias(),
                    "bitsize": sv.getBitSize(),
                    "kind": kind,
                })
        except Exception:
            pass

        # Quick check: are any symbolic vars mentioned in ANY branch constraint?
        all_branch_asts = []
        for pc in pcs:
            for br in pc.getBranchConstraints():
                all_branch_asts.append(str(br["constraint"]))
        combined = "\n".join(all_branch_asts)
        vars_in_constraints = [sv for sv in sym_var_list if sv["name"] in combined]

        return {
            "ok": True,
            "constraint_count": len(pcs),
            "symbolic_var_count": len(sym_vars),
            "constraints_with_symbolic": diag["constraints_with_symbolic"],
            "constraints_all_concrete": diag["constraints_all_concrete"],
            "symbolic_vars_referenced_in_any_branch": len(vars_in_constraints),
            "hint": diag["hint"],
            "symbolic_variables": sym_var_list,
            "path_constraints": constraint_details,
        }

    except IDAError as e:
        return {"ok": False, "error": e.message}
    except Exception as e:
        logger.exception("triton_diagnose_constraints failed")
        return {"ok": False, "error": str(e)}


@tool
@idasync
@tool_timeout(60.0)
def triton_explore_branches(
    timeout_ms: Annotated[int, "Per-branch Z3 solver timeout in milliseconds."] = 10000,
    max_alternatives: Annotated[
        int,
        "Maximum number of alternative (not-taken) branch inputs to find. "
        "Default 20. Each branch is tried independently.",
    ] = 20,
) -> dict:
    """Find concrete inputs that would have taken each NOT-taken branch.

    Implements the Triton path-exploration pattern from code_coverage_crackme_xor.py:
    for every branch constraint in the current path, it asks Z3 for an input
    that satisfies all prior (taken) constraints PLUS the negated (not-taken)
    constraint of that branch.

    This is the correct way to enumerate all alternative execution paths from
    a symbolic trace. Unlike triton_solve_path_constraints(negate_last=true)
    which only looks at the last branch, this explores EVERY branch in the trace.

    Returns a list of discovered alternative inputs, one per solvable branch.
    Each entry shows which branch it targets, the required input values, and
    the SMT constraint that was satisfied.

    **Workflow:**
      1. triton_init() + triton_setup_windows_x64() [for Windows]
      2. triton_symbolize_register("rcx")  [or memory range]
      3. triton_process_function("0x401000")
      4. triton_explore_branches()         ← this tool
    """
    if not TRITON_AVAILABLE:
        return {"ok": False, "error": "triton-library not installed"}
    try:
        ctx = _get_ctx()
        ast_ctx = ctx.getAstContext()
        pcs = ctx.getPathConstraints()
        sym_vars = ctx.getSymbolicVariables()

        if not pcs:
            diag = _constraint_diagnostics(ctx)
            return {
                "ok": True,
                "alternatives_found": 0,
                "alternatives": [],
                "diagnostics": diag,
            }

        alternatives = []
        # Build up path predicate incrementally (conjunction of taken predicates)
        # This mirrors the exact pattern from the Triton examples.
        previous_constraints = ast_ctx.equal(ast_ctx.bvtrue(), ast_ctx.bvtrue())

        for i, pc in enumerate(pcs):
            if len(alternatives) >= max_alternatives:
                break

            if pc.isMultipleBranches():
                branches = pc.getBranchConstraints()
                for branch in branches:
                    if branch["isTaken"]:
                        continue  # skip the taken path — we want the NOT-taken one
                    if len(alternatives) >= max_alternatives:
                        break

                    # Solve: all previous taken predicates AND this not-taken branch
                    candidate = ast_ctx.land([previous_constraints, branch["constraint"]])
                    try:
                        model = ctx.getModel(candidate, timeout=timeout_ms)
                    except Exception:
                        model = {}

                    if model:
                        inputs: dict[str, str] = {}
                        for _, sm in model.items():
                            sv = sm.getVariable()
                            alias = sv.getAlias() or sv.getName()
                            inputs[alias] = hex(sm.getValue())

                        alternatives.append({
                            "branch_index": i,
                            "src_addr": hex(branch["srcAddr"]),
                            "not_taken_dst": hex(branch["dstAddr"]),
                            "taken_dst": hex(pc.getTakenAddress()),
                            "constraint": str(branch["constraint"])[:200],
                            "inputs": inputs,
                        })

            # Accumulate the taken predicate for the next iteration
            previous_constraints = ast_ctx.land([previous_constraints, pc.getTakenPredicate()])

        diag = _constraint_diagnostics(ctx)
        return {
            "ok": True,
            "path_constraint_count": len(pcs),
            "symbolic_var_count": len(sym_vars),
            "alternatives_found": len(alternatives),
            "alternatives": alternatives,
            "diagnostics": diag,
        }

    except IDAError as e:
        return {"ok": False, "error": e.message}
    except Exception as e:
        logger.exception("triton_explore_branches failed")
        return {"ok": False, "error": str(e)}


@tool
@idasync
def triton_inject_comparison_constraint(
    buf1_addr: Annotated[str, "Address of the symbolic (user-controlled) buffer — hex or symbol."],
    buf2_addr: Annotated[str, "Address of the concrete (expected) buffer to read from IDA — hex or symbol."],
    size: Annotated[int, "Number of bytes to compare."],
    auto_symbolize: Annotated[
        bool,
        "If true (default), automatically symbolize any byte in buf1 that is not yet symbolic. "
        "Set false when you have already called triton_symbolize_bytes on buf1.",
    ] = True,
) -> dict:
    """Inject equality constraints modelling memcmp(buf1, buf2, size) == 0.

    Triton cannot trace into opaque external functions such as memcmp, strcmp, or
    strncmp. This tool works around that limitation by manually injecting the
    byte-level equality constraints that memcmp would have implied:

        buf1[0] == buf2[0]  AND  buf1[1] == buf2[1]  AND  ...  AND  buf1[n-1] == buf2[n-1]

    Injected constraints are ANDed with the path predicate at solve time by
    triton_solve_path_constraints and triton_analyze_function. They survive until
    triton_clear_injected_constraints (or triton_reset / triton_init) is called.

    Typical workflow for a memcmp-based crackme:
      1. triton_init()
      2. triton_symbolize_bytes(buf1_addr, size)   # symbolize user-input buffer
      3. triton_analyze_function(main_addr)         # run the function
      4. triton_inject_comparison_constraint(buf1_addr, expected_buf_addr, size)
      5. triton_solve_path_constraints()            # solver finds the password
    """
    if not TRITON_AVAILABLE:
        return {"ok": False, "error": "triton-library not installed. Run: ida-pro-mcp --install-deps triton"}
    import idc
    from .utils import parse_address

    try:
        ctx = _get_ctx()
        if ctx is None:
            return {"ok": False, "error": "Triton context not initialised — call triton_init first."}

        ea1 = parse_address(buf1_addr)
        ea2 = parse_address(buf2_addr)

        buf2_bytes = idc.get_bytes(ea2, size)
        if buf2_bytes is None or len(buf2_bytes) < size:
            return {
                "ok": False,
                "error": f"Could not read {size} bytes from buf2 at {hex(ea2)} — check IDA has that memory mapped.",
            }

        ast_ctx = ctx.getAstContext()
        injected = _get_injected()
        symbolized_now: list[str] = []
        constraints_added = 0

        for i in range(size):
            addr = ea1 + i
            ma = TritonMemoryAccess(addr, 1)

            if auto_symbolize and not ctx.isMemorySymbolized(ma):
                sv = ctx.symbolizeMemory(ma, f"buf1_{hex(addr)}")
                symbolized_now.append(sv.getName())

            mem_ast = ctx.getMemoryAst(ma)
            expected_byte = int(buf2_bytes[i])
            eq_node = ast_ctx.equal(mem_ast, ast_ctx.bv(expected_byte, 8))
            injected.append(eq_node)
            constraints_added += 1

        return {
            "ok": True,
            "buf1_addr": hex(ea1),
            "buf2_addr": hex(ea2),
            "size": size,
            "constraints_injected": constraints_added,
            "bytes_auto_symbolized": len(symbolized_now),
            "new_sym_vars": symbolized_now,
            "note": (
                "Injected constraints will be ANDed with the path predicate at next solve. "
                "Call triton_solve_path_constraints or triton_analyze_function to use them."
            ),
        }

    except IDAError as e:
        return {"ok": False, "error": e.message}
    except Exception as e:
        logger.exception("triton_inject_comparison_constraint failed")
        return {"ok": False, "error": str(e)}


@tool
@idasync
def triton_clear_injected_constraints() -> dict:
    """Remove all manually-injected comparison constraints.

    Call this before injecting a new set of constraints or after a solve cycle
    to avoid stale constraints from previous analyses polluting future solves.
    """
    if not TRITON_AVAILABLE:
        return {"ok": False, "error": "triton-library not installed. Run: ida-pro-mcp --install-deps triton"}
    try:
        before = len(_get_injected())
        _clear_injected()
        return {
            "ok": True,
            "constraints_removed": before,
            "message": f"Cleared {before} injected constraint(s).",
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}


@tool
@idasync
def triton_symbolize_stack_region(
    size: Annotated[int, "Number of bytes to symbolize."],
    offset: Annotated[
        int,
        "Signed byte offset from the base register. "
        "Use negative values for [rbp-N] (typical local variable), "
        "positive for [rsp+N] (typical argument shadow space). Default 0.",
    ] = 0,
    base: Annotated[
        str,
        "Base register or concrete hex address: 'rbp' (default), 'rsp', or '0x...'. "
        "Use 'rbp' for local variables (base pointer), 'rsp' for stack-pointer relative.",
    ] = "rbp",
    alias_prefix: Annotated[
        str,
        "Prefix for symbolic variable names, e.g. 'input' → 'input_0', 'input_1', ...",
    ] = "stack_sym",
) -> dict:
    """Symbolize a contiguous region of the stack relative to RBP or RSP.

    This is the right tool when user input lands in a local variable (function stack frame)
    rather than at a fixed address. After the function sets up its frame (PUSH RBP /
    MOV RBP, RSP), call this tool to mark the input buffer as symbolic so the solver
    can reason about it.

    Typical usage for a crackme that reads into a stack buffer:
      1. triton_init() and optionally triton_setup_windows_x64()
      2. Run enough instructions to set up the stack frame
         (e.g. triton_replay_instructions or partial triton_process_function)
      3. triton_symbolize_stack_region(size=64, offset=-0x50)  # [rbp-0x50]
      4. Continue execution through the comparison logic
      5. triton_solve_path_constraints()

    Works with triton_process_with_hooks too: symbolize the stack buffer BEFORE
    running process_with_hooks so the instructions that read from the buffer
    build symbolic AST nodes rather than concrete bytes.
    """
    if not TRITON_AVAILABLE:
        return {"ok": False, "error": "triton-library not installed. Run: ida-pro-mcp --install-deps triton"}
    try:
        from .utils import parse_address
        ctx = _get_ctx()
        if ctx is None:
            return {"ok": False, "error": "Triton context not initialised — call triton_init first."}

        arch = ctx.getArchitecture()
        is_64 = arch == ARCH.X86_64

        base_val: int
        base_lower = base.strip().lower()
        if base_lower == "rbp":
            base_val = ctx.getConcreteRegisterValue(ctx.registers.rbp if is_64 else ctx.registers.ebp)
        elif base_lower == "rsp":
            base_val = ctx.getConcreteRegisterValue(ctx.registers.rsp if is_64 else ctx.registers.esp)
        else:
            base_val = parse_address(base)

        effective_addr = (base_val + offset) & 0xFFFFFFFFFFFFFFFF

        sym_vars: list[dict] = []
        for i in range(size):
            ma = TritonMemoryAccess(effective_addr + i, 1)
            sv = ctx.symbolizeMemory(ma, f"{alias_prefix}_{i}")
            sym_vars.append({
                "name": sv.getName(),
                "id": sv.getId(),
                "addr": hex(effective_addr + i),
                "bitsize": sv.getBitSize(),
            })

        return {
            "ok": True,
            "base": base,
            "base_value": hex(base_val),
            "offset": offset,
            "effective_addr": hex(effective_addr),
            "size": size,
            "sym_var_count": len(sym_vars),
            "sym_vars": sym_vars,
            "note": (
                f"Symbolized {size} bytes at {hex(effective_addr)} "
                f"({base}{'%+d' % offset if offset else ''}). "
                "Instructions that read from this region will now build symbolic AST nodes."
            ),
        }

    except Exception as e:
        logger.exception("triton_symbolize_stack_region failed")
        return {"ok": False, "error": str(e)}


@tool
@idasync
def triton_symbolize_stdin(
    size: Annotated[
        int,
        "Number of symbolic stdin bytes. Default 128.",
    ] = 128,
    alias_prefix: Annotated[
        str,
        "Prefix for symbolic variable names: '<prefix>_0', '<prefix>_1', ... Default 'stdin'.",
    ] = "stdin",
) -> dict:
    """Pre-register a symbolic stdin buffer and return a hook configuration template.

    Call this BEFORE triton_process_with_hooks to set up stdin symbolization.
    The size and alias_prefix are stored in module state; when a 'fill_stdin_buffer'
    hook fires at the input function, it creates symbolic variables at the concrete
    runtime buffer address using these pre-registered names.

    This solves the fundamental stdin→symbolic bridge problem: user input's concrete
    address is only known at runtime (inside the hooked function), but alias naming
    can be configured statically here.

    Workflow:
        1. triton_init(pc_tracking_symbolic=False)
        2. triton_setup_windows_x64()
        3. stdin_info = triton_symbolize_stdin(size=64, alias_prefix="password")
        4. # Find the input function address (from triton_scan_call_sites or manual analysis)
        5. hooks = [{"address": "0x140002750", "action": "fill_stdin_buffer",
                     "alias_prefix": "password", "arg_reg": "rcx"}]
        6. triton_process_with_hooks("main", hooks=hooks)
        7. model = triton_solve_path_constraints()
        8. # Look up solved bytes using stdin_info["aliases"]

    Returns:
    - aliases: list ["password_0", ..., "password_63"] — query after solving
    - suggested_hook_template: partial hook dict — fill in 'address' and 'arg_reg'
    """
    if not TRITON_AVAILABLE:
        return {"ok": False, "error": "triton-library not installed. Run: ida-pro-mcp --install-deps triton"}
    try:
        aliases = [f"{alias_prefix}_{i}" for i in range(size)]
        _STDIN_BUFFER[alias_prefix] = {"size": size, "alias_prefix": alias_prefix}
        return {
            "ok": True,
            "size": size,
            "alias_prefix": alias_prefix,
            "aliases": aliases,
            "suggested_hook_template": {
                "address": "<fill_in_input_function_address>",
                "action": "fill_stdin_buffer",
                "alias_prefix": alias_prefix,
                "arg_reg": "rcx",
                "return_value": 1,
                "_note": "Set 'address' to the function that reads user input (e.g. from triton_scan_call_sites)",
            },
            "note": (
                f"Registered stdin buffer: {size} bytes, prefix '{alias_prefix}'. "
                "Use action='fill_stdin_buffer' in triton_process_with_hooks on the input function. "
                "After solving, map solution bytes back to character values using the aliases list."
            ),
        }
    except Exception as e:
        logger.exception("triton_symbolize_stdin failed")
        return {"ok": False, "error": str(e)}


# Known stdin/input function name patterns for triton_scan_for_input_calls.
# Each entry is a (name_fragment, abi_arg_reg_x64, abi_arg_reg_x86, default_size) tuple.
_INPUT_FUNC_SIGNATURES: tuple[tuple[str, str, str, int], ...] = (
    # C runtime stdin
    ("scanf",         "rdx", "esp+4",  64),   # scanf(fmt, buf) — buf in rdx
    ("sscanf",        "rdx", "esp+8",  64),
    ("fscanf",        "rdx", "esp+8",  64),
    ("vscanf",        "rdx", "esp+4",  64),
    ("gets",          "rcx", "esp+0",  256),  # gets(buf)
    ("gets_s",        "rcx", "esp+0",  256),
    ("fgets",         "rcx", "esp+0",  256),  # fgets(buf, n, fp)
    ("_getch",        None,  None,     1),    # returns single char in rax
    # POSIX
    ("read",          "rsi", "esp+4",  64),   # read(fd, buf, n)
    ("fread",         "rdi", "esp+0",  64),   # fread(buf, sz, n, fp)
    ("getline",       "rdi", "esp+0",  64),
    ("getdelim",      "rdi", "esp+0",  64),
    # Winsock / network
    ("recv",          "rdx", "esp+4",  4096),
    ("recvfrom",      "rdx", "esp+4",  4096),
    ("WSARecv",       "rdx", "esp+4",  4096),
    # Win32 file I/O
    ("ReadFile",      "rdx", "esp+4",  4096),
    ("ReadConsoleA",  "rdx", "esp+4",  256),
    ("ReadConsoleW",  "rdx", "esp+4",  256),
    ("ReadConsole",   "rdx", "esp+4",  256),
)

# Output/formatting function name fragments — callees matching these patterns are
# excluded from heuristic input-candidate detection in _scan_call_sites_internal.
_KNOWN_OUTPUT_PATTERNS: tuple[str, ...] = (
    "printf", "fprintf", "sprintf", "snprintf", "vprintf", "vfprintf",
    "wprintf", "fwprintf", "swprintf",
    "puts", "fputs", "fputc", "putchar", "putc",
    "cout", "cerr", "clog", "basic_ostream",
    "send", "sendto", "sendmsg", "WSASend",
    "WriteFile", "WriteConsole", "fwrite", "_write",
    "OutputDebugString", "MessageBox", "MessageBoxA", "MessageBoxW",
    "exit", "abort", "__cxa_terminate",
    "free", "HeapFree", "VirtualFree",
    "memcpy", "memmove", "memset", "strcpy", "strncpy", "wcscpy",
)


def _scan_call_sites_internal(
    func,
    lookback_insns: int = 10,
    watch_regs: "list[str] | None" = None,
) -> "list[dict]":
    """Return CALL site dicts for every CALL in func, annotated with heuristic input-candidate flags.

    This is the shared core for both triton_scan_call_sites and the fallback path
    in triton_scan_for_input_calls. Runs on IDA main thread (caller must be @idasync).
    """
    import idaapi
    import ida_funcs
    import ida_gdl
    import idc
    import ida_name

    if watch_regs is None:
        watch_regs = ["rcx", "rdx", "r8", "r9"]

    def _is_output(name: str) -> bool:
        nl = name.lower()
        return any(p.lower() in nl for p in _KNOWN_OUTPUT_PATTERNS)

    def _is_known_input(name: str) -> bool:
        nl = name.lower()
        return any(frag.lower() in nl for frag, *_ in _INPUT_FUNC_SIGNATURES)

    def _stack_relative(op_text: str) -> bool:
        lo = op_text.lower()
        return "[rbp" in lo or "[rsp" in lo or "[ebp" in lo or "[esp" in lo

    fc = ida_gdl.FlowChart(func)
    call_sites: list[dict] = []

    for bb in fc:
        # (ea, mnem, [op0, op1]) sliding window
        window: list[tuple] = []
        curr = bb.start_ea
        while curr < bb.end_ea:
            insn = idaapi.insn_t()
            length = idaapi.decode_insn(insn, curr)
            if length == 0:
                break

            mnem = idc.print_insn_mnem(curr).lower()
            op0 = idc.print_operand(curr, 0) or ""
            op1 = idc.print_operand(curr, 1) or ""

            if mnem in ("call", "callf"):
                target = idc.get_operand_value(curr, 0)
                callee_name = (
                    ida_name.get_short_name(target)
                    or ida_funcs.get_func_name(target)
                    or ""
                ) if target else ""

                # Look back for arg-register ← stack-ptr loads
                stack_ptr_args: list[dict] = []
                for w_ea, w_mnem, w_op0, w_op1 in window[-lookback_insns:]:
                    if w_mnem not in ("lea", "mov"):
                        continue
                    dst_reg = w_op0.lower().strip()
                    # Strip any size override: "byte ptr rcx" → "rcx"
                    for pfx in ("byte ptr ", "word ptr ", "dword ptr ", "qword ptr "):
                        dst_reg = dst_reg.replace(pfx, "")
                    dst_reg = dst_reg.split("[")[0].strip()
                    if dst_reg in watch_regs and _stack_relative(w_op1):
                        stack_ptr_args.append({
                            "insn_ea": hex(w_ea),
                            "mnem": w_mnem,
                            "dst": w_op0,
                            "src": w_op1,
                            "arg_reg": dst_reg,
                        })

                is_output = _is_output(callee_name)
                is_known_input = _is_known_input(callee_name)
                is_candidate = bool(stack_ptr_args) and not is_output and not is_known_input

                call_sites.append({
                    "call_site_ea": hex(curr),
                    "callee_ea": hex(target) if target else "unknown",
                    "callee_name": callee_name,
                    "is_known_output": is_output,
                    "is_known_input": is_known_input,
                    "stack_ptr_args": stack_ptr_args,
                    "input_candidate": is_candidate,
                })
            else:
                window.append((curr, mnem, op0, op1))

            curr += length

    return call_sites


@tool
@idasync
def triton_scan_for_input_calls(
    address: Annotated[str, "Function start address — hex or symbol name."],
    additional_names: Annotated[
        list[str],
        "Extra function name substrings to treat as input sources, e.g. ['my_read_input']. "
        "Match is case-insensitive substring. Default empty.",
    ] = [],
    default_size: Annotated[
        int,
        "Symbolic buffer size to use when the exact size cannot be determined. Default 128.",
    ] = 128,
    recursive_depth: Annotated[
        int,
        "How many call-graph levels deep to search for known input functions. "
        "Depth 0 = only direct calls from address; depth 1 (default) = also scan "
        "the bodies of direct callees (catches internal wrappers like sub_140002750 "
        "that call scanf internally). Increase for deeper wrapper chains.",
    ] = 1,
) -> dict:
    """Scan a function's call sites for known stdin/input functions using IDA.

    Returns a list of pre-configured hook dicts ready to pass directly to
    triton_process_with_hooks. Use this instead of manually looking up import
    addresses.

    **Handles internal wrappers**: with recursive_depth=1 (default), the scan also
    checks the bodies of every callee of the target function. If `main` calls
    `sub_140002750` and that calls `scanf`, the scanf call site is detected and
    the hook is configured on `sub_140002750` (the callee of main) with the
    buffer argument forwarded.

    Detected functions and their default actions:
    - scanf / fscanf / sscanf → symbolize_buffer_arg (buf pointer in rdx)
    - gets / fgets → symbolize_buffer_arg (buf pointer in rcx)
    - read / fread / recv / ReadFile → symbolize_buffer_arg
    - _getch / getchar → symbolize_return (single char in rax)

    Workflow:
      result = triton_scan_for_input_calls("main")
      hooks = result["hooks"]
      # Add memcmp/strcmp hooks manually, then:
      triton_process_with_hooks("main", hooks=hooks + [memcmp_hook])
      triton_solve_path_constraints()
    """
    if not TRITON_AVAILABLE:
        return {"ok": False, "error": "triton-library not installed. Run: ida-pro-mcp --install-deps triton"}
    import idaapi
    import ida_funcs
    import ida_gdl
    import idc
    import ida_name

    try:
        from .utils import parse_address
        ea = parse_address(address)
        func = ida_funcs.get_func(ea)
        if func is None:
            return {"ok": False, "address": address, "error": f"No function at {hex(ea)}"}

        # Build lookup: lower-case name fragment → (arg_reg_x64, arg_reg_x86, size)
        sig_map: dict[str, tuple] = {}
        for frag, reg64, reg86, sz in _INPUT_FUNC_SIGNATURES:
            sig_map[frag.lower()] = (reg64, reg86, sz)
        for extra in additional_names:
            sig_map[extra.lower()] = ("rdx", "esp+4", default_size)

        arch = _detect_arch_from_ida()
        is_64 = arch == ARCH.X86_64

        hooks: list[dict] = []
        found: list[dict] = []
        visited_funcs: set[int] = set()

        def _name_matches(name: str) -> tuple | None:
            name_lower = name.lower()
            for frag, sig in sig_map.items():
                if frag in name_lower:
                    return sig
            return None

        def _get_call_targets(scan_func_ea: int) -> list[tuple[int, int, str]]:
            """Return list of (call_site_ea, target_ea, target_name) for all CALL insns."""
            results = []
            f = ida_funcs.get_func(scan_func_ea)
            if f is None:
                return results
            fc = ida_gdl.FlowChart(f)
            for bb in fc:
                curr = bb.start_ea
                while curr < bb.end_ea:
                    insn = idaapi.insn_t()
                    length = idaapi.decode_insn(insn, curr)
                    if length == 0:
                        break
                    mnem = idc.print_insn_mnem(curr).lower()
                    if mnem in ("call", "callf"):
                        target = idc.get_operand_value(curr, 0)
                        tname = ida_name.get_short_name(target) or ida_funcs.get_func_name(target) or ""
                        results.append((curr, target, tname))
                    curr += length
            return results

        def _scan_function(scan_ea: int, hook_addr: int, depth: int, wrapper_chain: list[str]) -> None:
            """Recursively scan scan_ea for input functions.

            hook_addr is the address to put in the hook dict — it's the address
            in the PARENT function that calls this scanner's function. For a direct
            call this equals the callee; for recursive cases it's the outermost wrapper.
            """
            if scan_ea in visited_funcs:
                return
            visited_funcs.add(scan_ea)

            for call_site, target, target_name in _get_call_targets(scan_ea):
                sig = _name_matches(target_name)
                if sig is not None:
                    reg64, reg86, buf_sz = sig
                    chain_str = " → ".join(wrapper_chain + [target_name]) if wrapper_chain else target_name
                    call_info = {
                        "call_site": hex(call_site),
                        "target": hex(target),
                        "target_name": target_name,
                        "hook_address": hex(hook_addr),
                        "wrapper_chain": chain_str,
                        "depth": len(wrapper_chain),
                    }
                    found.append(call_info)

                    if reg64 is None:
                        hooks.append({
                            "address": hex(hook_addr),
                            "action": "symbolize_return",
                            "alias": f"input_char_{hex(call_site)}",
                            "_note": call_info,
                        })
                    else:
                        arg_reg = reg64 if is_64 else "ecx"
                        hooks.append({
                            "address": hex(hook_addr),
                            "action": "symbolize_buffer_arg",
                            "arg_reg": arg_reg,
                            "size": buf_sz,
                            "alias_prefix": "stdin",
                            "return_value": 1,
                            "_note": call_info,
                        })
                elif depth > 0 and target != 0:
                    # Recurse into unknown callees looking for wrapped input functions.
                    # The hook address stays as 'target' (the immediate callee from parent).
                    _scan_function(target, target, depth - 1, wrapper_chain + [target_name])

        _scan_function(func.start_ea, func.start_ea, recursive_depth, [])

        # De-duplicate hooks by hook address (multiple wrappers can resolve to same addr)
        seen_addrs: set[str] = set()
        deduped_hooks = []
        for h in hooks:
            key = h["address"]
            if key not in seen_addrs:
                seen_addrs.add(key)
                deduped_hooks.append(h)

        # When name-based detection found nothing, run the stack-ptr-arg heuristic
        # as a fallback so the caller gets actionable candidates instead of silence.
        heuristic_candidates: list[dict] = []
        heuristic_hooks: list[dict] = []
        if not deduped_hooks:
            try:
                all_call_sites = _scan_call_sites_internal(func, lookback_insns=10)
                candidates = [c for c in all_call_sites if c["input_candidate"]]
                heuristic_candidates = candidates
                seen_h: set[str] = set()
                for c in candidates:
                    if c["callee_ea"] in seen_h:
                        continue
                    seen_h.add(c["callee_ea"])
                    first_arg = c["stack_ptr_args"][0]["arg_reg"] if c["stack_ptr_args"] else "rcx"
                    heuristic_hooks.append({
                        "address": c["callee_ea"],
                        "action": "symbolize_buffer_arg",
                        "arg_reg": first_arg,
                        "size": 128,
                        "alias_prefix": "stdin",
                        "return_value": 1,
                        "_note": (
                            f"Heuristic candidate: '{c['callee_name']}' receives stack buffer "
                            f"in {first_arg}. Confirm this reads user input before using."
                        ),
                    })
            except Exception:
                pass  # heuristic is best-effort

        note: str
        if deduped_hooks:
            note = (
                "Pass 'hooks' directly to triton_process_with_hooks. "
                "Add memcmp / strcmp / strncmp hooks manually if needed. "
                "Wrapper functions are hooked at the callee boundary — the hook "
                "fires when main calls the wrapper, then the wrapper's body is skipped."
            )
        elif heuristic_hooks:
            note = (
                "No known input functions detected by name. "
                f"Heuristic found {len(heuristic_hooks)} candidate(s) that receive stack buffer "
                "pointers (see 'heuristic_candidates'). Review them and confirm which reads "
                "user input, then use 'heuristic_hooks' in triton_process_with_hooks, or call "
                "triton_scan_call_sites for the full heuristic analysis."
            )
        else:
            note = (
                "No input functions found by name or by stack-pointer-arg heuristic. "
                "The function may read input via a global buffer, command-line args, "
                "or a deeply nested call chain. Try triton_symbolize_stack_region to "
                "symbolize the buffer directly, or increase recursive_depth."
            )

        return {
            "ok": True,
            "function_ea": hex(func.start_ea),
            "function_name": ida_funcs.get_func_name(func.start_ea) or "",
            "scan_depth": recursive_depth,
            "input_calls_found": len(found),
            "found": found,
            "hooks": deduped_hooks,
            "heuristic_candidates": heuristic_candidates,
            "heuristic_hooks": heuristic_hooks,
            "note": note,
        }

    except Exception as e:
        logger.exception("triton_scan_for_input_calls failed")
        return {"ok": False, "error": str(e)}


@tool
@idasync
def triton_scan_call_sites(
    address: Annotated[str, "Function start address — hex or symbol name."],
    lookback_insns: Annotated[
        int,
        "How many instructions before each CALL to scan for stack-relative argument loads. "
        "Default 10.",
    ] = 10,
    arg_registers: Annotated[
        list[str],
        "Argument registers to watch. Empty list = Windows x64 ABI default: "
        "[rcx, rdx, r8, r9]. For x86, pass ['eax', 'ecx', 'edx'].",
    ] = [],
) -> dict:
    """Static heuristic: find CALL sites that pass stack-buffer pointers as arguments.

    Walks every CALL in the function and looks back lookback_insns instructions for
    LEA/MOV instructions that load a stack-relative address ([rbp-N] / [rsp+N]) into
    an argument register. A call site is flagged as an input_candidate when:

    - At least one argument register receives a stack-buffer pointer, AND
    - The callee is NOT a known output/formatting/free function.

    This is the key fallback when triton_scan_for_input_calls returns zero matches
    because the input function is an internal C++ wrapper or renamed import.
    The heuristic works without knowing function names — it detects the calling
    convention pattern.

    Returns:
    - call_sites: ALL calls with full argument analysis
    - input_candidates: subset flagged as likely input readers
    - suggested_hooks: pre-built hook dicts for triton_process_with_hooks

    Typical workflow (when name-based scan fails):
        cs = triton_scan_call_sites("main")
        for c in cs["input_candidates"]:
            print(c["call_site_ea"], c["callee_name"], c["stack_ptr_args"])
        # Confirm which candidate reads user input, then:
        hooks = cs["suggested_hooks"]  # already configured with detected arg_reg
        triton_process_with_hooks("main", hooks=hooks + [memcmp_hook])
        triton_solve_path_constraints()
    """
    if not TRITON_AVAILABLE:
        return {"ok": False, "error": "triton-library not installed. Run: ida-pro-mcp --install-deps triton"}
    import ida_funcs

    try:
        from .utils import parse_address
        ea = parse_address(address)
        func = ida_funcs.get_func(ea)
        if func is None:
            return {"ok": False, "address": address, "error": f"No function at {hex(ea)}"}

        arch = _detect_arch_from_ida()
        is_64 = arch == ARCH.X86_64
        watch_regs = [r.lower() for r in (arg_registers or (["rcx", "rdx", "r8", "r9"] if is_64 else ["eax", "ecx", "edx"]))]

        call_sites = _scan_call_sites_internal(func, lookback_insns=lookback_insns, watch_regs=watch_regs)
        input_candidates = [c for c in call_sites if c["input_candidate"]]

        # Build suggested hooks (one per unique callee)
        suggested_hooks: list[dict] = []
        seen_callees: set[str] = set()
        for c in input_candidates:
            if c["callee_ea"] in seen_callees:
                continue
            seen_callees.add(c["callee_ea"])
            first_arg = c["stack_ptr_args"][0]["arg_reg"] if c["stack_ptr_args"] else ("rcx" if is_64 else "ecx")
            suggested_hooks.append({
                "address": c["callee_ea"],
                "action": "symbolize_buffer_arg",
                "arg_reg": first_arg,
                "size": 128,
                "alias_prefix": "stdin",
                "return_value": 1,
                "_note": (
                    f"Heuristic: '{c['callee_name']}' @ {c['callee_ea']} receives "
                    f"stack buffer in {first_arg}. Verify it reads user input."
                ),
            })

        return {
            "ok": True,
            "function_ea": hex(func.start_ea),
            "function_name": ida_funcs.get_func_name(func.start_ea) or "",
            "lookback_insns": lookback_insns,
            "total_call_sites": len(call_sites),
            "input_candidates_count": len(input_candidates),
            "call_sites": call_sites,
            "input_candidates": input_candidates,
            "suggested_hooks": suggested_hooks,
            "note": (
                f"Found {len(input_candidates)} input candidate(s) by stack-pointer-arg heuristic. "
                "Review 'input_candidates' — check which callee reads user input — then pass "
                "'suggested_hooks' to triton_process_with_hooks."
                if input_candidates else
                "No stack-buffer-receiving callees found. Input may arrive via global buffer, "
                "registers, or a deeply nested chain. Try triton_symbolize_stack_region."
            ),
        }

    except Exception as e:
        logger.exception("triton_scan_call_sites failed")
        return {"ok": False, "error": str(e)}


@tool
@idasync
def triton_check_input_reaches_branch(
    branch_addr: Annotated[
        str,
        "Address of the branch instruction (jz, jnz, jg, etc.) to check — hex or symbol. "
        "Pass 'any' to check all collected path constraints and return a summary.",
    ],
    sym_var_ids: Annotated[
        list[int],
        "Optional list of symbolic variable IDs to check specifically. "
        "Empty list (default) = check all current symbolic variables.",
    ] = [],
) -> dict:
    """Check whether symbolized input variables flow into a branch's condition.

    This is the primary diagnostic tool for 'why does my input not affect the solver?'
    After running triton_analyze_function or triton_process_with_hooks, use this to see:
    - Which branches in the path predicate involve your symbolic inputs
    - Which branches are on concrete (non-symbolic) data and cannot be steered
    - The full AST of each constraint so you can see the formula

    If ALL branches report has_symbolic=false, your input does not flow into any
    branch condition — consider symbolizing a different register or memory region,
    or check if input is read AFTER the branches (wrong symbolization point).

    Returns a per-branch summary and an overall verdict.
    """
    if not TRITON_AVAILABLE:
        return {"ok": False, "error": "triton-library not installed. Run: ida-pro-mcp --install-deps triton"}
    try:
        from .utils import parse_address
        ctx = _get_ctx()
        if ctx is None:
            return {"ok": False, "error": "Triton context not initialised — call triton_init first."}

        pcs = ctx.getPathConstraints()
        all_sym_vars = ctx.getSymbolicVariables()

        # Resolve which sym var names we're looking for
        if sym_var_ids:
            target_names: set[str] = set()
            for vid in sym_var_ids:
                sv = all_sym_vars.get(vid)
                if sv:
                    target_names.add(sv.getName())
        else:
            target_names = {sv.getName() for sv in all_sym_vars.values()}

        check_all = branch_addr.strip().lower() == "any"
        target_ea: int = 0
        if not check_all:
            target_ea = parse_address(branch_addr)

        results: list[dict] = []
        symbolic_branch_count = 0
        concrete_branch_count = 0

        for pc_idx, pc in enumerate(pcs):
            for br in pc.getBranchConstraints():
                src = br.get("srcAddr", 0)
                dst = br.get("dstAddr", 0)

                if not check_all and src != target_ea:
                    continue

                ast_str = str(br["constraint"])
                # Find which of our target sym vars appear in this constraint
                vars_present = [name for name in target_names if name in ast_str]
                has_sym = bool(vars_present)

                if has_sym:
                    symbolic_branch_count += 1
                else:
                    concrete_branch_count += 1

                # Attempt to classify the constraint
                if not has_sym and "SymVar_" not in ast_str:
                    constraint_type = "concrete"
                elif has_sym:
                    constraint_type = "symbolic"
                else:
                    constraint_type = "symbolic_other"  # Has SymVar but not from our set

                results.append({
                    "pc_index": pc_idx,
                    "branch_src": hex(src),
                    "branch_dst": hex(dst),
                    "is_taken": br["isTaken"],
                    "constraint_type": constraint_type,
                    "has_symbolic": has_sym,
                    "sym_vars_present": vars_present,
                    "constraint_ast": ast_str,
                    "is_multiple_branches": pc.isMultipleBranches(),
                })

        if not check_all and not results:
            return {
                "ok": True,
                "branch_addr": branch_addr,
                "found": False,
                "message": (
                    f"No path constraint at {branch_addr}. The branch at that address "
                    "may not have been executed during the last symbolic run, "
                    "or pc_tracking_symbolic=True filtered it out (retry with pc_tracking_symbolic=False)."
                ),
            }

        total = len(results)
        verdict = (
            "INPUT_REACHES_BRANCH"
            if symbolic_branch_count > 0
            else ("NO_PATH_CONSTRAINTS" if total == 0 else "INPUT_DOES_NOT_REACH_BRANCH")
        )

        advice = ""
        if verdict == "INPUT_DOES_NOT_REACH_BRANCH":
            advice = (
                "Your symbolized input does not flow into any branch condition on this path. "
                "Possible causes: (1) input is read AFTER the branch — symbolize later; "
                "(2) wrong register/buffer symbolized — check the call that reads user data; "
                "(3) use triton_scan_for_input_calls to auto-detect the input function."
            )
        elif verdict == "INPUT_REACHES_BRANCH":
            advice = (
                f"Input affects {symbolic_branch_count}/{total} branch(es). "
                "Call triton_solve_path_constraints to find concrete input values."
            )

        return {
            "ok": True,
            "branch_addr": branch_addr if not check_all else "any",
            "found": total > 0,
            "total_constraints_checked": total,
            "symbolic_branches": symbolic_branch_count,
            "concrete_branches": concrete_branch_count,
            "verdict": verdict,
            "advice": advice,
            "results": results,
        }

    except Exception as e:
        logger.exception("triton_check_input_reaches_branch failed")
        return {"ok": False, "error": str(e)}


@tool
@idasync
def triton_get_register_ast(
    register: Annotated[str, "Register name, e.g. 'rax', 'rbx', 'eax', 'rcx'."],
    simplify: Annotated[bool, "If true, apply Triton AST simplification before returning. Default false."] = False,
) -> dict:
    """Return the symbolic AST expression for a register's current value.

    After running triton_process_function or triton_analyze_function, this shows
    how the register's value depends on the symbolic input variables. Useful for:
    - Verifying that a register IS symbolic (not a concrete bitvector)
    - Understanding the data-flow formula before solving
    - Debugging why the solver returns UNSAT (concrete formula = trivially False)

    Example: after symbolizing RCX and running 3 XOR instructions, rax might
    show as  (bvxor SymVar_0 #x6d)  — confirming the XOR relationship.
    """
    if not TRITON_AVAILABLE:
        return {"ok": False, "error": "triton-library not installed. Run: ida-pro-mcp --install-deps triton"}
    try:
        ctx = _get_ctx()
        if ctx is None:
            return {"ok": False, "error": "Triton context not initialised — call triton_init first."}

        reg_name = register.strip().lower()
        try:
            reg = ctx.getRegister(reg_name)
        except Exception as e:
            return {"ok": False, "register": register, "error": f"Unknown register: {e}"}

        reg_ast = ctx.getRegisterAst(reg)
        if simplify:
            reg_ast = ctx.simplify(reg_ast, True)

        ast_str = str(reg_ast)
        has_sym = _has_symbolic_in_ast(ast_str)
        concrete_val: int | None = None
        if not has_sym:
            try:
                concrete_val = ctx.getConcreteRegisterValue(reg)
            except Exception:
                pass

        is_symbolized = ctx.isRegisterSymbolized(reg)

        return {
            "ok": True,
            "register": register,
            "ast": ast_str,
            "has_symbolic": has_sym,
            "is_symbolized": is_symbolized,
            "concrete_value": hex(concrete_val) if concrete_val is not None else None,
            "bitsize": reg.getBitSize(),
        }

    except Exception as e:
        logger.exception("triton_get_register_ast failed")
        return {"ok": False, "register": register, "error": str(e)}


@tool
@idasync
@tool_timeout(120.0)
def triton_process_with_hooks(
    address: Annotated[str, "Function start address — hex or symbol name."],
    hooks: Annotated[
        list[dict],
        "List of hook definitions. Each hook: "
        "{\"address\": \"0x...\", \"action\": \"<action>\", ...action-specific fields...}. "
        "Actions: "
        "  return_concrete — skip the call, set RAX to a fixed value (field: 'value': '0x0'); "
        "  symbolize_return — skip the call, make RAX a fresh symbolic variable (field: 'alias'); "
        "  symbolize_buffer_arg — model scanf/gets/fgets/recv/ReadFile: read buffer ptr from "
        "    arg_reg (default rdx), symbolize 'size' bytes, set RAX=return_value. "
        "    Fields: 'arg_reg','size','alias_prefix','return_value'; "
        "  fill_stdin_buffer — like symbolize_buffer_arg but sources size/alias_prefix from "
        "    triton_symbolize_stdin registry. Fields: 'arg_reg','alias_prefix','return_value'; "
        "  memcmp_semantic — model memcmp(buf1,buf2,n): read expected bytes from buf2 "
        "    (tries IDA static then Triton concrete memory for runtime-computed values), "
        "    inject buf1[i]==buf2[i] equality constraints, set RAX=0. "
        "    Fields: 'buf1_reg','buf2_reg','size_reg' (register sources, Windows x64 defaults: rcx,rdx,r8) "
        "    OR individual overrides 'buf1','buf2','size'. "
        "    Literal override: 'expected': '<hex_or_ascii_string>' to bypass memory read entirely. "
        "    When size_reg is 0, auto-detects size from symbolized region at buf1; "
        "  strcmp_semantic — like memcmp_semantic but auto-detects size from null terminator in buf2. "
        "    Supports 'expected': 'literal_string' for direct constraint injection.",
    ],
    max_insns: Annotated[int, "Maximum instructions to process per function. Default 2000."] = 2000,
    setup_windows_abi: Annotated[
        bool,
        "Set up fake Windows x64 TEB/PEB/GS segment before processing. "
        "Required for binaries that read gs:[0x60] (BeingDebugged etc.).",
    ] = False,
    pc_tracking_symbolic: Annotated[
        "bool | None",
        "PC_TRACKING_SYMBOLIC mode: only collect path constraints for branches whose "
        "condition involves a symbolic variable. Default None → False (collect all branches). "
        "Set True only if you want to filter out concrete anti-debug branches.",
    ] = None,
) -> dict:
    """Process a function with CALL hooks that intercept external/opaque function calls.

    Triton cannot symbolically trace into CALL targets like memcmp, strcmp, or any
    function not inside the current function range. This tool intercepts those calls
    and applies a hook action instead:

    - return_concrete: Skip the call. Set RAX to a constant value you specify.
      Use when the external function always returns a fixed value in your scenario.

    - symbolize_return: Skip the call. Make RAX a fresh symbolic variable.
      Use when the return value's effect on branches is what you want to explore.

    - symbolize_buffer_arg: Model an input function (scanf, gets, fgets, recv, ReadFile).
      Reads the buffer pointer from arg_reg, symbolizes 'size' bytes there, sets RAX
      to return_value (default 1 = success). Use this to make user-controlled input
      symbolic so the solver can find what bytes satisfy downstream comparisons.

    - fill_stdin_buffer: Like symbolize_buffer_arg, but sources size and alias_prefix
      from the registry set by triton_symbolize_stdin. Minimal hook dict — just
      set address and arg_reg. Ensures alias names match across tools.

    - memcmp_semantic: Skip the call. Read expected bytes from buf2 — first tries
      IDA's static binary view, then falls back to Triton's runtime concrete memory
      (handles XOR-decoded or otherwise runtime-computed comparison buffers). If size
      register is 0, auto-detects from the symbolized region at buf1. Accepts an
      'expected' field with literal hex or ASCII to bypass memory reads entirely.
      Injects buf1[i]==expected[i] equality constraints. Sets RAX=0.

    - strcmp_semantic: Like memcmp_semantic but for null-terminated strings. Auto-
      detects size from the null terminator in buf2. Accepts 'expected': 'string'
      for direct ASCII string injection without needing to read buf2 from memory.

    All hooks advance PC past the CALL instruction (restore RSP, set RIP to return
    address) so execution continues correctly.

    ┌─── End-to-end crackme solve workflow (stdin → memcmp) ───────────────────┐
    │  # Step 1: find the addresses of scanf and memcmp in the import table    │
    │  hooks = triton_scan_for_input_calls("main")["hooks"]   # auto-detect    │
    │                                                                           │
    │  # Step 2: run with hooks — scanf symbolizes input, memcmp injects =     │
    │  triton_process_with_hooks("main", hooks=hooks,                          │
    │      setup_windows_abi=True)                                              │
    │                                                                           │
    │  # Step 3: solve — Z3 finds the bytes satisfying buf1==expected          │
    │  triton_solve_path_constraints()   # → {"stdin_0": "0x63", ...}          │
    └───────────────────────────────────────────────────────────────────────────┘
    """
    if not TRITON_AVAILABLE:
        return {"ok": False, "error": "triton-library not installed. Run: ida-pro-mcp --install-deps triton"}
    import idaapi
    import idc
    import ida_funcs
    from .utils import parse_address

    try:
        ctx = _get_ctx()
        if ctx is None:
            return {"ok": False, "error": "Triton context not initialised — call triton_init first."}

        ea = parse_address(address)
        func = ida_funcs.get_func(ea)
        if func is None:
            return {"ok": False, "address": address, "error": f"No function at {hex(ea)}"}

        # --- Parse and resolve hook addresses ---
        resolved_hooks: dict[int, dict] = {}
        for h in hooks:
            try:
                haddr = parse_address(str(h.get("address", "0")))
                resolved_hooks[haddr] = h
            except Exception as e:
                return {"ok": False, "error": f"Invalid hook address '{h.get('address')}': {e}"}

        # --- Resolve pc_tracking_symbolic: None → False (track all branches by default) ---
        pc_tracking = pc_tracking_symbolic if pc_tracking_symbolic is not None else False
        ctx.setMode(MODE.PC_TRACKING_SYMBOLIC, pc_tracking)

        # --- Windows ABI setup ---
        windows_abi_applied = False
        if setup_windows_abi and ctx.getArchitecture() == ARCH.X86_64:
            try:
                _setup_windows_x64_internal(ctx)
                windows_abi_applied = True
            except Exception as e:
                logger.warning("triton_process_with_hooks: Windows ABI setup failed: %s", e)

        # --- Determine PC/SP/return-val registers for the architecture ---
        arch = ctx.getArchitecture()
        is_64 = arch == ARCH.X86_64
        try:
            pc_reg = ctx.registers.rip if is_64 else ctx.registers.eip
            sp_reg = ctx.registers.rsp if is_64 else ctx.registers.esp
            ret_reg = ctx.registers.rax if is_64 else ctx.registers.eax
        except Exception as e:
            return {"ok": False, "error": f"Could not resolve architecture registers: {e}"}

        def _apply_hook(hook: dict, rip_after_call: int) -> dict:
            """Apply a hook action. rip_after_call is the return address (CALL+size)."""
            action = hook.get("action", "return_concrete")
            log_entry: dict = {"action": action}

            # Shared helper — available to ALL action branches
            def _reg_val(name: str) -> int:
                return ctx.getConcreteRegisterValue(ctx.getRegister(name.lower()))

            try:
                # Restore stack pointer (undo the CALL's push of return address)
                sp_val = ctx.getConcreteRegisterValue(sp_reg)
                ctx.setConcreteRegisterValue(sp_reg, sp_val + (8 if is_64 else 4))

                # Redirect PC to return address
                ctx.setConcreteRegisterValue(pc_reg, rip_after_call)

                if action == "return_concrete":
                    raw = hook.get("value", "0x0")
                    val = int(str(raw), 16) if isinstance(raw, str) and raw.startswith("0x") else int(str(raw), 0)
                    ctx.setConcreteRegisterValue(ret_reg, val)
                    log_entry["rax"] = hex(val)

                elif action == "symbolize_return":
                    alias = hook.get("alias", f"hook_ret_{hex(rip_after_call)}")
                    sv = ctx.symbolizeRegister(ret_reg, alias)
                    log_entry["sym_var"] = sv.getName()
                    log_entry["alias"] = alias

                elif action in ("memcmp_semantic", "strcmp_semantic"):
                    # --- Resolve buf1, buf2, size (individual overrides take priority) ---
                    b1_reg = hook.get("buf1_reg", "rcx" if is_64 else "ecx")
                    b2_reg = hook.get("buf2_reg", "rdx" if is_64 else "edx")
                    sz_reg = hook.get("size_reg", "r8" if is_64 else "ebx")

                    b1 = parse_address(str(hook["buf1"])) if "buf1" in hook else _reg_val(b1_reg)
                    b2 = parse_address(str(hook["buf2"])) if "buf2" in hook else _reg_val(b2_reg)
                    sz = int(hook["size"])               if "size" in hook else (
                         0 if action == "strcmp_semantic" else _reg_val(sz_reg)
                    )

                    # --- Validate buf1 address ---
                    if b1 < 0x1000:
                        raise ValueError(
                            f"buf1 address {hex(b1)} (from {b1_reg!r}) is implausibly small "
                            "— set 'buf1_reg' or 'buf1' in the hook dict."
                        )

                    # --- sz=0 or strcmp: auto-detect from consecutive symbolized bytes at buf1 ---
                    if sz == 0:
                        for _a in range(1, 513):
                            if not ctx.isMemorySymbolized(TritonMemoryAccess(b1 + _a - 1, 1)):
                                sz = _a - 1
                                break
                        else:
                            sz = 512
                        if sz > 0:
                            log_entry["size_auto_detected"] = sz
                        if sz == 0:
                            raise ValueError(
                                f"Cannot determine size: {sz_reg!r}=0 and no symbolized bytes "
                                f"found at buf1 {hex(b1)}. Set 'size' explicitly in the hook dict."
                            )

                    # --- Validate buf2 address ---
                    if b2 < 0x1000:
                        raise ValueError(
                            f"buf2 address {hex(b2)} (from {b2_reg!r}) is implausibly small — "
                            "the comparison target is likely in a different register. "
                            "Set 'buf2_reg' or 'buf2' explicitly, or use 'expected' with "
                            "the known comparison bytes as a hex string."
                        )

                    # --- Resolve expected bytes (priority: literal → IDA static → Triton concrete) ---
                    buf2_bytes: "bytes | None" = None
                    buf2_source = "unknown"

                    if "expected" in hook or "buf2_bytes" in hook:
                        raw = hook.get("expected") or hook.get("buf2_bytes")
                        if isinstance(raw, str) and not all(c in "0123456789abcdefABCDEF " for c in raw.strip()):
                            # Treat as ASCII string literal (e.g. "expected": "crackme")
                            buf2_bytes = raw.encode("utf-8")
                            buf2_source = "hook_string"
                        else:
                            # Treat as hex string (e.g. "expected": "41424344")
                            buf2_bytes = bytes.fromhex(str(raw).replace(" ", ""))[:sz]
                            buf2_source = "hook_hex"
                    else:
                        # Try IDA's static binary view first
                        ida_bytes_data = idc.get_bytes(b2, sz)
                        if ida_bytes_data and len(ida_bytes_data) >= sz:
                            buf2_bytes = bytes(ida_bytes_data)
                            buf2_source = "ida_static"
                        else:
                            # buf2 is runtime-computed (XOR-decoded, stack-allocated) — not
                            # in IDA's static view. Read from Triton's concrete memory model,
                            # which tracks all writes made during emulation.
                            try:
                                raw_triton = ctx.getConcreteMemoryAreaValue(b2, sz)
                                if raw_triton:
                                    buf2_bytes = bytes(raw_triton)
                                    buf2_source = "triton_concrete"
                            except Exception:
                                pass

                    if buf2_bytes is None or len(buf2_bytes) < sz:
                        raise ValueError(
                            f"Cannot read {sz} bytes from buf2 at {hex(b2)}: not found in "
                            "IDA static memory or Triton's concrete memory model. "
                            "If buf2 is XOR-decoded at runtime, ensure the decode loop ran "
                            "before this hook fires (linear processing must have reached it). "
                            "Or set 'expected': '<hexbytes>' in the hook dict to specify the "
                            "known expected bytes directly."
                        )

                    if action == "strcmp_semantic":
                        # strcmp compares up to (but not including) the null terminator
                        if b"\x00" in buf2_bytes:
                            buf2_bytes = buf2_bytes[:buf2_bytes.index(b"\x00")]
                        sz = len(buf2_bytes)

                    # --- Inject equality constraints: buf1[i] == buf2_bytes[i] ---
                    ast_ctx = ctx.getAstContext()
                    injected = _get_injected()
                    sym_created = []
                    for i in range(sz):
                        ma = TritonMemoryAccess(b1 + i, 1)
                        if not ctx.isMemorySymbolized(ma):
                            sv = ctx.symbolizeMemory(ma, f"inp_{hex(b1 + i)}")
                            sym_created.append(sv.getName())
                        mem_ast = ctx.getMemoryAst(ma)
                        injected.append(ast_ctx.equal(mem_ast, ast_ctx.bv(int(buf2_bytes[i]), 8)))

                    ctx.setConcreteRegisterValue(ret_reg, 0)  # 0 = equal
                    log_entry["buf1"] = hex(b1)
                    log_entry["buf2"] = hex(b2)
                    log_entry["size"] = sz
                    log_entry["buf2_source"] = buf2_source
                    log_entry["buf2_expected_hex"] = buf2_bytes[:sz].hex()
                    log_entry["constraints_injected"] = sz
                    log_entry["sym_vars_created"] = sym_created
                    log_entry["rax"] = "0x0"

                elif action == "symbolize_buffer_arg":
                    # Model a function that writes user-controlled bytes into a buffer
                    # argument: scanf(fmt, buf), gets(buf), fgets(buf, n, fp), recv(...),
                    # ReadFile(h, buf, n, ...), etc.
                    # Read the buffer pointer from the specified argument register.
                    arg_reg = hook.get("arg_reg", "rdx" if is_64 else "edx")
                    size = int(hook.get("size", 64))
                    alias_prefix = hook.get("alias_prefix", "stdin")
                    ret_value = int(str(hook.get("return_value", 1)), 0)

                    buf_addr = _reg_val(arg_reg)
                    if buf_addr == 0:
                        raise ValueError(
                            f"Buffer register {arg_reg!r} is 0 — function may not have been "
                            "called yet, or the register holds the wrong argument."
                        )

                    sym_created = []
                    for i in range(size):
                        ma = TritonMemoryAccess(buf_addr + i, 1)
                        sv = ctx.symbolizeMemory(ma, f"{alias_prefix}_{i}")
                        sym_created.append(sv.getName())

                    ctx.setConcreteRegisterValue(ret_reg, ret_value)
                    log_entry["buf_addr"] = hex(buf_addr)
                    log_entry["size"] = size
                    log_entry["sym_vars_created"] = sym_created
                    log_entry["rax"] = hex(ret_value)

                elif action == "fill_stdin_buffer":
                    # Like symbolize_buffer_arg but sources size/alias_prefix from the
                    # _STDIN_BUFFER registry set by triton_symbolize_stdin, so the hook
                    # dict is minimal and alias names match what the caller registered.
                    arg_reg = hook.get("arg_reg", "rcx" if is_64 else "ecx")
                    alias_prefix = hook.get("alias_prefix", "stdin")
                    ret_value = int(str(hook.get("return_value", 1)), 0)

                    stdin_cfg = _STDIN_BUFFER.get(alias_prefix, {})
                    size = int(hook.get("size", stdin_cfg.get("size", 128)))

                    buf_addr = _reg_val(arg_reg)
                    if buf_addr == 0:
                        raise ValueError(
                            f"Buffer register {arg_reg!r} is 0 — hook may have fired before "
                            "the function was called, or the register holds a different argument."
                        )

                    sym_created = []
                    for i in range(size):
                        ma = TritonMemoryAccess(buf_addr + i, 1)
                        sv = ctx.symbolizeMemory(ma, f"{alias_prefix}_{i}")
                        sym_created.append(sv.getName())

                    ctx.setConcreteRegisterValue(ret_reg, ret_value)
                    log_entry["buf_addr"] = hex(buf_addr)
                    log_entry["size"] = size
                    log_entry["alias_prefix"] = alias_prefix
                    log_entry["sym_vars_created"] = sym_created
                    log_entry["rax"] = hex(ret_value)

                else:
                    raise ValueError(f"Unknown hook action: '{action}'")

                log_entry["ok"] = True

            except Exception as e:
                log_entry["ok"] = False
                log_entry["error"] = str(e)

            return log_entry

        # --- Linear processing with hook interception ---
        func_start = func.start_ea
        func_end = func.end_ea

        raw_func = idc.get_bytes(func_start, func_end - func_start)
        if raw_func:
            ctx.setConcreteMemoryAreaValue(func_start, raw_func)

        pc_start = len(ctx.getPathConstraints())
        processed_count = 0
        hook_log: list[dict] = []
        curr = func_start
        truncated = False

        while curr < func_end and processed_count < max_insns:
            insn_ida = idaapi.insn_t()
            length = idaapi.decode_insn(insn_ida, curr)
            if length == 0:
                break

            raw = idc.get_bytes(curr, length)
            if not raw:
                curr += 1
                continue

            insn = TritonInstruction()
            insn.setAddress(curr)
            insn.setOpcode(raw)
            ctx.processing(insn)
            _get_trace().append(curr)
            processed_count += 1

            is_call = _is_call_insn(insn)
            if is_call:
                # After processing a CALL, Triton has pushed the return address and
                # set RIP to the call target.
                try:
                    call_target = ctx.getConcreteRegisterValue(pc_reg)
                    return_addr = curr + length
                    if call_target in resolved_hooks:
                        entry = _apply_hook(resolved_hooks[call_target], return_addr)
                        entry["call_site"] = hex(curr)
                        entry["target"] = hex(call_target)
                        hook_log.append(entry)
                        # Continue from return address
                        curr = return_addr
                        continue
                except Exception as e:
                    logger.debug("triton_process_with_hooks: hook check failed at %s: %s", hex(curr), e)

            curr += length

        truncated = processed_count >= max_insns and curr < func_end
        new_pcs = len(ctx.getPathConstraints()) - pc_start

        solve_result = _try_solve_predicate(ctx, 30000)

        return {
            "ok": True,
            "function_ea": hex(func_start),
            "function_name": ida_funcs.get_func_name(func_start) or "",
            "instructions_processed": processed_count,
            "instructions_truncated": truncated,
            "hooks_fired": len(hook_log),
            "hook_log": hook_log,
            "new_path_constraints": new_pcs,
            "windows_abi_applied": windows_abi_applied,
            "pc_tracking_symbolic": pc_tracking,
            "injected_constraints": len(_get_injected()),
            "solver": solve_result,
        }

    except IDAError as e:
        return {"ok": False, "error": e.message}
    except Exception as e:
        logger.exception("triton_process_with_hooks failed")
        return {"ok": False, "error": str(e)}


@tool
@idasync
def triton_get_ast_expression(
    sym_var_id_or_name: Annotated[str, "Symbolic variable ID (integer) or alias name."],
) -> dict:
    """Return the full symbolic AST for a variable as a Python-syntax string.

    Useful for inspecting what a register or memory cell evaluates to in
    terms of the symbolic inputs.
    """
    if not TRITON_AVAILABLE:
        return {"ok": False, "error": "triton-library not installed"}
    try:
        ctx = _get_ctx()
        ast = ctx.getAstContext()

        # Resolve to SymbolicVariable
        try:
            sv = ctx.getSymbolicVariable(int(sym_var_id_or_name))
        except (ValueError, TypeError):
            sv = ctx.getSymbolicVariable(sym_var_id_or_name)

        if sv is None:
            return {"ok": False, "error": f"Symbolic variable not found: {sym_var_id_or_name!r}"}

        node = ast.variable(sv)
        unrolled = ast.unroll(node)

        return {
            "ok": True,
            "sym_var_id": sv.getId(),
            "sym_var_name": sv.getName(),
            "alias": sv.getAlias(),
            "bitsize": sv.getBitSize(),
            "ast": str(node),
            "ast_unrolled": str(unrolled),
        }

    except IDAError as e:
        return {"ok": False, "error": e.message}
    except Exception as e:
        logger.exception("triton_get_ast_expression failed")
        return {"ok": False, "error": str(e)}


@tool
@idasync
def triton_simplify_expression(
    symbolic_expression_id: Annotated[int, "ID of the SymbolicExpression to simplify."],
    use_solver: Annotated[bool, "Also pass through Z3 for algebraic simplification (slower)."] = False,
) -> dict:
    """Simplify a symbolic expression using Triton's AST optimisation passes.

    Returns the original and simplified AST strings.
    """
    if not TRITON_AVAILABLE:
        return {"ok": False, "error": "triton-library not installed"}
    try:
        ctx = _get_ctx()
        expr = ctx.getSymbolicExpression(symbolic_expression_id)
        if expr is None:
            return {"ok": False, "error": f"SymbolicExpression {symbolic_expression_id} not found"}

        original_node = expr.getAst()
        simplified_node = ctx.simplify(original_node, solver=use_solver)

        return {
            "ok": True,
            "expression_id": symbolic_expression_id,
            "original_ast": str(original_node),
            "simplified_ast": str(simplified_node),
            "changed": str(original_node) != str(simplified_node),
        }

    except IDAError as e:
        return {"ok": False, "error": e.message}
    except Exception as e:
        logger.exception("triton_simplify_expression failed")
        return {"ok": False, "error": str(e)}


@tool
@idasync
def triton_lift_to_smt(
    symbolic_expression_id: Annotated[int, "ID of the SymbolicExpression to lift."],
) -> dict:
    """Lift a symbolic expression to SMT-LIB 2 format.

    The output can be pasted into Z3 or any SMT-LIB 2 compliant solver
    for external analysis.
    """
    if not TRITON_AVAILABLE:
        return {"ok": False, "error": "triton-library not installed"}
    try:
        ctx = _get_ctx()
        expr = ctx.getSymbolicExpression(symbolic_expression_id)
        if expr is None:
            return {"ok": False, "error": f"SymbolicExpression {symbolic_expression_id} not found"}

        smt = ctx.liftToSMT(expr, assert_=True, icomment=True)
        return {
            "ok": True,
            "expression_id": symbolic_expression_id,
            "smt": smt,
        }

    except IDAError as e:
        return {"ok": False, "error": e.message}
    except Exception as e:
        logger.exception("triton_reset failed")
        return {"ok": False, "error": str(e)}


# ============================================================================
# Snapshots
# ============================================================================

@tool
@idasync
def triton_snapshot_save(
    label: Annotated[str, "Human-readable label for this snapshot."] = "",
) -> SnapshotResult:
    """Save the current symbolic execution state to a named snapshot.

    Captures symbolic variables, path predicate, taint state, and concrete
    register values. Restore with triton_snapshot_restore.
    """
    if not TRITON_AVAILABLE:
        return {"ok": False, "error": "triton-library not installed"}
    global _next_snapshot_id

    try:
        ctx = _get_ctx()
        from triton import SYMBOLIC

        # Collect symbolic variable origins so we can re-symbolize on restore
        sym_vars_data = []
        for vid, sv in ctx.getSymbolicVariables().items():
            stype = sv.getType()
            sym_vars_data.append({
                "alias": sv.getAlias(),
                "bitsize": sv.getBitSize(),
                "type_is_register": stype == SYMBOLIC.REGISTER_VARIABLE,
                "origin": sv.getOrigin(),
            })

        # Concrete register values for all parent registers
        regs_data: dict[int, int] = {}
        for reg in ctx.getParentRegisters():
            try:
                regs_data[reg.getId()] = (reg.getName(), ctx.getConcreteRegisterValue(reg))
            except Exception:
                pass

        # Path predicate as SMT-LIB string (AST node references become invalid
        # when the original context is garbage collected)
        try:
            path_predicate_smt = ctx.liftToSMT(ctx.getPathPredicate(), assert_=True, icomment=False)
        except Exception:
            path_predicate_smt = ""

        # Taint state
        tainted_reg_ids = [r.getId() for r in ctx.getTaintedRegisters()]
        tainted_mem_addrs = list(ctx.getTaintedMemory())

        # Instruction trace for predicate reconstruction on restore
        trace_list = list(_get_trace())

        with _snapshots_lock:
            snap_id = _next_snapshot_id
            _next_snapshot_id += 1
            _snapshots[snap_id] = {
                "id": snap_id,
                "label": label or f"snapshot_{snap_id}",
                "timestamp": time.time(),
                "arch": ctx.getArchitecture(),
                "sym_vars": sym_vars_data,
                "registers": regs_data,
                "tainted_reg_ids": tainted_reg_ids,
                "tainted_mem_addrs": tainted_mem_addrs,
                "path_predicate_smt": path_predicate_smt,
                "instruction_trace": trace_list,
            }

        return {
            "ok": True,
            "snapshot_id": snap_id,
            "label": label or f"snapshot_{snap_id}",
            "timestamp": _snapshots[snap_id]["timestamp"],
            "sym_var_count": len(sym_vars_data),
            "instruction_trace_count": len(trace_list),
        }

    except IDAError as e:
        return {"ok": False, "error": e.message}
    except Exception as e:
        logger.exception("triton_snapshot_save failed")
        return {"ok": False, "error": str(e)}


@tool
@idasync
def triton_snapshot_restore(
    snapshot_id: Annotated[int, "Snapshot ID returned by triton_snapshot_save."],
    replay_trace: Annotated[
        bool,
        "Replay the stored instruction trace to rebuild path predicate "
        "(default True). Set False to skip replay and only restore register/symbol/taint state.",
    ] = True,
) -> dict:
    """Restore Triton context to a previously saved snapshot.

    Re-creates the context with the same architecture, re-symbolizes the same
    registers/memory, restores taint state, and replays the stored instruction
    trace to rebuild the path predicate. All symbolic expressions generated
    after the snapshot are discarded.
    """
    if not TRITON_AVAILABLE:
        return {"ok": False, "error": "triton-library not installed"}
    try:
        with _snapshots_lock:
            snap = _snapshots.get(snapshot_id)
        if snap is None:
            return {"ok": False, "error": f"Snapshot {snapshot_id} not found"}

        new_ctx = _build_ctx(snap["arch"])

        for reg_id, (reg_name, val) in snap["registers"].items():
            try:
                reg = new_ctx.getRegister(reg_name)
                new_ctx.setConcreteRegisterValue(reg, val)
            except Exception:
                pass

        for sv_info in snap["sym_vars"]:
            try:
                if sv_info["type_is_register"]:
                    reg = new_ctx.getRegister(sv_info["origin"])
                    new_ctx.symbolizeRegister(reg, sv_info["alias"])
                else:
                    mem = TritonMemoryAccess(sv_info["origin"], sv_info["bitsize"] // 8)
                    new_ctx.symbolizeMemory(mem, sv_info["alias"])
            except Exception:
                pass

        for reg_id in snap["tainted_reg_ids"]:
            try:
                new_ctx.taintRegister(new_ctx.getRegister(reg_id))
            except Exception:
                pass
        for addr in snap["tainted_mem_addrs"]:
            new_ctx.taintMemory(addr)

        # Replay stored instruction trace to rebuild path predicate naturally.
        # Because concrete register values and symbolic variables were restored
        # above before replay, re-executing the same instructions in the same
        # order produces the identical path constraints.
        replay_count = 0
        trace_ea_list = snap.get("instruction_trace", [])
        if replay_trace and trace_ea_list:
            try:
                import idaapi
                import idc
                _clear_trace()
                trace_deque = _get_trace()
                for ea in trace_ea_list:
                    insn_ida = idaapi.insn_t()
                    length = idaapi.decode_insn(insn_ida, ea)
                    if length == 0:
                        continue
                    raw = idc.get_bytes(ea, length)
                    if not raw:
                        continue
                    new_ctx.setConcreteMemoryAreaValue(ea, raw)
                    insn = TritonInstruction()
                    insn.setAddress(ea)
                    insn.setOpcode(raw)
                    new_ctx.processing(insn)
                    trace_deque.append(ea)
                    replay_count += 1
            except Exception:
                pass

        _set_ctx(_CTX_KEY, new_ctx)
        return {
            "ok": True,
            "snapshot_id": snapshot_id,
            "label": snap["label"],
            "sym_var_count": len(snap["sym_vars"]),
            "replay_count": replay_count,
            "trace_length": len(trace_ea_list),
        }

    except Exception as e:
        logger.exception("triton_snapshot_restore failed")
        return {"ok": False, "error": str(e)}


@tool
@idasync
@tool_timeout(60.0)
def triton_replay_instructions(
    addresses: Annotated[
        list[str],
        "List of instruction addresses (hex or symbol names) to replay in order. "
        "Each instruction is processed through the current Triton context, accumulating "
        "path constraints. Useful for rebuilding a path predicate after snapshot restore "
        "or for manually reconstructing constraint state.",
    ],
) -> dict:
    """Replay a list of instruction addresses through the current Triton context.

    Fetches bytes from IDA for each address and processes them through Triton,
    naturally accumulating path constraints in the same way as processing instructions
    individually. The current context must already be initialised (call triton_init first).

    This is a standalone tool for AI agents who want to:
    - Rebuild path constraints after triton_snapshot_restore (trace is stored in snapshot)
    - Replay a custom instruction sequence against the current context
    - Manually reconstruct symbolic state from a known instruction trace
    """
    if not TRITON_AVAILABLE:
        return {"ok": False, "error": "triton-library not installed"}
    try:
        ctx = _get_ctx()
        from .utils import parse_address

        trace_deque = _get_trace()
        processed = []
        pc_before = len(ctx.getPathConstraints())

        for addr_str in addresses:
            ea = parse_address(addr_str)
            import idaapi
            import idc

            insn_ida = idaapi.insn_t()
            length = idaapi.decode_insn(insn_ida, ea)
            if length == 0:
                continue
            raw = idc.get_bytes(ea, length)
            if not raw:
                continue

            ctx.setConcreteMemoryAreaValue(ea, raw)
            insn = TritonInstruction()
            insn.setAddress(ea)
            insn.setOpcode(raw)
            ctx.processing(insn)
            trace_deque.append(ea)

            processed.append({
                "address": hex(ea),
                "size": length,
                "is_branch": insn.isBranch(),
            })

        pc_after = len(ctx.getPathConstraints())
        return {
            "ok": True,
            "instructions_replayed": len(processed),
            "path_constraints_added": pc_after - pc_before,
            "processed": processed,
        }
    except IDAError as e:
        return {"ok": False, "error": e.message}
    except Exception as e:
        logger.exception("triton_replay_instructions failed")
        return {"ok": False, "error": str(e)}


@tool
@idasync
def triton_snapshot_list() -> dict:
    """List all saved snapshots with their IDs, labels, and state summaries."""
    if not TRITON_AVAILABLE:
        return {"ok": False, "error": "triton-library not installed"}
    with _snapshots_lock:
        snaps = list(_snapshots.values())

    items = [
        {
            "id": s["id"],
            "label": s["label"],
            "timestamp": s["timestamp"],
            "architecture": _arch_to_str(s["arch"]) if TRITON_AVAILABLE else "unknown",
            "sym_var_count": len(s["sym_vars"]),
        }
        for s in snaps
    ]
    return {"ok": True, "count": len(items), "snapshots": items}


@tool
@idasync
def triton_snapshot_delete(
    snapshot_id: Annotated[int, "Snapshot ID to delete."],
) -> dict:
    """Delete a saved snapshot to free memory."""
    if not TRITON_AVAILABLE:
        return {"ok": False, "error": "triton-library not installed"}
    with _snapshots_lock:
        if snapshot_id not in _snapshots:
            return {"ok": False, "error": f"Snapshot {snapshot_id} not found"}
        del _snapshots[snapshot_id]
    return {"ok": True, "snapshot_id": snapshot_id}


# ============================================================================
# Compound workflow tools (function-level)
# ============================================================================


def _setup_windows_x64_internal(ctx: "TritonContext") -> None:
    """Apply minimal Windows x64 ABI setup to an existing context (no return value).

    Sets GS base → fake TEB, writes TEB+PEB structs with safe anti-debug values,
    allocates stack memory. Called internally by compound tools when
    setup_windows_abi=True. For full parameter control use triton_setup_windows_x64.
    """
    import struct
    teb = 0x7ffa0000
    peb = 0x7ff90000
    heap_addr = peb + 0x1000
    stack = 0x7fffffffe000

    try:
        gs_reg = ctx.getRegister("gs_base")
        ctx.setConcreteRegisterValue(gs_reg, teb)
    except Exception:
        try:
            ctx.setConcreteRegisterValue(ctx.getRegister("gs"), teb)
        except Exception:
            pass

    teb_data = bytearray(0x200)
    struct.pack_into("<Q", teb_data, 0x000, stack)
    struct.pack_into("<Q", teb_data, 0x008, stack - 0x100000)
    struct.pack_into("<Q", teb_data, 0x030, peb)
    struct.pack_into("<Q", teb_data, 0x060, peb)
    ctx.setConcreteMemoryAreaValue(teb, bytes(teb_data))

    heap_data = bytearray(0x40)
    struct.pack_into("<I", heap_data, 0x14, 2)   # Heap.Flags = HEAP_GROWABLE
    struct.pack_into("<I", heap_data, 0x18, 0)   # Heap.ForceFlags = 0
    ctx.setConcreteMemoryAreaValue(heap_addr, bytes(heap_data))

    peb_data = bytearray(0x200)
    peb_data[0x002] = 0  # BeingDebugged = 0
    struct.pack_into("<I", peb_data, 0x068, 0)   # NtGlobalFlag = 0
    struct.pack_into("<Q", peb_data, 0x030, heap_addr)
    ctx.setConcreteMemoryAreaValue(peb, bytes(peb_data))

    ctx.setConcreteMemoryAreaValue(stack - 0x10000, b"\x00" * 0x10000)
    ctx.setConcreteRegisterValue(ctx.getRegister("rsp"), stack - 8)
    ctx.setConcreteRegisterValue(ctx.getRegister("rbp"), stack)


def _symbolize_registers_internal(ctx: "TritonContext", names: list[str]) -> list[dict]:
    """Helper: symbolize a list of register names. Returns per-register results."""
    out: list[dict] = []
    for raw in names:
        name = raw.strip()
        if not name:
            continue
        try:
            reg = ctx.getRegister(name.lower())
            sv = ctx.symbolizeRegister(reg, name)
            out.append({
                "ok": True,
                "register": name,
                "sym_var_id": sv.getId(),
                "sym_var_name": sv.getName(),
                "alias": sv.getAlias(),
                "bitsize": sv.getBitSize(),
            })
        except Exception as e:
            out.append({"ok": False, "register": name, "error": str(e)})
    return out

def _is_call_insn(insn: "TritonInstruction") -> bool:
    """Return True if the Triton instruction is a CALL (opcode group)."""
    try:
        from triton import OPCODE
        t = insn.getType()
        # x86/x64 CALL opcodes
        call_types = {OPCODE.X86.CALL, OPCODE.X86.LCALL}
        return t in call_types
    except Exception:
        # Fallback: check disassembly prefix
        try:
            return insn.getDisassembly().startswith("call ")
        except Exception:
            return False


def _process_function_instructions_linear(
    ctx: "TritonContext",
    func_start: int,
    func_end: int,
    max_insns: int,
) -> tuple[list[dict], bool, list[dict]]:
    """Linearly process every instruction in [func_start, func_end).

    Returns (processed_records, truncated_flag, call_sites).
    call_sites is a list of dicts for each CALL instruction detected, with
    the source address, disassembly, and resolved target if available.
    Bytes are preloaded once.
    """
    import idaapi
    import idc
    import ida_lines

    raw_func = idc.get_bytes(func_start, func_end - func_start)
    if raw_func:
        ctx.setConcreteMemoryAreaValue(func_start, raw_func)

    processed: list[dict] = []
    call_sites: list[dict] = []
    curr = func_start
    count = 0

    while curr < func_end and count < max_insns:
        insn_ida = idaapi.insn_t()
        length = idaapi.decode_insn(insn_ida, curr)
        if length == 0:
            break

        raw = idc.get_bytes(curr, length)
        if not raw:
            curr += 1
            continue

        insn = TritonInstruction()
        insn.setAddress(curr)
        insn.setOpcode(raw)
        ctx.processing(insn)
        _get_trace().append(curr)

        disasm_raw = ida_lines.generate_disasm_line(curr, 0)
        disasm = ida_lines.tag_remove(disasm_raw) if disasm_raw else ""
        is_call = _is_call_insn(insn)

        if is_call:
            # Try to resolve the call target from the post-processing RIP
            try:
                rip_val = ctx.getConcreteRegisterValue(ctx.registers.rip)
                target_outside = not (func_start <= rip_val < func_end)
                import ida_funcs
                target_name = ida_funcs.get_func_name(rip_val) or ""
            except Exception:
                rip_val = 0
                target_outside = True
                target_name = ""

            call_sites.append({
                "src": hex(curr),
                "disasm": disasm,
                "target": hex(rip_val) if rip_val else "?",
                "target_name": target_name,
                "is_external": target_outside,
            })

        processed.append({
            "address": hex(curr),
            "disasm": disasm,
            "size": length,
            "is_branch": insn.isBranch(),
            "is_call": is_call,
            "is_symbolised": insn.isSymbolized(),
            "is_tainted": insn.isTainted(),
        })

        curr += length
        count += 1

    truncated = count >= max_insns and curr < func_end
    return processed, truncated, call_sites


def _process_function_instructions_fast(
    ctx: "TritonContext",
    func_start: int,
    func_end: int,
    max_insns: int,
) -> tuple[int, bool]:
    """Lightweight linear instruction processing without metadata collection.

    Returns (instruction_count, truncated_flag). Bytes are preloaded once.
    Used when only the Triton side-effects (path constraints, taint) are needed.
    """
    import idaapi
    import idc

    raw_func = idc.get_bytes(func_start, func_end - func_start)
    if raw_func:
        ctx.setConcreteMemoryAreaValue(func_start, raw_func)

    curr = func_start
    count = 0

    while curr < func_end and count < max_insns:
        insn_ida = idaapi.insn_t()
        length = idaapi.decode_insn(insn_ida, curr)
        if length == 0:
            break

        raw = idc.get_bytes(curr, length)
        if not raw:
            curr += 1
            continue

        insn = TritonInstruction()
        insn.setAddress(curr)
        insn.setOpcode(raw)
        ctx.processing(insn)
        _get_trace().append(curr)

        curr += length
        count += 1

    truncated = count >= max_insns and curr < func_end
    return count, truncated

def _has_symbolic_in_ast(ast_str: str) -> bool:
    """Heuristic check: does an AST string reference any symbolic variable."""
    return "SymVar_" in ast_str or "ref!" in ast_str


def _constraint_diagnostics(ctx: "TritonContext") -> dict:
    """Inspect path constraints and explain why the solver may have failed.

    Returns a dict with constraint counts, concrete vs symbolic breakdown,
    and a human-readable hint for the most likely cause.
    """
    pcs = ctx.getPathConstraints()
    sym_vars = ctx.getSymbolicVariables()

    if not pcs:
        if sym_vars:
            hint = (
                "PC_TRACKING_SYMBOLIC mode is active and no branch conditions "
                "involved your symbolic variables. Branches on concrete memory "
                "(e.g. Windows PEB via gs:60h, stack canary, global flags) produce "
                "no path constraints even when registers like rdi/rbx are symbolic. "
                "Solutions: (1) call triton_setup_windows_x64 to model GS/PEB "
                "concretely before execution, (2) symbolize the memory that "
                "the branch actually reads, or (3) re-init with pc_tracking_symbolic=false "
                "to track all branches regardless."
            )
        else:
            hint = (
                "No symbolic variables and no path constraints. "
                "Symbolize at least one register or memory range before processing instructions."
            )
        return {
            "path_constraint_count": 0,
            "symbolic_var_count": len(sym_vars),
            "constraints_with_symbolic": 0,
            "constraints_all_concrete": 0,
            "hint": hint,
        }

    constraints_sym = 0
    constraints_concrete = 0
    concrete_always_false = 0

    for pc in pcs:
        for br in pc.getBranchConstraints():
            if not br["isTaken"]:
                continue
            ast_str = str(br["constraint"])
            if _has_symbolic_in_ast(ast_str):
                constraints_sym += 1
            else:
                constraints_concrete += 1
                # A concrete constraint can be literally False if the taken
                # branch condition evaluates to False in the concrete state.
                if "False" in ast_str or ast_str.strip() == "(= (bv 0 1) (bv 1 1))":
                    concrete_always_false += 1

    if constraints_sym == 0 and constraints_concrete > 0:
        hint = (
            f"All {constraints_concrete} path constraint(s) are fully concrete — "
            "they involve no symbolic variables. Z3 correctly returns UNSAT when a "
            "concrete constraint is False (e.g. a branch condition that was not taken "
            "due to a PEB flag being 0). The symbolic variables you created (rdi, rbx, etc.) "
            "do not flow into these branches. "
            "Fix: model the memory that the branch reads from concretely "
            "(call triton_setup_windows_x64 for PEB/TEB), or symbolize that memory instead."
        )
    elif constraints_sym > 0:
        hint = (
            f"{constraints_sym} symbolic + {constraints_concrete} concrete constraint(s). "
            "The constraint set may be over-constrained. Check triton_get_path_constraints "
            "for conflicting conditions, or increase the solver timeout."
        )
    else:
        hint = "Unexpected constraint state — no taken-branch constraints found."

    return {
        "path_constraint_count": len(pcs),
        "symbolic_var_count": len(sym_vars),
        "constraints_with_symbolic": constraints_sym,
        "constraints_all_concrete": constraints_concrete,
        "concrete_always_false_count": concrete_always_false,
        "hint": hint,
    }


def _try_solve_predicate(ctx: "TritonContext", timeout_ms: int) -> dict:
    """Attempt Z3 solve of the current path predicate.

    Returns a structured dict — never raises. When UNSAT or empty, includes
    diagnostic information explaining the likely cause.
    Injected constraints (from triton_inject_comparison_constraint) are ANDed
    into the predicate automatically.
    """
    try:
        pcs = ctx.getPathConstraints()
        sym_vars = ctx.getSymbolicVariables()
        predicate = ctx.getPathPredicate()

        # AND in any manually injected constraints (e.g. memcmp equality)
        injected = _get_injected()
        if injected:
            ast_ctx = ctx.getAstContext()
            predicate = ast_ctx.land([predicate] + injected)

        model = ctx.getModel(predicate, timeout=timeout_ms)

        if model:
            result: dict[str, str] = {}
            for _, sm in model.items():
                sv = sm.getVariable()
                alias = sv.getAlias() or sv.getName()
                result[alias] = hex(sm.getValue())
            return {"sat": True, "model": result, "solver_used": "z3"}

        # model == {} — could be UNSAT or trivially SAT (no vars to constrain).
        # Distinguish these cases for better diagnostics.
        diag = _constraint_diagnostics(ctx)

        if not pcs:
            # No path constraints at all — trivially satisfied, but no useful model
            return {
                "sat": False,
                "model": {},
                "solver_used": "z3",
                "reason": "no_path_constraints",
                "diagnostics": diag,
            }

        if diag.get("constraints_with_symbolic", 0) == 0:
            # All constraints are concrete — UNSAT because a concrete branch
            # condition is False, or SAT but with nothing to solve for
            return {
                "sat": False,
                "model": {},
                "solver_used": "z3",
                "reason": "concrete_constraints_only",
                "diagnostics": diag,
            }

        # Has symbolic constraints but still UNSAT → genuinely over-constrained
        return {
            "sat": False,
            "model": {},
            "solver_used": "z3",
            "reason": "unsat",
            "diagnostics": diag,
        }

    except Exception as e:
        logger.exception("_try_solve_predicate failed")
        return {"sat": False, "model": {}, "error": str(e)}

@tool
@idasync
@tool_timeout(90.0)
def triton_analyze_function(
    address: Annotated[str, "Function start address (hex or symbol name)."],
    symbolize_args: Annotated[
        str | list[str],
        "Registers to mark symbolic before execution — typical argument "
        "registers for the binary's ABI (e.g. 'rdi,rsi,rdx' for x86-64 SysV, "
        "'rcx,rdx,r8,r9' for Windows x64, 'r0,r1,r2,r3' for AArch32). "
        "Accepts a JSON array or comma-separated string. Pass empty string "
        "to skip symbolization.",
    ] = "",
    max_insns: Annotated[int, "Safety cap on instruction count (default 500)."] = 500,
    reinit: Annotated[
        bool,
        "When true, re-initialize the Triton context before analysis (fresh slate).",
    ] = True,
    timeout_ms: Annotated[int, "Z3 solver timeout in ms (0 = no limit)."] = 10000,
    setup_windows_abi: Annotated[
        bool,
        "When true, automatically call triton_setup_windows_x64 before symbolization. "
        "This models the GS segment base, fake TEB/PEB (BeingDebugged=0, NtGlobalFlag=0), "
        "stack pointer, and heap fields. Essential for Windows x64 binaries that access "
        "gs:[0x60] (PEB) — without this, anti-debug checks produce concrete-false "
        "constraints and the solver returns UNSAT. Default False.",
    ] = False,
    pc_tracking_symbolic: Annotated[
        bool | None,
        "When true, path constraints are only collected for branches whose condition "
        "involves at least one symbolic variable. When false or None (default), ALL "
        "branches are tracked — this ensures concrete branches (anti-debug PEB checks, "
        "length guards, sanity checks) appear in the path predicate and the solver can "
        "reason about them. Set true only when excluding concrete-only branches is "
        "intentional (high-noise functions with many unrelated concrete checks).",
    ] = None,
) -> dict:
    """One-shot symbolic execution analysis of a whole function.

    Runs the full pipeline in a single call:
      1. (re-)initialize the Triton context, auto-detecting architecture from IDA
      2. (optionally) set up Windows x64 ABI environment (GS/PEB/TEB/stack)
      3. mark the listed argument registers as symbolic
      4. linearly process every instruction inside the function (capped by max_insns)
      5. ask Z3 to find a concrete input satisfying the accumulated path predicate
      6. return symbolic variables, path constraints, taint state, solver model, and diagnostics

    When solver returns sat=false, check the ``solver.diagnostics`` field for an
    explanation. Common causes for Windows binaries:
    - Zero path constraints: branches on gs:[0x60] (PEB) aren't symbolized →
      use setup_windows_abi=true and symbolize_args='rcx,rdx,r8,r9'
    - Concrete constraints only: your symbolic registers don't flow into branches

    This is a convenience tool — for fine-grained control use triton_init,
    triton_symbolize_register, triton_process_function, and triton_solve_path_constraints
    individually.
    """
    if not TRITON_AVAILABLE:
        return {"ok": False, "error": "triton-library not installed. Run: ida-pro-mcp --install-deps triton"}
    import idaapi
    import ida_funcs

    try:
        from .utils import parse_address
        ea = parse_address(address)

        func = ida_funcs.get_func(ea)
        if func is None:
            return {"ok": False, "address": address, "error": f"No function at {hex(ea)}"}

        # Step 1: (re-)init context, auto-detecting architecture
        # Resolve pc_tracking_symbolic: None → False (track all branches by default).
        # When setup_windows_abi=True this is especially important so that concrete
        # PEB checks appear in the path predicate.
        pc_tracking = pc_tracking_symbolic if pc_tracking_symbolic is not None else False
        if reinit or _contexts.get(_CTX_KEY) is None:
            arch = _detect_arch_from_ida()
            ctx = _build_ctx(arch, pc_tracking_symbolic=pc_tracking)
            _set_ctx(_CTX_KEY, ctx)
        else:
            ctx = _get_ctx()

        # Step 2: Windows ABI setup (before symbolization — must happen first)
        windows_abi_applied = False
        if setup_windows_abi and ctx.getArchitecture() == ARCH.X86_64:
            try:
                _setup_windows_x64_internal(ctx)
                windows_abi_applied = True
            except Exception as e:
                logger.warning("triton_analyze_function: Windows ABI setup failed: %s", e)

        # Step 3: parse and symbolize argument registers
        if isinstance(symbolize_args, str):
            reg_list = [r.strip() for r in symbolize_args.split(",") if r.strip()]
        else:
            reg_list = [str(r).strip() for r in symbolize_args if str(r).strip()]

        symbolized = _symbolize_registers_internal(ctx, reg_list) if reg_list else []

        # Step 4: linearly process the function
        sym_start = len(ctx.getSymbolicExpressions())
        pc_start = len(ctx.getPathConstraints())
        tainted_reg_start = len(ctx.getTaintedRegisters())
        tainted_mem_start = len(ctx.getTaintedMemory())

        processed, truncated, call_sites = _process_function_instructions_linear(
            ctx, func.start_ea, func.end_ea, max_insns
        )

        sym_end = len(ctx.getSymbolicExpressions())
        pc_end = len(ctx.getPathConstraints())
        new_pcs = pc_end - pc_start

        # Step 5: capture state summaries
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
        branches_with_symbolic = 0
        try:
            for pc in ctx.getPathConstraints():
                branches_info = []
                for br in pc.getBranchConstraints():
                    ast_str = str(br["constraint"])
                    has_sym = _has_symbolic_in_ast(ast_str)
                    if has_sym:
                        branches_with_symbolic += 1
                    branches_info.append({
                        "is_taken": br["isTaken"],
                        "src": hex(br["srcAddr"]),
                        "dst": hex(br["dstAddr"]),
                        "has_symbolic": has_sym,
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

        # Step 6: solve
        solve_result = _try_solve_predicate(ctx, timeout_ms)

        # Warn when symbolic vars exist but 0 constraints collected (common trap)
        warnings = []
        if new_pcs == 0 and sym_vars_info:
            warnings.append(
                f"Zero path constraints despite {len(sym_vars_info)} symbolic variable(s). "
                "PC_TRACKING_SYMBOLIC mode is filtering out branches on concrete memory. "
                "If this function reads from gs:[0x60] (PEB), retry with setup_windows_abi=true. "
                "If symbolic vars don't flow into branch conditions, symbolize different registers or memory."
            )
        elif new_pcs > 0 and branches_with_symbolic == 0:
            warnings.append(
                f"{new_pcs} path constraint(s) collected but none reference symbolic variables. "
                "Branches are on concrete data — symbolic inputs don't affect the path taken. "
                "The solver will return UNSAT or an empty model (no useful assignments)."
            )

        return {
            "ok": True,
            "function_ea": hex(func.start_ea),
            "function_end": hex(func.end_ea),
            "function_name": ida_funcs.get_func_name(func.start_ea) or "",
            "architecture": _arch_to_str(ctx.getArchitecture()),
            "reinitialised": reinit,
            "windows_abi_applied": windows_abi_applied,
            "pc_tracking_symbolic": pc_tracking,
            "symbolized_args": symbolized,
            "instructions_processed": len(processed),
            "instructions_truncated": truncated,
            "new_symbolic_expressions": sym_end - sym_start,
            "new_path_constraints": new_pcs,
            "path_constraints_with_symbolic": branches_with_symbolic,
            "symbolic_variables": sym_vars_info,
            "path_constraints": pc_records,
            "tainted_outputs": tainted_outputs,
            "tainted_register_delta": len(ctx.getTaintedRegisters()) - tainted_reg_start,
            "tainted_memory_delta": len(ctx.getTaintedMemory()) - tainted_mem_start,
            "solver": solve_result,
            "warnings": warnings,
            "call_sites": call_sites,
            "instructions": processed,
        }

    except IDAError as e:
        return {"ok": False, "address": address, "error": e.message}
    except Exception as e:
        logger.exception("triton_analyze_function failed at %s", address)
        return {"ok": False, "address": address, "error": str(e)}

def _build_block_path_to_target(
    flowchart, target_ea: int, max_path_len: int = 256
) -> tuple[list, int | None]:
    """BFS over IDA basic blocks from the function entry to the block containing target_ea.

    Returns (path_of_blocks, target_block_id) or ([], None) if unreachable.
    The path is a list of basic-block objects, ordered entry → … → target.
    """
    from collections import deque

    blocks_by_id = {bb.id: bb for bb in flowchart}
    if not blocks_by_id:
        return [], None

    # Find target block
    target_id = None
    for bb_id, bb in blocks_by_id.items():
        if bb.start_ea <= target_ea < bb.end_ea:
            target_id = bb_id
            break
    if target_id is None:
        return [], None

    # Entry is conventionally the block at id 0, but verify with start_ea match
    entry = blocks_by_id.get(0)
    if entry is None:
        # Fallback: lowest id, lowest start_ea
        entry = min(blocks_by_id.values(), key=lambda b: (b.start_ea, b.id))

    # BFS with parent tracking
    parents: dict[int, int | None] = {entry.id: None}
    queue = deque([entry.id])
    found = False
    while queue:
        cur_id = queue.popleft()
        if cur_id == target_id:
            found = True
            break
        cur_bb = blocks_by_id[cur_id]
        for succ in cur_bb.succs():
            if succ.id not in parents:
                parents[succ.id] = cur_id
                queue.append(succ.id)

    if not found:
        return [], target_id

    # Reconstruct path
    path_ids: list[int] = []
    cur: int | None = target_id
    while cur is not None and len(path_ids) < max_path_len:
        path_ids.append(cur)
        cur = parents.get(cur)
    path_ids.reverse()
    return [blocks_by_id[i] for i in path_ids], target_id

@tool
@idasync
@tool_timeout(90.0)
def triton_find_input_for_branch(
    function_address: Annotated[str, "Function start address (hex or symbol)."],
    target_address: Annotated[
        str,
        "Address of the instruction (or block) we want execution to reach.",
    ],
    symbolize_args: Annotated[
        str | list[str],
        "Registers to mark symbolic — usually the function's ABI argument "
        "registers. Accepts JSON array or comma-separated string.",
    ] = "",
    max_insns: Annotated[
        int, "Per-instruction cap inside the CFG path (default 500)."
    ] = 500,
    reinit: Annotated[
        bool,
        "Re-initialize the Triton context before exploration (default true).",
    ] = True,
    timeout_ms: Annotated[int, "Z3 solver timeout in ms (default 10000)."] = 10000,
    setup_windows_abi: Annotated[
        bool,
        "When true, model the Windows x64 GS segment (TEB/PEB), stack, and heap "
        "before symbolization. Prevents anti-debug checks via gs:[0x60] from "
        "producing concrete-false constraints that make the solver return UNSAT.",
    ] = False,
    pc_tracking_symbolic: Annotated[
        bool | None,
        "When true, track path constraints only for branches involving symbolic variables. "
        "When false or None (default), ALL branches are tracked — ensures concrete branches "
        "(PEB anti-debug, length checks) appear in the path predicate. Set true only to "
        "exclude concrete-only branches intentionally.",
    ] = None,
) -> dict:
    """CFG-guided branch reachability: find concrete inputs that reach a target address.

    Algorithm:
      1. Init Triton + optionally set up Windows ABI + symbolize listed argument registers.
      2. Use IDA's basic-block CFG to BFS the shortest sequence of blocks
         from the function entry to the block containing target_address.
      3. Execute Triton symbolically over **only those blocks**, in order
         (side branches and dead paths are not visited).
      4. Ask Z3 for an input satisfying the accumulated path predicate —
         that is, an input that makes the program take exactly that path.

    Returns the chosen block path, the per-instruction trace, accumulated
    path constraints, a Z3 model, and diagnostics explaining any UNSAT result.

    **For Windows x64 crackmes**: always pass setup_windows_abi=true and set
    symbolize_args to the Windows ABI registers ('rcx,rdx,r8,r9'). Without
    setup_windows_abi, gs:[0x60] accesses resolve to address 0x60 (unmapped)
    and any anti-debug check produces a concrete-false constraint → UNSAT.
    """
    if not TRITON_AVAILABLE:
        return {"ok": False, "error": "triton-library not installed. Run: ida-pro-mcp --install-deps triton"}
    import idaapi
    import ida_funcs
    import ida_gdl
    import idc
    import ida_lines

    try:
        from .utils import parse_address
        func_ea = parse_address(function_address)
        target_ea = parse_address(target_address)

        func = ida_funcs.get_func(func_ea)
        if func is None:
            return {"ok": False, "error": f"No function at {hex(func_ea)}"}
        if not (func.start_ea <= target_ea < func.end_ea):
            return {
                "ok": False,
                "error": f"target_address {hex(target_ea)} is outside function "
                         f"{hex(func.start_ea)}-{hex(func.end_ea)}",
            }

        flowchart = ida_gdl.FlowChart(func)
        block_path, target_block_id = _build_block_path_to_target(flowchart, target_ea)
        if not block_path:
            return {
                "ok": False,
                "error": (
                    f"No reachable path from entry to {hex(target_ea)} "
                    f"(target_block_id={target_block_id})"
                ),
            }

        # Resolve pc_tracking_symbolic: None → False (track all branches by default)
        pc_tracking = pc_tracking_symbolic if pc_tracking_symbolic is not None else False

        # Init / reset context
        if reinit or _contexts.get(_CTX_KEY) is None:
            arch = _detect_arch_from_ida()
            ctx = _build_ctx(arch, pc_tracking_symbolic=pc_tracking)
            _set_ctx(_CTX_KEY, ctx)
        else:
            ctx = _get_ctx()

        # Windows ABI setup (before symbolization)
        windows_abi_applied = False
        if setup_windows_abi and ctx.getArchitecture() == ARCH.X86_64:
            try:
                _setup_windows_x64_internal(ctx)
                windows_abi_applied = True
            except Exception as e:
                logger.warning("triton_find_input_for_branch: Windows ABI setup failed: %s", e)

        # Symbolize the listed registers
        if isinstance(symbolize_args, str):
            reg_list = [r.strip() for r in symbolize_args.split(",") if r.strip()]
        else:
            reg_list = [str(r).strip() for r in symbolize_args if str(r).strip()]
        symbolized = _symbolize_registers_internal(ctx, reg_list) if reg_list else []

        # Preload the whole function's bytes once
        raw_func = idc.get_bytes(func.start_ea, func.end_ea - func.start_ea)
        if raw_func:
            ctx.setConcreteMemoryAreaValue(func.start_ea, raw_func)

        # Walk each block in the chosen path, instruction-by-instruction
        pc_before = len(ctx.getPathConstraints())
        trace: list[dict] = []
        insn_count = 0
        stop_after_target = False

        for bb in block_path:
            if insn_count >= max_insns:
                break

            # If this is the target block, stop AT the target instruction (inclusive)
            bb_end = bb.end_ea
            if bb.id == target_block_id:
                bb_end = min(bb.end_ea, target_ea + 1)
                stop_after_target = True

            curr = bb.start_ea
            while curr < bb_end and insn_count < max_insns:
                insn_ida = idaapi.insn_t()
                length = idaapi.decode_insn(insn_ida, curr)
                if length == 0:
                    break

                raw = idc.get_bytes(curr, length)
                if not raw:
                    curr += 1
                    continue

                insn = TritonInstruction()
                insn.setAddress(curr)
                insn.setOpcode(raw)
                ctx.processing(insn)
                _get_trace().append(curr)

                disasm_raw = ida_lines.generate_disasm_line(curr, 0)
                disasm = ida_lines.tag_remove(disasm_raw) if disasm_raw else ""

                trace.append({
                    "address": hex(curr),
                    "block_id": bb.id,
                    "disasm": disasm,
                    "size": length,
                    "is_branch": insn.isBranch(),
                    "is_symbolised": insn.isSymbolized(),
                })

                if stop_after_target and curr <= target_ea < curr + length:
                    insn_count += 1
                    curr += length
                    break

                curr += length
                insn_count += 1

            if stop_after_target:
                break

        pc_after = len(ctx.getPathConstraints())
        new_pcs = pc_after - pc_before

        # Collect the path constraints we accumulated
        pc_records = []
        branches_with_symbolic = 0
        try:
            for pc in ctx.getPathConstraints():
                branches_info = []
                for br in pc.getBranchConstraints():
                    ast_str = str(br["constraint"])
                    has_sym = _has_symbolic_in_ast(ast_str)
                    if has_sym:
                        branches_with_symbolic += 1
                    branches_info.append({
                        "is_taken": br["isTaken"],
                        "src": hex(br["srcAddr"]),
                        "dst": hex(br["dstAddr"]),
                        "has_symbolic": has_sym,
                    })
                pc_records.append({
                    "multiple_branches": pc.isMultipleBranches(),
                    "branches": branches_info,
                })
        except Exception:
            pass

        # Solve
        solve_result = _try_solve_predicate(ctx, timeout_ms)
        reached = any(int(t["address"], 16) == target_ea for t in trace)

        warnings = []
        if new_pcs == 0 and symbolized:
            warnings.append(
                f"Zero path constraints despite {len(symbolized)} symbolized register(s). "
                "Branches along this CFG path don't involve your symbolic registers. "
                "If Windows anti-debug checks (gs:[0x60]) are on this path, retry with "
                "setup_windows_abi=true to model PEB concretely."
            )
        elif new_pcs > 0 and branches_with_symbolic == 0:
            warnings.append(
                f"{new_pcs} constraint(s) collected but none involve symbolic variables. "
                "The path predicate is concrete — solver cannot produce useful input assignments."
            )

        return {
            "ok": True,
            "function_ea": hex(func.start_ea),
            "target_ea": hex(target_ea),
            "target_reached_in_trace": reached,
            "block_path": [
                {"id": bb.id, "start_ea": hex(bb.start_ea), "end_ea": hex(bb.end_ea)}
                for bb in block_path
            ],
            "windows_abi_applied": windows_abi_applied,
            "pc_tracking_symbolic": pc_tracking,
            "symbolized_args": symbolized,
            "instructions_executed": len(trace),
            "instructions_truncated": insn_count >= max_insns,
            "path_constraints_collected": new_pcs,
            "path_constraints_with_symbolic": branches_with_symbolic,
            "path_constraints": pc_records,
            "solver": solve_result,
            "warnings": warnings,
            "trace": trace,
        }

    except IDAError as e:
        return {"ok": False, "error": e.message}
    except Exception as e:
        logger.exception("triton_find_input_for_branch failed")
        return {"ok": False, "error": str(e)}

# ============================================================================
# IDA annotation tools
# ============================================================================

@tool
@idasync
@tool_timeout(60.0)
def triton_annotate_function(
    address: Annotated[str, "Function address (hex or symbol name)."],
    symbolize_args: Annotated[
        str | list[str],
        "Registers to symbolize before execution (comma-separated or JSON array). "
        "Pass empty string to skip symbolization.",
    ] = "",
    max_insns: Annotated[int, "Safety cap on instruction count (default 500)."] = 500,
    overwrite: Annotated[bool, "Overwrite existing comments at branch points."] = False,
) -> dict:
    """Run symbolic execution on a function and write IDA comments at branch points.

    Each comment contains the path condition (constraint) that determines
    which branch is taken. This makes the symbolic analysis results visible
    directly in the IDA disassembly view.
    """
    if not TRITON_AVAILABLE:
        return {"ok": False, "error": "triton-library not installed. Run: ida-pro-mcp --install-deps triton"}
    import ida_funcs
    import idc
    import idaapi
    import ida_lines

    try:
        from .utils import parse_address
        ea = parse_address(address)
        func = ida_funcs.get_func(ea)
        if func is None:
            return {"ok": False, "error": f"No function at {hex(ea)}"}

        # Re-use the compound analysis logic but keep it internal
        if _contexts.get(_CTX_KEY) is None:
            arch = _detect_arch_from_ida()
            ctx = _build_ctx(arch)
            _set_ctx(_CTX_KEY, ctx)
        else:
            ctx = _get_ctx()

        # Parse and symbolize argument registers
        if isinstance(symbolize_args, str):
            reg_list = [r.strip() for r in symbolize_args.split(",") if r.strip()]
        else:
            reg_list = [str(r).strip() for r in symbolize_args if str(r).strip()]

        if reg_list:
            _symbolize_registers_internal(ctx, reg_list)

        # Linearly process the function — only need side-effects (path constraints),
        # not the full per-instruction metadata list.
        _process_function_instructions_fast(
            ctx, func.start_ea, func.end_ea, max_insns
        )

        # Get path constraints with readable AST strings
        pcs = ctx.getPathConstraints()
        annotations = 0
        annotated_addrs: set[int] = set()

        for pc in pcs:
            for br in pc.getBranchConstraints():
                if not br["isTaken"]:
                    continue
                src_ea = br["srcAddr"]
                if src_ea in annotated_addrs and not overwrite:
                    continue
                cond_str = str(br["constraint"])
                # Truncate very long constraints
                if len(cond_str) > 240:
                    cond_str = cond_str[:237] + "..."
                new_comment = f"[Triton] {cond_str}"
                try:
                    existing = idc.get_cmt(src_ea, 0) or ""
                    if overwrite or not existing:
                        idc.set_cmt(src_ea, new_comment, 0)
                        annotations += 1
                        annotated_addrs.add(src_ea)
                except Exception:
                    pass

        return {
            "ok": True,
            "function_ea": hex(func.start_ea),
            "annotations_written": annotations,
            "path_constraints_found": len(pcs),
        }

    except IDAError as e:
        return {"ok": False, "error": e.message}
    except Exception as e:
        logger.exception("triton_annotate_function failed")
        return {"ok": False, "error": str(e)}

@tool
@idasync
@tool_timeout(60.0)
def triton_highlight_tainted_instructions(
    function_address: Annotated[str, "Function address (hex or symbol name)."],
    color: Annotated[str, "Hex color value (default 0x00ff00 for green)."] = "0x00ff00",
    max_insns: Annotated[int, "Maximum instructions to scan (default 500)."] = 500,
) -> dict:
    """Scan a function and highlight instructions that operate on tainted data.

    Processes each instruction through Triton and uses `insn.isTainted()`
    to determine whether the instruction touches tainted registers or memory.
    Highlighted instructions are colored in IDA's disassembly view.

    Note: this modifies the current Triton context state (registers, memory).
    Use triton_snapshot_save first if you need to preserve state.
    """
    if not TRITON_AVAILABLE:
        return {"ok": False, "error": "triton-library not installed. Run: ida-pro-mcp --install-deps triton"}
    import ida_funcs
    import idc
    import idaapi

    try:
        from .utils import parse_address
        ea = parse_address(function_address)
        func = ida_funcs.get_func(ea)
        if func is None:
            return {"ok": False, "error": f"No function at {hex(ea)}"}

        ctx = _get_ctx()
        color_val = int(color, 16) if isinstance(color, str) and color.startswith("0x") else int(color, 0)

        highlighted = 0
        curr = func.start_ea
        count = 0

        while curr < func.end_ea and count < max_insns:
            insn_ida = idaapi.insn_t()
            length = idaapi.decode_insn(insn_ida, curr)
            if length == 0:
                break

            raw = idc.get_bytes(curr, length)
            if not raw:
                curr += 1
                continue

            insn = TritonInstruction()
            insn.setAddress(curr)
            insn.setOpcode(raw)
            ctx.processing(insn)
            _get_trace().append(curr)

            if insn.isTainted():
                idc.set_color(curr, idc.CIC_ITEM, color_val)
                highlighted += 1

            curr += length
            count += 1

        return {
            "ok": True,
            "function_ea": hex(func.start_ea),
            "highlighted_count": highlighted,
            "instructions_scanned": count,
            "color": hex(color_val),
        }

    except IDAError as e:
        return {"ok": False, "error": e.message}
    except Exception as e:
        logger.exception("triton_highlight_tainted_instructions failed")
        return {"ok": False, "error": str(e)}


@tool
@idasync
@tool_timeout(30.0)
def triton_backward_slice(
    sym_var_id_or_name: Annotated[
        str,
        "Symbolic variable ID (integer) or alias name to slice backwards from.",
    ],
) -> dict:
    """Perform backward slicing from a symbolic variable to find all contributing instructions.

    Uses Triton's `sliceExpressions()` to reconstruct the data-flow graph
    for a given symbolic variable — showing which prior instructions and
    symbolic expressions contributed to its current value.

    This is useful for:
    - Understanding data origin in a symbolic execution trace
    - Identifying which instructions a tainted value flows through
    - Finding the full dependency chain of a register or memory cell

    Requires a Triton context that has already processed instructions
    (via triton_process_function or triton_analyze_function).
    """
    if not TRITON_AVAILABLE:
        return {"ok": False, "error": "triton-library not installed. Run: ida-pro-mcp --install-deps triton"}
    try:
        ctx = _get_ctx()

        # First try as integer ID; ValueError means the string isn't a valid int
        # TypeError means the ID was valid but no such variable exists — fall back to name
        try:
            sv = ctx.getSymbolicVariable(int(sym_var_id_or_name))
        except ValueError:
            # Not an integer — treat as a name directly
            try:
                sv = ctx.getSymbolicVariable(sym_var_id_or_name)
            except TypeError:
                # Name doesn't exist either
                return {"ok": False, "error": f"Symbolic variable not found: {sym_var_id_or_name!r}"}
        except TypeError:
            # Integer ID was valid syntax but no such variable exists — try name as fallback
            try:
                sv = ctx.getSymbolicVariable(sym_var_id_or_name)
            except TypeError:
                return {"ok": False, "error": f"Symbolic variable not found: {sym_var_id_or_name!r}"}

        if sv is None:
            return {"ok": False, "error": f"Symbolic variable not found: {sym_var_id_or_name!r}"}

        # sliceExpressions() requires a SymbolicExpression, not a SymbolicVariable.
        # Locate the current expression for this variable via its origin:
        #   REGISTER_VARIABLE → origin is the register ID (key in getSymbolicRegisters())
        #   MEMORY_VARIABLE   → origin is the memory address (arg to getSymbolicMemory())
        var_origin = sv.getOrigin()
        expr_to_slice = None

        # Try register-based lookup first (most common case)
        sym_regs = ctx.getSymbolicRegisters()  # dict[reg_id → SymbolicExpression]
        expr_to_slice = sym_regs.get(var_origin)

        # If not found in registers, try memory lookup
        if expr_to_slice is None:
            try:
                # getSymbolicMemory(addr) returns the expression at that address
                expr_to_slice = ctx.getSymbolicMemory(var_origin)
            except Exception:
                pass

        # Last resort: scan all expressions for the first one whose AST references
        # this variable by name (e.g. "SymVar_0" appears in the AST string)
        if expr_to_slice is None:
            sv_name = sv.getName()
            for _, expr in ctx.getSymbolicExpressions().items():
                try:
                    if sv_name in str(expr.getAst()):
                        expr_to_slice = expr
                        break
                except Exception:
                    pass

        if expr_to_slice is None:
            return {
                "ok": False,
                "error": (
                    f"Symbolic variable {sv.getName()!r} found but no SymbolicExpression "
                    "references it. The register/memory may have been restored to a concrete "
                    "value after symbolization. Try running more instructions before slicing."
                ),
            }

        slice_result = ctx.sliceExpressions(expr_to_slice)

        entries = []
        for expr_id, expr in slice_result.items():
            entries.append({
                "expr_id": expr_id,
                "kind": "memory" if expr.isMemory() else ("register" if expr.isRegister() else "volatile"),
                "is_symbolized": expr.isSymbolized(),
                "is_tainted": expr.isTainted(),
                "disasm": expr.getDisassembly(),
                "ast": str(expr.getAst()),
            })

        return {
            "ok": True,
            "target_sym_var_id": sv.getId(),
            "target_sym_var_name": sv.getName(),
            "target_alias": sv.getAlias(),
            "slice_expr_count": len(entries),
            "slice": entries,
        }

    except IDAError as e:
        return {"ok": False, "error": e.message}
    except Exception as e:
        logger.exception("triton_backward_slice failed")
        return {"ok": False, "error": str(e)}
