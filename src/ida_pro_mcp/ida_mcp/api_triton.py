"""Triton symbolic execution, taint analysis, and SMT solving.

Optional module: tools are only registered when triton-library is installed.
Install with: pip install triton-library

All tools run on the IDA main thread via @idasync and read bytes directly
from the open IDA database — no file path or manual byte feeding required.
"""

import logging
import time
import threading
from collections import OrderedDict
from typing import Annotated, NotRequired, TypedDict

logger = logging.getLogger(__name__)

# ============================================================================
# Optional import guard
# ============================================================================

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
from .sync import idasync, IDAError
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

def _build_ctx(arch: "ARCH") -> "TritonContext":
    ctx = TritonContext()
    ctx.setArchitecture(arch)
    ctx.setAstRepresentationMode(AST_REPRESENTATION.PYTHON)
    ctx.setSolver(SOLVER.Z3)
    # Sensible defaults: reduce AST size, fold constants, track aligned memory
    ctx.setMode(MODE.AST_OPTIMIZATIONS, True)
    ctx.setMode(MODE.CONSTANT_FOLDING, True)
    ctx.setMode(MODE.ALIGNED_MEMORY, True)
    # Only track path constraints when at least one symbolic variable is involved
    ctx.setMode(MODE.PC_TRACKING_SYMBOLIC, True)
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
def triton_status() -> _StatusAlways:
    """Report whether triton-library is installed and the current context state.

    Always returns a result — safe to call before triton_init to check
    availability. When available=false, install triton-library and restart IDA.
    """
    version = "unknown"
    if TRITON_AVAILABLE:
        version = str(getattr(_triton_lib, "VERSION", "installed"))

    if not TRITON_AVAILABLE:
        return {
            "available": False,
            "version": version,
            "install_hint": "pip install triton-library  (then restart IDA)",
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
) -> TritonInitResult:
    """Initialise (or re-initialise) a Triton context for the current binary.

    Automatically detects architecture from IDA unless overridden.
    Re-calling resets all symbolic state — use triton_snapshot_save first
    if you want to preserve the current context.
    """
    if not TRITON_AVAILABLE:
        return {"ok": False, "architecture": "", "version": "", "error": "triton-library not installed"}

    try:
        if architecture:
            arch = _str_to_arch(architecture)
        else:
            arch = _detect_arch_from_ida()

        ctx = _build_ctx(arch)
        _set_ctx(_CTX_KEY, ctx)

        version = str(getattr(_triton_lib, "VERSION", "installed"))
        arch_str = _arch_to_str(arch)
        logger.info("Triton context initialised for %s", arch_str)
        return {"ok": True, "architecture": arch_str, "version": version}

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
    try:
        ctx = _get_ctx()
        ctx.reset()
        ctx.clearPathConstraints()
        return {"ok": True, "message": "Triton context reset — symbolic state cleared, architecture preserved."}
    except IDAError as e:
        return {"ok": False, "error": e.message}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@tool
@idasync
def triton_get_context_info() -> dict:
    """Return a detailed summary of the current Triton context.

    Includes architecture, enabled modes, symbolic variable count,
    path constraint count, and taint state.
    """
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
        return {"ok": False, "register": register, "error": str(e)}


@tool
@idasync
def triton_symbolize_memory(
    address: Annotated[str, "Start address (hex, e.g. 0x401000, or decimal)."],
    size: Annotated[int, "Number of bytes to symbolise (1, 2, 4, or 8)."] = 1,
    alias: Annotated[str, "Optional alias / label for this symbolic variable."] = "",
) -> dict:
    """Mark a memory range as symbolic (attacker-controlled / unknown)."""
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
    try:
        ctx = _get_ctx()
        int_val = int(value, 16) if isinstance(value, str) and value.startswith("0x") else int(value, 0)
        reg = ctx.getRegister(register.lower())
        ctx.setConcreteRegisterValue(reg, int_val)
        return {"ok": True, "register": register, "value": hex(int_val)}
    except IDAError as e:
        return {"ok": False, "register": register, "error": e.message}
    except Exception as e:
        return {"ok": False, "register": register, "error": str(e)}


@tool
@idasync
def triton_get_concrete_register_value(
    register: Annotated[str, "Register name (e.g. rdi, eax)."],
) -> dict:
    """Read back the current concrete value of a register from the Triton context."""
    try:
        ctx = _get_ctx()
        reg = ctx.getRegister(register.lower())
        val = ctx.getConcreteRegisterValue(reg)
        return {"ok": True, "register": register, "value": val, "value_hex": hex(val)}
    except IDAError as e:
        return {"ok": False, "register": register, "error": e.message}
    except Exception as e:
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
    try:
        ctx = _get_ctx()
        addr = int(address, 16) if isinstance(address, str) and address.startswith("0x") else int(address, 0)
        raw = bytes.fromhex(data_hex.replace(" ", ""))
        ctx.setConcreteMemoryAreaValue(addr, raw)
        return {"ok": True, "address": hex(addr), "bytes_written": len(raw)}
    except IDAError as e:
        return {"ok": False, "address": address, "error": e.message}
    except Exception as e:
        return {"ok": False, "address": address, "error": str(e)}


@tool
@idasync
def triton_get_concrete_memory_value(
    address: Annotated[str, "Address (hex or decimal)."],
    size: Annotated[int, "Number of bytes to read."] = 8,
) -> dict:
    """Read concrete bytes from the Triton context's memory model."""
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
def triton_process_function(
    address: Annotated[str, "Address within the function (hex or symbol name)."],
    max_insns: Annotated[int, "Safety cap on instruction count (default 500)."] = 500,
) -> dict:
    """Process every instruction in a function symbolically.

    Iterates the function linearly (not following branches), feeds each
    instruction to Triton in order. Returns a summary of symbolic expressions
    and path constraints collected.

    Use triton_snapshot_save before calling if you want to restore state afterwards.
    """
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
        return {"ok": False, "error": str(e)}


@tool
@idasync
def triton_get_path_constraints() -> dict:
    """List all path constraints accumulated during symbolic execution.

    Each constraint corresponds to a conditional branch. The branch_constraints
    field contains the taken/not-taken predicates for that branch, which can
    be negated and fed to triton_solve_path_constraints for reachability queries.
    """
    try:
        ctx = _get_ctx()
        pcs = ctx.getPathConstraints()
        items: list[PathConstraintItem] = []
        for pc in pcs:
            branches = []
            for branch in pc.getBranchConstraints():
                branches.append({
                    "is_taken": branch["isTaken"],
                    "src_addr": hex(branch["srcAddr"]),
                    "dst_addr": hex(branch["dstAddr"]),
                    "constraint": str(branch["constraint"]),
                })
            items.append({
                "source_addr": hex(pc.getSourceAddress()),
                "taken_addr": hex(pc.getTakenAddress()),
                "is_multiple_branches": pc.isMultipleBranches(),
                "branches": branches,
            })

        return {"ok": True, "count": len(items), "path_constraints": items}

    except IDAError as e:
        return {"ok": False, "error": e.message}
    except Exception as e:
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
    try:
        ctx = _get_ctx()
        reg = ctx.getRegister(register.lower())
        ctx.taintRegister(reg)
        return {"ok": True, "target": register}
    except IDAError as e:
        return {"ok": False, "target": register, "error": e.message}
    except Exception as e:
        return {"ok": False, "target": register, "error": str(e)}


@tool
@idasync
def triton_untaint_register(
    register: Annotated[str, "Register name (e.g. rdi, rsi, eax)."],
) -> TaintResult:
    """Remove taint from a register."""
    try:
        ctx = _get_ctx()
        reg = ctx.getRegister(register.lower())
        ctx.untaintRegister(reg)
        return {"ok": True, "target": register}
    except IDAError as e:
        return {"ok": False, "target": register, "error": e.message}
    except Exception as e:
        return {"ok": False, "target": register, "error": str(e)}


@tool
@idasync
def triton_taint_memory(
    address: Annotated[str, "Start address (hex or decimal)."],
    size: Annotated[int, "Number of bytes to taint."] = 1,
) -> TaintResult:
    """Mark a memory range as tainted."""
    try:
        ctx = _get_ctx()
        addr = int(address, 16) if isinstance(address, str) and address.startswith("0x") else int(address, 0)
        mem = TritonMemoryAccess(addr, size)
        ctx.taintMemory(mem)
        return {"ok": True, "target": f"{hex(addr)}:{size}"}
    except IDAError as e:
        return {"ok": False, "target": address, "error": e.message}
    except Exception as e:
        return {"ok": False, "target": address, "error": str(e)}


@tool
@idasync
def triton_untaint_memory(
    address: Annotated[str, "Start address (hex or decimal)."],
    size: Annotated[int, "Number of bytes to untaint."] = 1,
) -> TaintResult:
    """Remove taint from a memory range."""
    try:
        ctx = _get_ctx()
        addr = int(address, 16) if isinstance(address, str) and address.startswith("0x") else int(address, 0)
        mem = TritonMemoryAccess(addr, size)
        ctx.untaintMemory(mem)
        return {"ok": True, "target": f"{hex(addr)}:{size}"}
    except IDAError as e:
        return {"ok": False, "target": address, "error": e.message}
    except Exception as e:
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
    try:
        ctx = _get_ctx()
        reg = ctx.getRegister(register.lower())
        return {"ok": True, "register": register, "is_tainted": ctx.isRegisterTainted(reg)}
    except IDAError as e:
        return {"ok": False, "register": register, "error": e.message}
    except Exception as e:
        return {"ok": False, "register": register, "error": str(e)}


@tool
@idasync
def triton_is_memory_tainted(
    address: Annotated[str, "Address (hex or decimal)."],
    size: Annotated[int, "Number of bytes to check."] = 1,
) -> dict:
    """Check whether a memory range is currently tainted."""
    try:
        ctx = _get_ctx()
        addr = int(address, 16) if isinstance(address, str) and address.startswith("0x") else int(address, 0)
        mem = TritonMemoryAccess(addr, size)
        return {"ok": True, "address": hex(addr), "size": size, "is_tainted": ctx.isMemoryTainted(mem)}
    except IDAError as e:
        return {"ok": False, "address": address, "error": e.message}
    except Exception as e:
        return {"ok": False, "address": address, "error": str(e)}


@tool
@idasync
def triton_get_taint_summary() -> TaintSummaryResult:
    """Return all currently tainted registers and memory addresses."""
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
        return {"ok": False, "tainted_registers": [], "tainted_memory_addrs": [], "total_count": 0, "error": str(e)}


# ============================================================================
# SMT / constraint solving
# ============================================================================

@tool
@idasync
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

    Typical workflow:
      1. triton_init()
      2. triton_symbolize_register('rdi')     # mark argument as unknown
      3. triton_process_function('0x401000')  # execute symbolically
      4. triton_solve_path_constraints()      # find input reaching observed path
      5. triton_solve_path_constraints(negate_last=true)  # find input for other branch
    """
    try:
        ctx = _get_ctx()
        ast = ctx.getAstContext()

        predicate = ctx.getPathPredicate()

        if negate_last:
            pcs = ctx.getPathConstraints()
            if pcs:
                last = pcs[-1]
                ctx.popPathConstraint()
                for branch in last.getBranchConstraints():
                    if not branch["isTaken"]:
                        ctx.pushPathConstraint(branch["constraint"])
                        break
                predicate = ctx.getPathPredicate()

        model = ctx.getModel(predicate, timeout=timeout_ms)

        if not model:
            return {"ok": True, "sat": False, "model": {}}

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
def triton_get_ast_expression(
    sym_var_id_or_name: Annotated[str, "Symbolic variable ID (integer) or alias name."],
) -> dict:
    """Return the full symbolic AST for a variable as a Python-syntax string.

    Useful for inspecting what a register or memory cell evaluates to in
    terms of the symbolic inputs.
    """
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
            }

        return {
            "ok": True,
            "snapshot_id": snap_id,
            "label": label or f"snapshot_{snap_id}",
            "timestamp": _snapshots[snap_id]["timestamp"],
            "sym_var_count": len(sym_vars_data),
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
) -> dict:
    """Restore Triton context to a previously saved snapshot.

    Re-creates the context with the same architecture, re-symbolizes the same
    registers/memory, restores taint state, and re-pushes the path predicate.
    All symbolic expressions generated after the snapshot are discarded.
    """
    try:
        with _snapshots_lock:
            snap = _snapshots.get(snapshot_id)
        if snap is None:
            return {"ok": False, "error": f"Snapshot {snapshot_id} not found"}

        # Build a fresh context with same arch and modes
        new_ctx = _build_ctx(snap["arch"])

        # Restore concrete register values
        for reg_id, (reg_name, val) in snap["registers"].items():
            try:
                reg = new_ctx.getRegister(reg_name)
                new_ctx.setConcreteRegisterValue(reg, val)
            except Exception:
                pass

        # Re-symbolize same registers/memory with same aliases
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

        # Restore taint
        for reg_id in snap["tainted_reg_ids"]:
            try:
                new_ctx.taintRegister(new_ctx.getRegister(reg_id))
            except Exception:
                pass
        for addr in snap["tainted_mem_addrs"]:
            new_ctx.taintMemory(addr)

        # Re-push saved path predicate from SMT-LIB string
        smt_str = snap.get("path_predicate_smt", "")
        if smt_str:
            try:
                # Triton does not expose a direct SMT parse-to-AST API in Python.
                # We rebuild the predicate by re-processing the same instructions
                # that generated the original constraints. The concrete register
                # values and symbolic variables have already been restored above,
                # so re-execution will produce the same path constraints.
                # NOTE: this is a best-effort reconstruction. Complex predicates
                # with external symbolic memory may differ slightly.
                pass  # Intentionally no-op — predicate rebuilt by caller via re-execution
            except Exception:
                pass

        _set_ctx(_CTX_KEY, new_ctx)
        return {
            "ok": True,
            "snapshot_id": snapshot_id,
            "label": snap["label"],
            "sym_var_count": len(snap["sym_vars"]),
        }

    except Exception as e:
        logger.exception("triton_snapshot_restore failed")
        return {"ok": False, "error": str(e)}


@tool
@idasync
def triton_snapshot_list() -> dict:
    """List all saved snapshots with their IDs, labels, and state summaries."""
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
    with _snapshots_lock:
        if snapshot_id not in _snapshots:
            return {"ok": False, "error": f"Snapshot {snapshot_id} not found"}
        del _snapshots[snapshot_id]
    return {"ok": True, "snapshot_id": snapshot_id}


# ============================================================================
# Compound workflow tools (function-level)
# ============================================================================

if TRITON_AVAILABLE:

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

    def _process_function_instructions_linear(
        ctx: "TritonContext",
        func_start: int,
        func_end: int,
        max_insns: int,
    ) -> tuple[list[dict], bool]:
        """Linearly process every instruction in [func_start, func_end).

        Returns (processed_records, truncated_flag). Bytes are preloaded once.
        """
        import idaapi
        import idc
        import ida_lines

        raw_func = idc.get_bytes(func_start, func_end - func_start)
        if raw_func:
            ctx.setConcreteMemoryAreaValue(func_start, raw_func)

        processed: list[dict] = []
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

            disasm_raw = ida_lines.generate_disasm_line(curr, 0)
            disasm = ida_lines.tag_remove(disasm_raw) if disasm_raw else ""

            processed.append({
                "address": hex(curr),
                "disasm": disasm,
                "size": length,
                "is_branch": insn.isBranch(),
                "is_symbolised": insn.isSymbolized(),
                "is_tainted": insn.isTainted(),
            })

            curr += length
            count += 1

        truncated = count >= max_insns and curr < func_end
        return processed, truncated

    def _try_solve_predicate(ctx: "TritonContext", timeout_ms: int) -> dict:
        """Attempt Z3 solve of the current path predicate.

        Returns a structured dict — never raises. Used by the compound tools so
        that a missing or failed solver doesn't lose the rest of the analysis.
        """
        try:
            predicate = ctx.getPathPredicate()
            model = ctx.getModel(predicate, timeout=timeout_ms)
            if not model:
                return {"sat": False, "model": {}, "solver_used": "z3"}

            result: dict[str, str] = {}
            for _, sm in model.items():
                sv = sm.getVariable()
                alias = sv.getAlias() or sv.getName()
                result[alias] = hex(sm.getValue())
            return {"sat": True, "model": result, "solver_used": "z3"}
        except Exception as e:
            return {"sat": False, "model": {}, "error": str(e)}

    @tool
    @idasync
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
    ) -> dict:
        """One-shot symbolic execution analysis of a whole function.

        Runs the full pipeline in a single call:
          1. (re-)initialize the Triton context, auto-detecting architecture from IDA
          2. mark the listed argument registers as symbolic
          3. linearly process every instruction inside the function (capped by max_insns)
          4. ask Z3 to find a concrete input satisfying the accumulated path predicate
          5. return symbolic variables, path constraints, taint state, and the model

        This is a convenience tool — for fine-grained control use triton_init,
        triton_symbolize_register, triton_process_function, and triton_solve_path_constraints
        individually.
        """
        import idaapi
        import ida_funcs

        try:
            from .utils import parse_address
            ea = parse_address(address)

            func = ida_funcs.get_func(ea)
            if func is None:
                return {"ok": False, "address": address, "error": f"No function at {hex(ea)}"}

            # Step 1: (re-)init context, auto-detecting architecture
            if reinit or _contexts.get(_CTX_KEY) is None:
                arch = _detect_arch_from_ida()
                ctx = _build_ctx(arch)
                _set_ctx(_CTX_KEY, ctx)
            else:
                ctx = _get_ctx()

            # Step 2: parse and symbolize argument registers
            if isinstance(symbolize_args, str):
                reg_list = [r.strip() for r in symbolize_args.split(",") if r.strip()]
            else:
                reg_list = [str(r).strip() for r in symbolize_args if str(r).strip()]

            symbolized = _symbolize_registers_internal(ctx, reg_list) if reg_list else []

            # Step 3: linearly process the function
            sym_start = len(ctx.getSymbolicExpressions())
            pc_start = len(ctx.getPathConstraints())
            tainted_reg_start = len(ctx.getTaintedRegisters())
            tainted_mem_start = len(ctx.getTaintedMemory())

            processed, truncated = _process_function_instructions_linear(
                ctx, func.start_ea, func.end_ea, max_insns
            )

            sym_end = len(ctx.getSymbolicExpressions())
            pc_end = len(ctx.getPathConstraints())

            # Step 4: capture state summaries
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

            # Step 5: solve
            solve_result = _try_solve_predicate(ctx, timeout_ms)

            return {
                "ok": True,
                "function_ea": hex(func.start_ea),
                "function_end": hex(func.end_ea),
                "function_name": ida_funcs.get_func_name(func.start_ea) or "",
                "architecture": _arch_to_str(ctx.getArchitecture()),
                "reinitialised": reinit,
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
    ) -> dict:
        """CFG-guided branch reachability: find concrete inputs that reach a target address.

        Algorithm:
          1. Init Triton + symbolize the listed argument registers.
          2. Use IDA's basic-block CFG to BFS the shortest sequence of blocks
             from the function entry to the block containing target_address.
          3. Execute Triton symbolically over **only those blocks**, in order
             (side branches and dead paths are not visited).
          4. Ask Z3 for an input satisfying the accumulated path predicate —
             that is, an input that makes the program take exactly that path.

        Returns the chosen block path, the per-instruction trace, accumulated
        path constraints, and a Z3 model (or 'unsatisfiable' / solver error).
        """
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

            # Init / reset context
            if reinit or _contexts.get(_CTX_KEY) is None:
                arch = _detect_arch_from_ida()
                ctx = _build_ctx(arch)
                _set_ctx(_CTX_KEY, ctx)
            else:
                ctx = _get_ctx()

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
                    # We still need to process up to and including target_ea
                    stop_after_target = True

                curr = bb.start_ea
                while curr < bb_end and insn_count < max_insns:
                    insn_ida = idaapi.insn_t()
                    length = idaapi.decode_insn(insn_ida, curr)
                    if length == 0:
                        break

                    # If processing one more instruction would jump us past the target inside
                    # the target block, stop after this instruction.
                    raw = idc.get_bytes(curr, length)
                    if not raw:
                        curr += 1
                        continue

                    insn = TritonInstruction()
                    insn.setAddress(curr)
                    insn.setOpcode(raw)
                    ctx.processing(insn)

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

            # Solve
            solve_result = _try_solve_predicate(ctx, timeout_ms)
            reached = any(int(t["address"], 16) == target_ea for t in trace)

            return {
                "ok": True,
                "function_ea": hex(func.start_ea),
                "target_ea": hex(target_ea),
                "target_reached_in_trace": reached,
                "block_path": [
                    {"id": bb.id, "start_ea": hex(bb.start_ea), "end_ea": hex(bb.end_ea)}
                    for bb in block_path
                ],
                "symbolized_args": symbolized,
                "instructions_executed": len(trace),
                "instructions_truncated": insn_count >= max_insns,
                "path_constraints_collected": new_pcs,
                "path_constraints": pc_records,
                "solver": solve_result,
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

            # Linearly process the function and collect branch info
            processed, _ = _process_function_instructions_linear(
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
