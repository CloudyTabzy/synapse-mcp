"""Miasm IR analysis, symbolic execution, cross-arch assembly, and CFG analysis.

Optional module: tools are only registered when miasm is installed.
Install with: pip install miasm future

All tools run on the IDA main thread via @idasync and read bytes directly
from the open IDA database — no file path or manual byte feeding required.
"""

import json
import logging
import threading
from typing import Annotated

logger = logging.getLogger(__name__)

# ============================================================================
# Optional import guard
# ============================================================================

try:
    from miasm.analysis.machine import Machine
    from miasm.core.locationdb import LocationDB
    from miasm.core.bin_stream import bin_stream_str
    from miasm.expression.expression import ExprId, ExprInt, get_expr_ids
    MIASM_AVAILABLE = True
except ImportError:
    MIASM_AVAILABLE = False
    Machine = None  # type: ignore[assignment,misc]
    LocationDB = None  # type: ignore[assignment,misc]
    bin_stream_str = None  # type: ignore[assignment]
    ExprId = None  # type: ignore[assignment,misc]
    ExprInt = None  # type: ignore[assignment,misc]
    get_expr_ids = None  # type: ignore[assignment]
    logger.warning(
        "miasm not installed — Miasm tools unavailable. "
        "Run: ida-pro-mcp --install-deps miasm"
    )

from .rpc import tool, unsafe
from .sync import idasync, IDAError
from . import compat
from .utils import parse_address

# ============================================================================
# Lazy manager — syncs architecture from IDA on first use
# ============================================================================


class _MiasmManager:
    """Thread-safe, lazily-initialized Miasm context for the current IDA session."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._machine: "Machine | None" = None
        self._arch_name: str = ""
        self._bitness: int = 0
        self._is_be: bool = False
        self._procname: str = ""

    def _detect_arch_from_ida(self) -> tuple[str, int, bool, str]:
        """Return (miasm_arch_str, bitness, is_big_endian, procname)."""
        procname = compat.inf_get_procname().lower()
        is_be = compat.inf_is_be()
        endian_suffix = "b" if is_be else "l"

        if compat.inf_is_64bit():
            bits = 64
        elif compat.inf_is_32bit():
            bits = 32
        else:
            bits = 16

        if procname.startswith("metapc") or procname.startswith("80"):
            # x86 is always little-endian — Miasm doesn't expose big-endian x86
            arch = f"x86_{bits}"
        elif procname.startswith("arm"):
            arch = f"aarch64{endian_suffix}" if bits == 64 else f"arm{endian_suffix}"
        elif procname.startswith("mips"):
            arch = f"mips32{endian_suffix}"
        elif procname.startswith("ppc"):
            arch = f"ppc32{endian_suffix}"
        else:
            raise IDAError(f"Unsupported architecture for Miasm: {procname!r}")

        return arch, bits, is_be, procname

    def _do_sync(self, override_arch: str = "") -> str:
        """(Re)build the Miasm Machine. Accepts an explicit arch override."""
        if override_arch:
            arch = override_arch
            # Best-effort bitness detection from the override string
            if "64" in arch:
                bits = 64
            elif "32" in arch:
                bits = 32
            else:
                bits = 32  # safe default
            is_be = arch.endswith("b") and not arch.startswith("x86")
            procname = self._procname or "<override>"
        else:
            arch, bits, is_be, procname = self._detect_arch_from_ida()

        self._machine = Machine(arch)
        self._arch_name = arch
        self._bitness = bits
        self._is_be = is_be
        self._procname = procname
        return arch

    def sync(self) -> str:
        with self._lock:
            return self._do_sync()

    def init(self, override_arch: str = "") -> str:
        """Explicit (re-)initialization. Discards any cached Machine."""
        with self._lock:
            self._machine = None
            self._arch_name = ""
            self._bitness = 0
            self._is_be = False
            return self._do_sync(override_arch=override_arch)

    @property
    def machine(self) -> "Machine":
        with self._lock:
            if self._machine is None:
                self._do_sync()
            return self._machine  # type: ignore[return-value]

    @property
    def arch_name(self) -> str:
        with self._lock:
            if not self._arch_name:
                self._do_sync()
            return self._arch_name

    @property
    def bitness(self) -> int:
        with self._lock:
            if not self._bitness:
                self._do_sync()
            return self._bitness

    @property
    def is_big_endian(self) -> bool:
        with self._lock:
            if not self._arch_name:
                self._do_sync()
            return self._is_be

    @property
    def procname(self) -> str:
        with self._lock:
            if not self._procname:
                self._do_sync()
            return self._procname

    def get_bytes(self, start_ea: int, end_ea: int) -> bytes:
        import ida_bytes
        data = ida_bytes.get_bytes(start_ea, end_ea - start_ea)
        if data is None:
            raise IDAError(f"Could not read bytes at {hex(start_ea)}-{hex(end_ea)}")
        return data

    def get_mdis(self, data: bytes, base_ea: int):
        """Create a configured Miasm disassembler for the byte range starting at base_ea."""
        bs = bin_stream_str(data, base_ea)
        loc_db = LocationDB()
        mdis = self.machine.dis_engine(bs, loc_db=loc_db)
        mdis.follow_call = False
        mdis.dont_dis_retcall = True
        return mdis, loc_db


_manager = _MiasmManager()


# ============================================================================
# Helper
# ============================================================================


def _iter_ircfg_blocks(ircfg):
    """Yield (loc_key, irblock) pairs regardless of Miasm version."""
    blocks = ircfg.blocks
    if hasattr(blocks, "items"):
        yield from blocks.items()
    else:
        for irblock in blocks:
            yield irblock.loc_key, irblock


def _ircfg_edges(ircfg):
    """Return list of (src, dst) loc_key edges."""
    edges_fn = ircfg.edges
    if callable(edges_fn):
        return list(edges_fn())
    return list(edges_fn)


def _find_all_paths(cfg, start_loc, target_loc, max_paths: int = 20):
    """BFS path finding between loc_keys. Returns list of loc_key lists."""
    from collections import deque

    paths = []
    queue = deque([[start_loc]])
    visited: set = set()

    while queue and len(paths) < max_paths:
        path = queue.popleft()
        current = path[-1]

        if current == target_loc:
            paths.append(path[:])
            continue

        state = (current, len(path))
        if state in visited or len(path) > 64:
            continue
        visited.add(state)

        for successor in cfg.successors(current):
            if successor not in path:
                queue.append(path + [successor])

    return paths


def _ir_blocks_to_dict(ircfg) -> list[dict]:
    blocks_out = []
    for loc_key, irblock in _iter_ircfg_blocks(ircfg):
        insts = []
        for assignblk in irblock:
            for dst, src in assignblk.items():
                insts.append({"dst": str(dst), "src": str(src)})
        blocks_out.append({"loc_key": str(loc_key), "instructions": insts})
    return blocks_out


# ============================================================================
# Tools — always-available status probe
# ============================================================================


@tool
@idasync
def miasm_status() -> dict:
    """Report Miasm availability and current architecture state."""
    if not MIASM_AVAILABLE:
        return {
            "ok": True,
            "available": False,
            "install_hint": "pip install miasm future  (then restart IDA)",
        }
    try:
        import miasm
        ver = getattr(miasm, "__version__", "unknown")
    except Exception:
        ver = "unknown"

    if _manager._arch_name:
        endian = "big" if _manager._is_be else "little"
        return {
            "ok": True,
            "available": True,
            "version": ver,
            "architecture": _manager.arch_name,
            "bitness": _manager.bitness,
            "endianness": endian,
            "procname": _manager.procname,
        }
    return {
        "ok": True,
        "available": True,
        "version": ver,
        "architecture": None,
        "note": "Machine not yet built. First Miasm call auto-syncs, or call miasm_init explicitly.",
    }


# ============================================================================
# Context / sync
# ============================================================================


if MIASM_AVAILABLE:

    @tool
    @idasync
    def miasm_sync() -> dict:
        """Re-synchronise Miasm architecture with the currently loaded IDA binary."""
        arch = _manager.sync()
        return {
            "ok": True,
            "architecture": arch,
            "bitness": _manager.bitness,
            "endianness": "big" if _manager.is_big_endian else "little",
        }

    @tool
    @idasync
    def miasm_init(
        arch: Annotated[
            str,
            "Optional architecture override (e.g. x86_32, x86_64, arml, armb, "
            "aarch64l, aarch64b, mips32l, mips32b, ppc32b). "
            "Leave empty to auto-detect from the loaded IDA binary.",
        ] = "",
    ) -> dict:
        """
        Explicitly (re-)initialize the Miasm Machine.

        Use this when you want a clean slate — e.g. after the IDA binary has
        been rebased, after switching binaries, or to force a specific architecture.
        This discards the cached Machine and rebuilds it. Architecture is
        auto-detected from IDA unless overridden.

        Endianness is derived from IDA's `inf_is_be()` for ARM / AArch64 / MIPS / PPC.
        """
        try:
            arch_resolved = _manager.init(override_arch=arch)
            return {
                "ok": True,
                "architecture": arch_resolved,
                "bitness": _manager.bitness,
                "endianness": "big" if _manager.is_big_endian else "little",
                "procname": _manager.procname,
                "override_used": bool(arch),
            }
        except IDAError as e:
            return {"ok": False, "error": str(e)}
        except Exception as e:
            logger.exception("miasm_init failed")
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}

    @tool
    @idasync
    def miasm_get_context_info() -> dict:
        """
        Return a detailed summary of the current Miasm session state.

        Includes architecture, bitness, endianness, the IDA procname that the
        Machine was built from, and the Miasm version. If the Machine has not
        been initialized yet, the response indicates that and points at the
        autodetected target.
        """
        try:
            import miasm
            miasm_version = getattr(miasm, "__version__", "unknown")
        except Exception:
            miasm_version = "unknown"

        if not _manager._arch_name:
            try:
                preview_arch, preview_bits, preview_be, preview_proc = _manager._detect_arch_from_ida()
                return {
                    "ok": True,
                    "initialized": False,
                    "miasm_version": miasm_version,
                    "would_auto_detect_as": {
                        "architecture": preview_arch,
                        "bitness": preview_bits,
                        "endianness": "big" if preview_be else "little",
                        "procname": preview_proc,
                    },
                    "note": "Machine not yet built. First Miasm call auto-syncs, or call miasm_init explicitly.",
                }
            except IDAError as e:
                return {
                    "ok": False,
                    "initialized": False,
                    "miasm_version": miasm_version,
                    "error": str(e),
                }

        machine = _manager.machine
        return {
            "ok": True,
            "initialized": True,
            "miasm_version": miasm_version,
            "architecture": _manager.arch_name,
            "bitness": _manager.bitness,
            "endianness": "big" if _manager.is_big_endian else "little",
            "procname": _manager.procname,
            "machine_name": getattr(machine, "name", _manager.arch_name),
        }

    @tool
    @idasync
    def miasm_reset() -> dict:
        """
        Reset the Miasm Machine and re-auto-detect architecture from IDA.

        Equivalent to calling `miasm_init()` with no override. Useful as a
        recovery step if the Miasm state somehow drifts from IDA's current
        view (e.g. after a forced architecture change in IDA's processor
        configuration).

        Tool calls use a fresh `LocationDB` per request by design, so there
        is no accumulated symbol state to clear — this resets only the
        Machine and its associated architectural metadata.
        """
        try:
            arch_resolved = _manager.init(override_arch="")
            return {
                "ok": True,
                "architecture": arch_resolved,
                "bitness": _manager.bitness,
                "endianness": "big" if _manager.is_big_endian else "little",
                "message": "Miasm Machine rebuilt from current IDA state.",
            }
        except IDAError as e:
            return {"ok": False, "error": str(e)}
        except Exception as e:
            logger.exception("miasm_reset failed")
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}

    # ========================================================================
    # IR lifting
    # ========================================================================

    @tool
    @idasync
    def miasm_lift_to_ir(
        address: Annotated[str, "Start address (hex or symbol name) of the range to lift"],
        end_address: Annotated[str, "End address (exclusive) of the range to lift (hex or symbol name)"],
    ) -> list[dict]:
        """Disassemble an address range and lift it to Miasm IR. Returns a list of IR blocks."""
        ea = parse_address(address)
        end_ea = parse_address(end_address)
        data = _manager.get_bytes(ea, end_ea)
        mdis, loc_db = _manager.get_mdis(data, ea)

        asm_block = mdis.dis_block(ea)
        lifter = _manager.machine.lifter_model_call(loc_db)
        ircfg = lifter.new_ircfg()
        lifter.add_asmblock_to_ircfg(asm_block, ircfg)

        return _ir_blocks_to_dict(ircfg)

    @tool
    @idasync
    def miasm_lift_function(
        address: Annotated[str, "Any address inside the function to lift (hex or symbol name)"],
    ) -> dict:
        """Lift an entire function's CFG to Miasm IR and return all IR blocks and edges."""
        import idaapi
        ea = parse_address(address)
        func = idaapi.get_func(ea)
        if not func:
            raise IDAError(f"No function found at {hex(ea)}")

        data = _manager.get_bytes(func.start_ea, func.end_ea)
        mdis, loc_db = _manager.get_mdis(data, func.start_ea)

        asmcfg = mdis.dis_multiblock(func.start_ea)
        lifter = _manager.machine.lifter_model_call(loc_db)
        ircfg = lifter.new_ircfg_from_asmcfg(asmcfg)

        edges = [{"src": str(s), "dst": str(d)} for s, d in _ircfg_edges(ircfg)]
        return {
            "function_ea": hex(func.start_ea),
            "blocks": _ir_blocks_to_dict(ircfg),
            "edges": edges,
        }

    # ========================================================================
    # SSA
    # ========================================================================

    @tool
    @idasync
    def miasm_get_ssa(
        address: Annotated[str, "Any address inside the function to transform (hex or symbol name)"],
    ) -> dict:
        """Lift a function to IR and transform it into Static Single Assignment (SSA) form."""
        import idaapi
        from miasm.analysis.ssa import SSADiGraph

        ea = parse_address(address)
        func = idaapi.get_func(ea)
        if not func:
            raise IDAError(f"No function found at {hex(ea)}")

        data = _manager.get_bytes(func.start_ea, func.end_ea)
        mdis, loc_db = _manager.get_mdis(data, func.start_ea)

        asmcfg = mdis.dis_multiblock(func.start_ea)
        lifter = _manager.machine.lifter_model_call(loc_db)
        ircfg = lifter.new_ircfg_from_asmcfg(asmcfg)

        heads = list(ircfg.heads())
        if not heads:
            raise IDAError("IRCFG has no head block — cannot apply SSA.")
        head = heads[0]

        ssa = SSADiGraph(ircfg)
        ssa.transform(head)

        edges = [{"src": str(s), "dst": str(d)} for s, d in _ircfg_edges(ircfg)]
        return {
            "function_ea": hex(func.start_ea),
            "form": "ssa",
            "blocks": _ir_blocks_to_dict(ircfg),
            "edges": edges,
        }

    # ========================================================================
    # CFG analysis
    # ========================================================================

    @tool
    @idasync
    def miasm_get_cfg_dot(
        address: Annotated[str, "Any address inside the function (hex or symbol name)"],
    ) -> dict:
        """Return a Graphviz DOT string for the function's assembly CFG."""
        import idaapi
        ea = parse_address(address)
        func = idaapi.get_func(ea)
        if not func:
            raise IDAError(f"No function found at {hex(ea)}")

        data = _manager.get_bytes(func.start_ea, func.end_ea)
        mdis, _ = _manager.get_mdis(data, func.start_ea)

        asmcfg = mdis.dis_multiblock(func.start_ea)
        return {"ok": True, "dot": asmcfg.dot()}

    @tool
    @idasync
    def miasm_find_paths(
        start_ea: Annotated[str, "Start address (hex or symbol name) — must be inside the same function as target"],
        target_ea: Annotated[str, "Target address to reach (hex or symbol name)"],
        max_paths: Annotated[int, "Maximum number of paths to return (default 20)"] = 20,
    ) -> list[dict]:
        """Find all execution paths between two addresses within the same function."""
        import idaapi
        start_addr = parse_address(start_ea)
        target_addr = parse_address(target_ea)
        func = idaapi.get_func(start_addr)
        if not func:
            raise IDAError(f"No function found at {hex(start_addr)}")

        data = _manager.get_bytes(func.start_ea, func.end_ea)
        mdis, loc_db = _manager.get_mdis(data, func.start_ea)

        asmcfg = mdis.dis_multiblock(func.start_ea)

        start_loc = None
        target_loc = None
        for block in asmcfg.blocks:
            if not block.lines:
                continue
            bstart = block.lines[0].offset
            bend = block.lines[-1].offset
            if bstart <= start_addr <= bend:
                start_loc = block.loc_key
            if bstart <= target_addr <= bend:
                target_loc = block.loc_key

        if start_loc is None:
            raise IDAError(f"Address {hex(start_addr)} not found in function blocks.")
        if target_loc is None:
            raise IDAError(f"Address {hex(target_addr)} not found in function blocks.")

        paths = _find_all_paths(asmcfg, start_loc, target_loc, max_paths)
        if not paths:
            return []

        results = []
        for idx, path in enumerate(paths):
            path_eas = []
            for loc in path:
                block = asmcfg.loc_key_to_block(loc)
                if block and block.lines:
                    path_eas.append(hex(block.lines[0].offset))
                else:
                    path_eas.append(str(loc))
            results.append({"path_index": idx + 1, "addresses": path_eas})
        return results

    # ========================================================================
    # Deobfuscation / simplification
    # ========================================================================

    @tool
    @idasync
    def miasm_deobfuscate_cfg(
        address: Annotated[str, "Any address inside the function to deobfuscate (hex or symbol name)"],
    ) -> dict:
        """
        Lift a function to IR and apply dead-code elimination to simplify obfuscated CFGs.
        Returns the simplified IR blocks and edges.
        """
        import idaapi
        from miasm.analysis.data_flow import DeadRemoval

        ea = parse_address(address)
        func = idaapi.get_func(ea)
        if not func:
            raise IDAError(f"No function found at {hex(ea)}")

        data = _manager.get_bytes(func.start_ea, func.end_ea)
        mdis, loc_db = _manager.get_mdis(data, func.start_ea)

        asmcfg = mdis.dis_multiblock(func.start_ea)
        lifter = _manager.machine.lifter_model_call(loc_db)
        ircfg = lifter.new_ircfg_from_asmcfg(asmcfg)

        dead_rm = DeadRemoval(lifter)
        dead_rm(ircfg)

        edges = [{"src": str(s), "dst": str(d)} for s, d in _ircfg_edges(ircfg)]
        return {
            "function_ea": hex(func.start_ea),
            "simplified": True,
            "blocks": _ir_blocks_to_dict(ircfg),
            "edges": edges,
        }

    @tool
    @idasync
    def miasm_simplify_block(
        address: Annotated[str, "Start address of the block to symbolically simplify (hex or symbol name)"],
    ) -> dict:
        """
        Symbolically execute a single basic block and return the simplified register state.
        Only registers whose values changed (i.e. are non-identity after simplification) are reported.
        """
        from miasm.ir.symbexec import SymbolicExecutionEngine

        ea = parse_address(address)
        end_ea = ea + 256
        data = _manager.get_bytes(ea, end_ea)
        mdis, loc_db = _manager.get_mdis(data, ea)

        asm_block = mdis.dis_block(ea)
        lifter = _manager.machine.lifter_model_call(loc_db)
        ircfg = lifter.new_ircfg()
        lifter.add_asmblock_to_ircfg(asm_block, ircfg)

        sb = SymbolicExecutionEngine(lifter)
        for _, irblock in _iter_ircfg_blocks(ircfg):
            sb.eval_updt_irblock(irblock)

        regs: dict[str, str] = {}
        for dest, expr in sb.symbols.items():
            simplified = expr.simplify()
            if str(dest) != str(simplified):
                regs[str(dest)] = str(simplified)

        return {"address": hex(ea), "simplified_registers": regs}

    # ========================================================================
    # Symbolic execution
    # ========================================================================

    @tool
    @idasync
    def miasm_emulate_symbolic(
        address: Annotated[str, "Start address of the block to emulate (hex or symbol name)"],
        context_json: Annotated[
            str,
            'JSON object mapping register names to integer values, e.g. {"EAX": 1, "EBX": 2}',
        ] = "{}",
    ) -> dict:
        """
        Symbolically emulate a basic block with an optional concrete initial register state.
        Returns all register assignments after execution.
        """
        from miasm.ir.symbexec import SymbolicExecutionEngine

        try:
            context: dict = json.loads(context_json)
        except Exception as exc:
            raise IDAError(f"Invalid context_json: {exc}") from exc

        ea = parse_address(address)
        end_ea = ea + 256
        data = _manager.get_bytes(ea, end_ea)
        mdis, loc_db = _manager.get_mdis(data, ea)

        asm_block = mdis.dis_block(ea)
        lifter = _manager.machine.lifter_model_call(loc_db)
        ircfg = lifter.new_ircfg()
        lifter.add_asmblock_to_ircfg(asm_block, ircfg)

        sb = SymbolicExecutionEngine(lifter)

        bits = _manager.bitness
        for reg_name, val in context.items():
            try:
                reg_expr = ExprId(reg_name.upper(), bits)
                sb.symbols[reg_expr] = ExprInt(int(val), bits)
            except Exception:
                pass

        for _, irblock in _iter_ircfg_blocks(ircfg):
            sb.eval_updt_irblock(irblock)

        regs: dict[str, str] = {}
        for dest, expr in sb.symbols.items():
            regs[str(dest)] = str(expr.simplify())

        return {"address": hex(ea), "registers": regs}

    # ========================================================================
    # Data flow / side effects
    # ========================================================================

    @tool
    @idasync
    def miasm_get_function_side_effects(
        address: Annotated[str, "Any address inside the function to analyse (hex or symbol name)"],
    ) -> dict:
        """
        Report which registers and memory locations are read and written by a function.
        Useful for quickly understanding a function's I/O surface.
        """
        import idaapi

        ea = parse_address(address)
        func = idaapi.get_func(ea)
        if not func:
            raise IDAError(f"No function found at {hex(ea)}")

        data = _manager.get_bytes(func.start_ea, func.end_ea)
        mdis, loc_db = _manager.get_mdis(data, func.start_ea)

        asmcfg = mdis.dis_multiblock(func.start_ea)
        lifter = _manager.machine.lifter_model_call(loc_db)
        ircfg = lifter.new_ircfg_from_asmcfg(asmcfg)

        written: set[str] = set()
        read: set[str] = set()

        for _, irblock in _iter_ircfg_blocks(ircfg):
            for assignblk in irblock:
                for dst, src in assignblk.items():
                    if dst.is_id():
                        written.add(str(dst))
                    elif dst.is_mem():
                        written.add(f"@mem[{dst}]")
                    for r in get_expr_ids(src):
                        read.add(str(r))

        return {
            "function_ea": hex(func.start_ea),
            "reads": sorted(read),
            "writes": sorted(written),
        }

    def _trace_data_flow_internal(register: str, ea: int) -> list[str]:
        """Non-decorated helper to trace data-flow origins without nested @idasync deadlock."""
        import idaapi
        from miasm.analysis.depgraph import DependencyGraph

        func = idaapi.get_func(ea)
        if not func:
            raise IDAError(f"No function found at {hex(ea)}")

        data = _manager.get_bytes(func.start_ea, func.end_ea)
        mdis, loc_db = _manager.get_mdis(data, func.start_ea)

        asmcfg = mdis.dis_multiblock(func.start_ea)
        lifter = _manager.machine.lifter_model_call(loc_db)
        ircfg = lifter.new_ircfg_from_asmcfg(asmcfg)

        dg = DependencyGraph(ircfg)
        reg_expr = ExprId(register.upper(), _manager.bitness)

        target_loc = None
        line_nb = 0
        for _, irblock in _iter_ircfg_blocks(ircfg):
            for idx, assignblk in enumerate(irblock):
                instr = getattr(assignblk, "instr", None)
                if instr is not None and instr.offset == ea:
                    target_loc = irblock.loc_key
                    line_nb = idx
                    break
            if target_loc is not None:
                break

        if target_loc is None:
            raise IDAError(f"Address {hex(ea)} not found in function IR blocks.")

        sols = dg.get(target_loc, {reg_expr}, line_nb, set())

        output: list[str] = []
        for graph in sols:
            for node in graph.nodes():
                output.append(str(node))

        return output

    @tool
    @idasync
    def miasm_trace_data_flow(
        register: Annotated[str, "Register name whose origin to trace (e.g. EAX, RAX)"],
        address: Annotated[str, "Address of the instruction where the register value is used (hex or symbol name)"],
    ) -> list[str]:
        """
        Trace the data-flow origins of a register at a given address using Miasm's dependency graph.
        Returns a list of IR expression nodes that contribute to the register's value.
        """
        ea = parse_address(address)
        return _trace_data_flow_internal(register, ea)

    # ========================================================================
    # Assembly / patching
    # ========================================================================

    @tool
    @idasync
    def miasm_assemble(
        asm_string: Annotated[str, "Assembly instruction text (e.g. 'MOV EAX, 1')"],
        arch: Annotated[
            str,
            "Override architecture string (e.g. x86_32, x86_64, arml). "
            "Leave empty to use the architecture of the currently loaded binary.",
        ] = "",
    ) -> dict:
        """Assemble a single instruction and return all possible encodings."""
        if arch:
            machine = Machine(arch)
            bits = int(arch.split("_")[-1]) if "_" in arch else _manager.bitness
        else:
            machine = _manager.machine
            bits = _manager.bitness

        loc_db = LocationDB()
        mn = machine.mn
        instr = mn.fromstring(asm_string, loc_db, bits)
        encodings = mn.asm(instr)

        if not encodings:
            raise IDAError(f"No encodings found for: {asm_string!r}")

        return {
            "instruction": str(instr),
            "encodings": [enc.hex() for enc in encodings],
            "shortest": min(encodings, key=len).hex(),
            "longest": max(encodings, key=len).hex(),
        }

    @unsafe
    @tool
    @idasync
    def miasm_patch_instruction(
        address: Annotated[str, "Address to patch in the IDA database (hex or symbol name)"],
        asm_string: Annotated[str, "Assembly instruction text to assemble and write"],
    ) -> dict:
        """
        Assemble an instruction and patch the bytes into the IDA database at the given address.
        Uses the shortest available encoding. The change is reflected immediately in IDA's view.
        """
        import ida_bytes

        ea = parse_address(address)
        machine = _manager.machine
        bits = _manager.bitness
        loc_db = LocationDB()
        mn = machine.mn
        instr = mn.fromstring(asm_string, loc_db, bits)
        encodings = mn.asm(instr)

        if not encodings:
            raise IDAError(f"No encodings found for: {asm_string!r}")

        shortest = min(encodings, key=len)

        if not ida_bytes.patch_bytes(ea, shortest):
            raise IDAError(f"IDA patch_bytes failed at {hex(ea)}")

        return {
            "ok": True,
            "address": hex(ea),
            "bytes_patched": len(shortest),
            "hex": shortest.hex(),
            "instruction": asm_string,
        }

    # ========================================================================
    # Pattern search (instruction-level)
    # ========================================================================

    @tool
    @idasync
    def miasm_search_instruction_pattern(
        address: Annotated[str, "Any address inside the function to search (hex or symbol name)"],
        mnemonics: Annotated[
            str | list[str],
            "Sequence of mnemonics to match consecutively (case-insensitive). "
            "Accept either a JSON list like ['MOV','PUSH','CALL'] or a "
            "comma-separated string 'MOV,PUSH,CALL'.",
        ],
        max_matches: Annotated[int, "Cap on returned match count (default 200)."] = 200,
    ) -> dict:
        """
        Find every location inside the given function where the supplied
        mnemonic sequence appears as consecutive instructions.

        Useful for spotting prologues, gadget-like sequences, or signature
        instruction patterns the AI wants to locate before deeper analysis.

        Matches are reported as the address of the first instruction in the
        sequence. Searches are case-insensitive and respect basic-block
        boundaries (a pattern straddling a basic-block edge is reported
        only when the consecutive Miasm-disassembled stream lists them in
        sequence within a single block).
        """
        import idaapi

        # Normalise the mnemonics argument
        if isinstance(mnemonics, str):
            seq = [m.strip().upper() for m in mnemonics.split(",") if m.strip()]
        else:
            seq = [str(m).strip().upper() for m in mnemonics if str(m).strip()]

        if not seq:
            return {"ok": False, "error": "Empty mnemonic sequence."}

        ea = parse_address(address)
        func = idaapi.get_func(ea)
        if not func:
            return {"ok": False, "error": f"No function found at {hex(ea)}"}

        data = _manager.get_bytes(func.start_ea, func.end_ea)
        mdis, _ = _manager.get_mdis(data, func.start_ea)

        try:
            asmcfg = mdis.dis_multiblock(func.start_ea)
        except Exception as e:
            return {"ok": False, "error": f"Miasm disassembly failed: {e}"}

        pattern_len = len(seq)
        matches: list[dict] = []

        for block in asmcfg.blocks:
            lines = list(getattr(block, "lines", []) or [])
            if len(lines) < pattern_len:
                continue

            for i in range(len(lines) - pattern_len + 1):
                ok = True
                for j in range(pattern_len):
                    if lines[i + j].name.upper() != seq[j]:
                        ok = False
                        break
                if ok:
                    head = lines[i]
                    tail = lines[i + pattern_len - 1]
                    matches.append(
                        {
                            "address": hex(head.offset),
                            "end_address": hex(tail.offset),
                            "block_loc_key": str(block.loc_key),
                            "instructions": [
                                {"address": hex(lines[i + k].offset), "mnemonic": lines[i + k].name}
                                for k in range(pattern_len)
                            ],
                        }
                    )
                    if len(matches) >= max_matches:
                        break
            if len(matches) >= max_matches:
                break

        return {
            "ok": True,
            "function_ea": hex(func.start_ea),
            "pattern": seq,
            "match_count": len(matches),
            "truncated": len(matches) >= max_matches,
            "matches": matches,
        }
