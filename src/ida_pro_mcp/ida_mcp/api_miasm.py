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

from .rpc import tool
from .sync import idasync, IDAError
from . import compat

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

    def _do_sync(self) -> str:
        procname = compat.inf_get_procname().lower()
        if compat.inf_is_64bit():
            bits = 64
        elif compat.inf_is_32bit():
            bits = 32
        else:
            bits = 16

        if procname.startswith("metapc") or procname.startswith("80"):
            arch = f"x86_{bits}"
        elif procname.startswith("arm"):
            arch = "aarch64l" if bits == 64 else "arml"
        elif procname.startswith("mips"):
            arch = "mips32l"
        elif procname.startswith("ppc"):
            arch = "ppc32b"
        else:
            raise IDAError(f"Unsupported architecture for Miasm: {procname!r}")

        self._machine = Machine(arch)
        self._arch_name = arch
        self._bitness = bits
        return arch

    def sync(self) -> str:
        with self._lock:
            return self._do_sync()

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
def miasm_status() -> str:
    """Report Miasm availability and current architecture state."""
    if not MIASM_AVAILABLE:
        return (
            "Miasm is NOT installed.\n"
            "Install with: ida-pro-mcp --install-deps miasm\n"
            "or: pip install miasm future"
        )
    try:
        import miasm
        ver = getattr(miasm, "__version__", "unknown")
    except Exception:
        ver = "unknown"

    lines = [
        f"Miasm version : {ver}",
        f"Available     : yes",
    ]
    if _manager._arch_name:
        lines.append(f"Architecture  : {_manager.arch_name}")
        lines.append(f"Bitness       : {_manager.bitness}")
    else:
        lines.append("Architecture  : (not synced — will auto-detect on first use)")
    return "\n".join(lines)


# ============================================================================
# Context / sync
# ============================================================================


if MIASM_AVAILABLE:

    @tool
    @idasync
    def miasm_sync() -> str:
        """Re-synchronise Miasm architecture with the currently loaded IDA binary."""
        arch = _manager.sync()
        return f"Miasm synchronised: architecture={arch}, bitness={_manager.bitness}"

    # ========================================================================
    # IR lifting
    # ========================================================================

    @tool
    @idasync
    def miasm_lift_to_ir(
        address: Annotated[int, "Start address (hex or decimal) of the range to lift"],
        end_address: Annotated[int, "End address (exclusive) of the range to lift"],
    ) -> list[dict]:
        """Disassemble an address range and lift it to Miasm IR. Returns a list of IR blocks."""
        data = _manager.get_bytes(address, end_address)
        mdis, loc_db = _manager.get_mdis(data, address)

        asm_block = mdis.dis_block(address)
        lifter = _manager.machine.lifter_model_call(loc_db)
        ircfg = lifter.new_ircfg()
        lifter.add_asmblock_to_ircfg(asm_block, ircfg)

        return _ir_blocks_to_dict(ircfg)

    @tool
    @idasync
    def miasm_lift_function(
        address: Annotated[int, "Any address inside the function to lift"],
    ) -> dict:
        """Lift an entire function's CFG to Miasm IR and return all IR blocks and edges."""
        import idaapi
        func = idaapi.get_func(address)
        if not func:
            raise IDAError(f"No function found at {hex(address)}")

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
        address: Annotated[int, "Any address inside the function to transform"],
    ) -> dict:
        """Lift a function to IR and transform it into Static Single Assignment (SSA) form."""
        import idaapi
        from miasm.analysis.ssa import SSADiGraph

        func = idaapi.get_func(address)
        if not func:
            raise IDAError(f"No function found at {hex(address)}")

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
        address: Annotated[int, "Any address inside the function"],
    ) -> str:
        """Return a Graphviz DOT string for the function's assembly CFG."""
        import idaapi
        func = idaapi.get_func(address)
        if not func:
            raise IDAError(f"No function found at {hex(address)}")

        data = _manager.get_bytes(func.start_ea, func.end_ea)
        mdis, _ = _manager.get_mdis(data, func.start_ea)

        asmcfg = mdis.dis_multiblock(func.start_ea)
        return asmcfg.dot()

    @tool
    @idasync
    def miasm_find_paths(
        start_ea: Annotated[int, "Start address — must be inside the same function as target_ea"],
        target_ea: Annotated[int, "Target address to reach"],
        max_paths: Annotated[int, "Maximum number of paths to return (default 20)"] = 20,
    ) -> list[dict]:
        """Find all execution paths between two addresses within the same function."""
        import idaapi
        func = idaapi.get_func(start_ea)
        if not func:
            raise IDAError(f"No function found at {hex(start_ea)}")

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
            if bstart <= start_ea <= bend:
                start_loc = block.loc_key
            if bstart <= target_ea <= bend:
                target_loc = block.loc_key

        if start_loc is None:
            raise IDAError(f"Address {hex(start_ea)} not found in function blocks.")
        if target_loc is None:
            raise IDAError(f"Address {hex(target_ea)} not found in function blocks.")

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
        address: Annotated[int, "Any address inside the function to deobfuscate"],
    ) -> dict:
        """
        Lift a function to IR and apply dead-code elimination to simplify obfuscated CFGs.
        Returns the simplified IR blocks and edges.
        """
        import idaapi
        from miasm.analysis.data_flow import DeadRemoval

        func = idaapi.get_func(address)
        if not func:
            raise IDAError(f"No function found at {hex(address)}")

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
        address: Annotated[int, "Start address of the block to symbolically simplify"],
    ) -> dict:
        """
        Symbolically execute a single basic block and return the simplified register state.
        Only registers whose values changed (i.e. are non-identity after simplification) are reported.
        """
        from miasm.ir.symbexec import SymbolicExecutionEngine

        end_ea = address + 256
        data = _manager.get_bytes(address, end_ea)
        mdis, loc_db = _manager.get_mdis(data, address)

        asm_block = mdis.dis_block(address)
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

        return {"address": hex(address), "simplified_registers": regs}

    # ========================================================================
    # Symbolic execution
    # ========================================================================

    @tool
    @idasync
    def miasm_emulate_symbolic(
        address: Annotated[int, "Start address of the block to emulate"],
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

        end_ea = address + 256
        data = _manager.get_bytes(address, end_ea)
        mdis, loc_db = _manager.get_mdis(data, address)

        asm_block = mdis.dis_block(address)
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

        return {"address": hex(address), "registers": regs}

    # ========================================================================
    # Data flow / side effects
    # ========================================================================

    @tool
    @idasync
    def miasm_get_function_side_effects(
        address: Annotated[int, "Any address inside the function to analyse"],
    ) -> dict:
        """
        Report which registers and memory locations are read and written by a function.
        Useful for quickly understanding a function's I/O surface.
        """
        import idaapi

        func = idaapi.get_func(address)
        if not func:
            raise IDAError(f"No function found at {hex(address)}")

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

    @tool
    @idasync
    def miasm_trace_data_flow(
        register: Annotated[str, "Register name whose origin to trace (e.g. EAX, RAX)"],
        address: Annotated[int, "Address of the instruction where the register value is used"],
    ) -> list[str]:
        """
        Trace the data-flow origins of a register at a given address using Miasm's dependency graph.
        Returns a list of IR expression nodes that contribute to the register's value.
        """
        import idaapi
        from miasm.analysis.depgraph import DependencyGraph

        func = idaapi.get_func(address)
        if not func:
            raise IDAError(f"No function found at {hex(address)}")

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
                if instr is not None and instr.offset == address:
                    target_loc = irblock.loc_key
                    line_nb = idx
                    break
            if target_loc is not None:
                break

        if target_loc is None:
            raise IDAError(f"Address {hex(address)} not found in function IR blocks.")

        sols = dg.get(target_loc, {reg_expr}, line_nb, set())

        output: list[str] = []
        for graph in sols:
            for node in graph.nodes():
                output.append(str(node))

        return output

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

    @tool
    @idasync
    def miasm_patch_instruction(
        address: Annotated[int, "Address to patch in the IDA database"],
        asm_string: Annotated[str, "Assembly instruction text to assemble and write"],
    ) -> str:
        """
        Assemble an instruction and patch the bytes into the IDA database at the given address.
        Uses the shortest available encoding. The change is reflected immediately in IDA's view.
        """
        import ida_bytes

        machine = _manager.machine
        bits = _manager.bitness
        loc_db = LocationDB()
        mn = machine.mn
        instr = mn.fromstring(asm_string, loc_db, bits)
        encodings = mn.asm(instr)

        if not encodings:
            raise IDAError(f"No encodings found for: {asm_string!r}")

        shortest = min(encodings, key=len)

        if not ida_bytes.patch_bytes(address, shortest):
            raise IDAError(f"IDA patch_bytes failed at {hex(address)}")

        return (
            f"Patched {len(shortest)} bytes at {hex(address)}: {shortest.hex()}\n"
            f"Instruction: {asm_string}"
        )
