# Miasm Integration Architecture

## Overview

`api_miasm.py` exposes Miasm's IR lifting, SSA transformation, deobfuscation, and cross-architecture assembly directly inside IDA Pro via the MCP server. Like Triton, there is no separate server — bytes are read from the open IDA database.

## Session Management

Miasm uses a single `_MiasmManager` singleton per IDA process. The `Machine` object is stateless and reused per architecture. A fresh `LocationDB` is created on each `init()` / `reset()` call to prevent symbol contamination.

```python
class _MiasmManager:
    def __init__(self):
        self._lock = threading.Lock()
        self._machine: "Machine | None" = None
        self._arch_name: str = ""
        self._bitness: int = 0
```

## Architecture Detection

IDA `procname` → Miasm arch string. Endianness is checked via `compat.inf_is_be()`:

| IDA procname | Endian | Miasm arch |
|-------------|--------|------------|
| `metapc` | LE | `x86_32` / `x86_64` |
| `arm` | LE | `arml` / `aarch64l` |
| `arm` | BE | `armb` / `aarch64b` |
| `mips` | LE | `mips32l` |
| `mips` | BE | `mips32b` |
| `ppc` | BE | `ppc32b` |

## IR Serialization

The `_ir_blocks_to_dict()` helper converts Miasm IRCFG blocks to a JSON-friendly representation:

```python
def _ir_blocks_to_dict(ircfg) -> list[dict]:
    blocks_out = []
    for loc_key, irblock in _iter_ircfg_blocks(ircfg):
        insts = []
        for assignblk in irblock:
            for dst, src in assignblk.items():
                insts.append({"dst": str(dst), "src": str(src)})
        blocks_out.append({"loc_key": str(loc_key), "instructions": insts})
    return blocks_out
```

This is used by `miasm_lift_function`, `miasm_get_ssa`, `miasm_deobfuscate_cfg`, and the MCP resources.

## Key Analysis Tools

### SSA Transformation
`miasm_get_ssa` applies `SSADiGraph(ircfg).transform(head)` in-place. After transformation, variable names are versioned (e.g., `EAX.0`, `EAX.1`). Phi nodes appear at merge points.

### Dead-Code Elimination
`miasm_deobfuscate_cfg` uses `DeadRemoval(lifter)(ircfg)` which is a callable-style pass. It removes assignments whose results are never used.

### CFG Summary
`miasm_get_cfg_summary` computes:
- Block count, edge count
- Cyclomatic complexity = edges - nodes + 2
- Entry blocks (`ircfg.heads()`)
- Exit blocks (no successors)
- Loop detection via DFS back-edge detection
- Topological ordering via Kahn's algorithm (if DAG)

### Path Constraint Solving
`miasm_solve_path_constraints`:
1. Lifts function to IRCFG
2. Maps target address to `loc_key` via AsmCFG block ranges
3. Enumerates paths using BFS (`_find_all_paths`)
4. Symbolically executes each path with `SymbolicExecutionEngine`
5. Collects branch conditions by inspecting `IRDst` after each block
6. Translates conditions to Z3 via `TranslatorZ3`
7. Solves with `z3.Solver`

**Note:** This tool requires `z3-solver` to be installed separately (`pip install z3-solver`).

### Cross-Architecture Assembly
`miasm_assemble` uses `machine.mn.fromstring()` and `mn.asm()` to produce all valid encodings. `miasm_patch_instruction` writes the shortest encoding into the IDA database via `ida_bytes.patch_bytes`.

## Testing Notes

- All tests skip gracefully when `miasm` is not installed
- `bin_stream_str(data, base_ea)` must receive the absolute IDA EA, not 0
- `lifter.new_ircfg_from_asmcfg(asmcfg)` is the correct official API for IRCFG creation
