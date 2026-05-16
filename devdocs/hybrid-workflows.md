# Hybrid Cross-Engine Workflows

## Overview

The hybrid tools in `api_composite.py` combine Miasm's static IR analysis with Triton's dynamic symbolic execution. The goal is to give AI agents a single-call interface for complex obfuscated-binary analysis tasks that would otherwise require multiple round-trips.

## Design Philosophy

1. **Miasm first** — Use Miasm to simplify the IR before Triton sees it. This reduces path explosion on obfuscated code.
2. **Triton verifies** — After Miasm proposes simplifications, Triton can symbolically execute both original and simplified paths to check semantic equivalence.
3. **Safe by default** — Destructive operations (`hybrid_deobfuscate_and_patch` with `dry_run=False`) require `confirm=True` and are marked `@unsafe`.

## `hybrid_analyze_function`

### Data Flow

```
IDA bytes
    ↓
Miasm: lift → DeadRemoval → simplified IRCFG
    ↓
Triton: init → symbolize args → linear execute → Z3 solve
    ↓
Unified JSON report
```

### Implementation Details

- Miasm and Triton phases run sequentially in the same `@idasync` context.
- Internal helpers are imported lazily inside the function to avoid circular imports (`api_composite` is loaded before `api_triton` / `api_miasm` in `__init__.py`).
- The Triton context is initialized/reused via `_CTX_KEY`.
- Miasm's `_manager` handles architecture detection and byte reading.

### Return Value

```json
{
  "ok": true,
  "function_ea": "0x401000",
  "miasm": {
    "block_count": 12,
    "block_reduction": 3,
    "deobfuscation_applied": true
  },
  "triton": {
    "instructions_processed": 87,
    "new_path_constraints": 4,
    "symbolic_variables": [...],
    "tainted_outputs": {...}
  },
  "solver": {
    "sat": true,
    "model": {"arg0": "0x2a"}
  }
}
```

## `hybrid_deobfuscate_and_patch`

### Data Flow

```
IDA bytes
    ↓
Miasm: lift → DeadRemoval
    ↓
Identify empty IR blocks (all assignments dead)
    ↓
Map empty blocks back to AsmCFG address ranges
    ↓
Report patch candidates (dry_run=True)
    ↓
If dry_run=False + confirm=True: assemble NOPs → ida_bytes.patch_bytes
```

### Safety Measures

- `@unsafe` decorator — tool is disabled unless `--unsafe` flag is passed to the server
- `dry_run=True` by default — only reports, never patches
- `confirm=True` required when `dry_run=False` — explicit user confirmation
- NOP bytes are generated via Miasm's assembler for the current architecture (fallback to `\x90`)

### Patch Candidate Format

```json
{
  "address": "0x401020",
  "size": 15,
  "reason": "Block empty after dead-code elimination"
}
```

## When to Use Which

| Scenario | Recommended Tool |
|----------|-----------------|
| Understand a function's symbolic behavior | `hybrid_analyze_function` |
| Find inputs that reach a specific branch | `triton_find_input_for_branch` or `miasm_solve_path_constraints` |
| Remove obvious dead code from obfuscated binary | `hybrid_deobfuscate_and_patch` (dry_run first) |
| Annotate IDA with analysis results | `triton_annotate_function`, `miasm_annotate_data_flow` |
| Browse IR/SSA without running analysis | `miasm://function/{addr}/ir` resource |

## Known Limitations

- `hybrid_deobfuscate_and_patch` only patches entire empty blocks, not individual dead instructions within live blocks.
- Miasm's `DeadRemoval` may not catch all forms of obfuscation (e.g., opaque predicates that Miasm cannot prove constant).
- Triton path explosion is still possible on large functions even after Miasm simplification; use `max_insns` caps.
- `miasm_solve_path_constraints` requires `z3-solver` to be installed separately.
