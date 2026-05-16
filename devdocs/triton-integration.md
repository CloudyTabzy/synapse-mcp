# Triton Integration Architecture

## Overview

`api_triton.py` exposes Triton's symbolic execution engine directly inside IDA Pro via the MCP server. There is no separate Triton MCP server, no port juggling, and no manual byte feeding — bytes are read directly from the open IDA database.

## Session Management

Each MCP session gets its own `TritonContext`. Contexts are stored in `_contexts: dict[str, TritonContext]` keyed by `_CTX_KEY = "__default__"`. The implementation uses LRU eviction (max 8 contexts) to prevent memory bloat in long-running IDA instances.

```python
_contexts: "OrderedDict[str, TritonContext]" = OrderedDict()
_contexts_lock = threading.Lock()
```

Snapshots are stored separately in `_snapshots: dict[int, dict]` with metadata including:
- symbolic variable origins (register names / memory addresses)
- concrete register values
- taint state
- path predicate AST reference

## Architecture Detection

Triton architecture is always derived from `idaapi.get_inf_structure()` via `compat.inf_get_procname()` and `compat.inf_is_64bit()`. Supported mappings:

| IDA procname | 64-bit | Triton ARCH |
|-------------|--------|-------------|
| `metapc` | True | `ARCH.X86_64` |
| `metapc` | False | `ARCH.X86` |
| `arm` | True | `ARCH.AARCH64` |
| `arm` | False | `ARCH.ARM32` |

## Context Factory

The `_build_ctx()` helper configures sensible defaults:
- `AST_REPRESENTATION.PYTHON`
- `SOLVER.Z3`
- `MODE.AST_OPTIMIZATIONS = True`
- `MODE.CONSTANT_FOLDING = True`
- `MODE.ALIGNED_MEMORY = True`
- `MODE.PC_TRACKING_SYMBOLIC = True`

## Key Internal Helpers

- `_symbolize_registers_internal()` — batch symbolization with error-per-register handling
- `_process_function_instructions_linear()` — linear sweep of a function's instructions, preloading bytes once
- `_try_solve_predicate()` — Z3 solve wrapped in try/except, never raises
- `_build_block_path_to_target()` — BFS over `ida_gdl.FlowChart` to find shortest block path

## Compound Workflows

### `triton_analyze_function`
Runs the full pipeline in one call:
1. (Re-)initialize context
2. Symbolize argument registers
3. Linearly process all instructions
4. Capture state summaries
5. Z3 solve

### `triton_find_input_for_branch`
CFG-guided reachability:
1. BFS over IDA basic blocks from function entry to target block
2. Symbolically execute only blocks on the chosen path
3. Z3 solve for inputs satisfying accumulated constraints

## Annotation Tools

### `triton_annotate_function`
After symbolic execution, writes IDA comments (`idc.set_cmt`) at each branch source address with the stringified path condition.

### `triton_highlight_tainted_instructions`
Processes the function through Triton and uses `idc.set_color` to highlight instructions where `insn.isTainted()` is true.

## Testing Notes

- All tests skip gracefully when `triton-library` is not installed (`pytestmark = pytest.mark.skipif(...)`)
- The test binary assumed by address constants is `crackme03.elf` (x86-64 ELF)
- Compound workflow tests need a live IDA instance
