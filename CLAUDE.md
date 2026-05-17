# CLAUDE.md

Guidance for working in this repository.

## What this project is

Fork of [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) that adds **Triton symbolic execution** and **Miasm IR analysis** as native built-in tool modules.

Main pieces:
- `src/ida_pro_mcp/server.py`: MCP server entrypoint
- `src/ida_pro_mcp/idalib_server.py`: headless idalib server
- `src/ida_pro_mcp/ida_mcp/`: IDA/plugin-side APIs

Core API modules (upstream):
- `api_core.py`: IDB metadata, functions, strings, imports
- `api_analysis.py`: decompilation, disassembly, xrefs, paths, pattern search
- `api_memory.py`: bytes/ints/strings, patching
- `api_types.py`: structs, type inference, type application
- `api_modify.py`: comments, renaming, asm patching
- `api_stack.py`: stack frame operations
- `api_sigmaker.py`: signature creation, scanning, xref signatures (uses sigmaker.py)
- `api_debug.py`: debugger control, unsafe / low priority for tests
- `api_python.py`: execute Python in IDA context
- `api_resources.py`: `ida://` MCP resources
- `api_recon.py`: reconnaissance tools for stripped binaries — sections, global writers, VTable candidates, indirect calls, cleanup/method resolution, function prologue detection
- `api_flirt.py`: FLIRT signature management tools

Optional analysis engine modules (this fork):
- `api_triton.py`: Triton symbolic execution — 38 tools covering context lifecycle, symbolization, concrete values, instruction processing, taint analysis, SMT solving, snapshots, instruction trace replay, IDA annotation, taint highlighting, and backward slicing. Requires `pip install triton-library`.
- `api_miasm.py`: Miasm IR analysis — 21 tools covering IR lifting, SSA, CFG analysis, dead-code elimination, symbolic emulation, data-flow tracing, cross-arch assembly/patching, CFG summary, path constraint solving, and IDA annotation. Requires `pip install miasm future`.
- `api_composite.py`: Hybrid cross-engine workflows — `hybrid_analyze_function` (Miasm deobfuscation + Triton symbolic execution), `hybrid_deobfuscate_and_patch` (dead-code detection + safe patching), and `hybrid_iterative_deobfuscate` (iterative Miasm simplification loop with Triton equivalence verification until convergence).
- `api_construct.py`: Declarative binary format parsing — 5 tools using `construct 2.10.x` grammar to parse/build arbitrary binary structures. Per-endian registry isolation. Requires `pip install construct`.
- `api_cstruct.py`: C-syntax binary structure parsing — 7 tools using Fox-IT `dissect.cstruct 4.x`. Supports C-style struct/enum/typedef definitions. Uses **per-endian registry isolation** (separate `cstruct` instances keyed by `f"{session}_{endian}"`) to avoid `cs.endian` live-reference mutation bugs. Requires `pip install dissect.cstruct`.
- `api_filetype.py`: Magic-byte file type identification — 4 tools using `filetype 1.x` (79+ formats, 261-byte window). Can identify formats from hex buffers, IDA addresses, or named segments. Requires `pip install filetype`.
- `api_tasks.py`: Async task queue — `task_submit`, `task_poll`, `task_list`, `task_cancel`. Submit heavy tools (decompile, Triton/Miasm analysis, callgraph) as background tasks to avoid MCP client timeouts. Worker threads replay the submitter's extension/unsafe context.

**Instruction trace (Triton):** Each session maintains a `deque` of executed instruction addresses (max 10,000). On `triton_snapshot_save`, the trace is stored in the snapshot. On `triton_snapshot_restore`, it is replayed to rebuild the path predicate. The new `triton_replay_instructions` tool gives AI agents manual control over custom instruction sequences.

**Server name:** The MCP server identifies itself to clients as `ida-pro-triton-miasm-mcp`. The canonical name is defined once in `ida_mcp/rpc.py` as `MCP_SERVER_NAME` and imported by `server.py`, `idalib_supervisor.py`, and `installer.py` — no duplication.

**Return-type design principle:**
Every tool in this fork returns a **structured `dict` / `TypedDict`**, never raw strings or untyped lists. This is intentional:
- AI agents parse fields programmatically without regex.
- Consistent error shape: `{"ok": false, "error": "..."}` across all modules.
- Downstream tools can chain outputs directly.

If you find a tool that returns a plain string where a dict is expected, that's a bug — fix it.

Workflow skills (`skills/`):
- `binary-survey`: Initial reconnaissance — metadata, segments, imports, strings, function triage
- `stripped-binary-recovery`: Recover semantics from stripped binaries — FLIRT signatures, code gaps, string xrefs, constant matching, call-graph hub analysis, structural similarity
- `function-deep-dive`: Thorough single-function analysis — decompile, disasm, xrefs, control flow, stack frame, rename, type, comment
- `triton-symbolic-exec`: Symbolic execution workflows — one-shot, instruction-by-instruction, taint analysis, branch-target solving
- `miasm-ir-analysis`: IR analysis workflows — CFG metrics, SSA, deobfuscation, data-flow tracing, path solving
- `hybrid-deobfuscate`: Cross-engine deobfuscation — Miasm simplification → Triton analysis → optional patching
- `vuln-hunter-static`: Static vulnerability hunting — dangerous API enumeration, xref analysis, input validation checks

## Optional-import pattern

Both `api_triton.py` and `api_miasm.py` guard their tool registrations so the plugin loads cleanly when the engine is absent:

```python
try:
    import triton as _triton_lib
    TRITON_AVAILABLE = True
except ImportError:
    TRITON_AVAILABLE = False

# One status probe tool is always registered (outside the guard)
# It returns a dict so AI agents can check availability programmatically
@tool
@idasync
def triton_status() -> dict: ...

# All other tools are inside the guard
if TRITON_AVAILABLE:
    @tool
    @idasync
    def triton_init(...): ...
```

`__init__.py` imports both modules inside `try/except Exception: pass` so a bad install can't break the plugin.

## Core implementation rules

### IDA thread safety
All IDA SDK calls must run on the main thread.
Use:
```python
from .rpc import tool
from .sync import idasync

@tool
@idasync
def my_tool(...):
    ...
```

Decorator order matters: `@tool` is outer, `@idasync` is inner.

### API conventions
- Prefer batch-first APIs.
- Many functions accept either a comma-separated string or a list.
- Use full type hints and `Annotated[...]` descriptions.
- The function docstring becomes the MCP tool description.

Example:
```python
def my_api(addrs: Annotated[str, "Addresses (0x401000, main) or list"]) -> list[dict]:
    ...
```

### Common helpers
- Parse addresses with `parse_address()`
- Normalize batch input with `normalize_list_input()` / `normalize_dict_list()`
- Use shared pagination / filtering helpers from `utils.py`

### Unsafe operations
Debugger or destructive operations should be marked unsafe:
```python
from .rpc import tool, unsafe

@unsafe
@tool
@idasync
def dangerous_op(...):
    ...
```

## Development commands

### Run
```bash
uv run ida-pro-mcp
uv run ida-pro-mcp --transport http://127.0.0.1:8744/sse
uv run idalib-mcp --stdio path/to/binary
uv run idalib-mcp --host 127.0.0.1 --port 8745 path/to/binary
uv run idalib-mcp --isolated-contexts --host 127.0.0.1 --port 8745 path/to/binary
uv run ida-pro-mcp --unsafe
```

### MCP inspector
```bash
uv run mcp dev src/ida_pro_mcp/server.py
```

### Install / uninstall plugin
```bash
uv run ida-pro-mcp --install
uv run ida-pro-mcp --uninstall
```

### Install optional analysis engines
```bash
# Triton symbolic execution
uv run ida-pro-mcp --install-deps triton
# Miasm IR analysis
uv run ida-pro-mcp --install-deps miasm
# Both at once
uv run ida-pro-mcp --install-deps all

# Binary format parsing libraries (install manually into IDA's Python)
pip install construct          # construct_* tools
pip install dissect.cstruct    # cstruct_* tools
pip install filetype           # filetype_* tools
```

### Verify installation
After connecting your MCP client, call the probe tools:
```
triton_status   # → {"ok": true, "available": true, ...}
miasm_status    # → {"ok": true, "available": true, ...}
```

## Testing and coverage

### Run tests
Use the headless test runner:
```bash
uv run ida-mcp-test tests/crackme03.elf -q
uv run ida-mcp-test tests/typed_fixture.elf -q
uv run ida-mcp-test tests/crackme03.elf -c api_analysis
uv run ida-mcp-test tests/typed_fixture.elf -p "*stack*"
```

Notes:
- Use `uv run ...`
- Non-interactive output should show failures only plus a summary
- Binary-specific tests should use `@test(binary="...")` with the executable basename

### Coverage
Measure coverage across both maintained fixtures:
```bash
uv run coverage erase
uv run coverage run -m ida_pro_mcp.test tests/crackme03.elf -q
uv run coverage run --append -m ida_pro_mcp.test tests/typed_fixture.elf -q
uv run coverage report --show-missing
```

Current fixture intent:
- `tests/crackme03.elf`: compact general regression fixture
- `tests/typed_fixture.elf`: typed globals / structs / locals / stack coverage fixture

### Test expectations
- Prefer semantic assertions, not weak "field exists" checks
- Prefer round-trip tests for mutating APIs
- If tests expose clearly wrong API behavior, fix the API instead of weakening the test
- Focus on IDA-facing modules, not server/config plumbing
- Expect some IDA / Hex-Rays variance; guarded assertions or runtime skips are acceptable when justified

### Generic-test sanity check
When adding generic tests, also try a non-fixture binary to avoid ELF-specific assumptions:
```bash
uv run ida-mcp-test "C:\CodeBlocks\x64dbg\bin\x64\x64dbg.dll" -q
```

## Scope priorities

High priority:
- `api_analysis.py`
- `api_types.py`
- `api_modify.py`
- `api_stack.py`
- `api_memory.py`
- `api_core.py`
- `api_resources.py`
- `api_triton.py`
- `api_miasm.py`
- `api_composite.py` (hybrid tools)
- `utils.py`
- `framework.py`

Lower priority:
- `api_debug.py`
- MCP transport / hosting details
- install / config mutation logic

## Practical notes

- Server/plugin Python: 3.11+
- IDA Pro 8.3+; 9.0 recommended
- IDA Free is not supported
- If IDA uses the wrong Python, use `idapyswitch`

### Dependency notes
- `triton-library`: Prebuilt wheels available on Windows. On Linux/macOS you may need to build from source or use Conda.
- `miasm>=0.1.5`: Pure-Python core. The `future` package is an additional dependency (bundled with `--install-deps miasm`). JIT compilation is optional and disabled by default on Windows.
- Both engines are optional. The plugin loads cleanly without them; only the `*_status` probe tools report `"available": false`.

### Return-type design principle
Every tool in this fork returns a **structured `dict` / `TypedDict`**, never raw strings or untyped lists. This is intentional:
- AI agents parse fields programmatically without regex.
- Consistent error shape: `{"ok": false, "error": "..."}` across all modules.
- Downstream tools can chain outputs directly.

If you find a tool that returns a plain string, that's a bug — fix it.
