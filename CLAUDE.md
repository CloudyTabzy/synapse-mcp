# CLAUDE.md — Developer Guide

Guidance for contributors and AI agents building tools in this repository.

---

## What this project is

Fork of [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) that extends IDA Pro with **14 analysis engines** and **360+ tools** — all registered through the same `@tool @idasync` machinery.

**Main pieces:**
- `src/ida_pro_mcp/server.py` — MCP server entrypoint (proxy dispatcher; lazy mode lives here)
- `src/ida_pro_mcp/idalib_supervisor.py` — headless idalib worker supervisor
- `src/ida_pro_mcp/idalib_server.py` — headless idalib server
- `src/ida_pro_mcp/ida_mcp/` — IDA/plugin-side APIs (all `api_*.py` modules)
- `src/ida_pro_mcp/installer.py` — MCP client config generation and plugin installation
- `tests/` — standalone pytest tests (no IDA needed): protocol compliance + server transport
- `skills/` — ~13 workflow playbooks teaching agents how to use the tools

**Server name:** The server identifies itself as `synapse-mcp`, defined once in `ida_mcp/rpc.py` as `MCP_SERVER_NAME`.

---

## Adding a new tool

1. Choose the right `api_*.py` module.
2. Define a `TypedDict` for the return type.
3. Apply `@tool` then `@idasync` (in that order — `@tool` is the outer decorator).
4. The docstring becomes the MCP tool description — write it for an AI reader, not a human dev.
5. Add a test in `tests/test_api_*.py`.

```python
from .rpc import tool
from .sync import idasync

class MyResult(TypedDict):
    ok: bool
    value: str

@tool
@idasync
def my_new_tool(
    address: Annotated[str, "Target address (hex or symbol name)"],
) -> MyResult:
    """One-sentence description of what this tool does for an AI agent."""
    ea = parse_address(address)
    ...
    return {"ok": True, "value": ...}
```

### Adding a new optional-engine module

1. Create `api_<engine>.py`.
2. Guard tool registrations with `if ENGINE_AVAILABLE:` block.
3. Register a `*_status` probe tool **outside** the guard so it always reports availability.
4. In `__init__.py`, import the module inside `try/except Exception: pass` so a missing dependency doesn't break the plugin.
5. In `pyproject.toml`, add the dependency to `[project.optional-dependencies]` and the `all` group.
6. Add a `*_status` entry to `_TOOL_MODULE_PREFIXES` in `rpc.py` for lazy-mode grouping.
7. Sync + restart + verify.

---

## Core implementation rules

### IDA thread safety

All IDA SDK calls must execute on the main thread. Use:

```python
@tool
@idasync
def my_tool(...):
    ...
```

`@idasync` wraps the call in `ida_auto.execute_sync()`. Do not call IDA APIs outside of `@idasync`-decorated functions.

### Return-type convention

Every tool returns a **structured `dict` / `TypedDict`** — never raw strings or untyped lists:
- Success: `{"ok": true, ...}`
- Failure: `{"ok": false, "error": "descriptive message"}`
- **Never `raise IDAError(...)`** from within a tool function body — the exception propagates as an ugly JSON-RPC traceback. Return the error dict instead.
- The internal `_MiasmManager` methods and `_trace_data_flow_internal` helper may still raise, but all `@tool @idasync` public functions must return error dicts.

### Canonical parameter names

The server proxy normalizes old aliases for backward compat, but **new tools must use the canonical name**:

| Concept | Canonical name | Notes |
|---------|---------------|-------|
| Single address (hex or symbol) | `addr` | Not `address`, `ea`, or `func_addr` |
| List of addresses | `addrs` | Accepts comma-separated string or Python list via `normalize_list_input()` |
| Address range start/end | `start` / `end` | These are address params, not pagination |
| Hard cap on results | `limit` | Not `max_results`, `max_entries`, or `count` |
| Paginated list size | `count` | Used in `list_*/query` tools alongside `offset` |
| Page start position | `offset` | Not `start` (which is an address) or `skip` |
| Pagination resume token | `cursor` | Opaque value from previous response |
| Name/glob filter | `filter` | For glob patterns against entity names |
| Text/pattern search | `pattern` | For regex, glob, or substring search |
| Binary file path | `file_path` | Not `path` or `binary_path` |
| Output file path | `output_path` | Not `out_path` or `output` |

Aliases accepted by the proxy (old → canonical): `address`→`addr`, `addresses`→`addrs`, `max_results`→`limit`, `max_entries`→`limit`.

### Unsafe operations

Destructive or debugger operations use `@unsafe`:

```python
from .rpc import tool, unsafe

@unsafe
@tool
@idasync
def dangerous_op(...):
    ...
```

Unsafe tools are disabled by default and require the `--unsafe` flag. `miasm_patch_instruction` and `hybrid_deobfuscate_and_patch` (with `dry_run=False`) are examples.

### Output size

Responses >50 KB are auto-truncated with an `output_id` and served via download URL. Handled by `rpc.py` — no per-tool handling needed.

### Error handling principle

Every tool returns a structured `dict`. On success, it includes `{"ok": true, ...}`. On failure, it returns `{"ok": false, "error": "descriptive message"}`. **Never `raise IDAError(...)` from within a tool function body** — the exception propagates as an ugly JSON-RPC traceback to the AI client. Return the error dict instead. The internal `_MiasmManager` methods and `_trace_data_flow_internal` helper may still raise, but all `@tool @idasync` public functions must return error dicts.

### Lazy-mode grouping

When the server runs with `--lazy`, `tools/list` returns only 4 meta-tools. Every new tool must be grouped:

- **Prefix-based**: If the tool has a distinctive prefix (e.g., `triton_`, `miasm_`, `lief_`), add it to `_TOOL_MODULE_PREFIXES` in `rpc.py`. This auto-maps all tools with that prefix to a group.
- **Exact-name**: For tools without a prefix, add to `_TOOL_MODULE_EXACT` in `rpc.py`.
- **Fallback**: Tools that fall through to `core` trigger a startup warning from `_validate_groups()`.

---

## Development commands

### Run the MCP server

```bash
# Normal mode (all tools)
uv run ida-pro-mcp

# Lazy mode (4 meta-tools, ~95% context reduction)
uv run ida-pro-mcp --lazy

# HTTP transport
uv run ida-pro-mcp --transport http://127.0.0.1:8744/sse

# Headless
uv run idalib-mcp --stdio path/to/binary

# Unsafe mode (debugger tools)
uv run ida-pro-mcp --unsafe
```

### Install optional engines

```bash
# Single engine
uv run ida-pro-mcp --install-deps triton
uv run ida-pro-mcp --install-deps yara
uv run ida-pro-mcp --install-deps xor   # z3-solver

# All at once (excludes angr which is ~200 MB)
uv run ida-pro-mcp --install-deps all
```

### MCP client config

```bash
uv run ida-pro-mcp --config
uv run ida-pro-mcp --config --lazy
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

---

## Testing

### IDA-side tests (headless)

```bash
uv run ida-mcp-test tests/crackme03.elf -q
uv run ida-mcp-test tests/typed_fixture.elf -q
uv run ida-mcp-test tests/crackme03.elf -c api_analysis
uv run ida-mcp-test tests/crackme03.elf -p "*xor*"
```

### Standalone pytest (no IDA)

```bash
uv run pytest tests/ -q
```

### Coverage

```bash
uv run coverage erase
uv run coverage run -m ida_pro_mcp.test tests/crackme03.elf -q
uv run coverage run --append -m ida_pro_mcp.test tests/typed_fixture.elf -q
uv run coverage report --show-missing
```

### Test conventions

- Use `@test()` decorator from `framework.py`.
- Use `@test(binary="crackme03.elf")` for fixture-specific tests.
- Guard optional-engine tests: `pytestmark = pytest.mark.skipif(not MIASM_AVAILABLE, ...)`.
- Prefer semantic assertions over weak "field exists" checks.
- Prefer round-trip tests for mutating APIs.
- If tests expose clearly wrong API behaviour, fix the API instead of weakening the test.
- Expect some IDA / Hex-Rays variance; guarded assertions or runtime skips are acceptable.
- When adding generic tests, also try a non-fixture binary to avoid ELF-specific assumptions.

---

## Module index

| Module | Tools | Purpose |
|--------|------:|---------|
| `api_core.py` | 18 | IDB metadata, functions, strings, imports, entity queries |
| `api_analysis.py` | 35 | Decompilation, disassembly, xrefs, callgraph, feature analysis, XOR pattern detection |
| `api_memory.py` | 7 | Bytes/ints/strings read and patch |
| `api_types.py` | 12 | Structs, type inference, type application, enum management |
| `api_modify.py` | 12 | Comments, renaming, asm patching, function definition |
| `api_stack.py` | 3 | Stack frame variables |
| `api_sigmaker.py` | 5 | Signature creation and scanning |
| `api_debug.py` | 24 | Debugger control, breakpoints, `sync_debugger_to_idb` (unsafe) |
| `api_python.py` | 2 | Execute Python in IDA context |
| `api_recon.py` | 11 | Stripped binary recon, vtable scanning, indirect call detection |
| `api_flirt.py` | 4 | FLIRT signature application |
| `api_survey.py` | 1 | One-call binary triage |
| `api_composite.py` | 11 | Multi-step composite + cross-engine workflows |
| `api_discovery.py` | 6 | Instance discovery and proxying |
| `api_tasks.py` | 4 | Async task queue |
| `api_triton.py` | 51 | Symbolic execution, taint, SMT solving |
| `api_miasm.py` | 22 | IR lifting, SSA, deobfuscation, cross-arch assembly |
| `api_construct.py` | 10 | Declarative format parsing |
| `api_cstruct.py` | 7 | C-syntax struct parsing |
| `api_filetype.py` | 4 | Magic-byte file type identification |
| `api_lief.py` | 26 | Binary format analysis, checksec, signatures |
| `api_yara.py` | 11 | Signature scanning, crypto/threat detection |
| `api_angr.py` | 23 | Symbolic execution, stdin/argv solving |
| `api_networkx.py` | 24 | Graph metrics, centrality, communities |
| `api_numpy.py` | 9 | Entropy maps, byte histograms, XOR recovery, similarity |
| `api_unicorn.py` | 14 | Concrete CPU emulation, decrypt-and-patch |
| `api_xor.py` | 3 | Universal XOR cipher solver (always-on) |

---

## Scope priorities

**High:** `api_analysis.py`, `api_types.py`, `api_modify.py`, `api_memory.py`, `api_core.py`, `api_triton.py`, `api_miasm.py`, `api_construct.py`, `api_cstruct.py`, `api_filetype.py`, `api_lief.py`, `api_yara.py`, `api_angr.py`, `api_networkx.py`, `api_numpy.py`, `api_unicorn.py`, `api_xor.py`, `api_recon.py`, `api_tasks.py`, `api_composite.py`, `utils.py`, `framework.py`

**Medium:** `api_sigmaker.py`, `api_flirt.py`, `api_survey.py`, `api_discovery.py`, `api_stack.py`

**Lower:** `api_debug.py`, MCP transport / hosting internals, install / config mutation logic

---

## Practical notes

- **Python**: 3.11+ required (server and plugin side).
- **IDA Pro**: 8.3+; 9.x recommended. IDA Free is **not supported**.
- **Package manager**: Use `uv run`, not `python` directly.
- **Python interpreter**: If IDA uses the wrong one, run `idapyswitch`.
- **Dependencies**:
  - `triton-library`: Prebuilt wheels on Windows. On Linux/macOS you may need to build from source or use Conda.
  - `miasm>=0.1.5`: Pure-Python core. JIT compilation is optional and disabled by default on Windows.
  - `construct>=2.10.68`: Pure-Python.
  - `dissect.cstruct>=4.0`: Pure-Python.
  - `filetype>=1.2.0`: Pure-Python.
  - `yara-python>=4.3.0`: C-extension binding. Built-in crypto and threat rules are embedded as Python string constants — no external `.yar` files needed.
  - `networkx>=3.0`: Pure-Python.
  - `toon_format>=0.9.0`: Token-efficient response encoding. Install into whichever Python serializes responses (IDA's Python for HTTP transport, server's Python for stdio proxy). Installing in both is safe.
  - All engines are optional. The plugin loads cleanly without them.

### Sync script

`C:\Dev\IDA_Pro_Plugin\ida-mcp-sync.ps1` copies all `.py` files from `src\ida_pro_mcp\ida_mcp\` → `AppData\ida_mcp\`, clears bytecode, and launches IDA. Use `-NoLaunch` to skip the IDA launch.

### Post-sync validation

The sync script does **not** check Python syntax. Run this after syncing:
```bash
python -m py_compile src/ida_pro_mcp/ida_mcp/api_*.py
```
