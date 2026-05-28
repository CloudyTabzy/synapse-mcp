# CLAUDE.md

Guidance for working in this repository.

## What this project is

Fork of [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) that evolves IDA Pro into a **comprehensive binary analysis powerhouse** for AI agents. Built-in symbolic execution, IR lifting, deobfuscation, declarative format parsing, stripped-binary reconnaissance, and cross-engine hybrid workflows — all as native MCP tool modules, with no separate servers required.

Main pieces:
- `src/ida_pro_mcp/server.py`: MCP server entrypoint (proxy to IDA plugin)
- `src/ida_pro_mcp/idalib_server.py`: headless idalib server
- `src/ida_pro_mcp/idalib_supervisor.py`: multi-worker supervisor for headless mode
- `src/ida_pro_mcp/ida_mcp/`: IDA/plugin-side APIs (25 modules, 160+ tools)
- `src/ida_pro_mcp/installer.py`: MCP client config generation and plugin installation

Core API modules (upstream + enhanced):
- `api_core.py`: IDB metadata, functions, strings, imports, exports, entity queries; `list_functions_enhanced` (is_thunk/is_library/is_noret/has_prototype/is_external flags); `list_classes` (C++ namespace/class inventory from mangled names)
- `api_analysis.py`: decompilation, disassembly, xrefs, call graphs, basic blocks, instruction queries, function profiling; `decompile_batch`; `get_function_callers` / `callees` for bidirectional caller-callee lookup; `get_function_signature` (IDB type + Hex-Rays fallback); `get_function_jump_targets` (control-flow triage without full CFG); `get_function_hash` + `get_bulk_function_hashes` (SHA-256 of normalised opcodes — stable across rebase, useful for cross-binary matching); `analyze_function_completeness` + `batch_analyze_completeness` (0–100 documentation score: custom name, type, comment, named stack vars, inline comments); `diff_functions` (unified diff of two decompiled functions with similarity score)
- `api_memory.py`: bytes/ints/strings read and patch, typed integer I/O
- `api_types.py`: structs, type inference, type application, enum management, constructor analysis (`analyze_constructor` — extracts field layout from `*(this+N)=value` patterns, detects vtable pointer writes, memset/memcpy zero-regions, and delegating constructor calls)
- `api_modify.py`: comments, renaming, asm patching, function definition, forced range analysis (`analyze_range`), bulk function creation (`scan_and_define_funcs`), user xref creation (`add_xref`)
- `api_stack.py`: stack frame operations
- `api_sigmaker.py`: signature creation, scanning, xref-based signature generation
- `api_debug.py`: debugger control, breakpoints, `sync_debugger_to_idb` (live memory → IDB patch + analysis), unsafe / low priority for tests
- `api_python.py`: execute Python in IDA context
- `api_resources.py`: `ida://`, `triton://`, `miasm://` MCP resources
- `api_recon.py`: reconnaissance tools for stripped binaries — sections, global writers, VTable candidates (`find_vtable_candidates` auto-detects bitness), `dump_vtable` (read a full vtable by address or class name pattern), indirect calls with diagnostic output, cleanup/method resolution, function prologue detection
- `api_flirt.py`: FLIRT signature management tools — apply signatures, load type libraries, and suggest names for unidentified functions via structural similarity scoring (prologue match, callee Jaccard, string xref overlap)
- `api_survey.py`: one-call binary triage (metadata, segments, imports, strings, statistics)
- `api_composite.py`: multi-step composite operations and cross-engine workflows
- `api_discovery.py`: instance discovery and proxying (`list_instances`, `select_instance`, `get_active_instance` — unambiguously shows which IDB is currently active)
- `api_tasks.py`: async task queue for long-running operations

Optional analysis engine modules (this fork):
- `api_triton.py`: Triton symbolic execution — context lifecycle, symbolization, concrete values, instruction processing, taint analysis, SMT solving, snapshots, instruction trace replay, IDA annotation. Requires `pip install triton-library`.
- `api_miasm.py`: Miasm IR analysis — IR lifting, SSA, CFG analysis, dead-code elimination, symbolic emulation, data-flow tracing, cross-arch assembly/patching, CFG summary, path constraint solving, IDA annotation. Requires `pip install miasm future`.
- `api_composite.py`: Hybrid cross-engine workflows — `hybrid_analyze_function` (Miasm deobfuscation + Triton symbolic execution), `hybrid_deobfuscate_and_patch` (dead-code detection + safe patching), and `hybrid_iterative_deobfuscate` (iterative Miasm simplification loop with Triton equivalence verification until convergence).
- `api_construct.py`: Declarative binary format parsing — PE/ELF/protocol header extraction, custom struct templates, safe DSL evaluator, IDA struct bridge, heuristic guessing, struct scanning. Requires `pip install construct`.
- `api_cstruct.py`: C-syntax binary structure parsing — C-style struct/enum/typedef definitions, pre-built Windows & ELF headers, serialization round-trips, per-endian registry isolation. Requires `pip install dissect.cstruct`.
- `api_filetype.py`: Magic-byte file type identification — 79+ format detection from buffers, IDA addresses, or segments. Requires `pip install filetype`.
- `api_lief.py`: LIEF binary format analysis — `lief_info`, `lief_checksec`, `lief_sections`, `lief_imports`, `lief_exports`, `lief_strings`, `lief_tls_callbacks`, `lief_verify_signature` (Authenticode chain verification), `lief_rich_header` (PE compiler fingerprinting), `lief_pe_overlay` (packed/SFX detection), `lief_guard_functions` (CFG table), `lief_compare_to_idb` (raw file vs IDB diff), `lief_add_section`, `lief_patch_import`, `lief_strip_metadata`, `hybrid_lief_yara_section_scan`, `hybrid_lief_checksec_exploit_assess`, `hybrid_lief_sync_symbols`. Requires `pip install lief`. Extended features (DWARF/PDB debug symbols) require LIEF Extended (commercial).
- `api_yara.py`: YARA signature-based scanning — `yara_scan` (custom rules against IDB range, whole binary, or raw file), `yara_scan_builtin_crypto` (AES/MD5/SHA/CRC32/RC4 constants, no external files), `yara_scan_builtin_threats` (packers, C2 frameworks, hack tools, shellcode), `yara_rule_validate` (syntax check without scanning), `yara_generate_rule` (generate rule from IDA function bytes with pointer wildcarding ⭐), `yara_idb_annotate` (scan all functions + auto-annotate/rename with YARA-derived names ⭐ KILLER FEATURE), `yara_function_classifier` (per-function category heat map), `hybrid_yara_lief_profile` (section-isolated YARA + LIEF checksec → threat profile), `hybrid_yara_triton_verify_crypto` (YARA finds crypto → Triton confirms via symbolic execution), `hybrid_yara_miasm_deobfuscate` (YARA detects packer stubs → Miasm lifts and simplifies). Requires `pip install yara-python`.
- `api_angr.py`: Angr symbolic execution engine — `angr_status`, `angr_load_segment`, `angr_cfg_fast`, `angr_cfg_from_ida`, `angr_diff_cfg`, `angr_find_paths` (⭐ KILLER FEATURE — stdin/argv symbolic modeling solves serial-key crackmes Triton cannot), `angr_enumerate_reachable`, `angr_state_evaluate`, `angr_hook_function` (skip/observe SimProcedures), `angr_backward_slice` (CFG-only fast path or DDG-backed precise mode), `angr_value_set`, `angr_snapshot_save`/`angr_snapshot_restore`, `hybrid_angr_triton_solve` (angr finds the path → Triton enriches with deep register-level state), `hybrid_angr_stdin_fuzz` (char-class-constrained input enumeration), `hybrid_angr_miasm_path`, `hybrid_angr_triton_decompile`, `hybrid_angr_z3_formula` (export SMT-LIB2 path constraints), `workflow_solve_crackme` (⭐ one-call end-to-end serial solver with auto-detect via IDB string xrefs), `workflow_trace_data_flow`, `workflow_find_gadgets` (ROP/JOP), `workflow_enum_code_hints` (prefix constraints across paths). Requires `pip install angr` (~200 MB; NOT in `--install-deps all`). Unicorn hybrid (`hybrid_angr_unicorn_concrete`) is pending Phase 6.3.
- `api_networkx.py`: Graph analysis engine — `nx_status`, `nx_call_graph` (cached LRU), `nx_function_cfg`, `nx_xref_graph`, `nx_subgraph`, `nx_graph_metrics`, `nx_central_functions` (PageRank + betweenness + degree centrality ranking), `nx_shortest_path`, `nx_all_paths`, `nx_cycles`, `nx_strongly_connected`, `nx_neighborhood`, `nx_dominators` (with natural loop header detection), `nx_communities` (Louvain / label-prop / modularity), `nx_topological_order`, `nx_graph_diff` (with name_alignment for cross-binary diffs), `nx_export_graph` (DOT/GraphML/GML/JSON), `hybrid_nx_angr_target_ranking` (centrality-driven symex target recommendations), `hybrid_nx_yara_cluster_detection` (YARA categories + community detection → behavior-labeled clusters), `hybrid_nx_lief_import_graph` (module-centrality), `hybrid_nx_triton_taint_graph`, `workflow_reveng_overview` (⭐ KILLER FEATURE — one-call first-pass binary overview: ranked function importance + SCCs + Louvain communities + YARA labels + prioritized recommendations), `workflow_find_critical_paths` (entry → dangerous-import paths), `workflow_binary_diff_summary` (structural diff with similarity score). Requires `pip install networkx>=3.0` (small, pure-Python; included in `--install-deps all`).

**Instruction trace (Triton):** Each session maintains a `deque` of executed instruction addresses (max 10,000). On `triton_snapshot_save`, the trace is stored in the snapshot. On `triton_snapshot_restore`, it is replayed to rebuild the path predicate. The `triton_replay_instructions` tool gives AI agents manual control over custom instruction sequences.

**Server name:** The MCP server identifies itself to clients as `synapse-mcp`. The canonical name is defined once in `ida_mcp/rpc.py` as `MCP_SERVER_NAME` and imported by `server.py`, `idalib_supervisor.py`, and `installer.py` — no duplication.

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
- `idapython`: IDAPython scripting workflows — py_eval patterns, common IDA API idioms

## Optional-import pattern

All optional modules guard their tool registrations so the plugin loads cleanly when the engine is absent:

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

`__init__.py` imports all modules inside `try/except Exception: pass` so a bad install can't break the plugin.

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

For unsafe operations:
```python
from .rpc import tool, unsafe

@unsafe
@tool
@idasync
def dangerous_op(...):
    ...
```

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

### Canonical parameter names

Use these names consistently. The server proxy normalizes common aliases (e.g. `address`→`addr`, `max_results`→`limit`) for backward compat, but new tools must use the canonical name.

| Concept | Canonical name | Notes |
|---------|---------------|-------|
| Single address (hex or symbol) | `addr` | Not `address`, not `ea`, not `func_addr` unless the param is exclusively a function address |
| List of addresses | `addrs` | Accepts comma-separated string or Python list via `normalize_list_input()` |
| Address range start | `start` | Pair with `end`; these are address params, not pagination |
| Address range end | `end` | Exclusive upper bound |
| Hard cap on results returned | `limit` | Not `max_results`, `max_entries`, or `count` |
| Paginated list size | `count` | Used in list_*/query tools alongside `offset` |
| Page start position | `offset` | Not `start` (which is an address), not `skip` |
| Pagination resume token | `cursor` | Opaque value from previous response; used in `search_text` and streaming tools |
| Name/glob filter | `filter` | For glob patterns against entity names in core list/query tools |
| Text/pattern search | `pattern` | For regex, glob, or substring search across content |
| Binary file path | `file_path` | Not `path`, not `binary_path` |
| Output file path | `output_path` | Not `out_path`, not `output` |

Aliases accepted by the proxy (old → canonical): `address`→`addr`, `addresses`→`addrs`, `max_results`→`limit`, `max_entries`→`limit`, `search_text.start`→`search_text.cursor`.

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
# Normal mode — exposes all 160+ tools (default; backward compatible)
uv run ida-pro-mcp

# Lazy mode — exposes 4 meta-tools only (~95% context reduction, recommended for agents)
uv run ida-pro-mcp --lazy

# Override a saved --lazy config back to full tools for one session
uv run ida-pro-mcp --no-lazy

# HTTP transport
uv run ida-pro-mcp --transport http://127.0.0.1:8744/sse
uv run ida-pro-mcp --lazy --transport http://127.0.0.1:8744/sse

# Headless idalib
uv run idalib-mcp --stdio path/to/binary
uv run idalib-mcp --host 127.0.0.1 --port 8745 path/to/binary
uv run idalib-mcp --isolated-contexts --host 127.0.0.1 --port 8745 path/to/binary

# Unsafe mode (enables debugger tools etc.)
uv run ida-pro-mcp --unsafe
```

### Lazy mode meta-tools
When running with `--lazy`, the server exposes exactly 4 tools instead of 160+:

| Tool | Purpose |
|---|---|
| `list_modules` | List tool groups with live counts. Description embeds the full group directory (top tool names per group) so agents can skip calling this and go straight to `invoke_tool` if they know the name. |
| `list_tools(module=..., search=..., limit=50, offset=0)` | List tools with one-line descriptions. Use `search=` for keyword lookup across all groups — much cheaper than browsing. Use `module=` to see a full group. Both can be combined. |
| `describe_tool(name)` | Get the full input schema for a specific tool. Response includes `module` field. |
| `invoke_tool(tool, args)` | Call any tool by name. Put ALL tool arguments inside `args={...}`. Never place tool inputs beside `tool` at the top level — they are silently ignored. |

**Optimized discovery paths (cheapest first):**
1. Know the name → `invoke_tool` directly (0 discovery calls)
2. Know a keyword → `list_tools(search='keyword')` → `invoke_tool` (1 call)
3. Know the group → `list_tools(module='analysis')` → `invoke_tool` (1 call)
4. Exploring → `list_modules` → `list_tools(module=...)` → `invoke_tool` (2 calls)

**Cache behaviour:** Populated on first `list_tools`, `describe_tool`, or `invoke_tool` call. The `list_modules` description is built with live counts at startup. Call `invoke_tool(tool='__reset_cache__')` to force a refresh (e.g. after IDA loads a new IDB).

### MCP inspector
```bash
uv run mcp dev src/ida_pro_mcp/server.py
```

### Generate MCP client config
```bash
# Normal mode config (all tools)
uv run ida-pro-mcp --config

# Lazy mode config (4 meta-tools, --lazy in args)
uv run ida-pro-mcp --config --lazy
```

### Install / uninstall plugin
```bash
uv run ida-pro-mcp --install
uv run ida-pro-mcp --install --lazy   # writes --lazy into the generated MCP client config
uv run ida-pro-mcp --uninstall
```

### Install optional analysis engines
```bash
# Triton symbolic execution
uv run ida-pro-mcp --install-deps triton
# Miasm IR analysis
uv run ida-pro-mcp --install-deps miasm
# Construct declarative parsing
uv run ida-pro-mcp --install-deps construct
# dissect.cstruct + filetype
uv run ida-pro-mcp --install-deps cstruct
# LIEF binary format analysis
uv run ida-pro-mcp --install-deps lief
# YARA signature scanning
uv run ida-pro-mcp --install-deps yara
# NetworkX graph analysis (small; INCLUDED in --install-deps all)
uv run ida-pro-mcp --install-deps networkx
# Angr symbolic execution (~200 MB; NOT in --install-deps all)
pip install angr
# All at once (excludes angr)
uv run ida-pro-mcp --install-deps all
# TOON token-efficient encoding (server-side; install into the MCP server's Python, NOT IDA's)
pip install toon_format
```

### Verify installation
After connecting your MCP client, call the probe tools:
```
triton_status      # → {"ok": true, "available": true, ...}
miasm_status       # → {"ok": true, "available": true, ...}
construct_status   # → {"ok": true, "available": true, ...}
cstruct_status     # → {"ok": true, "available": true, ...}
filetype_status    # → {"ok": true, "available": true, ...}
lief_status        # → {"ok": true, "available": true, "version": "0.17.x", ...}
yara_status        # → {"ok": true, "available": true, "version": "4.5.x", ...}
angr_status        # → {"ok": true, "available": true, "version": "9.2.x", "claripy_version": "9.2.x", ...}
nx_status          # → {"ok": true, "available": true, "version": "3.x", "cached_graphs": 0, ...}
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
- `api_construct.py`
- `api_cstruct.py`
- `api_filetype.py`
- `api_recon.py`
- `api_tasks.py`
- `utils.py`
- `framework.py`

Medium priority:
- `api_sigmaker.py`
- `api_flirt.py`
- `api_survey.py`
- `api_discovery.py`

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
- `construct>=2.10.68`: Pure-Python, works everywhere. Provides declarative binary format parsing.
- `dissect.cstruct>=4.0`: Pure-Python. C-syntax struct/enum parsing with per-endian registry isolation.
- `filetype>=1.2.0`: Pure-Python. Magic-byte detection (79+ formats).
- `yara-python>=4.3.0`: C-extension YARA binding. Built-in crypto and threat rules are embedded as Python string constants — no external `.yar` files needed. The `yara_idb_annotate` killer feature maps matches back to IDA virtual addresses and cannot be replicated by standalone YARA.
- `networkx>=3.0`: Pure-Python graph algorithms. Powers call-graph centrality (PageRank, betweenness), community detection (Louvain), SCC analysis, shortest paths, dominators, graph diff. The `workflow_reveng_overview` killer feature combines all of these into a one-call structural binary analysis with prioritized recommendations.
- `toon_format>=0.9.0`: **Server-side only** (install into the MCP server's Python, not IDA's). When present, the proxy post-processor automatically TOON-encodes tool responses that contain a uniform flat array of ≥20 rows, yielding ~40% fewer context tokens. Qualifying tools: `lief_exports`, `list_functions_enhanced`, `get_bulk_function_hashes`, `find_global_writers`, `find_function_prologues`, `find_indirect_calls`, and others returning large flat lists. Encoded responses start with `_format: TOON_TABULAR` so agents immediately know the encoding. Falls back to JSON silently when the response doesn't qualify or when an error occurs.
- All engines are optional. The plugin loads cleanly without them; only the `*_status` probe tools report `"available": false`.

### Return-type design principle
Every tool in this fork returns a **structured `dict` / `TypedDict`**, never raw strings or untyped lists. This is intentional:
- AI agents parse fields programmatically without regex.
- Consistent error shape: `{"ok": false, "error": "..."}` across all modules.
- Downstream tools can chain outputs directly.

If you find a tool that returns a plain string, that's a bug — fix it.
