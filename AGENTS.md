# AGENTS.md

Guidance for AI agents and contributors working in this repository.

---

## What this project is

**Synapse MCP** (`synapse-mcp` on PyPI) is a fork of [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) that extends the IDA Pro MCP server with built-in support for seven optional binary analysis engines:

- **Triton** (`triton-library`) — dynamic symbolic execution, taint analysis, SMT constraint solving
- **Miasm** (`miasm`) — binary IR lifting, SSA transformation, deobfuscation, cross-architecture assembly
- **Construct** (`construct`) — declarative binary format parsing, PE/ELF/protocol header extraction, IDA struct bridge
- **dissect.cstruct** (`dissect.cstruct`) — C-syntax struct/enum parsing and serialization
- **filetype** (`filetype`) — magic-byte file type identification
- **LIEF** (`lief`) — binary format analysis (PE/ELF/Mach-O), checksec, Authenticode, Rich Header
- **YARA** (`yara-python`) — signature-based scanning, built-in crypto/threat rules, IDB annotation

All engines are **optional built-in modules**, not separate servers. They register their tools through the same `@tool @idasync` machinery as the rest of the IDA API modules. If a library is not installed, its tools are silently absent (except a `*_status` probe tool that always reports availability).

---

## Project goals

1. Give AI agents the full Triton symbolic execution surface inside IDA — no separate MCP, no zeromcp patching, no port juggling.
2. Give AI agents Miasm's IR lifting, deobfuscation, and assembly capabilities inside IDA — same constraint.
3. Provide composite cross-engine workflows (`hybrid_*` tools) for obfuscated binary analysis.
4. Give AI agents LIEF binary intelligence and YARA signature scanning inside IDA — same constraint.
5. Maintain full backward compatibility with the upstream `ida-pro-mcp` API and test suite.

---

## Project layout

```
synapse-mcp/
├── CLAUDE.md                        ← IDA-specific dev rules (authoritative)
├── pyproject.toml                   ← package metadata, optional deps, scripts
├── uv.lock                          ← locked dependencies
├── devdocs/                         ← architecture notes and deep dives
├── plans/                           ← (outside repo) phased implementation plans
├── profiles/                        ← installation profiles (Claude Code plugin etc.)
├── skills/                          ← Claude Code skills for this project
├── tests/                           ← standalone pytest tests (no IDA needed)
│   ├── test_mcp_spec_*.py           ← MCP protocol compliance tests
│   └── test_server_transport.py     ← HTTP/SSE transport tests
└── src/ida_pro_mcp/
    ├── server.py                    ← MCP server entrypoint (proxy dispatcher)
    ├── idalib_supervisor.py         ← headless idalib worker supervisor
    ├── idalib_server.py             ← headless idalib server
    ├── ida_mcp.py                   ← IDA plugin entrypoint (loaded by IDA)
    └── ida_mcp/
        ├── __init__.py              ← imports all API modules; ADD new modules here
        ├── rpc.py                   ← @tool, @unsafe, @resource decorators + MCP_SERVER
        ├── sync.py                  ← @idasync thread-safety decorator
        ├── utils.py                 ← shared helpers (parse_address, paginate, ...)
        ├── compat.py                ← IDA version shims
        ├── discovery.py            ← IDA instance discovery + port probing
        ├── http.py                  ← HTTP transport handler
        ├── zeromcp/                 ← vendored + extended zeromcp (do not edit)
        │
        ├── api_core.py              ← IDB metadata, functions, strings, imports
        ├── api_analysis.py          ← decompilation, disassembly, xrefs, callgraph
        ├── api_memory.py            ← bytes/ints/strings read and patch
        ├── api_types.py             ← structs, type inference, type application
        ├── api_modify.py            ← comments, renaming, asm patching
        ├── api_stack.py             ← stack frame variables
        ├── api_debug.py             ← debugger control (unsafe)
        ├── api_python.py            ← execute Python in IDA context
        ├── api_resources.py         ← ida:// MCP resources
        ├── api_survey.py            ← high-level survey tools
        ├── api_composite.py         ← multi-step composite operations
        ├── api_discovery.py         ← instance discovery tools
        ├── api_sigmaker.py          ← FLIRT signature tools
        ├── api_recon.py             ← stripped binary reconnaissance
        ├── api_tasks.py             ← async task queue
        ├── api_flirt.py             ← FLIRT signature application
        │
        ├── api_triton.py            ← Triton symbolic execution (optional)
        ├── api_miasm.py             ← Miasm IR analysis (optional)
        ├── api_construct.py         ← Construct declarative parsing (optional)
        ├── api_cstruct.py           ← C-syntax struct parsing (optional)
        ├── api_filetype.py          ← Magic-byte file type ID (optional)
        ├── api_lief.py              ← LIEF binary analysis (optional)
        ├── api_yara.py              ← YARA signature scanning (optional)
        ├── api_angr.py              ← Angr symbolic execution (optional)
        ├── api_networkx.py          ← NetworkX graph metrics (optional)
        │
        └── tests/                   ← IDA-side tests (run via ida-mcp-test)
            ├── test_api_core.py
            ├── test_api_analysis.py
            ├── ... (one file per api_*.py)
            ├── test_api_triton.py   ← auto-skip if triton-library absent
            ├── test_api_miasm.py    ← auto-skip if miasm absent
            ├── test_api_construct.py ← auto-skip if construct absent
            ├── test_api_lief.py     ← auto-skip if lief absent
            ├── test_api_yara.py     ← auto-skip if yara-python absent
            ├── test_api_angr.py     ← auto-skip if angr absent
            └── test_api_networkx.py ← auto-skip if networkx absent
```

---

## The three new modules

### `api_triton.py` — Triton Symbolic Execution

**Requires:** `pip install triton-library`

**What it does:** Exposes IDA's binary data to Triton's symbolic execution engine. An AI agent can symbolize function arguments, feed IDA instructions into Triton one-by-one, accumulate path constraints, and ask Z3 to solve for concrete inputs that trigger a specific branch.

**Tool prefix:** `triton_*`

**Key tools:**

| Tool | Description |
|---|---|
| `triton_status` | Always available. Reports library presence and session state. |
| `triton_init` | Initialize context. Auto-detects architecture from IDA. |
| `triton_reset` | Discard symbolic state, keep architecture. |
| `triton_symbolize_register` | Mark a register as symbolic (attacker-controlled). |
| `triton_symbolize_memory` | Mark a memory range as symbolic. |
| `triton_process_instruction` | Feed bytes at an IDA address into Triton. |
| `triton_process_function` | Process all instructions in a function. |
| `triton_get_path_constraints` | List accumulated branch conditions. |
| `triton_solve_path_constraints` | Ask Z3 to find a concrete input satisfying constraints. |
| `triton_taint_register` | Mark a register as tainted (attacker-influenced). |
| `triton_taint_memory` | Mark a memory range as tainted. |
| `triton_get_taint_summary` | List all tainted registers and memory regions. |
| `triton_snapshot_save` | Save full symbolic state to a named slot. |
| `triton_snapshot_restore` | Roll back to a saved state. |
| `triton_replay_instructions` | Manually replay a custom instruction sequence (for AI agents needing fine-grained trace control). |
| `triton_analyze_function` | Full workflow: init → symbolize args → process → solve. |
| `triton_annotate_function` | Write IDA comments at branch points with path conditions. |

**Session management:** Each MCP session gets its own `TritonContext`. Contexts are stored in `_contexts: dict[session_id, TritonContext]` with LRU eviction at 20 entries. This prevents concurrent AI sessions from interfering.

**Instruction trace:** Each session maintains a `deque` of executed instruction addresses (max 10,000 entries). `triton_snapshot_save` stores the trace alongside symbolic state; `triton_snapshot_restore` replays it against a fresh context to rebuild the path predicate. Use `triton_replay_instructions` for manual control of custom instruction sequences.

**Architecture detection:** Always derived from `idaapi.get_inf_structure()`. Never hardcoded. An explicit override parameter is accepted but the default is always auto-detect.

---

### `api_miasm.py` — Miasm IR Analysis

**Requires:** `pip install miasm`

**What it does:** Lifts IDA functions to Miasm's intermediate representation (IRCFG), enables SSA transformation, deobfuscation passes, data flow tracing, and cross-architecture assembly with direct database patching.

**Tool prefix:** `miasm_*`

**Key tools:**

| Tool | Description |
|---|---|
| `miasm_status` | Always available. Reports library presence and session arch. |
| `miasm_init` | Initialize Machine for current IDA binary. Auto-detects architecture. |
| `miasm_sync` | Re-sync architecture after IDA rebase or reanalysis. |
| `miasm_lift_function` | Lift a function to IRCFG and return JSON representation. |
| `miasm_lift_to_ir` | Lift an address range (single block) to IR; covers basic block lifting. |
| `miasm_get_ssa` | Apply SSA transformation, return SSA-form IR blocks. |
| `miasm_get_cfg_dot` | Export function CFG as Graphviz DOT. |
| `miasm_get_cfg_summary` | Block count, cyclomatic complexity, loop detection (Tarjan's SCC). |
| `miasm_deobfuscate_cfg` | Apply constant folding, dead code elimination, expression simplification. |
| `miasm_simplify_block` | Symbolically execute a single basic block, return simplified register state. |
| `miasm_emulate_symbolic` | Symbolic emulation of a basic block with optional concrete register state. |
| `miasm_trace_data_flow` | Backward slice: where does a register's value come from? |
| `miasm_annotate_data_flow` | Write IDA comments at data-flow origin instructions (`@unsafe`). |
| `miasm_find_paths` | Enumerate all CFG paths between two addresses. |
| `miasm_solve_path_constraints` | Miasm CFG + Z3: find input reaching a target block. |
| `miasm_get_function_side_effects` | Report registers/memory read and written by a function. |
| `miasm_assemble` | Assemble an instruction string to hex bytes (cross-arch). |
| `miasm_patch_instruction` | Assemble + patch directly into the IDA database (`@unsafe`). |
| `miasm_search_instruction_pattern` | Find consecutive mnemonic sequences within basic blocks. |
| `miasm_get_context_info` | Detailed session state (arch, bitness, endianness, version). |
| `miasm_reset` | Reset Machine and re-auto-detect architecture. |

---

### `api_construct.py` — Construct Declarative Parsing

**Requires:** `pip install construct`

**What it does:** Parses binary data structures using declarative Construct templates. Provides pre-built PE/ELF/protocol parsers, an IDA struct-to-Construct bridge (no DSL required), a safe DSL evaluator for ad-hoc structures, and heuristic structure guessing.

**Tool prefix:** `construct_*`

**Key tools:**

| Tool | Description |
|---|---|
| `construct_status` | Always available. Reports library presence and loaded templates. |
| `construct_parse_pe_headers` | Parse DOS/NT/File/Optional/Section headers from a PE file. |
| `construct_parse_elf_headers` | Parse ELF header, program headers, section headers. |
| `construct_parse_custom_struct` | Parse at an IDA address using a user-provided Construct DSL. |
| `construct_build_struct` | Build bytes from a dict using a Construct DSL. |
| `construct_parse_ida_struct` | Bridge: auto-convert an IDA struct type to Construct and parse. |
| `construct_guess_struct` | Heuristic auto-guess structure layout (strings, pointers, padding). |
| `construct_batch_parse_array` | Parse multiple consecutive instances of a struct (tables). |
| `construct_extract_protocol_header` | Pre-built parsers for IPv4, TCP, UDP, ICMP, Ethernet, DNS, TLS. |
| `construct_scan_for_structs` | Scan a region for all occurrences of a struct pattern. |

**DSL Security:** Custom templates are evaluated through an AST whitelist — no raw `eval()`. Only Construct types and Python literals are permitted. Node count capped at 256.

**Session management:** Stateless — each tool call is independent. Compiled templates are cached in `_dsl_compile_cache` for performance.

**Architecture detection:** Pointer size inferred from `compat.inf_is_64bit()` for the IDA struct bridge.

**Session management:** Each session gets a `_MiasmManager` with a lazily-initialized Miasm `Machine`. Miasm's `Machine` object is stateless and reused per architecture. Thread-safe via `threading.Lock`.

**Architecture mapping:** IDA `procname` → Miasm arch string (x86_32, x86_64, arml, aarch64l, mips32l). Endianness checked via `ida_idaapi.cvar.inf.is_be()`.

---

### `api_lief.py` — LIEF Binary Analysis

**Requires:** `pip install lief`

**What it does:** Parses PE, ELF, and Mach-O binaries for metadata, security mitigations, sections, imports, exports, strings, TLS callbacks, digital signatures, and compiler fingerprinting. Also provides binary modification tools (add section, patch import, strip metadata) and composite threat assessment.

**Tool prefix:** `lief_*`

**Key tools:**

| Tool | Description |
|---|---|
| `lief_status` | Always available. Reports library presence and version. |
| `lief_info` | High-level binary metadata (format, arch, entry point, counts). |
| `lief_checksec` | Security mitigations score (NX, ASLR, CFG, RELRO, canary, etc.). |
| `lief_sections` | Section table with virtual addresses, sizes, entropy, permissions. |
| `lief_imports` / `lief_exports` | Import/export directories with addresses and ordinals. |
| `lief_strings` | Extract ASCII/UTF-16 strings from sections and overlay. |
| `lief_verify_signature` | Full Authenticode chain verification (native Python, no WinTrust). |
| `lief_rich_header` | Decode PE Rich Header for compiler fingerprinting and attribution. |
| `lief_pe_overlay` | Inspect data after the last section (packers, SFX, embedded payloads). |
| `lief_guard_functions` | Read Windows CFG tables (valid indirect-call targets). |
| `lief_compare_to_idb` | Cross-reference raw binary against loaded IDB state. |
| `hybrid_lief_checksec_exploit_assess` | Composite exploit-surface rating (checksec + CFG + signature + overlay). |
| `hybrid_lief_sync_symbols` | Sync symbol names from LIEF into the IDA database. |

---

### `api_yara.py` — YARA Signature Scanning

**Requires:** `pip install yara-python`

**What it does:** Scans binary data with YARA rules — custom user rules, built-in crypto constant detection, built-in threat indicator rules, and automatic IDB annotation. The `yara_idb_annotate` tool is a killer feature: it scans every function against your rules and writes comments + renames `sub_XXXX` stubs to `yara_<rule_name>`.

**Tool prefix:** `yara_*`

**Key tools:**

| Tool | Description |
|---|---|
| `yara_status` | Always available. Reports library presence and built-in rule counts. |
| `yara_scan` | Scan an IDA range, whole binary, or raw file against custom rules. |
| `yara_scan_builtin_crypto` | Detect AES S-box, MD5/SHA IVs, CRC32 poly, RC4 KSA — no files needed. |
| `yara_scan_builtin_threats` | Detect packers, C2 frameworks, hack tools, shellcode patterns. |
| `yara_generate_rule` | Generate a YARA rule from bytes at an IDA address with pointer wildcarding. |
| `yara_idb_annotate` | ⭐ Scan all functions, write comments, rename matched stubs — unique to this fork. |
| `yara_function_classifier` | Per-function category heat map (crypto / packers / c2 / shellcode / custom). |
| `hybrid_yara_lief_profile` | Composite threat profile: LIEF checksec + YARA scan + section entropy. |
| `hybrid_yara_triton_verify_crypto` | YARA finds crypto candidates → Triton symbolically verifies actual usage. |
| `hybrid_yara_miasm_deobfuscate` | YARA detects packer stubs → Miasm lifts and simplifies IR. |

---

## Adding a new tool (the pattern)

1. Choose the correct module (`api_triton.py`, `api_miasm.py`, or an appropriate existing one).
2. Define a `TypedDict` for the return type.
3. Write the function with full `Annotated[type, "description"]` type hints.
4. Apply `@tool` then `@idasync` (in that order — `@tool` is the outer decorator).
5. The docstring becomes the MCP tool description — write it for an AI reader, not a human dev.
6. Add a test in the corresponding `tests/test_api_*.py`.

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

---

## Adding a new optional-lib tool

If the tool requires `triton`, `miasm`, or `construct`, it must be inside a `if TRITON_AVAILABLE:` / `if MIASM_AVAILABLE:` / `if CONSTRUCT_AVAILABLE:` block:

```python
if TRITON_AVAILABLE:
    @tool
    @idasync
    def triton_my_new_tool(...) -> MyResult:
        """Description."""
        ctx = _get_or_create_ctx()
        ...
```

The corresponding test must skip gracefully:

```python
pytestmark = pytest.mark.skipif(not TRITON_AVAILABLE, reason="triton-library not installed")
# or
pytestmark = pytest.mark.skipif(not CONSTRUCT_AVAILABLE, reason="construct not installed")
```

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

### API conventions

- Prefer batch-first APIs (accept a comma-separated string or list where sensible).
- Use full type hints and `Annotated[...]` descriptions on every parameter.
- Use `parse_address()` from `utils.py` to normalize hex strings and symbol names.
- Use `normalize_list_input()` / `normalize_dict_list()` for batch input normalization.
- Return structured `TypedDict` results, never raw strings or untyped dicts.

### Unsafe operations

Destructive or debugger operations use the `@unsafe` decorator:

```python
from .rpc import tool, unsafe

@unsafe
@tool
@idasync
def dangerous_op(...):
    ...
```

Unsafe tools are disabled by default and require `--unsafe` flag to activate. The `miasm_patch_instruction` and `hybrid_deobfuscate_and_patch` (with `dry_run=False`) tools should be marked `@unsafe`.

### Output size

Large outputs are automatically truncated at 50KB and served via a download URL. This is handled by `rpc.py` infrastructure — no per-tool handling needed.

---

## Development commands

```bash
# Run MCP server (IDA plugin mode)
uv run ida-pro-mcp

# Run headless with a binary
uv run idalib-mcp --stdio path/to/binary

# Install optional dependencies
pip install triton-library          # Triton
pip install miasm                   # Miasm
pip install construct               # Construct
pip install dissect.cstruct         # C-syntax structs
pip install filetype                # Magic-byte identification
pip install lief                    # Binary format analysis
pip install yara-python             # Signature scanning
pip install 'triton-library miasm construct dissect.cstruct filetype lief yara-python'  # All

# Run IDA-side tests (headless)
uv run ida-mcp-test tests/crackme03.elf -q
uv run ida-mcp-test tests/typed_fixture.elf -q

# Run standalone pytest tests (no IDA needed)
uv run pytest tests/ -q

# Coverage
uv run coverage erase
uv run coverage run -m ida_pro_mcp.test tests/crackme03.elf -q
uv run coverage run --append -m ida_pro_mcp.test tests/typed_fixture.elf -q
uv run coverage report --show-missing
```

---

## Development workflow

### Iterative improvement cycle

When fixing bugs or adding features in the deployed IDA plugin:

1. **Edit the source file** in `src/ida_pro_mcp/ida_mcp/`
2. **Sync to deployed plugin + restart IDA in one command:**
   ```powershell
   C:\Dev\IDA_Pro_Plugin\ida-mcp-sync.ps1
   ```
   This copies all `.py` files from the source tree to the AppData plugin directory, clears `__pycache__` and `.pyc` bytecode, then launches IDA.

   To skip the IDA launch (e.g. for batch syncing without restarting):
   ```powershell
   C:\Dev\IDA_Pro_Plugin\ida-mcp-sync.ps1 -NoLaunch
   ```
3. **Verify the fix** by calling the tool via MCP.

### Sync script

`C:\Dev\IDA_Pro_Plugin\ida-mcp-sync.ps1` — automates the deploy workflow:

| Step | What it does |
|---|---|
| 1 | Copies all `.py` files from `src\ida_pro_mcp\ida_mcp\` → `AppData\ida_mcp\` |
| 2 | Deletes all `*.pyc` and `__pycache__` in the target directory |
| 3 | Launches `IDA Pro 9.3` (`ida.exe`) unless `-NoLaunch` is passed |

The script is the **single source of truth** for the deploy step — do not copy files manually.

### Server name

The MCP server advertises itself to clients as `synapse-mcp`. The canonical name is defined once in `ida_mcp/rpc.py` as `MCP_SERVER_NAME` and imported by `server.py`, `idalib_supervisor.py`, and `installer.py`. Do not hardcode the string elsewhere — if you need it, import it.

### Error handling principle

Every tool returns a structured `dict`. On success, it includes `{"ok": true, ...}`. On failure, it returns `{"ok": false, "error": "descriptive message"}`. **Never `raise IDAError(...)` from within a tool function body** — the exception propagates as an ugly JSON-RPC traceback to the AI client. Return the error dict instead. The internal `_MiasmManager` methods and `_trace_data_flow_internal` helper may still raise, but all `@tool @idasync` public functions must return error dicts.

### Adding a new tool

1. Add the `@tool @idasync` function to the appropriate `api_*.py` file in `src/ida_pro_mcp/ida_mcp/`
2. Define a `TypedDict` return type for structured output
3. Write the docstring for an AI reader, not a human dev
4. Add a test in `tests/test_api_*.py` with `@test()` decorator and `_require_triton()` / `_require_miasm()` guard
5. Sync to deployed plugin + restart IDA + verify

### Adding a new optional-engine module (Triton/Miasm pattern)

1. Create `api_<engine>.py` in `src/ida_pro_mcp/ida_mcp/`
2. Guard tool registrations with `if TRITON_AVAILABLE:` / `if MIASM_AVAILABLE:` / `if CONSTRUCT_AVAILABLE:`
3. Register a `*_status` probe tool **outside** the guard so it always reports availability
4. In `__init__.py`, import the module inside `try/except Exception: pass` so a missing dependency doesn't break the plugin
5. In `pyproject.toml`, add the dependency to `[project.optional-dependencies]` and the `all` group
6. Sync + restart + verify with the `*_status` probe tool

### Lazy mode (`--lazy`)

When the proxy is started with `--lazy`, `tools/list` returns only 4 meta-tools instead of all 180+ tools. This reduces agent context usage by ~95% at session start.

**The 4 meta-tools:**
| Tool | Purpose |
|---|---|
| `list_modules` | Show 6 tool groups (core, analysis, modify, symbolic, formats, recon) with counts |
| `list_tools(module=..., limit=50, offset=0)` | Paginated tool discovery within a group |
| `describe_tool(name)` | Full JSON schema for a single tool |
| `invoke_tool(tool, args)` | Invoke any tool by name |

**Adding a new tool to the lazy-mode grouping:**
- If the tool has a distinctive prefix (e.g., `triton_`, `miasm_`, `dbg_`), add it to `_TOOL_MODULE_PREFIXES` in `server.py`.
- If it has no prefix, add it to `_TOOL_MODULE_EXACT` in `server.py`.
- If it falls through to `core`, `_validate_groups()` will log a startup warning in lazy mode.

**Cache invalidation:**
- `_lazy_tools_cache` stores the flat tool list from IDA.
- `_lazy_module_cache` stores per-module slices.
- Both are cleared automatically when `invoke_tool` hits a "not found" error (e.g., after IDA reload).
- Agents can force a clear by calling `invoke_tool("__reset_cache__")`.

### Testing tools

```bash
# Headless with a binary fixture
uv run ida-mcp-test tests/crackme03.elf -q
uv run ida-mcp-test tests/typed_fixture.elf -q

# Specific test pattern
uv run ida-mcp-test tests/crackme03.elf -p "*triton*"

# Standalone pytest (no IDA needed)
uv run pytest tests/ -q
```

---

## What NOT to touch

- `ida_mcp/zeromcp/` — vendored modified zeromcp. This is the fork of mrexodia's modifications on top of the original zeromcp. Do not edit unless fixing a protocol-level bug.
- `idalib_supervisor.py`, `idalib_server.py` — transport and proxy layer. Changes here require protocol-level testing.
- `server.py` may be modified for lazy-mode and proxy-layer improvements (it is our code, not upstream).
- Upstream API modules (`api_core.py` through `api_sigmaker.py`) should not be modified to accommodate Triton/Miasm. Keep the new engines in their own files.

---

## Upstream relationship

This is a fork of [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp). The upstream project is actively maintained. To pull upstream improvements:

1. Fetch from upstream remote
2. Merge into `main` — conflicts will be in `pyproject.toml` (version/name) and `__init__.py` (our new imports)
3. Resolve: keep our optional import block, keep our version/name, take upstream changes elsewhere

Do not add Triton/Miasm/Construct logic to any file that upstream also maintains heavily (the existing `api_*.py` files). Keep our additions isolated in `api_triton.py`, `api_miasm.py`, and `api_construct.py`.

---

## Scope priorities

**High:**
- `api_triton.py`
- `api_miasm.py`
- `api_construct.py`
- `api_lief.py`
- `api_yara.py`
- `api_analysis.py`, `api_types.py`, `api_modify.py`, `api_memory.py`
- `utils.py`, `framework.py`

**Medium:**
- `api_core.py`, `api_stack.py`, `api_resources.py`
- `api_survey.py`, `api_composite.py`
- `api_cstruct.py`, `api_filetype.py`

**Lower:**
- `api_debug.py`
- MCP transport / hosting internals
- Install / config mutation logic

---

## Phase 4 Tools — Accuracy Notes & Known Limitations

### `find_similar_functions`

**What it does:** Cosine similarity on a 14-dimensional feature vector (7 CFG/size counts + 7 mnemonic ratios). Includes embedded fingerprints for 11 common library functions (memcpy, memset, strlen, strcpy, malloc, free, open, read, write, printf, exit).

**Combined scoring:** `0.7 × cosine_score + 0.3 × fingerprint_score`. Fingerprint scores use the same unit-normalized vector comparison against each fingerprint's feature profile.

**Accuracy notes for AI agents:**
- **Threshold 0.99 is very lenient.** Any function with similar mnemonic ratios to the reference (both having e.g. high `mov` ratio) will score >0.99 even if structurally different. For strict matching, use ≥0.999.
- **Raw-count features and ratio features are separately unit-normalized** before concatenation, then cosine similarity is applied across the full 14-dim vector. This prevents raw counts from dominating the dot product and ensures ratio features contribute equally.
- **Functions with 0 callers** may produce unexpected scores — `caller_count=0` across all candidates contributes zero to the dot product, and the remaining features dominate.
- **Store mnemonic set does NOT include `mov`** — only `stos*` (string store instructions) are counted as stores. `mov` variants are counted as loads. This prevents double-counting of `mov` in both load_ratio and store_ratio.
- **FlowChart iterator exhaustion:** `ref_fc` is consumed by `_compute_function_features` (single-pass block+edge counting). The reference's `block_count` in the result comes from the feature dict, not re-iteration.
- **Matches include `fingerprint_name` and `fingerprint_description`** when a library function pattern is detected. Absence of these fields means no fingerprint matched above threshold.

### `trace_data_chain`

**What it does:** Multi-hop BFS traversal via `idautils.XrefsTo`/`XrefsFrom`. Each node is an address; edges are xref records with detailed type classification (call_near, jump_near, flow, offset, data_read, data_write, informational).

**Accuracy notes for AI agents:**
- **`cross_functions` (default False):** When False, traversal stops at call/jump xrefs and does NOT enter the target function's CFG. When True, `call_near`/`call_far` xrefs expand all basic blocks of the called function into the traversal queue, enabling multi-level call chain data-flow tracing.
- **`terminated_at` address:** Reports the address of the node that actually had no outgoing xrefs (for `no_more_xrefs`) or hit a limit boundary. Not always the last node in `nodes[]` (BFS may have queued multiple nodes at the same depth).
- **`include_code=false` + `include_data=false`** → returns `no_more_xrefs` with an empty path. This is correct behavior (the set of acceptable xref types is empty).
- **`dr_I` (Informational) data xrefs** → `xref_type="informational"`. These are valid data xrefs used for things like debug info or relocations.
- **Start node is always visited** even if it would be filtered by xref type — it is the traversal origin, not an xref target.
- **`functions_entered`** is included in the result when `cross_functions=True`, listing every function whose basic blocks were expanded into the traversal.

### `deobfuscate_segment`

**What it does:** Segment-level batch deobfuscation. Fast-screens every function in a segment using IDA `FlowChart` (no Miasm), ranks by composite obfuscation score, then runs the iterative Miasm simplification pipeline on the top candidates.

**Obfuscation score formula:**
- `branch_density = edge_count / block_count`
- `block_size_score = block_count / (size_bytes / 20)`
- `complexity_score = min(cyclomatic_complexity / 20, 3.0)`
- `score = 0.35*branch_density + 0.35*min(block_size_score,5.0) + 0.30*complexity_score`

**Accuracy notes for AI agents:**
- **Screening is pure IDA; Miasm is only used for candidates.** This makes the scan fast (seconds for thousands of functions) but the score is a heuristic. Legitimate code with extreme control-flow complexity (large switch tables, heavy error-handling) may score >1.5. Tune `complexity_threshold` or set `min_function_size` to filter out tiny stubs.
- **Candidates are sorted by score descending** and capped at `max_functions` (clamped 1–500). The result includes every candidate's raw metrics so you can adjust the threshold for a second pass.
- **`exclude_libraries=True` (default)** skips functions marked `FUNC_LIB`. If a packer/obfuscator has already been partially identified by FLIRT, its stubs may be marked library and skipped — disable this if you want to target them.
- **Per-function error isolation:** One candidate failing does not abort the batch. After 10 consecutive failures the batch aborts early with `aborted_early=True` to avoid spinning on systemic corruption or architecture mismatch.
- **`_hybrid_iterative_deobfuscate_core`** is the same pipeline as `hybrid_iterative_deobfuscate` (convergence on block/edge/IR-stmt signature, optional Triton verification, NOP patching). The batch tool simply calls it in a loop.
- **Patch candidates come from three signals:** (1) empty IR block, (2) bare unconditional jump-only IR block, (3) block removed from IRCFG entirely (merged by `merge_blocks` or became unreachable). The function entry block is never patched. Triton verification is the safety net for signal-3 candidates (merged blocks may not be memory-adjacent to their predecessor, so NOPing them could change fall-through behavior).
- **All-or-nothing Triton verification:** If `verify_with_triton=True` and ANY candidate causes a register mismatch, ALL patches for that function are skipped. Set `verify_with_triton=False` if you want to apply patches without verification (review dry_run output first).

---

## Hard-won lessons & debugging strategy

### One bad tool must never crash `tools/list`

`_mcp_tools_list` iterates over every registered tool and calls `_generate_tool_schema` for each. If **any single tool** throws an exception during schema generation, the **entire `tools/list` JSON-RPC call fails**, and every MCP client reports "Failed to get tools."

**Root cause we've hit:** An orphaned `@tool @idasync` decorator got attached to a `TypedDict` class instead of a function. When `inspect.signature(dict)` ran, it raised `ValueError: no signature found for builtin type <class 'dict'>`, crashing the whole tools list.

**Defensive fix in `zeromcp/mcp.py`:** `_mcp_tools_list` now wraps each `_generate_tool_schema` call in `try/except`. A broken tool is logged and skipped rather than killing the server. `_generate_tool_schema` also falls back through multiple `get_type_hints` strategies before giving up.

**Lesson:** Always wrap per-item operations inside list-builders with `try/except`. One malformed item should never deny service to every other item.

### File reconstruction is hazardous — validate decorator bindings

When salvaging code from archives or stitching together large files (e.g., restoring `type_propagate` from `plans/Archives/` into `api_types.py`), decorators can get orphaned:

```python
# WRONG — decorator orphaned above a class
@tool
@idasync

class ConstructorFieldEntry(TypedDict, total=False):
    ...
```

**Validation after reconstruction:**
```bash
# Check every @tool is immediately followed by a def, not a class or blank line
grep -n "^@tool$" src/ida_pro_mcp/ida_mcp/api_*.py
```

Always visually inspect the 3–5 lines after every `@tool` / `@idasync` block when reconstructing files.

### Live debugging by process of elimination

When MCP clients give vague errors ("Failed to get tools") and server logs show nothing conclusive:

1. **Make the critical path resilient** (wrap `_generate_tool_schema` in `try/except`)
2. **Log the skip** with tool name + exception type
3. **Sync, restart IDA, retry the client**
4. **Observe which tool got skipped** — that's the culprit
5. **Fix the root cause, then remove debug noise if desired**

This is faster than trying to reproduce the exact schema-generation failure in a mock environment.

### Sync script copies blindly — it does not validate

`ida-mcp-sync.ps1` copies `.py` files and clears bytecode, but it does **not**:
- Check Python syntax
- Verify decorator bindings
- Ensure imports resolve
- Confirm schema generation succeeds

Always run a quick sanity check after syncing:
```bash
# Validate syntax on all synced files
python -m py_compile src/ida_pro_mcp/ida_mcp/api_*.py
```

---

## Environment notes

- Python 3.11+ required (server and plugin side)
- IDA Pro 8.3+; IDA Pro 9.x recommended
- `uv` is the package manager — use `uv run` not `python` directly
- IDA Free is not supported
- If IDA uses the wrong Python interpreter: `idapyswitch`
- Windows: `triton-library` has prebuilt wheels. `miasm` pure-Python core works; JIT compilation optional and disabled by default on Windows. `construct` is pure-Python and works everywhere.
