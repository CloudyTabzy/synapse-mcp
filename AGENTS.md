# Synapse MCP — Agent Quick Reference

This document is for **AI agents** connected to the Synapse MCP server. It tells you what engines are available, how to discover tools efficiently, what patterns the tools follow, and how the codebase is organised so you can debug or report issues with confidence.

---

## Project layout

```
synapse-mcp/
├── CLAUDE.md                        ← Developer guide (how to contribute, build, test)
├── AGENTS.md                        ← This file — agent quick reference
├── pyproject.toml                   ← Package metadata, optional deps, scripts
├── uv.lock                          ← Locked dependencies
├── README.md                        ← Full project documentation
├── devdocs/                         ← Architecture notes and deep dives
├── plans/                           ← Phased implementation plans (outside repo)
├── profiles/                        ← Installation profiles (Claude Code plugin etc.)
├── skills/                          ← ~13 workflow playbooks teaching agents how to use the tools
├── tests/                           ← Standalone pytest tests (no IDA needed)
│   ├── test_mcp_spec_*.py           ← MCP protocol compliance tests
│   └── test_server_transport.py     ← HTTP/SSE transport tests
└── src/ida_pro_mcp/
    ├── server.py                    ← MCP server entrypoint (proxy dispatcher; lazy mode lives here)
    ├── idalib_supervisor.py         ← Headless idalib worker supervisor
    ├── idalib_server.py             ← Headless idalib server
    ├── ida_mcp.py                   ← IDA plugin entrypoint (loaded by IDA)
    ├── installer.py                 ← MCP client config generation and plugin installation
    └── ida_mcp/                     ← All plugin-side APIs
        ├── __init__.py              ← Imports all API modules; ADD new modules here
        ├── rpc.py                   ← @tool, @unsafe, @resource decorators + MCP_SERVER
        ├── sync.py                  ← @idasync thread-safety decorator
        ├── utils.py                 ← Shared helpers (parse_address, paginate, ...)
        ├── compat.py                ← IDA version shims
        ├── discovery.py             ← IDA instance discovery + port probing
        ├── http.py                  ← HTTP transport handler
        ├── task_backend.py          ← Async task queue backend
        ├── trace.py                 ← IDB netnode tracing for tools/call
        ├── profile.py               ← Profile file parsing and application
        ├── zeromcp/                 ← Vendored + extended zeromcp (do not edit)
        │
        ├── framework.py             ← Test framework (assert helpers, decorators, fixtures)
        │
        ├── api_core.py              ← IDB metadata, functions, strings, imports
        ├── api_analysis.py          ← Decompilation, disassembly, xrefs, callgraph
        ├── api_memory.py            ← Bytes/ints/strings read and patch
        ├── api_types.py             ← Structs, type inference, type application
        ├── api_modify.py            ← Comments, renaming, asm patching
        ├── api_stack.py             ← Stack frame variables
        ├── api_debug.py             ← Debugger control (unsafe)
        ├── api_python.py            ← Execute Python in IDA context
        ├── api_resources.py         ← ida:// MCP resources
        ├── api_survey.py            ← High-level survey tools
        ├── api_composite.py         ← Multi-step composite operations
        ├── api_discovery.py         ← Instance discovery tools
        ├── api_sigmaker.py          ← FLIRT signature tools
        ├── api_recon.py             ← Stripped binary reconnaissance
        ├── api_tasks.py             ← Async task queue
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
        ├── api_numpy.py             ← NumPy numerical analysis (optional)
        ├── api_unicorn.py           ← Unicorn concrete emulation (optional)
        ├── api_xor.py               ← Universal XOR cipher solver (always-on; Z3 optional)
        │
        └── tests/                   ← IDA-side tests (run via ida-mcp-test)
            ├── test_api_core.py
            ├── test_api_analysis.py
            ├── ... (one file per api_*.py)
            ├── test_api_triton.py   ← auto-skip if triton-library absent
            └── test_api_networkx.py ← auto-skip if networkx absent
```

---

## Architecture

```
MCP Client (Claude, Cursor, Roo, VS Code, etc.)
       │
       ▼  JSON-RPC
┌──────────────────┐
│  ida-pro-mcp     │  ← server.py (proxy dispatcher)
│  Server          │     • Output limiter (50 KB auto-truncate)
│                  │     • Unsafe gate (--unsafe flag)
│                  │     • Async task queue
│                  │     • Lazy mode (4 meta-tools, ~95% context saving)
└────────┬─────────┘
         │  HTTP or stdio
         ▼
┌──────────────────┐
│  IDA Pro /       │  ← ida_mcp.py
│  idalib worker   │     • Main thread (all @idasync calls)
│                  │     • IDB database
└────────┬─────────┘
         │  In-process (optional engines loaded dynamically)
         ├─ Triton (symbolic execution)
         ├─ Miasm (IR lifting)
         ├─ Construct / cstruct / filetype
         ├─ LIEF / YARA
         ├─ NetworkX / NumPy
         ├─ Unicorn (concrete emulation)
         └─ XOR solver (always-on)
         │
         │  Socket IPC (out-of-process)
         └─ Angr worker (avoids pickle crashes on IDA's main thread)
```

Three execution modes:
1. **GUI Plugin** — `ida_mcp.py` loads inside IDA Pro, starts HTTP server, writes discovery JSON.
2. **Headless Single-Process** — `idalib-mcp --stdio` opens binaries via `idapro` without GUI.
3. **Headless Supervisor** — `idalib-mcp --supervise` spawns per-binary workers with `--max-workers N`.

---

## Module descriptions

### Infrastructure (no tools)

| File | Purpose |
|------|---------|
| `__init__.py` | Imports all `api_*.py` modules. Each optional module is wrapped in `try/except Exception: pass` so a bad install can never take down the plugin. New modules are added here. |
| `rpc.py` | Defines the `@tool`, `@unsafe`, and `@resource` decorators that register functions as MCP tools. Also defines `MCP_SERVER_NAME` ("synapse-mcp"), the tool-grouping dictionaries for lazy mode (`_TOOL_MODULE_PREFIXES` and `_TOOL_MODULE_EXACT`), and output-size limiting logic. |
| `sync.py` | Defines `@idasync` — wraps tool calls in `ida_auto.execute_sync()` to ensure all IDA SDK calls run on the main thread. |
| `utils.py` | Shared helpers: `parse_address()` (hex string or symbol → `ea_t`), `normalize_list_input()` (comma-separated string or list → `list[str]`), `normalize_dict_list()`, `tool_error()`, pagination helpers, etc. |
| `compat.py` | IDA version compatibility shims (`inf_is_64bit()`, etc.). |
| `discovery.py` | IDA instance discovery and port probing — finds all running IDA windows and their MCP ports on the local machine. |
| `http.py` | HTTP/SSE transport handler. |
| `task_backend.py` | Background task queue backend — runs long operations off the MCP connection. |
| `trace.py` | IDB netnode tracing for tools/call — records each tool invocation to the database for audit/debug. |
| `profile.py` | Profile file parsing and application — restricts which tools are visible per profile. |
| `framework.py` | Test framework imported by `tests/test_api_*.py`: `test()`, `assert_ok()`, `assert_error()`, `get_any_function()`, `skip_test()`, etc. |
| `zeromcp/` | Vendored and extended zeromcp library. Do not edit unless fixing a protocol-level bug. |

### Core IDA tools (always-on, built-in)

| Module | Tools | What it does |
|--------|------:|--------------|
| `api_core.py` | 18 | IDB metadata, function listing/querying, strings, imports, exports, entity catalog (`entity_query`), C++ class/namespace inventory (`list_classes`), enhanced function flags (`list_functions_enhanced`: is_thunk, is_library, is_noret, has_prototype, is_external). |
| `api_analysis.py` | 35 | Decompilation (`decompile`, `decompile_batch`), disassembly (`disasm`, `disasm_batch`), cross-references (`xrefs_to`, `xref_query`, `trace_data_chain`), call graphs (`callgraph`, `callees`, `get_function_callers`), function profiling (`func_profile`, `analyze_function`), instruction queries, byte/pattern finding, function hashing, completeness scoring, diff, XOR pattern detection, constraint classification. |
| `api_memory.py` | 7 | Read/write bytes (`get_bytes`, `patch`), typed integers (`get_int`, `put_int`), strings (`get_string`), global values. |
| `api_types.py` | 12 | Declare/inspect/remove types, apply types to functions/globals/locals, struct recovery from decompiler ctree (`struct_recovery`), cross-function type propagation (`type_propagate`), constructor analysis (`analyze_constructor`), enum management. |
| `api_modify.py` | 12 | Comments (`set_comments`, `append_comments`), renaming (`rename`), assembly patching (`patch_asm`), function definition (`define_func`, `define_code`, `undefine`), forced range analysis (`analyze_range`), xref creation (`add_xref`). |
| `api_stack.py` | 3 | Stack frame inspection and variable management. |
| `api_debug.py` | 24 | Debugger start/stop, breakpoints, register/memory read, stack trace, live memory sync (`sync_debugger_to_idb`). Requires `--unsafe` + `?ext=dbg`. |
| `api_python.py` | 2 | Execute Python code in IDA's context (`py_eval`, `py_exec_file`). |
| `api_resources.py` | 0 | `ida://` MCP resources (IDB metadata, segments, entrypoints). |
| `api_survey.py` | 1 | One-call binary triage (`survey_binary`). |
| `api_composite.py` | 11 | Multi-step composite operations and cross-engine hybrid workflows. |
| `api_discovery.py` | 6 | Find and switch between IDA instances (`list_instances`, `select_instance`, `get_active_instance`). |
| `api_sigmaker.py` | 5 | FLIRT signature creation and scanning. |
| `api_recon.py` | 11 | Stripped binary reconnaissance: sections, vtable candidates, indirect call discovery, function prologue scanning, render-loop detection, COM vtable resolution. |
| `api_tasks.py` | 4 | Background task queue (`task_submit`, `task_poll`, `task_list`, `task_cancel`). |
| `api_flirt.py` | 4 | FLIRT signature application and name suggestion. |

### Optional analysis engines (require `pip install`)

| Module | Tools | Install | What it does |
|--------|------:|---------|--------------|
| `api_triton.py` | 51 | `triton-library` | Context lifecycle, register/memory symbolisation, instruction processing, path constraint accumulation, Z3 SMT solving, taint analysis, snapshots with instruction trace replay, IDA annotation at branch points. |
| `api_lief.py` | 26 | `lief` | Binary format metadata, checksec, sections, imports/exports, strings, TLS callbacks, Authenticode chain verification, Rich Header decompilation, PE overlay/version-info/resource analysis, CFG guard tables, section/import surgery, cross-engine workflows. |
| `api_networkx.py` | 24 | `networkx>=3.0` | Call graph / CFG / xref graph construction, PageRank/betweenness/degree centrality, Louvain community detection, SCC/cycle analysis, shortest/enumerated paths, k-hop neighborhood, dominators, graph diff, export to DOT/GraphML. |
| `api_angr.py` | 23 | `angr` (~200 MB) | Binary loading into cached Projects (LRU max 3), CFGFast/IDA-based CFG, stdin/argv/register symbolic solving (`angr_find_paths` ⭐), BFS reachability, state evaluation, hooking, backward slicing, value-set analysis, cross-engine workflows, crackme workflow (`workflow_solve_crackme`). Runs in a dedicated out-of-process worker. |
| `api_miasm.py` | 22 | `miasm` | IR lifting (single block or full function), SSA transformation, CFG summary + DOT export, dead-code elimination, symbolic emulation, data-flow tracing, cross-arch assembly/patching, path enumeration, Z3 path-constraint solving. |
| `api_debug.py` | 24 | Built-in (unsafe) | Debugger start/stop/continue, breakpoint management, register/memory read/write, stack trace, live-to-IDB memory sync. |
| `api_unicorn.py` | 14 | `unicorn` | Concrete emulation of IDA segments, instruction/block tracing with loop detection, decrypt-and-patch (`unicorn_emulate_and_patch` ⭐), shellcode syscall sandbox, API-hash brute-forcing, stackstring recovery, cross-engine workflows, workflow (`workflow_unicorn_decrypt_analyze`). |
| `api_yara.py` | 11 | `yara-python` | Custom rule scanning (IDB range / whole binary / raw file), built-in crypto constant detection (AES/MD5/SHA/CRC32/RC4), built-in threat detection (packers, C2, shellcode), rule generation from IDA bytes with pointer wildcarding, per-function annotation with auto-rename (`yara_idb_annotate` ⭐). |
| `api_construct.py` | 10 | `construct` | PE/ELF header parsing, custom Construct DSL templates (safe AST whitelist, 256-node cap), IDA struct bridge, heuristic structure guessing, array scanning, pre-built protocol headers. |
| `api_numpy.py` | 9 | `numpy>=2.0.0` | Block-level entropy maps, byte-distribution histograms (256-bucket + chi-square), repeating-XOR key recovery, function/binary similarity, opcode profiling, typed value scanning, memmap pattern search. |
| `api_cstruct.py` | 7 | `dissect.cstruct` | C-syntax struct/enum/typedef parsing from memory, IDA struct bridge, serialisation round-trips, pre-built PE/ELF/protocol templates. |
| `api_elf.py` | 6 | `pyelftools>=0.31` | ELF/DWARF debug info recovery (functions, types, line info), symbol table reading with GNU versioning, IDB name sync. |
| `api_filetype.py` | 4 | `filetype` | Magic-byte identification of raw buffers, IDA addresses, or segments (79+ formats). |
| `api_xor.py` | 3 | `z3-solver` (optional) | 8-family universal XOR cipher solver (fixed, repeating, self-referential, rolling, position-dependent, two-layer, table-lookup, cumulative) with algebraic simplification, Z3 constraint path, and model extraction from disassembly. Always-on; Z3 only enriches the constraint path. |

---

## Engine inventory

| Engine | Tools | Install |
|--------|------:|---------|
| **Native IDA** (core, analysis, modify, types, recon, composite, debug, tasks…) | 154 | Built-in |
| **Triton** — symbolic execution, taint analysis, SMT solving | 51 | `pip install triton-library` |
| **LIEF** — PE/ELF/Mach-O format analysis, checksec, Authenticode, Rich Header | 26 | `pip install lief` |
| **NetworkX** — call/CFG graph metrics, centrality, communities | 24 | `pip install networkx>=3.0` |
| **Debugger** — live debugger control, breakpoints, memory sync | 24 | Built-in (requires `--unsafe`) |
| **Angr** — symbolic execution, stdin/argv solving, backward slicing | 23 | `pip install angr` (~200 MB) |
| **Miasm** — IR lifting, SSA, deobfuscation, cross-arch assembly | 22 | `pip install miasm` |
| **YARA** — signature scanning, crypto/threat detection, IDB annotation | 11 | `pip install yara-python` |
| **Construct** — declarative PE/ELF/protocol parsing | 10 | `pip install construct` |
| **NumPy** — entropy maps, byte histograms, XOR key recovery, similarity | 9 | `pip install numpy>=2.0.0` |
| **dissect.cstruct** — C-syntax struct/enum parsing & serialization | 7 | `pip install dissect.cstruct` |
| **pyelftools** — ELF/DWARF debug info, symbol tables | 6 | `pip install pyelftools>=0.31` |
| **filetype** — magic-byte file type identification | 4 | `pip install filetype` |
| **XOR solver** — 8-family universal cipher solver (always-on; Z3 optional) | 3 | `pip install z3-solver` (optional) |
| **Unicorn** — concrete CPU emulation, decrypt stubs, shellcode sandbox | 14 | `pip install unicorn` |

**All engines are optional.** The plugin loads cleanly without any of them. If an engine is not installed, its tools are silently absent — only the `*_status` probe tool reports `available: false`.

---

## Discovery: lazy mode

When the server runs with `--lazy`, `tools/list` returns only **4 meta-tools**:

| Meta-tool | What it does |
|-----------|-------------|
| `list_modules` | Show 6 groups with live tool counts + representative tool names (in the description) |
| `list_tools(module=…, search=…, limit=50, offset=0)` | Browse a group, or keyword-search across all groups |
| `describe_tool(name)` | Get full input schema for one tool |
| `invoke_tool(tool, args)` | Execute any tool by name — all arguments go inside `args={}` |

**Cheapest discovery paths (fewest round-trips):**
1. Know the name → `invoke_tool(tool="decompile", args={"addr": "main"})`
2. Know a keyword → `list_tools(search="entropy")` → `invoke_tool`
3. Know the group → `list_tools(module="analysis")` → `invoke_tool`
4. Exploring → `list_modules` → `list_tools(module=…)` → `invoke_tool`

---

## Tool groups (lazy mode)

### `analysis` — Decompilation, disassembly, xrefs, callgraph, profiling, XOR
`decompile`, `disasm`, `xrefs_to`, `trace_data_chain`, `find_similar_functions`, `callgraph`, `func_profile`, `find_xor_pattern`, `xor_solve_universal`, `xor_model_from_disassembly`, `numpy_entropy_map`, `numpy_byte_histogram`, `analyze_function_completeness`, `diff_functions`, `demangle_names`, `decompile_batch`

### `core` — Server health, instance discovery, IDB metadata, strings, imports
`server_health`, `list_funcs`, `func_query`, `entity_query`, `find_regex`, `search_text`, `imports`, `list_strings`, `survey_binary`, `list_instances`, `select_instance`, `get_active_instance`, `idb_save`, `task_submit`, `task_poll`

### `formats` — LIEF, YARA, Construct, cstruct, filetype, pyelftools
`lief_info`, `lief_checksec`, `lief_verify_signature`, `lief_rich_header`, `lief_imports`, `lief_strings`, `yara_scan`, `yara_scan_builtin_crypto`, `yara_scan_builtin_threats`, `yara_idb_annotate`, `construct_parse_pe_headers`, `construct_parse_elf_headers`, `cstruct_parse_c_definition`, `filetype_identify_buffer`, `elf_dwarf_functions`, `hybrid_lief_checksec_exploit_assess`

### `modify` — Renaming, comments, patching, types, structs, stack
`rename`, `set_comments`, `patch_asm`, `define_func`, `scan_and_define_funcs`, `declare_type`, `set_type`, `type_propagate`, `struct_recovery`, `analyze_constructor`, `stack_frame`, `enum_upsert`

### `recon` — Graph metrics, FLIRT signatures, vtable scanning, stripped-binary recon
`nx_call_graph`, `nx_central_functions`, `workflow_reveng_overview`, `get_binary_sections`, `find_vtable_candidates`, `dump_vtable`, `find_indirect_calls`, `find_global_writers`, `apply_flirt_signature`, `make_signature`, `find_function_prologues`, `py_eval`

### `symbolic` — Triton, Miasm, Angr, Unicorn, hybrid workflows
`triton_init`, `triton_symbolize_register`, `triton_process_function`, `triton_solve_path_constraints`, `miasm_lift_function`, `miasm_deobfuscate_cfg`, `miasm_get_cfg_summary`, `angr_find_paths`, `angr_load_segment`, `unicorn_emulate`, `unicorn_emulate_and_patch`, `hybrid_analyze_function`, `hybrid_iterative_deobfuscate`, `hybrid_unicorn_triton_analyze`, `workflow_solve_crackme`, `workflow_unicorn_decrypt_analyze`

---

## Tool conventions

All tools return a structured `dict`. On success: `{"ok": true, ...}`. On failure: `{"ok": false, "error": "descriptive message"}`. There are no raw strings or untyped lists at the top level.

**Addresses:** Pass as hex strings (`"0x401000"`) or symbol names (`"main"`). Never pass raw integers.

**Batch input:** Many tools accept a comma-separated string or Python list — e.g. `addrs="0x11a9,0x123e"` or `addrs=["0x11a9", "0x123e"]`.

**Pagination:** Search results use `offset`/`limit` (max 10,000). Tools like `list_funcs` and `entity_query` use `offset`/`count`.

**Output limiting:** Responses >50 KB are auto-truncated with an `output_id`. Call `read_mcp_output(output_id=..., offset=0)` for full chunks.

**Async tasks:** Long-running operations can be submitted via `task_submit`+`task_poll`, or by adding `async_mode=True` to `invoke_tool` (auto-polls every 2s up to 300s).

**Unsafe tools:** Destructive operations (patching, symbol surgery, debugger) require `--unsafe`. Without it, the server returns `{"ok": false, "error": "unsafe tool not available..."}`.

**Debugger tools:** `dbg_*` tools additionally require the `?ext=dbg` extension. Without it: `{"ok": false, "error": "tool requires debugger extension (?ext=dbg)"}`.

---

## First-call recommendations

| If you want to… | Call this first |
|-----------------|----------------|
| Understand what binary is loaded | `survey_binary()` |
| Find all available functions | `list_funcs()` or `func_query()` |
| Decompile and analyze one function | `decompile(addr=…, include_addresses=true)`, then `analyze_function(addr=…)` |
| Find which functions reference a string | `find_functions_by_string(pattern=…)` |
| Trace data flow through xrefs | `trace_data_chain(address=…, direction="backward")` |
| Solve a serial-key crackme (Triton path) | `triton_analyze_function(address=…, symbolize_args=…)` |
| Solve a stdin-fed crackme (Angr path) | `workflow_solve_crackme(target_address="auto-detect", input_mode="stdin")` |
| Decrypt a runtime-encrypted section | `workflow_unicorn_decrypt_analyze(decrypt_stub=…, encrypted_start=…, encrypted_size=…)` |
| Find XOR-obfuscated constants | `find_xor_pattern(addr=...)`, then `xor_solve_universal(addr=..., family="auto")` |
| Check security mitigations | `lief_checksec()` |
| Scan for crypto constants | `yara_scan_builtin_crypto()` |
| Detect packers / threat indicators | `yara_scan_builtin_threats()` |
| Identify packed/encrypted section layout | `numpy_entropy_map(addr=…, size=…)` |
| Get binary-wide structural overview | `workflow_reveng_overview()` or `nx_central_functions(top_n=20)` |
| List instances or switch binaries | `list_instances()`, `select_instance(port=…)` |
