# Synapse MCP — Agent Quick Reference

This document is for **AI agents** connected to the Synapse MCP server. It tells you what engines are available, how to discover tools efficiently, and what patterns the tools follow.

---

## What this server is

Synapse MCP is a fork of [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) that extends IDA Pro with **14 optional analysis engines** and **360+ tools**, all registered through the same `@tool @idasync` machinery. If an engine is not installed, its tools are silently absent (except a `*_status` probe tool that always reports availability).

---

## Engine inventory

| Engine | Tools | Install |
|--------|------:|---------|
| **Native IDA** (core, analysis, modify, types, recon, composite, debug, tasks…) | 154 | Built-in |
| **Triton** — symbolic execution, taint analysis, SMT solving | 51 | `pip install triton-library` |
| **LIEF** — PE/ELF/Mach-O format analysis, checksec, Authenticode, Rich Header | 26 | `pip install lief` |
| **Unicorn** — concrete CPU emulation, decrypt stubs, shellcode sandbox | 14 | `pip install unicorn` |
| **NetworkX** — call/CFG graph metrics, centrality, communities | 24 | `pip install networkx>=3.0` |
| **Angr** — symbolic execution, stdin/argv solving, backward slicing | 23 | `pip install angr` (~200 MB) |
| **Miasm** — IR lifting, SSA, deobfuscation, cross-arch assembly | 22 | `pip install miasm` |
| **NumPy** — entropy maps, byte histograms, XOR key recovery, similarity | 9 | `pip install numpy>=2.0.0` |
| **YARA** — signature scanning, crypto/threat detection, IDB annotation | 11 | `pip install yara-python` |
| **Construct** — declarative PE/ELF/protocol parsing | 10 | `pip install construct` |
| **dissect.cstruct** — C-syntax struct/enum parsing & serialization | 7 | `pip install dissect.cstruct` |
| **pyelftools** — ELF/DWARF debug info, symbol tables | 6 | `pip install pyelftools>=0.31` |
| **filetype** — magic-byte file type identification | 4 | `pip install filetype` |
| **XOR solver** — 8-family universal cipher solver (always-on; Z3 optional) | 3 | `pip install z3-solver` (optional) |
| **Debugger** — live debugger control, breakpoints, memory sync | 24 | Built-in (requires `--unsafe`) |

---

## Discovery: lazy mode

When the server runs with `--lazy`, `tools/list` returns only **4 meta-tools**:

| Meta-tool | What it does |
|-----------|-------------|
| `list_modules` | Show 6 groups with live tool counts + representative tool names (in the description) |
| `list_tools(module=…, search=…, limit=50, offset=0)` | Browse a group, or keyword-search across all groups |
| `describe_tool(name)` | Get full input schema for one tool |
| `invoke_tool(tool, args)` | Execute any tool by name |

**Cheapest discovery paths (fewest round-trips):**
1. Know the name → `invoke_tool(tool="decompile", args={"addr": "main"})`
2. Know a keyword → `list_tools(search="entropy")` → `invoke_tool`
3. Know the group → `list_tools(module="analysis")` → `invoke_tool`
4. Exploring → `list_modules` → `list_tools(module=…)` → `invoke_tool`

All tool arguments go inside `args={...}`. Arguments placed at the top level alongside `tool` are silently ignored.

---

## Lazy mode groups

### `analysis` — Decompilation, disassembly, xrefs, callgraph, profiling, XOR
Representative tools: `decompile`, `disasm`, `xrefs_to`, `trace_data_chain`, `find_similar_functions`, `callgraph`, `func_profile`, `find_xor_pattern`, `xor_solve_universal`, `xor_model_from_disassembly`, `numpy_entropy_map`, `numpy_byte_histogram`, `analyze_function_completeness`, `diff_functions`, `demangle_names`, `decompile_batch`

### `core` — Server health, instance discovery, IDB metadata, strings, imports
Representative tools: `server_health`, `list_funcs`, `func_query`, `entity_query`, `find_regex`, `search_text`, `imports`, `list_strings`, `survey_binary`, `list_instances`, `select_instance`, `get_active_instance`, `idb_save`, `task_submit`, `task_poll`

### `formats` — LIEF, YARA, Construct, cstruct, filetype, pyelftools
Representative tools: `lief_info`, `lief_checksec`, `lief_verify_signature`, `lief_rich_header`, `lief_imports`, `lief_strings`, `yara_scan`, `yara_scan_builtin_crypto`, `yara_scan_builtin_threats`, `yara_idb_annotate`, `construct_parse_pe_headers`, `construct_parse_elf_headers`, `cstruct_parse_c_definition`, `filetype_identify_buffer`, `elf_dwarf_functions`, `hybrid_lief_checksec_exploit_assess`

### `modify` — Renaming, comments, patching, types, structs, stack
Representative tools: `rename`, `set_comments`, `patch_asm`, `define_func`, `scan_and_define_funcs`, `declare_type`, `set_type`, `type_propagate`, `struct_recovery`, `analyze_constructor`, `stack_frame`, `enum_upsert`

### `recon` — Graph metrics, FLIRT signatures, vtable scanning, stripped-binary recon
Representative tools: `nx_call_graph`, `nx_central_functions`, `workflow_reveng_overview`, `get_binary_sections`, `find_vtable_candidates`, `dump_vtable`, `find_indirect_calls`, `find_global_writers`, `apply_flirt_signature`, `make_signature`, `find_function_prologues`, `py_eval`

### `symbolic` — Triton, Miasm, Angr, Unicorn, hybrid workflows
Representative tools: `triton_init`, `triton_symbolize_register`, `triton_process_function`, `triton_solve_path_constraints`, `miasm_lift_function`, `miasm_deobfuscate_cfg`, `miasm_get_cfg_summary`, `angr_find_paths`, `angr_load_segment`, `unicorn_emulate`, `unicorn_emulate_and_patch`, `hybrid_analyze_function`, `hybrid_iterative_deobfuscate`, `hybrid_unicorn_triton_analyze`, `workflow_solve_crackme`, `workflow_unicorn_decrypt_analyze`

---

## Tool conventions

All tools return a structured `dict`. On success: `{"ok": true, ...}`. On failure: `{"ok": false, "error": "descriptive message"}`. There are no raw strings or untyped lists at the top level.

### Addresses
Pass addresses as hex strings (`"0x401000"`) or symbol names (`"main"`). Never pass raw integers — the server converts via `parse_address()`.

### Batch input
Many tools accept a comma-separated string or Python list where sensible (e.g. `addrs="0x11a9,0x123e"` or `addrs=["0x11a9", "0x123e"]`).

### Pagination
Search results use cursor-based pagination: pass `offset=` / `limit=` (max 10,000). Tools like `list_funcs`, `entity_query`, and `get_bulk_function_hashes` support `offset` + `count` pagination.

### Output limiting
Responses >50 KB are auto-truncated with an `output_id`. Call `read_mcp_output(output_id=..., offset=0)` to retrieve the full result in chunks.

### Async tasks
Heavy tools (callgraph on large binaries, `triton_process_function`, `angr_find_paths`, `workflow_reveng_overview`, `yara_idb_annotate`, …) can be submitted as background tasks instead of blocking the connection:
```python
task_id = task_submit(tool_name="decompile", arguments={"addr": "0x401000"})["task_id"]
# … poll until done:
result = task_poll(task_id=task_id)
```
Or use the zero-boilerplate path with `invoke_tool`:
```python
invoke_tool(tool="workflow_reveng_overview", args={}, async_mode=True)
```
This submits, polls every 2 seconds up to 300 seconds, and returns the completed result transparently.

### Unsafe tools
Destructive/debugger tools (patching, symbol surgery, debugger control) are gated behind `--unsafe`. If you call them without `--unsafe`, the server returns `{"ok": false, "error": "unsafe tool not available — server must be started with --unsafe"}`.

### Debugger tools
Debugger control tools (`dbg_*`) additionally require the `?ext=dbg` extension to be active. Without it, they return: `{"ok": false, "error": "tool requires debugger extension (?ext=dbg)"}`.

---

## First-call recommendations

| If you want to… | Call this first |
|-----------------|----------------|
| Understand what binary is loaded | `survey_binary()` |
| Find all available functions | `list_funcs()` or `func_query()` |
| Decompile and analyze one function | `decompile(addr=…, include_addresses=true)`, then `analyze_function(addr=…)` for combined analysis |
| Find which functions reference a string | `find_functions_by_string(pattern=…)` |
| Trace data flow through xrefs | `trace_data_chain(address=…, direction="backward")` |
| Solve a serial-key crackme (Triton path) | `hybrid_analyze_function(address=…)` or `triton_analyze_function(address=…, symbolize_args=…)` |
| Solve a stdin-fed crackme (Angr path) | `workflow_solve_crackme(target_address="auto-detect", input_mode="stdin")` |
| Decrypt a runtime-encrypted section | `workflow_unicorn_decrypt_analyze(decrypt_stub=…, encrypted_start=…, encrypted_size=…)` |
| Find XOR-obfuscated constants | `find_xor_pattern(addr=...)`, then `xor_solve_universal(addr=..., family="auto")` |
| Check security mitigations | `lief_checksec()` |
| Scan for crypto constants | `yara_scan_builtin_crypto()` |
| Detect packers / threat indicators | `yara_scan_builtin_threats()` |
| Identify packed/encrypted section layout | `numpy_entropy_map(addr=…, size=…)` |
| Get binary-wide structural overview | `workflow_reveng_overview()` or `nx_central_functions(top_n=20)` |
| List instances or switch binaries | `list_instances()`, `select_instance(port=…)` |
