# Changelog

All notable changes to this fork of `ida-pro-mcp` are documented in this file.

## [1.0.0] — 2026-05-16

### Phase 3 — Advanced Features, Testing & Polish

#### Triton Symbolic Execution
- Added `triton_annotate_function` — writes IDA comments at branch points with path conditions
- Added `triton_highlight_tainted_instructions` — colors instructions that operate on tainted data

#### Miasm IR Analysis
- Added `miasm_get_cfg_summary` — structural CFG metrics: block/edge counts, cyclomatic complexity, loop detection, topological ordering
- Added `miasm_solve_path_constraints` — enumerates paths to a target block and solves for concrete inputs via Z3
- Added `miasm_annotate_data_flow` — writes IDA comments showing data-flow origins of a register

#### Hybrid Cross-Engine Workflows
- Added `hybrid_analyze_function` — Miasm deobfuscation → Triton symbolic execution → Z3 solving in a single unified report
- Added `hybrid_deobfuscate_and_patch` — Miasm dead-code elimination → identify empty blocks → optionally NOP them out in IDA (marked `@unsafe`)

#### MCP Resources
- Added `triton://session/context` — Triton context dump
- Added `triton://session/constraints` — path predicate in SMT-LIB 2
- Added `triton://session/symbolic-vars` — symbolic variable listing
- Added `miasm://function/{address}/ir` — IRCFG JSON
- Added `miasm://function/{address}/ssa` — SSA-form IRCFG JSON
- Added `miasm://function/{address}/cfg-dot` — Graphviz DOT output

#### Tests
- Extended `test_api_triton.py` with annotation and highlight tests
- Extended `test_api_miasm.py` with CFG summary, path solving, and annotation tests
- Added `test_hybrid.py` with cross-engine workflow tests

#### Documentation
- Updated `README.md` with new tool tables, hybrid workflow tips, and resource listings
- Updated `CLAUDE.md` with expanded scope priorities and module descriptions
- Added `CHANGELOG.md`

### Phase 3.5 — Pre-Release Refinement

#### API Consistency (AI-Agent-First)
- **All Miasm tools now accept `str` addresses** (hex or symbol name) via `parse_address()`, matching Triton and upstream tool conventions. Previously Miasm tools accepted `int` directly, creating an inconsistent API surface.
- **All Miasm status/context tools now return structured `dict`** instead of raw strings:
  - `miasm_status` → `{"ok": true, "available": true, "architecture": "...", ...}`
  - `miasm_sync` → `{"ok": true, "architecture": "...", "bitness": 64, ...}`
  - `miasm_get_cfg_dot` → `{"ok": true, "dot": "digraph ..."}`
  - `miasm_patch_instruction` → `{"ok": true, "address": "0x...", "bytes_patched": 3, ...}`
- This aligns with the fork's design goal: **every return value is structured, self-describing, and predictable for AI agents**.

#### Bug Fixes
- **Fixed `triton_solve_path_constraints(negate_last=True)` permanently corrupting the Triton context.** The code popped the last path constraint but never pushed the negated one back, leaving the context with a broken path predicate. Now it pops and pushes correctly, maintaining a consistent symbolic state.
- **Fixed `miasm_patch_instruction` missing `@unsafe` decorator.** It patches the IDA database but was not gated behind the `--unsafe` flag.
- **Fixed `miasm_annotate_data_flow` nested `@idasync` deadlock.** It called `miasm_trace_data_flow()` directly; both are `@idasync`-decorated tools, causing a nested `execute_sync` deadlock. Fixed by extracting `_trace_data_flow_internal()` as a non-decorated helper.
- **Fixed Triton snapshot restore crash.** Snapshots stored `path_predicate` as a C++ AST node reference. If the original `TritonContext` was garbage-collected (e.g., by `triton_init`), restoring the snapshot would segfault. Now stores the predicate as an SMT-LIB string.
- **Fixed `miasm_get_cfg_summary` topological sort performance.** Used `list.pop(0)` → O(n²); now uses `collections.deque`.
- **Relaxed `miasm>=0.1.17` to `>=0.1.5`** in `pyproject.toml` — the previous constraint was unsatisfiable in standard environments.

#### Test Fixes
- Fixed all Triton test assertions that expected `str`/`list` returns but tools actually return `dict` (TypedDict). Every Triton test was asserting wrong return types after the Phase 3 API migration.
- Added missing tests for `triton_analyze_function` and `triton_find_input_for_branch`.
- Updated Miasm tests to pass `str` addresses and assert `dict` returns.

### Phase 3.6 — Async Task System + Enhanced Fork Cherry-Pick + Skills

#### Async Task System (New)
- Added `task_submit` — submit any MCP tool as a background task, get a `task_id` immediately
- Added `task_poll` — poll status every 2-3 seconds; returns result when `status == "done"`
- Added `task_list` — list all active/recent tasks with auto-detected categories (`triton` / `miasm` / `hybrid` / `core`)
- Added `task_cancel` — cancel pending tasks; flag running tasks with `cancel_requested`
- **Design improvements over reference implementation:**
  - Structured `{"ok": true/false, ...}` returns matching this fork's conventions
  - Non-daemon worker threads with `atexit` graceful shutdown
  - Task category auto-detection for richer `task_list` output
  - Consistent error shapes across all 4 task tools

#### Enhanced Fork Cherry-Picks (xjoker/ida-pro-mcp-xjoker)
All practical features from the enhanced fork were already present in our codebase from prior integration work. Verified:
- `compat.py` — enhanced IDA 8.3–9.0 compatibility layer (identical)
- `trace.py` + `trace_dump.py` — tool-call trace persistence to IDB netnode
- `server_health` / `server_warmup` — health checks and cache pre-warming
- `export_funcs` / `insn_query` / `callgraph` limits — analysis enhancements
- `search_text` / `decompile(include_addresses=False)` — search and token-saving features

#### Skills (New)
Added 7 modular workflow skills under `skills/`:
- `binary-survey` — initial reconnaissance
- `stripped-binary-recovery` — recover semantics from stripped binaries via FLIRT, string xrefs, constant matching, call-graph analysis
- `function-deep-dive` — thorough single-function analysis
- `triton-symbolic-exec` — symbolic execution workflows
- `miasm-ir-analysis` — IR lifting and deobfuscation workflows
- `hybrid-deobfuscate` — cross-engine obfuscated code analysis
- `vuln-hunter-static` — static vulnerability hunting

#### Tests
- Added `tests/test_task_backend.py` — 18 unit tests (CRUD, cancellation, TTL expiry, concurrency)

---

## [0.2.0] — 2026-05-16

### Phase 2 — Triton Advanced + Miasm Core

#### Triton Symbolic Execution
- Added `triton_analyze_function` — one-shot pipeline: init → symbolize args → linear execute → Z3 solve
- Added `triton_find_input_for_branch` — CFG-guided branch reachability using IDA FlowChart BFS
- Added internal helpers: `_symbolize_registers_internal`, `_process_function_instructions_linear`, `_try_solve_predicate`, `_build_block_path_to_target`

#### Miasm IR Analysis
- Added `miasm_init` — explicit re-init with optional architecture override
- Added `miasm_get_context_info` — detailed session state with preview of auto-detect
- Added `miasm_reset` — full Machine rebuild from current IDA state
- Added `miasm_search_instruction_pattern` — consecutive mnemonic sequence search within basic blocks
- Fixed endianness detection: `armb`/`arml`, `aarch64b`/`aarch64l`, `mips32b`/`mips32l`, `ppc32b`/`ppc32l`

---

## [0.1.0] — 2026-05-16

### Phase 1 — Foundation

#### Project Bootstrap
- Forked from `mrexodia/ida-pro-mcp` upstream
- Added `[project.optional-dependencies]` groups: `triton`, `miasm`, `all`
- Added `ida-triton-miasm-mcp` script alias
- Wired optional imports in `ida_mcp/__init__.py`

#### Triton Symbolic Execution (32 tools)
- Context lifecycle: `triton_status`, `triton_init`, `triton_reset`, `triton_get_context_info`
- Symbolization: `triton_symbolize_register`, `triton_symbolize_memory`, `triton_batch_symbolize_registers`
- Concrete I/O: `triton_set_concrete_register_value`, `triton_get_concrete_register_value`, `triton_set_concrete_memory_value`, `triton_get_concrete_memory_value`
- Instruction processing: `triton_process_instruction`, `triton_process_function`
- Taint analysis: `triton_taint_register`, `triton_untaint_register`, `triton_taint_memory`, `triton_untaint_memory`, `triton_is_register_tainted`, `triton_is_memory_tainted`, `triton_get_taint_summary`, `triton_batch_taint_registers`
- SMT solving: `triton_solve_path_constraints`, `triton_get_ast_expression`, `triton_simplify_expression`, `triton_lift_to_smt`
- Snapshots: `triton_snapshot_save`, `triton_snapshot_restore`, `triton_snapshot_list`, `triton_snapshot_delete`

#### Miasm IR Analysis (14 tools)
- Status and context: `miasm_status`, lazy-initialized `_MiasmManager`
- IR lifting: `miasm_lift_to_ir`, `miasm_lift_function`
- SSA: `miasm_get_ssa`
- CFG: `miasm_get_cfg_dot`, `miasm_find_paths`
- Deobfuscation: `miasm_deobfuscate_cfg`, `miasm_simplify_block`
- Symbolic emulation: `miasm_emulate_symbolic`
- Data flow: `miasm_trace_data_flow`, `miasm_get_function_side_effects`
- Assembly: `miasm_assemble`, `miasm_patch_instruction`

#### Compatibility
- Added `compat.py` shims: `inf_is_32bit()`, `inf_get_procname()`, `inf_is_be()`

#### Tests
- Added `test_api_triton.py` (22 tests, auto-skip if triton-library absent)
- Added `test_api_miasm.py` (19 tests, auto-skip if miasm absent)
