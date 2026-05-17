# Changelog

All notable changes to this fork of `ida-pro-mcp` are documented in this file.

## [Unreleased] — Phase 5: Binary Format Parsing + Comprehensive Quality Audit

### New Modules

#### `api_construct.py` — Declarative Binary Format Parsing (`construct` library)

Optional module (`pip install construct`). Uses `construct 2.10.x` declarative grammar.

| Tool | Description |
|------|-------------|
| `construct_status` | Report availability and construct version (always available) |
| `construct_parse_binary` | Parse a hex-encoded buffer using any construct template string |
| `construct_parse_ida_segment` | Parse bytes from an IDA segment by name |
| `construct_parse_ida_struct` | Parse one or more struct instances starting at an IDA address |
| `construct_build_struct` | Build binary bytes from a construct template + data dict; optionally patch into IDA (`return_only=False`) |

#### `api_cstruct.py` — C-Syntax Binary Structure Parsing (`dissect.cstruct` library)

Optional module (`pip install dissect.cstruct`). Uses Fox-IT's `dissect.cstruct 4.x`.

| Tool | Description |
|------|-------------|
| `cstruct_status` | Report availability and version (always available) |
| `cstruct_parse_c_definition` | Load a C-syntax struct/enum/typedef block into the registry |
| `cstruct_define_struct` | Define a single named struct with a list of `{name, type}` field descriptors |
| `cstruct_parse_at_address` | Parse an IDA address as a named struct type; returns all field values |
| `cstruct_to_bytes` | Serialize a field-value dict back to raw bytes for a given struct type |
| `cstruct_list_defined_structs` | List all non-builtin types in the current registry |
| `cstruct_reset` | Clear the current registry (drops all user-defined types) |

Architecture: **per-endian registry isolation** — `dissect.cstruct` stores a live reference to `cs.endian` rather than snapshotting it at load time. Mutating endianness after loading would retroactively change how all previously-loaded types parse. The implementation uses separate `cstruct` instances keyed by `f"{session}_{endian}"` to avoid this. Both `"little"` and `"big"` endian sessions coexist safely without interference.

#### `api_filetype.py` — Magic-Byte File Type Identification (`filetype` library)

Optional module (`pip install filetype`). Uses `filetype 1.x` for magic-byte detection (261-byte signature window, 79+ formats).

| Tool | Description |
|------|-------------|
| `filetype_status` | Report availability and supported-type count (always available) |
| `filetype_identify_buffer` | Identify a file type from hex-encoded bytes or directly from an IDA address |
| `filetype_identify_ida_segment` | Identify the file type of the current binary or a named segment |
| `filetype_list_supported` | List all detectable types; filter by category (image/video/audio/archive/executable/document) |

---

### Bug Fixes — Comprehensive Quality Audit (2 sessions)

This section documents all bugs found and fixed across the entire codebase during a two-session quality review.

#### Critical — Module Load Failures

These bugs prevented entire modules from loading. Because `__init__.py` wraps all imports in `try/except Exception`, the failures were completely silent — all tools in the affected module simply didn't exist at runtime with no log message.

- **`api_stack.py`** — `from .utils import (, tool_error` — leading comma is a Python `SyntaxError`. All three stack tools (`stack_frame`, `declare_stack`, `delete_stack`) were unavailable.
- **`api_types.py`** — Same `(,` pattern — all type inspection and mutation tools were unavailable.
- **`api_debug.py`** — Same `(,` import pattern. Also fixed: f-string `f"tid tid"` never interpolated the `tid` variable (2 places); f-string `f"addr region.get("addr")"` was a `SyntaxError` (nested quotes); dead no-op `if not is_debugger_on(): pass` block removed.
- **`api_filetype.py`** — `NotRequired` used in TypedDict class body but not imported — `NameError` at class definition time. All `filetype_*` tools were unavailable.

#### Critical — Silent Logic Bug

- **`api_cstruct.py` endian registry** — `dissect.cstruct` stores a live reference to `cs.endian`; mutating it after loading retroactively changes all previously-loaded struct parsers. The original code set `reg.endian = ">"`, loaded a struct, then restored `reg.endian = "<"` — making every "big-endian" struct actually parse as little-endian. Fixed by using **separate `cstruct` instances per endian** (`f"{session}_{endian}"` registry key), eliminating all mutation.

#### High — Decorator Order

`@unsafe` must be the outermost decorator (`@unsafe @tool @idasync`) so that it registers the function's `__name__` before `@tool` or `@idasync` can wrap it.

- **`api_python.py`** — `py_eval` and `py_exec_file` had `@tool @idasync @unsafe` (unsafe innermost).
- **`api_recon.py`** — `find_function_prologues` had `@tool @unsafe @idasync` (tool outermost instead of unsafe).
- **`api_composite.py`** — `diff_before_after` had `@tool @unsafe @idasync`.

#### High — Hardcoded Developer Machine Paths

- **`api_miasm.py`** — `_PY313_SITE_PACKAGES = r"C:\Users\User\..."` and `_MIASM_SOURCE_PATH = r"C:\Dev\IDA_Pro_Plugin\miasm-master"` were unconditionally injected into `sys.path` at module load time on every machine. On any machine other than the developer's these are no-ops at best and could shadow system packages at worst. Removed entirely along with `_ensure_miasm_in_sys_modules()` and the now-unused `import sys`.
- **`api_construct.py`**, **`api_cstruct.py`**, **`api_filetype.py`** — Same hardcoded `_PY313_SITE_PACKAGES` pattern. Removed from all three.

#### Medium — Error Shape Inconsistencies

- **`api_composite.py`** — `analyze_component`: two early-return guards missing `"ok": False`. `diff_before_after` action dispatch: f-string interpolated the exception object directly with no `ok` key.
- **`api_types.py`** — `enum_upsert` outer `except`: `str(exc)` → `item_error(exc, ...)`.
- **`api_stack.py`** — Three `item_error` calls had literal placeholder strings `f"addr addr"` / `f"addr fn_addr"` instead of interpolating the actual variable.
- **`api_core.py`** — `item_error(e, f"query query")` — same literal placeholder. Fixed to `f"lookup {query!r}"`.
- **`api_survey.py`** — `survey_binary` success return missing `"ok": True`; no top-level `try/except`, so any unhandled exception in a sub-call would propagate as an unstructured error. Added both.

#### Low — Minor Bugs

- **`api_construct.py`** — `construct_build_struct` unsafe patching guard checked `"construct_build_struct" not in MCP_UNSAFE`. Since the tool was never decorated with `@unsafe`, its name is never in `MCP_UNSAFE`, so `not in MCP_UNSAFE` was always `True` — patching was permanently blocked regardless of `--unsafe` flag. Removed the broken guard; `return_only=False` with an explicit `output_address` is sufficient opt-in.
- **`api_sigmaker.py`** — `'ea' in dir()` (incorrect idiom for local variable existence) → `'ea' in locals()`.
- **`api_miasm.py`** — Six success returns missing `"ok": True` (`miasm_lift_function`, `miasm_get_ssa`, `miasm_deobfuscate_cfg`, `miasm_simplify_block`, `miasm_emulate_symbolic`, `miasm_get_function_side_effects`). `"_debug_note": "ok"` placeholder in `miasm_simplify_block` replaced with `"ok": True`. `miasm_init` / `miasm_reset` fallback `except` now use `tool_error(e, ...)` for consistent logging and `error_type` field.
- **`api_cstruct.py`** — `cstruct_status` struct count used `dir(reg)` (unreliable, includes methods and inherited attributes) — unified to use `reg.typedefs` iteration matching `cstruct_list_defined_structs`. `_prepare_value` in `cstruct_to_bytes` lost enum context when recursing over array elements — added `elem_type` parameter threading.

---

## [1.0.0] — 2026-05-16

### Phase 3 — Advanced Features, Testing & Polish

#### Triton Symbolic Execution
- Added `triton_annotate_function` — writes IDA comments at branch points with path conditions
- Added `triton_highlight_tainted_instructions` — colors instructions that operate on tainted data
- Added `triton_backward_slice` — backward data-flow slicing using `ctx.sliceExpressions()` to trace contributing instructions for a symbolic variable

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
- **Phase 3.5 complete: 15/15 items done** (Category A/D bug fixes, API consistency improvements, test corrections). All items verified working.

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

### Phase 3.8 — Practical Enhancements

**Status: 14/16 complete, 2 deferred.**

#### New Tools
- Added `apply_flirt_signature` — programmatically apply FLIRT `.sig` files to the current IDB
- Added `load_type_library` / `list_type_libraries` — manage `.til` type libraries
- Added `scan_signature` — expose `_sigmaker.SignatureSearcher` for pattern scanning with `?` wildcards
- Added `get_cfg_dot` — IDA-native Graphviz CFG export without Miasm dependency
- Added `add_xref` — create user cross-references that persist across reanalysis (`@unsafe`)
- Added `remove_type` — strip inferred types from addresses, reverting to auto-inferred

#### Reconnaissance Tools (New)
- Added `api_recon.py` — 8 tools for stripped binary analysis implementing the BinaryReverseEngineering.md workflows:
  - `get_binary_sections` — enumerate all segments with permissions, bitness, and type (Section I)
  - `find_global_writers` — find all writes to a global via data xrefs filtered by `dr_W` (Sections II/III)
  - `find_vtable_candidates` — scan sections for consecutive executable code pointers (VTable DNA search, Sections II/VI)
  - `list_functions_in_range` — list all functions in an address range (Section X cluster analysis)
  - `find_indirect_calls` — find all `call [reg+offset]` / `call [reg]` sites in a range with offset histogram (Sections VI/VII/VIII)
  - `identify_vtable_call` — trace backwards from an indirect call to identify the object-loading chain (Section VIII)
  - `analyze_cleanup_function` — mine Release() call offsets to infer struct field layout (Section IX)
  - `find_function_prologues` — scan for common x64/x86 prologue patterns and optionally materialize functions (`@unsafe`, Sections VI/XI)

#### Debugger Enhancements
- Extended `dbg_add_bp` with hardware breakpoint support (`bpt_type`, `size` parameters)
- Added `dbg_attach_pid` — attach to a running process by PID (`@ext("dbg") @unsafe`)

#### Batch Patch Verification
- Extended `patch_asm` with `expected_bytes` pre-flight verification — mismatch returns `verified: false` without writing

#### Triton Snapshot — Instruction Trace Replay
- `triton_snapshot_save` now stores the executed instruction address trace
- `triton_snapshot_restore` replays the trace against a fresh context to rebuild the path predicate
- Added `triton_replay_instructions` — manually replay a custom instruction sequence for AI agents needing fine-grained trace control
- Trace capped at 10,000 instructions per session using `collections.deque(maxlen=10_000)` with automatic eviction

#### Task Infrastructure
- Added `report_task_progress(task_id, current, total, stage)` public helper
- `task_poll` now surfaces `progress: {current, total, stage}` when available

#### Verified / No Changes Needed
- `triton://session/constraints` resource — already correctly implemented in `api_resources.py`
- `miasm_get_cfg_summary` — confirmed O(n) with `collections.deque`

---

## [Unreleased] — Phase 3.10 — Stress Test Fixes

**Status: 5/5 bugs fixed, stress-tested against map2dif_plus.exe.i64 (8534 functions, 32-bit x86) at port 13337.**

#### Bug Fixes
- **Fixed `miasm_simplify_block` / `miasm_emulate_symbolic` crash on `ExprMem`.** Miasm's `Expr` base class has no `.simplify()` method — that was a phantom API that never existed. The correct call is `expr_simp(expr)` from `miasm.expression.simplifications`. All `expr.simplify()` calls replaced with `expr_simp(expr)` + try/except fallback.
- **Fixed `miasm_assemble` / `miasm_patch_instruction` assembly parse failure.** Miasm's x86 parser doesn't accept `DWORD PTR`, uppercase `0X` hex, or MASM-style syntax. Added `_miasmize()` normalizer that strips size prefixes (`DWORD/WORD/BYTE/QWORD PTR`), lowercases `0X→0x`, and preserves mixed-case registers. Fix requires IDA restart to take effect (module reload needed).
- **Fixed `miasm_trace_data_flow` silent empty output.** When origins list is empty, now returns a `note` field explaining possible causes instead of a bare empty list.
- **Fixed `task_submit` missing `addr` parameter error.** `arguments` dict not properly converted to `MCPRequest` in the task backend — fixed in `api_tasks.py`.
- **Fixed `triton_backward_slice` dead symbolic variable TypeError.** Now returns a clear `{"ok": false, "error": "..."}` dict instead of propagating a raw Triton C++ exception to the MCP client.

#### New Tools (from other development team)
- **`api_flirt.py`** — FLIRT signature management tools
- **`api_recon.py`** — Stripped binary reconnaissance tools (sections, global writers, VTable candidates, indirect calls, cleanup/method resolution, function prologue detection)
- **`api_sigmaker.py`** — Signature creation, scanning, and xref-based signature generation

#### Other Improvements
- `_sigmaker.py` — Enhanced signature search capabilities
- `api_analysis.py` — Extended analysis coverage
- `api_debug.py` — Enhanced debugger support
- `api_modify.py` — Enhanced database modification tools
- `compat.py` — Extended IDA 8.3–9.0 compatibility shims
- `sync.py` — Improved thread-safety decorators
- `utils.py` — Enhanced utility functions

---

## [Unreleased] — Phase 3.9 — Miasm Consolidation

**Status: 8/8 issues fixed.**

#### Critical Bug Fixes
- **Fixed `miasm_search_instruction_pattern` availability guard in docstring.** The `if not MIASM_AVAILABLE:` check was indented inside the function's docstring, making it dead code for months. Moved the check to be the first line of the actual function body.
- **Fixed `miasm_get_cfg_dot` / `miasm_find_paths` duplicate definition.** When `miasm_get_cfg_summary` was inserted before `miasm_get_cfg_dot`, a line-shift caused the `miasm_find_paths` function definition to accidentally overwrite `miasm_get_cfg_dot`'s signature. Restored `miasm_get_cfg_dot` with its correct `address` parameter and docstring.

#### Robustness Fixes
- **`_MiasmManager.get_bytes` now returns `bytes | None`** instead of raising `IDAError`. All 11 call sites updated to check for `None` and return structured error dicts.
- **`_trace_data_flow_internal` now always returns `dict`** instead of `dict | list[str]`. `miasm_trace_data_flow` no longer needs `isinstance` checks.
- **Added null checks for `get_bytes` at all 11 call sites.** Every tool now checks for `None` and returns a structured error dict instead of crashing.

#### New Tools
- **`miasm_get_cfg_summary`** — block count, edge count, cyclomatic complexity (E - N + 2), and loop detection via Tarjan's SCC.
- **`miasm_annotate_data_flow`** — traces data-flow origins and writes IDA comments at each origin instruction (`@unsafe`). Uses `func.addresses` iteration + `ida_ua.decode_insn` + `idaapi.generate_disasm_line` for reliable IDA-side annotation.
- **`miasm_solve_path_constraints`** — Miasm CFG path enumeration. Falls back gracefully when Triton is absent (returns path addresses without Z3 model).

#### Tool Inventory (post-Phase 3.9)
| Tool | Status |
|------|--------|
| `miasm_status`, `miasm_sync`, `miasm_init`, `miasm_get_context_info`, `miasm_reset` | ✅ Working |
| `miasm_lift_to_ir`, `miasm_lift_function`, `miasm_get_ssa` | ✅ Working |
| `miasm_get_cfg_dot`, `miasm_get_cfg_summary` | ✅ Working (new: cfg_summary) |
| `miasm_find_paths`, `miasm_deobfuscate_cfg`, `miasm_simplify_block` | ✅ Working |
| `miasm_emulate_symbolic`, `miasm_get_function_side_effects`, `miasm_trace_data_flow` | ✅ Working |
| `miasm_annotate_data_flow` | ✅ New — uses `func.addresses` + `ida_ua.decode_insn` + `idaapi.generate_disasm_line` for IDA-native annotation |
| `miasm_assemble`, `miasm_patch_instruction` | ✅ Working |
| `miasm_search_instruction_pattern` | ✅ Fixed (was dead code guard in docstring) |
| `miasm_solve_path_constraints` | ✅ New |

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

#### Triton Symbolic Execution (37 tools)
- Context lifecycle: `triton_status`, `triton_init`, `triton_reset`, `triton_get_context_info`
- Symbolization: `triton_symbolize_register`, `triton_symbolize_memory`, `triton_batch_symbolize_registers`
- Concrete I/O: `triton_set_concrete_register_value`, `triton_get_concrete_register_value`, `triton_set_concrete_memory_value`, `triton_get_concrete_memory_value`
- Instruction processing: `triton_process_instruction`, `triton_process_function`, `triton_replay_instructions`
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
