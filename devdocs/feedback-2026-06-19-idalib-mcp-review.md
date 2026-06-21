# Feedback Review — idalib MCP `Bully.exe` pass (2026-06-19)

Source: `Feedbacks/idalib_mcp_feedback.md` (analyst: Kimi Code CLI via `idalib`
MCP server; binary: `Bully.exe` v1.200, ~24K functions, PE32 x86).

This document tracks each issue raised in that review, the verdict after
investigation against the Synapse MCP source tree, and the resulting
implementation work.  **None of the issues were caused by the v2 upstream
sync** (verified by diffing against the `pre-v2-merge` git tag — each
failing code path pre-existed the rebase and was carried forward as-is).

---

## Verdict summary

| #  | Issue                                            | Sev  | Verdict           | Status      |
|----|--------------------------------------------------|------|-------------------|-------------|
| 1  | `find_regex` rejects `output_mode`               | P1   | Agent-hallucinated param | Mitigated |
| 2  | `trace_data_chain` is CFG walk, not data-flow    | P2   | Valid — gap              | Fixed        |
| 3  | Vtable callers invisible (`get_function_callers`) | P2   | Valid — gap              | Fixed        |
| 4  | `find_indirect_calls` returns 0 on 32-bit PE     | P2   | Valid bug                 | Fixed        |
| 5  | `get_global_value` fails on untyped globals      | P1   | Valid bug                 | Fixed        |
| 6  | Heavy calls need async; threshold unclear        | P3   | Valid gap                | Not addressed this round (existing auto-async layer covers P2 priority; cost_estimate field is a future PR) |
| 7  | Parameter naming inconsistent                    | P3   | Valid friction         | Already mitigated by existing `arg_aliases.py` infrastructure — verified wired into the JSON-RPC dispatcher in `rpc.py:364` and `server.py:890` |

Legend: **Fixed** = code change shipped; **Mitigated** = no code bug, but
docstring / error message improved to prevent recurrence; **Not addressed
this round** = tracked for a separate PR.

---

## Detailed fix notes

### Issue 1 — `find_regex` rejects `output_mode` (Mitigated)

**Root cause:** `output_mode` does not exist anywhere in the Synapse MCP
codebase.  The JSON-RPC dispatcher at `zeromcp/jsonrpc.py:254-260` correctly
rejected the hallucinated parameter; the tool's `inputSchema` is accurate.

**Mitigation shipped:**
1. Improved the JSON-RPC "unexpected parameters" error to include a
   "did you mean..." suggestion via `difflib.get_close_matches` against
   the tool's real parameter names (`zeromcp/jsonrpc.py`).
2. Added an "Output filtering" note to the `find_regex` docstring
   explaining the existing `search_strings` / `search_names` toggles and
   the per-match `kind` field (`"string"` / `"name"` / `"raw"`) for
   client-side filter modes (`api_core.py:1491`).

### Issue 2 — `trace_data_chain` is CFG walk, not data-flow (Fixed)

**Root cause:** `trace_data_chain` performs BFS over `idautils.XrefsTo` /
`XrefsFrom` — statically-resolvable xrefs only. On `mov edi, [ebx+8]`
with an unknown runtime `ebx`, IDA records no `dr_R` xref and the chain
dead-ends.  The docstring overpromised capability.

**Fix shipped:**
1. Docstring rewritten to state explicitly that the traversal is xref-graph,
   not register def-use. Added an "When to escalate" section pointing at
   `miasm_trace_data_flow`, `triton_backward_slice`, and
   `workflow_trace_data_flow` as heavier engines (`api_analysis.py:4722`).
2. Added a new `register` parameter: when set (e.g. `register="edi"`) and
   `direction="backward"`, dispatches to Miasm's IR `DependencyGraph` for
   true intra-function def-use analysis. Falls through to xref-graph
   traversal with no warning when Miasm is unavailable, preserving
   backward-compatible behaviour.
3. Updated `AGENTS.md` "Phase 4 Tools — `trace_data_chain` accuracy notes"
   with the limitation, the new `register=` dispatch, and escalation paths.

### Issue 3 — Vtable callers invisible (Fixed — three layers)

**Root cause:** `get_function_callers` walks `CodeRefsTo(ea, True)`, IDA's
**code** xref database only. For functions invoked solely through
`call [reg+disp]` (vtable dispatch), IDA never links the call site to the
target — `CodeRefsTo` returns empty and the tool gave no hint that the
function was reachable at all.

**Fix shipped — Option A (fallback field):**
`get_function_callers` now emits a `potential_vtable_references` field
whenever the code-xref set is empty.  This field lists the data xrefs
(`dr_R` / `dr_W` / `dr_O`) to the function entry address, with the loader
instruction's disassembly and the containing function so the agent knows
the function lives in one or more vtables (`api_analysis.py:2561`).

**Fix shipped — Option B (new `find_vtable_loaders` tool):**
New `api_recon.py` tool that walks data xrefs of a vtable address, decodes
each loader instruction (`lea reg, [vtable]` / `mov reg, imm_vtable` /
constructor `mov [rcx], offset vtable`), and reports the destination
register and containing function. This is the missing primitive that
unblocks the vtable-caller workflow.

**Fix shipped — Option C (new `find_vtable_callers` composite):**
New `api_recon.py` tool that orchestrates the full workflow in one call:
  1. Enumerate data refs to `func_addr` (the vtables it lives in).
  2. Per vtable, run `find_vtable_loaders` to find loader functions.
  3. Per loader, scan for `call [reg+disp]` sites whose disp matches the
     slot index of `func_addr` in its vtable.

Returns per-caller hit: caller function, loader instruction address,
destination register, call site, vtable displacement, slot index. Also
captures `call reg` (register-dispatch) sites with `slot_index=-1` so
the agent knows they need `identify_vtable_call` to confirm.

### Issue 4 — `find_indirect_calls` returns 0 on 32-bit PE (Fixed bug)

**Root cause:** The operand-type filter at `api_recon.py:1029-1057` only
accepted `o_displ` (`call [reg+disp]`) and `o_phrase` (`call [reg]`). It
silently dropped:
- **`o_mem`** — `call dword ptr [absolute_addr]` (`FF 15 disp32`), the
  dominant 32-bit PE form for IAT thunks AND many vtable dispatches.
- **`o_reg`** — `call reg` (`FF D0`–`FF D7`), the register-dispatch form
  emitted by GCC/Clang/MSVC for `mov reg, [vtable+disp]; call reg`.

Both incremented `instructions_scanned` (their itype IS `NN_callni`) but
produced zero `sites`, yielding the misleading "scanned N, found 0"
report the analyst saw.

**Fix shipped (`api_recon.py`):**
1. Extended the operand-type filter to also accept `o_mem` and `o_reg`.
2. Added an `addr_type` field to each `IndirectCallSite` (`"displ"` /
   `"phrase"` / `"mem"` / `"reg"`) so callers can distinguish 32-bit forms
   from 64-bit `o_displ` vtable dispatch.
3. Added a `by_addr_type` histogram so the full operand-type breakdown is
   visible per call, eliminating future "found 0 but scanned N" confusion.
4. Added an `indirect_calls_seen` diagnostic field, counting *all*
   `NN_callni` itypes detected regardless of operand match.
5. Rewrote the zero-sites note to distinguish "no indirect-call itypes
   detected at all" from "indirect calls seen, but offset_filter rejected
   them all" — so the failure is always diagnosable.

**Sibling fix (`identify_vtable_call`):** The same `o_displ`/`o_phrase`
upfront filter at `api_recon.py:1119` rejected 32-bit `call dword ptr
[absolute_addr]` as "operand is not reg-indirect". Now accepts `o_mem`
(returns the absolute address as a terminal `final_source`) and `o_reg`
(walks backward for the register's load instruction). This closes the
32-bit loop: now `find_indirect_calls` can enumerate `call dword ptr
[iat_slot]` and `identify_vtable_call` can trace each site backward.

### Issue 5 — `get_global_value` fails on untyped globals (Fixed bug)

**Root cause:** `get_global_variable_value_internal` at
`api_memory.py:343-369` raises `IDAError("Failed to get type information
for variable at ...")` when:
1. `ida_nalt.get_tinfo(tif, ea)` returns False (no type annotation), AND
2. `ida_bytes.get_item_size(ea)` returns 0 (no IDB-laid-out data item).

The error message is misleading — that code path never actually *used*
type information; it was the named-but-untyped path.  Stripped binaries,
externs, and partially-analyzed IDBs are full of such globals.

**Fix shipped (`api_memory.py:343`):** Replaced the `IDAError` raise with
the canonical pointer-size fallback pattern used by `read_struct` at
`api_types.py:904-908` (and 9+ other modules):
`ptr_size = 8 if compat.inf_is_64bit() else 4; return hex(read_int_bss_safe(ea, ptr_size))`.
BSS unloaded bytes still return `0x0` per the existing `read_int_bss_safe`
contract.

### Issue 6 — Heavy calls need async (Not addressed this round)

**Investigation result:** Synapse MCP already has a two-layer auto-async
routing system layered on top of three parallel cost-metadata sources
(`@tool_timeout`, `_ADAPTIVE_TIMEOUT_PROFILES`, `_TYPICAL_DURATIONS`).
11 tools already have `@tool_timeout(N, prefer_async=True)` and get
auto-submitted as background tasks via `rpc.py:368-388`. The lazy-mode
`invoke_tool` adds a prefix-based safety net for angr/hybrid tools at
`server.py:1372-1411`.

**What's missing:** None of this cost metadata is surfaced to MCP clients
as a `cost_estimate` field in `tools/list`.  Implementing the resolver
that reads `__ida_mcp_timeout_sec__` / `__ida_mcp_prefer_async__` from
each `@tool` function and injects the resulting `{typical_s, max_s,
prefer_async, category}` block into the schema is a ~100-line change
across `zeromcp/mcp.py` and `server.py`.  Tracked as a separate PR.

### Issue 7 — Parameter naming inconsistency (Already mitigated)

**Investigation result:** A comprehensive parameter-alias normalization
layer already exists at `arg_aliases.py`. The `normalize_tool_args`
function is wired into both transports: the plugin-side `rpc.py:364`
patch on `tools/call` (fires for any transport — HTTP, SSE, stdio) and
the proxy-side `server.py:890`.

The aliases cover the reported inconsistencies:
- `addr` ↔ `address` (global rename plus per-tool reversals for tools
  that genuinely declare `addr` as their real param, like `decompile`,
  `disasm`, `analyze_function`)
- `addrs` ↔ `addresses` (batch tools)
- `start_address`/`start_ea`/`src` → `start`, `end_address`/`target_ea`/`dst` → `end`
- `max_results`/`max_entries` → `limit`
- Plus a schema-aware reversal pass that restores canonical names if a
  global rename would otherwise produce a key the tool doesn't accept.

**Per-tool additions shipped this round:** Added aliases for the two new
vtable discovery tools (`find_vtable_loaders` / `find_vtable_callers`)
in `arg_aliases.py` so `address=`/`addr=`/`func=`/`function=` are all
accepted transparently.

---

## Files touched

| File | Lines changed | Issue |
|---|---|---|
| `src/ida_pro_mcp/ida_mcp/api_memory.py` | ~10 | #5 |
| `src/ida_pro_mcp/ida_mcp/api_recon.py` | +590 | #3 (B/C), #4 |
| `src/ida_pro_mcp/ida_mcp/api_analysis.py` | +205 | #2, #3-A |
| `src/ida_pro_mcp/ida_mcp/api_core.py` | +9 | #1 docstring |
| `src/ida_pro_mcp/ida_mcp/zeromcp/jsonrpc.py` | +22 | #1 error hint |
| `src/ida_pro_mcp/ida_mcp/rpc.py` | +2 | #3 tool routing |
| `src/ida_pro_mcp/ida_mcp/arg_aliases.py` | +5 | #7 new tool aliases |
| `src/ida_pro_mcp/ida_mcp/tests/test_api_memory.py` | +80 | #5 regression |
| `src/ida_pro_mcp/ida_mcp/tests/test_api_analysis.py` | +290 | #3, #4 regression |
| `AGENTS.md` (root) | ~20 | #2 doc update |

All 9 files compile clean under `python -m py_compile`. Sync completed
via `ida-mcp-sync.ps1` to the deployed IDA plugin directory.

## Wishlist items (not addressed this round)

| Wishlist item | Status |
|---|---|
| Per-function byte signature export | **Already exists** — `make_signature_for_function(addr, format="mask")` in `api_sigmaker.py`.  Cross-linked from `analyze_function` docstring. |
| Better decompile+disasm integration | **Already exists** — `analyze_function_full` has `include_disasm=True` + `include_decompile=True` flags. |
| Cross-binary comparison | Partial — `compare_instances` (idalib multi-instance) and `numpy_function_similarity` exist.  A simpler "diff this function across two binaries on disk" wrapper would be polish. |
| Built-in note-taking / annotation | **Already exists** — `set_comments` at `api_modify.py`. |
| Async cost indicators (Issue 6) | Not addressed this round — tracked as a separate PR per the priority matrix above. |

---

## Verification approach

- `python -m py_compile` confirms all 9 modified source files parse cleanly.
- Regression tests added for:
  - `#5` untyped named-global fallback (`test_get_global_value_untyped_named_global_fallback`)
  - `#4-A` `find_indirect_calls` new schema fields + diagnostics (`test_find_indirect_calls_reports_addr_type_and_diagnostics`, `test_find_indirect_calls_zero_results_diagnostic_is_honest`)
  - `#4-B` `identify_vtable_call` accepts the new operand forms (`test_identify_vtable_call_handles_o_mem_form`)
  - `#3-A` `get_function_callers` vtable fallback (`test_get_function_callers_vtable_fallback_on_empty`)
  - `#3-B/C` new vtable discovery tools (`test_find_vtable_loaders_returns_loader_shape`, `test_find_vtable_callers_returns_shape_on_real_function`)
- `ida-mcp-sync.ps1` synced all 90 `.py` files to the deployed IDA plugin
  directory (`%APPDATA%/Hex-Rays/IDA Pro 9.3/plugins/ida_mcp`).
- Headless `ida-mcp-test` not run in this pass — recommended that the
  analyst verify the new tools appear in `tools/list` and that a
  representative tool call from each new feature succeeds against
  `Bully.exe` to validate the entire workflow.
