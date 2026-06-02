# Phase 7 — MCP Reliability, Workflow & Coverage Improvements

**Source:** [`Feedbacks/MCP_PAIN_POINTS.md`](../../Feedbacks/MCP_PAIN_POINTS.md)
**Session date of original report:** 2026-06-02
**Status:** Deferred — awaiting prioritisation

This plan consolidates all open items from the Affinity.exe session pain-points report into
actionable work items, grouped by theme and ordered within each group by estimated
value-to-effort ratio. Items already resolved (§2.1 survey_binary, §2.2 lief_strings,
session_summary phantom) are excluded — see the source document for the full history.

---

## Group A — Quick wins (< 1 day each, no design decision needed)

### A.1 Structured decompilation failure reasons
**Source:** §2.3, §7 row 5
**Problem:** `decompile` and `decompile_batch` return a flat `"Decompilation failed"` string.
The agent cannot distinguish `function_too_small` (skip and move on) from `no_license`
(stop completely) from `code_is_data` (use `disasm` instead).
**Fix:**
- Read `hexrays_failure_t.code` from the Hex-Rays API after a failed decompile call.
- Map to a structured `failure_reason` enum:
  `no_license | function_too_small | code_is_data | unsupported_isa | timeout | unknown`
- Add `failure_reason` and `failure_detail` fields to the existing error dict in `decompile`
  and `decompile_batch` (backwards-compatible addition).
- Update the `hint` string in the error response to suggest the right next tool per reason.
**Files:** `api_analysis.py` — `decompile`, `decompile_batch`
**Effort:** ~2h

---

### A.2 `lief_info` guard for IDA database extensions
**Source:** §2.4, §4.4, §7 row 13
**Problem:** Calling `lief_info` on a `.i64` / `.idb` / `.id0` path produces a raw LIEF
parse error with no actionable hint. The agent must already know that `.i64` is not a PE.
**Fix:**
- At the top of `lief_info` (and `lief_sections`, `lief_imports`, `lief_exports`), detect
  IDA database extensions (`.i64`, `.idb`, `.id0`, `.id1`, `.nam`, `.til`).
- Return a structured error: `{"ok": false, "error": "Path is an IDA database, not a binary",
  "hint": "Use lief_info on the source PE. IDA source path: <ida_nalt.get_input_file_path()>"}`
- Include the source PE path in the hint by calling `ida_nalt.get_input_file_path()` when
  running inside IDA context.
**Files:** `api_lief.py` — `_resolve_lief_path` helper or per-tool guard
**Effort:** ~1h

---

### A.3 Section health / entropy classification in `lief_sections`
**Source:** §5.4, §7 row 11
**Problem:** `lief_sections` returns raw LIEF section data but no interpretation. An agent
cannot tell whether `.text` with entropy 7.957 is encrypted, packed, or just dense code
without computing and reasoning about Shannon entropy separately.
**Fix:**
- Add `entropy` (float, 0–8) and `entropy_class` (string enum) to each section entry.
- Classification thresholds (tunable):
  - `encrypted`: entropy > 7.2
  - `compressed`: entropy 6.0–7.2
  - `code`: entropy 4.5–6.0
  - `data`: entropy < 4.5
- Add `recommendation` string: `skip | analyze | dump_at_runtime`
  (encrypted/compressed → `dump_at_runtime`; code → `analyze`; data → `skip` or `analyze`).
- Gate on optional LIEF availability as usual; gracefully degrade if section content is
  inaccessible.
**Files:** `api_lief.py` — `lief_sections`
**Effort:** ~2h

---

### A.4 UAC-locked IDB path warning in `get_active_instance`
**Source:** §5.1, §7 row 6
**Problem:** When the active IDB is saved inside `C:\Program Files\...` or other
UAC-restricted locations, IDA silently fails to write (autosave, new analyses). The agent
never learns about this until something breaks.
**Fix:**
- In `get_active_instance`, check whether `idb_path` starts with any of the known UAC
  locations: `C:\Program Files`, `C:\Program Files (x86)`, `C:\Windows`,
  `C:\ProgramData`, plus the equivalent `%SYSTEMDRIVE%` prefixes.
- If so, add a `uac_warning` field to the result:
  `{"uac_warning": "IDB is in a UAC-protected directory. IDA may fail to autosave. Move the IDB to a user-writable path."}`
- Windows-only guard (skip on Linux/macOS IDA builds).
**Files:** `api_discovery.py` — `get_active_instance`
**Effort:** ~1h

---

### A.5 Orphaned IDB detection in `get_active_instance`
**Source:** §3.1
**Problem:** `get_active_instance` can return an IDB whose source PE no longer exists on
disk. The agent then wastes multiple tool calls confirming "this path is dead".
**Fix:**
- After reading `idb_path` and `input_file_path`, check `os.path.exists(input_file_path)`.
- If missing, add `source_missing: true` and a `source_warning` hint to the result:
  `"Source binary not found on disk. IDA analysis is read-only; tools requiring live PE data (lief_*, entropy checks) will fail."`
- This is a one-liner that prevents an entire investigation branch.
**Files:** `api_discovery.py` — `get_active_instance`
**Effort:** ~30 min

---

## Group B — Medium complexity (design straightforward, more code)

### B.1 `find_dll_by_purpose` — keyword search across an install directory
**Source:** §4.1, §7 row 12
**Problem:** When the target is a multi-DLL application, the agent has no way to narrow
down which of 100+ DLLs contains the relevant code without loading each one into IDA.
**Fix:** New tool `find_dll_by_purpose(install_dir, keywords, max_results=20)` that:
1. Walks `install_dir` for `*.dll` / `*.exe` files.
2. For each file, calls `lief.parse()` and scans:
   - Import names for keyword matches
   - String literals (quick ASCII scan, no full LIEF strings pass) for keyword matches
   - Export names for keyword matches
3. Returns a ranked list of candidates with match evidence:
   `{"path": "...", "matches": [{"source": "import|string|export", "value": "..."}]}`
4. Cap at `max_results`; respect `max_section_size` from `lief_strings` for speed.
**Notes:**
- Pure Python, no IDA dependency — can run from the proxy side.
- Walking 100 DLLs with minimal LIEF parse is fast (< 5 s for typical install).
- Could be gated as an LIEF-optional tool using the existing `_lief` guard pattern.
**Files:** `api_lief.py` — new tool
**Effort:** ~3h

---

### B.2 `find_instance` — locate IDA instance by binary name or path pattern
**Source:** §7 row 7
**Problem:** `select_instance` requires knowing the instance ID. When multiple IDA windows
are open (e.g. one for each DLL), there is no way to ask "which instance has libplugins.dll
loaded?" without calling `get_active_instance` on each one.
**Fix:** New tool `find_instance(matching)` where `matching` is a glob or substring against
the IDB source path or module name:
- Returns the matching instance ID(s) and their current IDB paths.
- If exactly one match, auto-selects it (equivalent to `select_instance`).
- If multiple matches, returns all candidates for the agent to choose.
**Files:** `api_discovery.py` — new tool
**Effort:** ~2h

---

### B.3 Decompile failure hint enrichment in `analyze_function`
**Source:** §2.3
**Problem:** `analyze_function` was not tried because the decompile error hint pointed
elsewhere. The hint should be contextual — if Hex-Rays is unavailable, say so; if the
function is tiny, suggest `disasm`; if code-is-data, suggest `lief_sections`.
**Fix:**
- Wire the `failure_reason` enum from A.1 into `analyze_function` as well.
- The `hint` field in the error dict becomes a lookup by reason code rather than a static
  string. This is a follow-on to A.1 with minimal additional effort once A.1 is done.
**Files:** `api_analysis.py` — `analyze_function`
**Effort:** ~1h (depends on A.1 being done first)

---

## Group C — Requires design decision before implementation

### C.1 `open_ida_file(path)` — drive IDA to open a new binary from MCP
**Source:** §3.2, §4.1, §7 row 2
**Problem:** The agent cannot initiate a new analysis session. Every new binary requires
manual File → Open in IDA, then the agent discovers the new IDB only after the human acts.

**Design considerations:**
- IDA's `ida_loader.load_file()` / `idc.RunTo()` can be called from IDA's main thread,
  but opening a new database while one is already open requires closing the current one
  first — destructive if the agent doesn't save first.
- Safer approach: `ida_pro.qexit(0)` + relaunch with new file. But this kills the plugin.
- Alternative: use IDA's batch mode flag and spawn a new IDA process from the MCP server
  side, then register the new instance automatically.
- The MCP already has instance registration (`list_instances`, `select_instance`); a new
  IDA process would register itself on first connection.
- Simplest viable version: `open_ida_file(path)` spawns `idat64.exe -A path` as a
  subprocess from the server side, waits for it to register, returns the new instance ID.
  User's existing IDA session is unaffected.

**Decision needed:** Is spawning a headless `idat64` subprocess acceptable? Does the user
have a licensed `idat64` in `PATH`? Does `idalib` mode work better here?

**Files:** `api_discovery.py` or new `api_session.py`, `server.py` (subprocess logic)
**Effort:** ~1 day once design is settled

---

### C.2 Progressive tool disclosure — reduce first-call context cost
**Source:** §6.1
**Problem:** All 162+ tools are listed in the system prompt on every session start. This
consumes a large fraction of the context budget before any analysis begins.

**Design considerations:**
- Lazy mode already exists (`--lazy` flag, `list_tools_by_group`, `invoke_tool`). The
  problem is agents don't know to use it until they've already loaded the full schema.
- Option A: Default to lazy mode for all connections, require agents to call
  `list_tools_by_group` first.
- Option B: Expose a "core" group of ~20 tools always, expand on demand.
- Option C: Let the system prompt describe groups and their member count rather than
  individual tool schemas; agents expand a group when they need it.
- Risk: some agents (especially non-Claude) may not handle lazy mode gracefully; they
  may try to call tools that aren't yet registered in their local schema cache.

**Decision needed:** Which option? Any option changes the agent's first-turn experience
significantly.

**Files:** `server.py`, `rpc.py`, `zeromcp/mcp.py`
**Effort:** ~2 days

---

### C.3 Dump decrypted process memory into IDB
**Source:** §4.2, §7 row 4
**Problem:** For packed/encrypted binaries (Affinity, most 2020s commercial software),
the code to analyse is only present in memory after the unpacker runs. No current MCP
tool covers this path.

**Design considerations (IDA-side options):**
1. **IDA debugger API**: `ida_dbg.run_to()` + `ida_bytes.patch_bytes()` to snapshot
   live memory and write it back into the IDB. Requires a debugger backend attached.
2. **Unicorn emulate + patch**: Run the unpacker stub under Unicorn (`unicorn_emulate`),
   capture the written memory, patch it into the IDB with `unicorn_emulate_and_patch`.
   Already partially possible with existing tools — might need a dedicated workflow.
3. **x64dbg bridge**: `sandbox_run_to_entry` + `sandbox_dump` already exists; the gap
   is connecting the dump back into the IDA IDB for analysis.
4. **Dedicated `workflow_unpack_and_analyze`**: Orchestrates option 2 or 3 end-to-end.

**Decision needed:** Which backend (IDA debugger / Unicorn / x64dbg)? Unicorn is the
most self-contained since it's already integrated.

**Files:** `api_unicorn.py` or new `api_debug.py` workflow, `api_modify.py`
**Effort:** ~3–5 days depending on approach

---

## Group D — Documentation & UX (no code, no risk)

### D.1 Document `find_regex` vs `lief_strings` search semantics
**Source:** §4.3, §7 row 9
- `find_regex` operates on IDA's string database (strings IDA recognised during analysis).
- `lief_strings` scans raw section bytes via LIEF (works on files not loaded into IDA).
- Add a one-paragraph note to both tool docstrings explaining the distinction and when
  to use each.
**Files:** `api_analysis.py` — `find_regex`; `api_lief.py` — `lief_strings`
**Effort:** 15 min

### D.2 Canonical "load fresh IDB" workflow documentation
**Source:** §3.2, §9 row 10
- Add a `skills/` entry or a `WORKFLOWS.md` doc describing the standard flow:
  1. `get_active_instance` to discover current state
  2. User opens file in IDA → plugin auto-registers
  3. `get_active_instance` again to confirm new IDB
  4. `survey_binary` for first-pass triage
- Until `open_ida_file` (C.1) is implemented, this documents the manual step explicitly
  so agents can instruct users instead of silently failing.
**Files:** `skills/` directory or new `docs/WORKFLOWS.md`
**Effort:** 30 min

### D.3 Document the `entity_query` / `func_query` / `list_funcs` overlap
**Source:** §4.5
- Add a comparison note to each tool's docstring explaining what it covers and when to
  prefer it over the others. No consolidation needed yet — just documentation.
**Files:** `api_core.py`, `api_analysis.py`
**Effort:** 30 min

---

## Implementation Order (when ready to pick this up)

| Priority | Item | Why first |
|---|---|---|
| 1 | A.5 — orphaned IDB detection | 30 min, prevents wasted tool calls on session start |
| 2 | A.4 — UAC path warning | 1h, prevents a confusing save failure |
| 3 | A.1 — structured decompile errors | 2h, directly impacts agent reasoning on every failed decompile |
| 4 | A.2 — lief_info `.i64` guard | 1h, prevents a recurring agent confusion pattern |
| 5 | A.3 — section entropy classification | 2h, turns lief_sections into a first-pass encryption detector |
| 6 | D.1–D.3 — documentation | 1h total, zero risk |
| 7 | B.1 — `find_dll_by_purpose` | 3h, high impact for multi-DLL targets |
| 8 | B.2 — `find_instance` | 2h, quality-of-life for multi-IDA sessions |
| 9 | B.3 — `analyze_function` hint enrichment | 1h, depends on A.1 |
| 10 | C.1 — `open_ida_file` | Design first |
| 11 | C.2 — progressive tool disclosure | Design first |
| 12 | C.3 — dump decrypted memory | Design first, largest scope |
