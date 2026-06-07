# idalib Headless — Validation Gate (for agents)

A step-by-step gate test an agent runs to validate idalib headless **session
lifecycle, open honesty, health, and teardown**. Complements
`idalib-heavy-idb-gate-tests.md` (which covers the heavy-IDB / pagefile path).

It also **corrects the test methodology** that produced false failures in the
2026-06-07 stress reports — read Section 0 first or your results will be wrong.

---

## 0. Methodology — read this or your test is invalid

These caused bogus "P0" findings in prior reports. They are **not bugs**:

1. **Do NOT launch `idalib-mcp --stdio` in a shell and poke it.** stdio MCP
   servers get their requests over **stdin from the MCP client (Kilo/Claude)**,
   which owns the pipe. Launched standalone, the server correctly **exits when
   stdin closes** ("exits after bootstrap" is expected). To drive it: either
   call the tools **through your MCP client** (the client launches/holds the
   daemon), or for a standalone/persistent daemon use **HTTP mode**:
   `uv run idalib-mcp --host 127.0.0.1 --port 8745`.
2. **~200 MB per worker is normal, not a leak.** Every worker loads the full IDA
   runtime (`idalib`) regardless of binary size. 232 MB for a 15 KB binary is
   expected. Judge leaks by *worker count over time*, not per-worker size.
3. **A missing `.i64` on disk right after open is normal.** idalib keeps the
   database **in memory**; it's only written on `idalib_save` or `idalib_close`.
   "IDB file doesn't exist yet" ≠ "open failed." Use `function_count` / a real
   tool call to judge success (Section 2), not the filesystem.
4. **Kill the right process.** The visible `idalib-mcp.exe` is a thin console
   launcher; the **Python supervisor** (a `python.exe` running
   `ida_pro_mcp.idalib_supervisor`) is what owns the worker Job Object. Killing
   the launcher does NOT trigger Job-Object teardown — kill the **supervisor**
   (or just disconnect the client). Use `idalib_health()` → daemon pid.

### Pre-flight: confirm a single clean daemon
```powershell
Get-Process | ? { $_.Name -match 'idalib|python' -and $_.CommandLine -match 'idalib' }
```
There should be **one** supervisor (+ its workers). The supervisor now enforces a
**singleton on startup** (kills a stale prior supervisor + its workers; opt out
with `IDA_MCP_IDALIB_SINGLETON=0`), so a fresh client launch self-cleans. If you
see two supervisors from two client windows, that's intentional concurrency —
test in one.

---

## 1. Automated (no IDA) — run first
```bash
uv run pytest tests/test_idalib_supervisor.py tests/test_idalib_supervisor_hardening.py -q
```
Expect all green (43+). Covers RPC timeout/death, channel sharing, crash
diagnostics, analysis gating, orphan selection, mem-limit parse, Job Object,
singleton lock, open-stats surfacing.

---

## 2. Open honesty (the core fix) — needs IDA + any small ELF/PE

```
idalib_open(input_path="<small binary>", run_auto_analysis=true, session_id="gate")
```
The result now carries **honest post-open stats**. Pass if:
- `function_count` is present and **> 0** for a normal binary, and
- there is **no** `analysis_warning`.

If you instead get `function_count: 0` **with** `analysis_warning` ("Auto-analysis
finished with 0 functions…"), that's the system telling you the truth (not a
silent false success). Then it's a genuine analysis problem for *that* binary —
escalate with:
```
idalib_start_analysis(session_id="gate")     # re-run analysis, poll the task
# or reopen with an explicit processor:
idalib_open(input_path="<same>", processor="metapc", run_auto_analysis=true, session_id="gate2")
```
Capture the worker `stderr_log` (in the open result / `idalib_health`) for the dev.

**Then prove the session is actually functional** (don't trust `success` alone):
```
idalib_list_functions(database="gate")   # or list_strings / get_metadata
```
Pass if it returns real data consistent with `function_count`.

---

## 3. Health is bounded and repeatable
```
idalib_health(session_id="gate")     # call it twice
```
Pass if **both** calls return promptly. A wedged worker now yields
`error="worker_unresponsive"` + `stderr_log` within ~20s instead of hanging the
client. `idalib_health()` (no arg) must show the worker with
`state`/`active_calls`/`age_sec`.

`idalib_current()` and `idalib_list()` must **agree** (same session present, or
both empty). A session in `current` but missing from `list` is a desync bug —
report it with the surrounding tool sequence.

---

## 4. Save + close release everything
```
idalib_save(session_id="gate")                 # now the .i64 exists on disk
idalib_close(session_id="gate", save=true)
```
Pass if: after `idalib_save` the `.i64` exists; after `idalib_close` the worker
process for that session is gone and `idalib_list()` no longer lists it.

---

## 5. Teardown "no matter what" (Job Object)
1. `idalib_open(...)` a binary; note the **supervisor** pid via `idalib_health()`
   (not the `idalib-mcp.exe` launcher).
2. Kill the supervisor: `Stop-Process -Id <supervisor_pid> -Force` — or just
   close the MCP client.

Pass if every `ida_pro_mcp.idalib_server` worker dies within a few seconds
(Windows Job Object `KILL_ON_JOB_CLOSE`), freeing memory and releasing `.i64`
locks. Verify:
```powershell
Get-Process python -ErrorAction SilentlyContinue | ? { $_.CommandLine -match 'idalib_server' }
# expect: none
```
If workers survive, confirm you killed the **supervisor** and not the launcher
(Section 0 #4).

---

## 6. Orphan & zombie recovery
- Force the bad case: `idalib_open(...)`, then kill ONLY the supervisor's
  **launcher** (leaving the python supervisor) — or hard-kill the supervisor and
  let a worker linger. Start a fresh client.
  Pass if the new supervisor's **startup orphan sweep** killed the leftover
  worker (check the daemon log: "Swept N orphaned idalib worker(s)") and the
  `.i64` is openable again.
- On-demand reap:
  ```
  idalib_cleanup_zombies(include_foreign_workers=true, max_age_minutes=5)
  ```
  Pass if `killed_detail` lists orphan/foreign `idalib_server` workers and stale
  `ida.exe` by reason. Note: workers **owned by the live supervisor are
  protected** even with 0 sessions (the schema worker is reused on purpose) —
  that is by design, not a leak. Idle ones are reaped by the idle timeout
  (`IDA_MCP_IDALIB_IDLE_TIMEOUT_SEC`, default 1800; lower it to reclaim sooner).

---

## 7. Memory / pagefile (optional)
Set a cap and confirm it bounds commit:
```
# in the daemon's env, then restart the client:
IDA_MCP_IDALIB_MEM_LIMIT_GB=6
```
Pass if total worker commit stays under the cap (Task Manager → Commit size);
an IDB needing more fails to load instead of ballooning `pagefile.sys`.

---

## Pass/fail summary

| # | Check | Pass signal |
|---|---|---|
| 1 | Unit suite | 43+ tests green |
| 2 | Open honesty | `function_count>0`, no `analysis_warning`; a real tool returns data |
| 2b | Honest failure | 0 funcs ⇒ `analysis_warning` present (not silent success) |
| 3 | Health bounded | both calls return; `worker_unresponsive` instead of hang; current==list |
| 4 | Save/close | `.i64` after save; worker gone + delisted after close |
| 5 | Teardown | killing the **supervisor** kills all `idalib_server` workers |
| 6 | Recovery | startup sweep + `cleanup_zombies` reap orphans/foreign |
| 7 | Mem cap | commit bounded by `IDA_MCP_IDALIB_MEM_LIMIT_GB` |

## If something still fails
Attach: the open result JSON (with `function_count`/`analysis_warning`), the
worker `stderr_log`, `idalib_health()` output, and the exact process list
(`Name,Id,CommandLine`). Distinguish "killed the launcher vs the supervisor"
(Section 0 #4) before filing a teardown bug.
