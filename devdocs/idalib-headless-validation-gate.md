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

## Architecture & contracts (read this to judge "as intended")

You can't tell a bug from intended behavior without the model. Here it is.

**Process topology (3 layers):**
```
MCP client (Kilo)
  └─ idalib-mcp.exe        ← thin console launcher (do not kill to test teardown)
       └─ python supervisor (ida_pro_mcp.idalib_supervisor)   ← owns Job Object, sessions, routing; NO IDA imported
            ├─ worker A (python -m ida_pro_mcp.idalib_server) ← imports idalib; owns ONE active DB; ~200 MB + DB
            ├─ worker B ...
            └─ schema/bootstrap worker                        ← reused; persists by design for fast tool-list + file tools
```

**RPC / threading model (this explains most "hangs"):**
- Supervisor ↔ worker = newline-delimited JSON-RPC over stdio pipes. One **reader
  thread per worker process** (channel keyed by pid); senders wait on a condition
  with a deadline and re-check `process.poll()` ~1×/sec ⇒ a silent/dead worker
  **fails fast**, it cannot hang the supervisor forever.
- **Each worker is single-threaded** and runs IDA on the thread that imported
  `idapro`; `@idasync` executes inline. Therefore: tool calls to **one** database
  **serialize** (a long decompile blocks the next call to *that* DB); tool calls
  to **different** databases run on **different** workers **in parallel**. This is
  expected, not a bug — see Test 8.

**Session model:**
- `session_id` ↔ one worker/DB. `context_id` (always `shared:fallback` for stdio)
  binds the "current" session. Every worker tool accepts `database=<session_id>`
  to target a specific DB; without it, the context's bound session is used.
- `idalib_current` (bound session) and `idalib_list` (all sessions) must agree.

**Contract table — what each feature must do + how to observe it:**

| Feature | Intended behavior | Observe via | Env knob |
|---|---|---|---|
| Open (small <10 MB) | Synchronous; returns `success` + `function_count` | open result | — |
| Open (≥10 MB) | Async; returns `task_id`; poll to `done` (carries `function_count`) | `idalib_task_poll` | `_LARGE_FILE_THRESHOLD` (10 MB) |
| Open honesty | 0 functions ⇒ `analysis_warning`; never a silent empty success | open result / task done | — |
| `.i64`/`.idb` reopen | No re-analysis, no `-o` onto the DB, sweep stale `.lck` | worker log lines | — |
| Memory precheck | Refuse with `insufficient_memory` if est. > free RAM | open result | `force=true` to override |
| Non-blocking RPC | A silent worker → `TimeoutError`/structured error, never ∞ hang | any tool on wedged worker | tool timeout 60 s |
| Analysis gating | Tools during bg analysis → `analysis_in_progress` + task_id | tool call result | — |
| Crash diagnostics | Dead worker mid-call → `worker_crashed` + `exit_code`/`stderr_tail`; session pruned | tool result + `idalib_list` | — |
| Bounded health | Wedged worker → `worker_unresponsive` ≤20 s | `idalib_health(session_id)` | — |
| Job Object | Supervisor death (any cause) kills all workers | process list | — |
| Singleton | New supervisor kills a stale prior one + its workers | daemon log + process list | `IDA_MCP_IDALIB_SINGLETON=0` |
| Orphan sweep | Startup kills workers whose supervisor parent is gone | daemon log | — |
| Idle reaper | Worker untouched > timeout is killed (saved first if persistent) | process list | `IDA_MCP_IDALIB_IDLE_TIMEOUT_SEC`, `IDA_MCP_IDALIB_SAVE_ON_IDLE` |
| Commit cap | Total worker commit bounded; over-cap IDB fails to load | Task Manager commit | `IDA_MCP_IDALIB_MEM_LIMIT_GB` |

When a test result contradicts this table, **that's the bug** — capture the row
it violates plus the artifacts in "Diagnostics bundle" below.

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
idalib_list_functions_enhanced(database="gate")   # or list_strings / survey_binary
```
Pass if it returns real data consistent with `function_count`.

> Tool-name note: worker tools are exposed as `idalib_<name>` (e.g.
> `idalib_survey_binary`, `idalib_disasm`, `idalib_list_funcs`,
> `idalib_get_binary_sections`, `idalib_analyze_range`, `idalib_list_strings`,
> `idalib_lief_info`). Management tools may appear with a doubled prefix
> (`idalib_idalib_open`/`_health`/`_list`/`_task_poll`/`_cleanup_zombies`)
> depending on your client. Every worker tool accepts `database=<session_id>`.

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

## 8. Multi-database isolation & parallel routing (proves the pool + routing)

**Intended:** each opened binary gets its **own** worker; `database=` routes to
the right one; calls to different DBs run in parallel (different workers), calls
to the same DB serialize (single-threaded worker).

```
idalib_open(input_path="<binary A>", session_id="A", run_auto_analysis=true)
idalib_open(input_path="<binary B>", session_id="B", run_auto_analysis=true)
idalib_list()
idalib_survey_binary(database="A")   # metadata+segments+function count in one call
idalib_survey_binary(database="B")
```
**Capture:** `idalib_list()` JSON (expect 2 sessions, distinct `pid` per worker);
the two metadata results (input_path/imagebase must match the right binary — no
cross-talk); from the process list, confirm **2 distinct** `idalib_server` pids.
**Parallelism probe (optional):** start a slow op on A (e.g. a large
`decompile_batch`) and immediately call a fast tool on B — B should answer while
A is still working. Record both wall-clock times.
**Pass:** 2 isolated workers, correct routing, no cross-talk; B not blocked by A.
**If fail:** capture which `database=` returned which binary's data + the pids.

## 9. Heavy `.i64` reopen fast path (needs a saved IDB, ideally ≥1 GB)

**Intended:** opening a pre-analyzed `.i64`/`.idb` **skips re-analysis**, returns
a `task_id` for large files, and loads (not re-analyzes) — much faster than the
original binary's first analysis.

```
# make one first if needed:
idalib_open(input_path="<binary>", run_auto_analysis=true, session_id="mk"); # wait done
idalib_save(session_id="mk"); idalib_close(session_id="mk", save=true)
# now the real test:
t0 = now
idalib_open(input_path="<binary>.i64", session_id="ro")   # → task_id
idalib_task_poll(task_id)  # poll to status=done; record elapsed
```
**Capture:** the open result (`task_id`, `estimated_sec`, `size_mb`), the poll
sequence with timestamps, the final `function_count`, and the **worker log lines**
(should NOT say it ran auto-analysis; should mention reopening the IDB). Compare
load time vs. the original first-analysis time.
**Pass:** completes via task→done, `function_count>0`, no re-analysis, faster than
first open. **If fail:** capture `task_poll` `stage`/`error`, free RAM at the
time, and the worker stderr tail.

## 10. Stale `.lck` sweep (proves the 0-CPU "database already open" fix)

**Intended:** a leftover IDA lock next to a saved IDB does NOT cause a hang; the
worker sweeps it and logs the removal.

```
# with a saved <binary>.i64 present and NO worker holding it:
# create a fake lock:  New-Item "<binary>.i64.lck" -ItemType File
idalib_open(input_path="<binary>.i64", session_id="lck")
```
**Capture:** worker log (expect `Removed stale IDA lock before reopen: ...`), open
result, and whether it completed (vs hung — abort after 60 s and report).
**Pass:** open completes; lock-removal logged. **If fail:** capture the worker
log + whether the `.lck` still exists.

## 11. Worker crash diagnostics + fail-fast (proves error surfacing)

**Intended:** a worker dying mid-use → next tool returns `worker_crashed` with
`exit_code`/`stderr_log`/`stderr_tail`, and the session is pruned immediately
(not left lingering until the 5 s death watcher).

```
idalib_open(input_path="<small binary>", session_id="crash")
# find that worker's pid (idalib_health → workers[].pid), then:
#   Stop-Process -Id <worker_pid> -Force
idalib_survey_binary(database="crash")   # immediately after
idalib_list()
```
**Capture:** the tool result (expect `error="worker_crashed"`, an `exit_code`, and
a non-empty `stderr_tail`), and `idalib_list()` (the `crash` session should be
gone). **Pass:** structured crash error + session pruned. **If fail:** capture the
raw error text + whether the session persists.

## 12. Analysis gating + cancel (proves no silent pipe-block)

**Intended:** while a background analysis runs, other tools on that DB return
`analysis_in_progress` + the task_id (not a 5-minute hang); `idalib_cancel_task`
kills the work and the worker.

```
idalib_open(input_path="<binary that takes >30 s to analyze>", run_auto_analysis=false, session_id="an")
r = idalib_start_analysis(session_id="an")      # → analysis task_id
idalib_survey_binary(database="an")             # during analysis
idalib_cancel_task(task_id=r.task_id)
```
**Capture:** the gated tool result (expect `error="analysis_in_progress"` + the
`task_id`), and the cancel result (`status="cancelled"`), plus a process check
that the worker was terminated. **Pass:** clear gate + clean cancel. **If fail:**
note whether the tool hung instead, and for how long.

## 13. Idle reaping + save-on-idle (proves lifecycle reclaim)

**Intended:** a worker untouched past the idle timeout is killed; if its IDB is
persistent it's saved first.

```
# restart the daemon with a short timeout for the test:
#   IDA_MCP_IDALIB_IDLE_TIMEOUT_SEC=60   (and IDA_MCP_IDALIB_SAVE_ON_IDLE=1)
idalib_open(input_path="<binary>", session_id="idle"); idalib_save(session_id="idle")
# do nothing for ~90 s, then:
idalib_list()
```
**Capture:** daemon log (expect `Idle timeout (...): killing worker ...` and a
`Saved IDB ... before teardown` line), `idalib_list()` (session gone), and the
`.i64` mtime (updated by the pre-kill save). **Pass:** reaped + saved. **If
fail:** record how long the worker survived idle and whether the save happened.

## 14. Singleton restart cleanup (proves the multi-daemon root-cause fix)

**Intended:** starting a new supervisor kills a stale prior one + its workers.

```
# Note current supervisor pid + worker pids (idalib_health / process list).
# Then cause a fresh supervisor start (restart the MCP client/session).
# After restart, inspect processes again.
```
**Capture:** before/after process lists (Name,Id,CommandLine), the new daemon log
line `Singleton: killed stale prior supervisor <pid> and its workers [...]`, and
the lockfile content `%TEMP%\synapse-idalib-supervisor.lock`. **Pass:** old
supervisor + its workers gone; exactly one supervisor remains. **If fail:** list
every surviving `idalib`/`idalib_server` process with pid + start time.

## 15. Commit / pagefile behavior + cap (proves the pagefile control)

**Intended:** worker commit ≈ IDA runtime + DB; killing the worker frees commit;
`IDA_MCP_IDALIB_MEM_LIMIT_GB` bounds total worker commit.

```
# Record system commit charge (Task Manager → Performance → Committed) at each step:
#  (a) before open  (b) after open  (c) after idalib_close  (d) after killing supervisor
idalib_open(input_path="<mid/large binary>", run_auto_analysis=true, session_id="mem")
idalib_close(session_id="mem", save=false)
```
**Capture:** the 4 commit numbers + per-worker `WorkingSet`/`PrivateMemorySize`
(PowerShell). Then repeat with `IDA_MCP_IDALIB_MEM_LIMIT_GB=<N>` set and confirm
total worker commit never exceeds N (an over-cap IDB should fail to load with a
memory error, not balloon). **Pass:** commit returns near baseline after
close/teardown; cap is respected. **Note:** the `pagefile.sys` *file* won't shrink
below its session high-water mark until reboot — judge by **commit charge**, not
file size on disk.

## 16. `function_count: 0` diagnostic protocol (the one genuinely-open issue)

The 15 KB `selfkey` ELF reportedly opened with `function_count: 0`. We need data
to tell "broken analysis" from "unusual binary." If ANY open returns 0 functions
(or `analysis_warning`), run this **in full** and paste everything:

```
# 1. What did IDA think the file is? (survey_binary bundles metadata+segments+
#    imports+strings+stats; idalib_health adds imagebase/auto_analysis_ready)
idalib_survey_binary(database="<sid>")
idalib_health(session_id="<sid>")
idalib_get_binary_sections(database="<sid>")   # segments + perms (X = code?)
# 2. Is there code at the entry point? (entry_point comes from survey_binary)
idalib_disasm(database="<sid>", addr="<entry_point>", count=20)
# 3. Does forcing analysis help?
idalib_start_analysis(session_id="<sid>")        # poll to done, re-check survey_binary
idalib_analyze_range(database="<sid>", start="<code seg start>", end="<code seg end>")
idalib_survey_binary(database="<sid>")           # re-check function count
# 4. Does an explicit processor help (compare)?
idalib_open(input_path="<same>", processor="metapc", run_auto_analysis=true, session_id="<sid>_mp")
# 5. Ground truth from raw tools (no IDA analysis needed):
idalib_lief_info(file_path="<same>")       # format, machine, entry
idalib_lief_sections(file_path="<same>")   # section sizes/flags
```
**Capture (all of it):** every result above, the worker `stderr_log` **full
contents** (not just tail), the exact file (`Get-Item <path> | fl Length`), and
`file`/magic bytes if available. **Report which step (if any) produced
functions** — that single fact tells us whether it's loader, processor,
analysis-trigger, or genuinely-codeless input.

---

## Diagnostics bundle — run on ANY failure and paste the output

```powershell
# One-shot environment + process + log snapshot for the dev team.
"=== ENV ===" ; "IDADIR=$env:IDADIR" ; "free RAM(MB)=" + [math]::Round((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory/1KB)
"committed(MB)=" + [math]::Round((Get-Counter '\Memory\Committed Bytes').CounterSamples.CookedValue/1MB)
"=== SUPERVISOR LOCK ===" ; Get-Content "$env:TEMP\synapse-idalib-supervisor.lock" -ErrorAction SilentlyContinue
"=== PROCESS TREE (idalib) ==="
Get-CimInstance Win32_Process | ? { $_.CommandLine -match 'idalib|ida_pro_mcp' -or $_.Name -eq 'idalib-mcp.exe' } |
  Select ProcessId,ParentProcessId,Name,
    @{N='WS_MB';E={[math]::Round($_.WorkingSetSize/1MB)}},
    @{N='Commit_MB';E={[math]::Round($_.PageFileUsage/1MB)}},
    CommandLine | Format-Table -Auto
"=== WORKER LOGS (newest 3, last 40 lines each) ==="
Get-ChildItem "$env:TEMP\idalib-worker-logs\*.stderr" -ErrorAction SilentlyContinue |
  Sort LastWriteTime -Desc | Select -First 3 | % { "--- $($_.Name) ---"; Get-Content $_.FullName -Tail 40 }
```
Also paste the **raw JSON** of the failing tool call(s) and the exact tool name +
args you used (with the `idalib_idalib_*` client prefix if your client adds one).

---

## Agent report template (fill this in — keeps it one round-trip)

```markdown
# idalib Validation Gate Result
Date / tester / client (Kilo? version):
Commit under test (git -C synapse-mcp-main rev-parse --short HEAD):
IDA version / IDADIR / free RAM at start:
How the daemon was started (client-managed stdio? HTTP? bare --stdio = INVALID):
Number of supervisors seen at preflight (must be 1):

## Results
| # | Test | Result (PASS/FAIL/SKIP) | Key observed values |
|---|------|-------------------------|---------------------|
| 1 | unit suite | | N passed |
| 2 | open honesty | | function_count=, analysis_warning?= |
| 3 | health bounded | | 1st/2nd return times; current==list? |
| 4 | save/close | | .i64 created? worker gone? |
| 5 | teardown (kill supervisor) | | workers after kill= |
| 6 | orphan/zombie recovery | | killed_detail= |
| 7 | mem cap | | commit before/after/cap |
| 8 | multi-db isolation | | 2 pids? routing correct? parallel? |
| 9 | .i64 reopen | | reopen time vs first; re-analysis avoided? |
| 10| .lck sweep | | lock removed log? hung? |
| 11| crash diagnostics | | error=, exit_code=, stderr_tail? pruned? |
| 12| analysis gating+cancel | | analysis_in_progress? cancelled? |
| 13| idle reaping | | survived Ns idle; saved? |
| 14| singleton restart | | old supervisor killed? lock pid= |
| 15| commit/pagefile | | 4 commit numbers |
| 16| function_count=0 protocol | | which step produced functions (if any) |

## Contradictions with the contract table (cite the row)
## Diagnostics bundle output (paste)
## Per-failure: raw tool JSON + worker stderr
```

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
| 8 | Multi-DB isolation | 2 distinct workers; `database=` routes correctly; B not blocked by A |
| 9 | `.i64` reopen | task→done, `function_count>0`, no re-analysis, faster than first open |
| 10 | `.lck` sweep | open completes; "Removed stale IDA lock" logged |
| 11 | Crash diagnostics | `worker_crashed` + `exit_code`/`stderr_tail`; session pruned |
| 12 | Analysis gating + cancel | `analysis_in_progress` + task_id; clean `cancelled` |
| 13 | Idle reaping | worker killed after timeout; persistent IDB saved first |
| 14 | Singleton restart | stale prior supervisor + workers killed; one remains |
| 15 | Commit/pagefile | commit returns to baseline after close; cap respected |
| 16 | `function_count=0` protocol | report which step (if any) produced functions |

## If something fails
Run the **Diagnostics bundle** and fill in the **Agent report template** above —
that's everything we need in one round-trip. Always distinguish "killed the
launcher vs the supervisor" (Section 0 #4) before filing a teardown bug, and cite
the **contract-table row** a result contradicts so we know intended-vs-actual.
