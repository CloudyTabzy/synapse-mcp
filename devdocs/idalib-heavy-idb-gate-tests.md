# idalib Heavy-IDB Gate Tests

Gate tests for the 2026-06-06 heavy-IDB hardening (non-blocking RPC, `.i64`/`.idb`
reopen, stale-lock sweep, memory precheck, stuck-open watchdog, safe force-kill).

There are two layers:

1. **Automated (no IDA)** — covers the supervisor RPC/precheck logic.
2. **Agent-driven (needs IDA + a saved IDB)** — covers the real `.i64` reopen,
   lock sweep, and worker load that can't be unit-tested without IDA.

---

## 1. Automated — run this first

```bash
uv run pytest tests/test_idalib_supervisor_hardening.py -q
# and the pre-existing supervisor suite (must still pass):
uv run pytest tests/test_idalib_supervisor.py -q
```

Expected: all green. The load-bearing case is
`test_worker_rpc_times_out_on_silent_worker` — it simulates a wedged worker and
asserts the call raises `TimeoutError` in <3 s instead of hanging forever (the
exact regression from the heavy-IDB report). Also asserted:

- worker-death wakes the caller with an error (no hang),
- one shared reader thread per process (lief-only copy safety),
- concurrent RPC id routing,
- `_is_idb_path`, memory estimate scaling, `insufficient_memory` gate + `force`.

`psutil` must be importable for the stuck-open watchdog (it is in
`[project].dependencies`). Without it, the watchdog degrades gracefully and the
bounded RPC timeout is the backstop.

---

## 2. Agent-driven — needs IDA + a saved `.i64`/`.idb`

Run against a real headless server: `uv run idalib-mcp --stdio` (or your Kilo
idalib MCP). Use a **pre-analyzed** database you already have on disk. All tool
names below are the raw tool names; your client may prefix them (e.g. Kilo shows
`idalib_idalib_open`).

### Prep: make a saved IDB to test against
Open a mid-size binary once with analysis, save, then close:
```
idalib_open(input_path="C:\\path\\to\\sample.dll", run_auto_analysis=true)
# poll idalib_task_poll(task_id) until status == "done"
idalib_save()                     # writes sample.dll.i64 next to it
idalib_close(session_id=...)
```

### T1 — Direct `.i64` reopen is fast (no 30-min re-analysis)
```
idalib_open(input_path="C:\\path\\to\\sample.dll.i64")
```
Pass if: returns a `task_id` (or success for <10 MB), and polling reaches
`status="done"` in time proportional to **load**, not analysis. Then a query
works immediately:
```
idalib_list()                     # the session is present, is_analyzing=false
get_metadata(database=<session>)  # returns IDB metadata, no analysis wait
```

### T2 — Stale-lock sweep (the classic 0-CPU hang)
1. Open the `.i64` (T1) and leave it open, OR manually create a lock file:
   drop an empty `sample.dll.i64.lck` next to the IDB.
2. `idalib_close(...)` if open.
3. `idalib_open(input_path="...sample.dll.i64")`.
Pass if: the open completes (does not hang at 0 CPU). Worker log should show
`Removed stale IDA lock before reopen: ...`.

### T3 — Memory precheck
On a machine with limited free RAM (or temporarily fill RAM), open an IDB whose
estimate exceeds free RAM:
```
idalib_open(input_path="<large>.i64")
```
Pass if: returns `error="insufficient_memory"` with `required_mb` > `available_mb`
and a recommendation mentioning `force=true`. Then:
```
idalib_open(input_path="<large>.i64", force=true)
```
Pass if: it proceeds past the precheck (loads, or fails for a real reason — not
`insufficient_memory`).

### T4 — Force-kill safety (the server must survive)
1. Start a large/slow open so a worker is busy.
2. From a shell, hard-kill that worker:
   `Stop-Process -Id <worker_pid> -Force` (find it via `idalib_health()` →
   `workers[].pid`).
Pass if: `idalib_health()` still responds afterward (supervisor alive), the
dead session is reported gone, and a fresh `idalib_open(...)` works.

### T5 — Cancel a hung/slow open
```
r = idalib_open(input_path="<large>.i64")        # returns task_id
idalib_cancel_task(task_id=r.task_id)
```
Pass if: the worker is terminated (no orphaned `ida.exe`), the task reports
`status="cancelled"`, and `idalib_health()` shows the worker gone. (Before the
fix the worker reference was `None`, so cancel was a no-op.)

### T6 — Stuck-open watchdog (optional, needs a genuine wedge)
Hard to force deterministically. If an open ever sits at ~0 CPU past the grace +
no-progress window (`IDA_MCP_OPEN_STALL_GRACE_SEC`=90 + `IDA_MCP_OPEN_STALL_SEC`=150
by default), `idalib_task_poll` should flip to
`status="failed"`, `stage="stuck_no_progress"` and the worker should be gone —
without manual intervention.

### T7 — Zombie cleanup uses psutil (not removed `wmic`)
With one or more orphan `ida.exe` present:
```
idalib_cleanup_zombies(max_age_minutes=0)
```
Pass if: `killed` > 0 and `killed_pids` lists them (the old `wmic` path silently
returned `killed=0` on current Windows). Managed workers must be untouched.

### T8 — Crash diagnostics surface the real cause
Open a database, then hard-kill its worker (`Stop-Process -Id <pid> -Force`),
then call any worker tool on it (e.g. `get_metadata(database=<id>)`).
Pass if: the result is `error="worker_crashed"` with `exit_code`, `stderr_log`,
and a `stderr_tail` snippet — not a generic "connection lost". A second call
returns a clean "no database / not found" (the dead worker was pruned
immediately, not left lingering).

### T9 — Analysis gating
```
r = idalib_open(input_path="<mid-size>.dll", run_auto_analysis=false)   # poll to done
a = idalib_start_analysis(session_id=<id>)                              # returns analysis task
get_function_count(database=<id>)   # or any worker tool, while analysis runs
```
Pass if: the tool call returns `error="analysis_in_progress"` with the analysis
`task_id` to poll — immediately, not after a long block. After
`idalib_task_poll(task_id)` reports done, the same call succeeds.

### T10 — Save-before-kill
```
idalib_open(...); idalib_start_analysis(...); wait for done
idalib_close(session_id=<id>, save=true)
```
Pass if: the message reports "(saved)" and the `.i64` on disk has a newer mtime.
Also: with the default `IDA_MCP_IDALIB_SAVE_ON_IDLE=1`, a worker killed by the
idle timeout saves its IDB first (check the `.i64` mtime / worker log).

### T11 — Detailed health
```
idalib_health()    # no session_id
```
Pass if: `pool` includes `workers_analyzing`, `workers_busy`, `save_on_idle`,
and each `workers[]` entry has `state` (idle/busy/analyzing/dead),
`active_calls`, `age_sec`, and `stderr_log`.

### T12 — Status probes need no database
With NO database open, call `lief_status` (or any `*_status`).
Pass if: it returns `available`/version instead of "no database bound".

### T13 — Orphan recovery on restart (file-lock release)
1. Open a binary, then hard-kill the **supervisor** process (not the worker).
2. Confirm a `python -m ida_pro_mcp.idalib_server` worker is left behind and the
   `.i64` shows "in use" in IDA GUI.
3. Start a new idalib-mcp.
Pass if: the leftover worker is gone (startup sweep killed it) and the `.i64`
opens cleanly. Also: `idalib_cleanup_zombies()` now lists those python workers
in `killed_detail` (reason `orphan`/`foreign_stale`), not just `ida.exe`.

### T14 — Memory / pagefile lifecycle (Windows)
1. Open a large binary so a worker commits multi-GB (watch Task Manager →
   "Commit size" / pagefile usage rise).
2. Kill the supervisor by ANY means (close client, `taskkill /F`, Ctrl-C).
Pass if: the worker process dies within ~1s (Job Object KILL_ON_JOB_CLOSE) and
commit charge drops. With `IDA_MCP_IDALIB_MEM_LIMIT_GB=<N>` set, total worker
commit never exceeds N GB (a too-large IDB instead fails to load).

---

## Pass criteria summary

| Behavior | Tool/Signal | Pass |
|---|---|---|
| Silent worker can't hang server | automated | TimeoutError <3s |
| `.i64` reopens without re-analysis | T1 | done in load-time, is_analyzing=false |
| Stale `.lck` swept | T2 | open completes, log line present |
| Low RAM blocked with guidance | T3 | `insufficient_memory` + force works |
| Force-kill doesn't crash server | T4 | health still responds |
| Cancel kills hung open | T5 | `cancelled`, no orphan |
| Watchdog frees wedged opens | T6 | `stuck_no_progress` auto-set |
| Zombie cleanup works on Win11 | T7 | `killed_pids` populated |
| Crash surfaces stderr + prunes | T8 | `worker_crashed` + `stderr_tail` |
| Tools gated during analysis | T9 | `analysis_in_progress` + task_id |
| Analysis preserved on close/idle | T10 | `.i64` mtime updated |
| Health reports state/active_calls | T11 | per-worker `state` present |
