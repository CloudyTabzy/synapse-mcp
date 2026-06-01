"""Async task queue for long-running IDA operations.

Instead of blocking the HTTP connection, submit heavy tools as background tasks
and poll for completion every few seconds.

Typical workflow:
  1. task_submit("decompile", {"addr": "0x401000"})
     → {"ok": true, "task_id": "a1b2c3d4", "status": "pending"}
  2. task_poll("a1b2c3d4") every 2-3 s
     → {"ok": true, "status": "running"}
  3. When status == "done":
     → {"ok": true, "status": "done", "result": <tool_output>}

Scheduling model:
  Tasks are queued in a priority heap (lower number = higher priority, default 5).
  A single persistent worker thread drains the heap in priority order and executes
  each task serially via execute_sync on the IDA main thread. This matches IDA's
  serial main-thread model and ensures high-priority tasks run before lower-priority
  ones already waiting in the queue.

  Within the same priority level, tasks execute in FIFO (submission) order.

  Future option: replace with register_timer + generator cooperative scheduling
  for true interleaving on the main thread — see plans/phase4-ambitious-expansion.md
  Part I (Cooperative Task Scheduler).

Environment:
  IDA_MCP_TASK_TTL_SECONDS  – expiry for done/error tasks (default: 300)
"""
from __future__ import annotations

import atexit
import heapq
import os
import threading
import time
import uuid
from typing import Annotated

from .rpc import tool, MCP_SERVER
from .task_backend import InMemoryTaskBackend, TaskBackend

# ── Configuration ─────────────────────────────────────────────────────────────

_TASK_TTL_SEC = int(os.environ.get("IDA_MCP_TASK_TTL_SECONDS", "300"))

# ── Backend initialisation ────────────────────────────────────────────────────

_backend: TaskBackend = InMemoryTaskBackend()

# ── Priority queue ─────────────────────────────────────────────────────────────
# Heap entries: (priority, seq, task_id)
# Lower priority number = runs first. seq breaks ties in FIFO submission order.

_task_heap: list[tuple[int, int, str]] = []
_heap_cv = threading.Condition(threading.Lock())
_seq_counter = 0
_shutdown_flag = threading.Event()


# ── Helpers ───────────────────────────────────────────────────────────────────


def _cleanup_expired() -> None:
    _backend.delete_expired(_TASK_TTL_SEC)


def report_task_progress(task_id: str, current: int, total: int, stage: str = "") -> None:
    """Update a running task's progress metadata.

    Call this from within a long-running tool to let task_poll callers see
    intermediate progress without blocking the final result.

    Args:
        task_id: The task ID returned by task_submit.
        current:  Number of items processed so far.
        total:    Total number of items to process.
        stage:    Optional human-readable stage name (e.g. 'analyzing_functions').
    """
    _backend.update_state(
        task_id,
        "running",
        progress={"current": current, "total": total, "stage": stage},
    )


def _detect_category(tool_name: str) -> str:
    """Auto-detect task category for richer task_list output."""
    if tool_name.startswith("triton_"):
        return "triton"
    if tool_name.startswith("miasm_"):
        return "miasm"
    if tool_name.startswith("hybrid_"):
        return "hybrid"
    return "core"


# ── Worker ────────────────────────────────────────────────────────────────────


def _execute_task(task_id: str) -> None:
    """Run a single task on the worker thread with progress estimation."""
    task = _backend.get_task(task_id)
    if task is None or task.get("status") == "cancelled":
        return

    tool_name: str = task["tool"]
    arguments: dict = task.get("arguments") or {}

    # Replay captured request context so unsafe/extension gates and per-session
    # routing behave as they would for a synchronous call.
    caller_extensions: set[str] = set(task.get("_caller_extensions") or [])
    caller_session_id: str | None = task.get("_caller_session_id")
    MCP_SERVER._enabled_extensions.data = caller_extensions
    if caller_session_id is not None:
        MCP_SERVER._transport_session_id.data = caller_session_id

    def _estimate_duration(name: str) -> float:
        """Return expected seconds for this tool type (0 = unknown)."""
        for prefix, typical_s in _TYPICAL_DURATIONS.items():
            if name.startswith(prefix):
                return typical_s
        return 0.0

    _TYPICAL_DURATIONS: dict[str, float] = {
        "angr_cfg_fast": 100.0,
        "angr_cfg_emulated": 180.0,
        "angr_find_paths": 90.0,
        "angr_backward_slice": 120.0,
        "angr_enumerate_reachable": 60.0,
        "angr_diff_cfg": 30.0,
        "hybrid_angr_stdin_fuzz": 120.0,
        "hybrid_angr_triton_solve": 90.0,
        "hybrid_angr_miasm_path": 90.0,
        "hybrid_angr_z3_formula": 60.0,
        "hybrid_nx_angr_target_ranking": 45.0,
        "triton_analyze_function": 45.0,
        "triton_process_function": 30.0,
        "miasm_lift_function": 30.0,
        "miasm_deobfuscate_cfg": 60.0,
        "yara_idb_annotate": 90.0,
        "scan_and_define_funcs": 60.0,
        "analyze_batch": 60.0,
    }

    _expected = _estimate_duration(tool_name)
    _start_time = time.monotonic()

    _stop_progress = threading.Event()

    def _progress_updater():
        while not _stop_progress.wait(timeout=3.0):
            elapsed = time.monotonic() - _start_time
            pct = None
            if _expected > 0:
                pct = min(99, round(elapsed / _expected * 100, 1))
            _backend.update_state(
                task_id,
                "running",
                progress={
                    "elapsed_s": round(elapsed, 1),
                    "progress_pct": pct,
                    "typical_s": _expected if _expected > 0 else None,
                    "stage": ("estimated" if _expected > 0 else "running"),
                },
            )

    _progress_thread = threading.Thread(
        target=_progress_updater, name=f"progress-{task_id[:8]}", daemon=True
    )
    _progress_thread.start()

    try:
        _backend.update_state(task_id, "running", started_at=_start_time)
        envelope = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
            "id": task_id,
        }
        # Set re-entry guard so prefer_async tools execute synchronously
        # inside the task worker rather than spawning nested tasks.
        guard = getattr(MCP_SERVER.registry, "_reentry_guard", None)
        if guard is not None:
            guard.active = True
        try:
            resp = MCP_SERVER.registry.dispatch(envelope)
        finally:
            if guard is not None:
                guard.active = False
        if resp is not None and "error" in resp:
            err_msg = resp["error"].get("message", "unknown error")
            _backend.update_state(
                task_id, "error", error=err_msg, completed_at=time.monotonic()
            )
            return

        call_result = resp.get("result") if resp else None
        if isinstance(call_result, dict) and call_result.get("isError"):
            msg = "tool error"
            content = call_result.get("content") or []
            if content and isinstance(content[0], dict):
                msg = content[0].get("text", msg)
            _backend.update_state(
                task_id, "error", error=msg, completed_at=time.monotonic()
            )
            return

        _backend.update_state(
            task_id, "done", result=call_result, completed_at=time.monotonic()
        )
    except Exception as exc:
        _backend.update_state(
            task_id, "error", error=str(exc), completed_at=time.monotonic()
        )
    finally:
        _stop_progress.set()
        _cleanup_expired()


def _worker_loop() -> None:
    """Persistent worker: drain the priority heap serially until shutdown."""
    while not _shutdown_flag.is_set():
        with _heap_cv:
            while not _task_heap and not _shutdown_flag.is_set():
                _heap_cv.wait(timeout=1.0)
            if _shutdown_flag.is_set():
                break
            _, _, task_id = heapq.heappop(_task_heap)

        _execute_task(task_id)


_worker_thread = threading.Thread(
    target=_worker_loop, name="mcp-task-worker", daemon=False
)
_worker_thread.start()


# ── Tools ─────────────────────────────────────────────────────────────────────


@tool
def task_submit(
    tool_name: Annotated[str, "Tool to run in the background (e.g. 'decompile', 'triton_process_function')"],
    arguments: Annotated[dict | None, "Tool arguments as a dict (same as you would pass directly)"] = None,
    priority: Annotated[int, "Execution priority 1–9 (1=urgent, 5=normal, 9=low). Lower runs first. Default: 5."] = 5,
) -> dict:
    """Submit a tool call as a background task and return a task_id immediately.

    Use this for heavy operations (decompile, analyze_funcs, triton_process_function,
    miasm_lift_function, callgraph, …) that may block the IDA main thread for a long
    time. After submitting, poll with task_poll(task_id) every 2-3 seconds until status
    is 'done' or 'error'.

    Tasks queue in priority order (1=urgent, 5=normal, 9=low) and execute serially.
    Within the same priority, FIFO order is preserved. The worker replays the
    submitter's MCP extension context so ?ext=dbg and --unsafe gated tools behave
    identically to synchronous calls."""
    global _seq_counter

    if tool_name.startswith("task_"):
        return {"ok": False, "error": "Cannot submit task management tools as async tasks"}
    if tool_name not in MCP_SERVER.tools.methods:
        return {"ok": False, "error": f"Unknown tool: {tool_name!r}"}

    priority = max(1, min(9, int(priority)))

    caller_extensions: set[str] = set(
        getattr(MCP_SERVER._enabled_extensions, "data", set())
    )
    caller_session_id: str | None = getattr(
        MCP_SERVER._transport_session_id, "data", None
    )

    while True:
        task_id = uuid.uuid4().hex
        if _backend.get_task(task_id) is None:
            break

    category = _detect_category(tool_name)

    _backend.create_task(
        task_id,
        {
            "task_id": task_id,
            "tool": tool_name,
            "category": category,
            "priority": priority,
            "status": "pending",
            "result": None,
            "error": None,
            "created_at": time.monotonic(),
            "started_at": None,
            "completed_at": None,
            "cancelled": False,
            # Execution context — read back by _execute_task on the worker thread.
            "arguments": arguments or {},
            "_caller_extensions": list(caller_extensions),
            "_caller_session_id": caller_session_id,
        },
    )

    with _heap_cv:
        _seq_counter += 1
        heapq.heappush(_task_heap, (priority, _seq_counter, task_id))
        _heap_cv.notify()

    return {
        "ok": True,
        "task_id": task_id,
        "status": "pending",
        "priority": priority,
        "category": category,
        "_hint": f"Poll with task_poll(task_id='{task_id}') every 2-3 seconds",
    }


def _suggested_poll_interval(progress_pct: float | None, typical_s: float) -> int:
    """Return suggested seconds between task_poll calls based on progress/typical duration.

    Early stages: poll more often (agent is waiting). Late stages: less often
    (close to completion). Unknown progress: poll based on typical duration.
    """
    if progress_pct is not None:
        if progress_pct < 25:
            return 5
        if progress_pct < 75:
            return 8
        return 3  # close to done — poll faster to catch result quickly
    if typical_s >= 120:
        return 15
    if typical_s >= 60:
        return 8
    return 5


@tool
def task_poll(
    task_id: Annotated[str, "Task ID returned by task_submit"],
) -> dict:
    """Poll a background task's status and retrieve the result when done.

    Call every 2-3 seconds. When status is 'done', the result field contains
    the same output that the tool would have returned synchronously."""
    _cleanup_expired()
    task = _backend.get_task(task_id)

    if task is None:
        return {"ok": False, "error": f"Task '{task_id}' not found (expired after {_TASK_TTL_SEC} s or invalid ID)"}

    elapsed = round(time.monotonic() - task["created_at"], 1)
    resp: dict = {
        "ok": True,
        "task_id": task_id,
        "tool": task["tool"],
        "category": task.get("category", "core"),
        "priority": task.get("priority", 5),
        "status": task["status"],
        "elapsed_s": elapsed,
    }

    status = task["status"]
    if status == "done":
        resp["result"] = task["result"]
    elif status == "error":
        resp["error"] = task["error"]
    elif status == "cancelled":
        resp["error"] = "Task was cancelled before execution started"
    else:
        progress = task.get("progress")
        if isinstance(progress, dict):
            pct = progress.get("progress_pct")
            typical = progress.get("typical_s")
            stage_elapsed = progress.get("elapsed_s", elapsed)
            if pct is not None and typical:
                resp["_hint"] = (
                    f"Running — {pct}% complete (est. {round(stage_elapsed)}s / "
                    f"~{int(typical)}s). Poll again in {_suggested_poll_interval(pct, typical)}s."
                )
            elif typical:
                resp["_hint"] = (
                    f"Running — {round(stage_elapsed)}s elapsed (typical: ~{int(typical)}s). "
                    f"Poll again in {_suggested_poll_interval(None, typical)}s."
                )
            else:
                resp["_hint"] = f"Still running — {round(stage_elapsed)}s elapsed. Poll again in 3-5s."
        else:
            resp["_hint"] = f"Still running — {elapsed}s elapsed. Poll again in 3-5s."

    if "progress" in task and task["progress"] is not None:
        resp["progress"] = task["progress"]

    return resp


@tool
def task_list() -> dict:
    """List all active or recently completed background tasks."""
    _cleanup_expired()
    tasks = _backend.list_tasks()
    return {
        "ok": True,
        "tasks": [
            {
                "task_id": t["task_id"],
                "tool": t["tool"],
                "category": t.get("category", "core"),
                "priority": t.get("priority", 5),
                "status": t["status"],
                "elapsed_s": round(time.monotonic() - t["created_at"], 1),
            }
            for t in tasks
        ],
        "count": len(tasks),
    }


@tool
def task_cancel(
    task_id: Annotated[str, "Task ID to cancel"],
) -> dict:
    """Cancel a pending background task. Running tasks cannot be cancelled
    (IDA main thread operations are not interruptible), but they will be
    marked with cancel_requested in their metadata."""
    task = _backend.get_task(task_id)
    if task is None:
        return {"ok": False, "error": f"Task '{task_id}' not found"}

    if task["status"] == "pending":
        ok = _backend.cancel_task(task_id)
        if ok:
            return {"ok": True, "task_id": task_id, "status": "cancelled", "message": "Task cancelled before execution"}
        return {"ok": False, "error": "Failed to cancel task"}

    if task["status"] == "running":
        # Preserve current status, only add the cancel_requested flag.
        _backend.update_state(task_id, task["status"], cancel_requested=True)
        return {
            "ok": True,
            "task_id": task_id,
            "status": task["status"],
            "message": "Cancellation requested, but task is already running on IDA main thread and cannot be interrupted",
        }

    return {
        "ok": False,
        "error": f"Task is already {task['status']} — cannot cancel",
        "task_id": task_id,
    }


# ── Graceful shutdown ─────────────────────────────────────────────────────────


def _shutdown_tasks() -> None:
    """Signal the worker to stop and wait for it to finish on process exit."""
    _shutdown_flag.set()
    with _heap_cv:
        _heap_cv.notify_all()
    _worker_thread.join(timeout=5.0)


atexit.register(_shutdown_tasks)
