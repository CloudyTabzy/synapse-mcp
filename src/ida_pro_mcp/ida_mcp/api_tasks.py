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

Enhancements over the reference implementation:
- Structured {"ok": true/false, ...} returns matching this fork's conventions
- task_cancel: remove pending tasks or flag running tasks for cancellation
- Task category auto-detection (triton / miasm / hybrid / core) for richer task_list
- Trace integration: task lifecycle events are logged when tracing is enabled
- Non-daemon worker threads with graceful atexit cleanup

Environment:
  IDA_MCP_TASK_TTL_SECONDS  – expiry for done/error tasks (default: 300)
"""
from __future__ import annotations

import atexit
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

# ── Worker tracking ───────────────────────────────────────────────────────────

_active_workers: dict[str, threading.Thread] = {}
_workers_lock = threading.Lock()


def _cleanup_expired() -> None:
    _backend.delete_expired(_TASK_TTL_SEC)


def _detect_category(tool_name: str) -> str:
    """Auto-detect task category for richer task_list output."""
    if tool_name.startswith("triton_"):
        return "triton"
    if tool_name.startswith("miasm_"):
        return "miasm"
    if tool_name.startswith("hybrid_"):
        return "hybrid"
    return "core"


# ── Tools ─────────────────────────────────────────────────────────────────────


@tool
def task_submit(
    tool_name: Annotated[str, "Tool to run in the background (e.g. 'decompile', 'triton_process_function')"],
    arguments: Annotated[dict | None, "Tool arguments as a dict (same as you would pass directly)"] = None,
) -> dict:
    """Submit a tool call as a background task and return a task_id immediately.

    Use this for heavy operations (decompile, analyze_funcs, triton_process_function,
    miasm_lift_function, callgraph, …) that may block the IDA main thread for a long
    time. After submitting, poll with task_poll(task_id) every 2-3 seconds until status
    is 'done' or 'error'.

    The worker thread replays the submitter's MCP extension context so that
    ?ext=dbg and --unsafe gated tools behave identically to synchronous calls."""
    if tool_name.startswith("task_"):
        return {"ok": False, "error": "Cannot submit task management tools as async tasks"}
    if tool_name not in MCP_SERVER.tools.methods:
        return {"ok": False, "error": f"Unknown tool: {tool_name!r}"}

    # Capture request-scoped thread-locals so the worker re-evaluates gates with
    # the *submitter's* context, not the default empty state it would see in a
    # fresh thread.
    caller_extensions: set[str] = set(
        getattr(MCP_SERVER._enabled_extensions, "data", set())
    )
    caller_session_id: str | None = getattr(
        MCP_SERVER._transport_session_id, "data", None
    )

    # Collision-safe ID; retry on the astronomically unlikely duplicate.
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
            "status": "pending",
            "result": None,
            "error": None,
            "created_at": time.monotonic(),
            "started_at": None,
            "completed_at": None,
            "cancelled": False,
        },
    )

    def _worker() -> None:
        # Replay captured request context on the worker thread so unsafe/extension
        # gates and per-session routing behave as they would for a synchronous call.
        MCP_SERVER._enabled_extensions.data = caller_extensions
        if caller_session_id is not None:
            MCP_SERVER._transport_session_id.data = caller_session_id

        # Check for cancellation before we even start
        task = _backend.get_task(task_id)
        if task is not None and task.get("status") == "cancelled":
            with _workers_lock:
                _active_workers.pop(task_id, None)
            return

        _backend.update_state(task_id, "running", started_at=time.monotonic())
        try:
            envelope = {
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {"name": tool_name, "arguments": arguments or {}},
                "id": task_id,
            }
            resp = MCP_SERVER.registry.dispatch(envelope)
            if resp is not None and "error" in resp:
                err_msg = resp["error"].get("message", "unknown error")
                _backend.update_state(
                    task_id,
                    "error",
                    error=err_msg,
                    completed_at=time.monotonic(),
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
            with _workers_lock:
                _active_workers.pop(task_id, None)
            _cleanup_expired()

    t = threading.Thread(target=_worker, name=f"mcp-task-{task_id[:8]}")
    with _workers_lock:
        _active_workers[task_id] = t
    t.start()

    return {
        "ok": True,
        "task_id": task_id,
        "status": "pending",
        "category": category,
        "_hint": f"Poll with task_poll(task_id='{task_id}') every 2-3 seconds",
    }


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
        resp["_hint"] = "Still running — poll again in 2-3 seconds"

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
        _backend.update_state(task_id, cancel_requested=True)
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
    """Wait for active worker threads to finish on process exit."""
    with _workers_lock:
        workers = list(_active_workers.values())
    if workers:
        for t in workers:
            t.join(timeout=5.0)


atexit.register(_shutdown_tasks)
