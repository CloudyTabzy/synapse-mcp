"""Abstract storage backend for the async task queue.

Concrete implementations:
- InMemoryTaskBackend  (default, single-process)

Future extensions could add RedisTaskBackend for multi-host deployments,
but that is intentionally out of scope for this fork.
"""
from __future__ import annotations

import threading
import time
from abc import ABC, abstractmethod
from typing import Any


class TaskBackend(ABC):
    """Abstract storage backend for async task queue."""

    @abstractmethod
    def create_task(self, task_id: str, params: dict) -> None:
        """Persist a new task in pending state."""

    @abstractmethod
    def update_state(self, task_id: str, state: str, **fields) -> None:
        """Atomically update the task's status and any extra fields.

        Implementations MUST be thread-safe.
        """

    @abstractmethod
    def get_task(self, task_id: str) -> dict | None:
        """Return a copy of the task record, or ``None`` if not found."""

    @abstractmethod
    def list_tasks(self, filter_state: str | None = None) -> list[dict]:
        """Return all task records, optionally filtered by status string."""

    @abstractmethod
    def delete_expired(self, ttl_seconds: int) -> int:
        """Delete done/error/cancelled tasks whose ``completed_at`` is older than ttl_seconds.

        Returns the number of tasks deleted.
        """

    @abstractmethod
    def cancel_task(self, task_id: str) -> bool:
        """Mark a pending task as cancelled. Returns True if cancelled, False if not found or already running."""

    @abstractmethod
    def healthcheck(self) -> bool:
        """Return True if the backend is reachable and functioning."""


class InMemoryTaskBackend(TaskBackend):
    """Default backend; thread-safe in-process dict storage."""

    def __init__(self) -> None:
        self._tasks: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()

    def create_task(self, task_id: str, params: dict) -> None:
        with self._lock:
            self._tasks[task_id] = dict(params)

    def update_state(self, task_id: str, state: str, **fields) -> None:
        with self._lock:
            if task_id not in self._tasks:
                return
            self._tasks[task_id]["status"] = state
            self._tasks[task_id].update(fields)

    def get_task(self, task_id: str) -> dict | None:
        with self._lock:
            task = self._tasks.get(task_id)
            return dict(task) if task is not None else None

    def list_tasks(self, filter_state: str | None = None) -> list[dict]:
        with self._lock:
            tasks = list(self._tasks.values())
        if filter_state is not None:
            tasks = [t for t in tasks if t.get("status") == filter_state]
        return [dict(t) for t in tasks]

    def delete_expired(self, ttl_seconds: int) -> int:
        now = time.monotonic()
        with self._lock:
            expired = [
                tid
                for tid, t in self._tasks.items()
                if t.get("status") in ("done", "error", "cancelled")
                and t.get("completed_at") is not None
                and now - t["completed_at"] > ttl_seconds
            ]
            for tid in expired:
                del self._tasks[tid]
        return len(expired)

    def cancel_task(self, task_id: str) -> bool:
        with self._lock:
            task = self._tasks.get(task_id)
            if task is None:
                return False
            if task.get("status") != "pending":
                return False
            task["status"] = "cancelled"
            task["completed_at"] = time.monotonic()
            return True

    def healthcheck(self) -> bool:
        return True
