"""Headless idalib MCP supervisor.

This module is the public ``idalib-mcp`` entry point. It intentionally does
not import idapro/IDAPython modules. Instead it exposes the MCP transport and
routes IDA-facing calls to per-database ``idalib_server`` worker subprocesses.
"""

from __future__ import annotations

import argparse
import copy
import http.client
import importlib.util
import json
import logging
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from threading import RLock, Thread, Event
from typing import Annotated, Any, NotRequired, Optional, TypedDict


logger = logging.getLogger(__name__)

_DEATH_WATCH_INTERVAL_S = 5.0
_IDLE_TIMEOUT_S = int(os.environ.get("IDA_MCP_IDALIB_IDLE_TIMEOUT_SEC", "1800"))
_BOOTSTRAP_DISCOVER_TIMEOUT_S = 30.0

STDIO_DEFAULT_CONTEXT_ID = "stdio:default"
SHARED_FALLBACK_CONTEXT_ID = "shared:fallback"
_DATABASE_ARG = "database"
_DATABASE_ARG_SCHEMA = {
    "type": "string",
    "description": (
        "Database/session to route this call to. Accepts a session_id, filename, "
        "or input path. If omitted, uses the database bound to the current MCP context."
    ),
}

IDALIB_MANAGEMENT_TOOLS = {
    "idalib_open",
    "idalib_close",
    "idalib_switch",
    "idalib_unbind",
    "idalib_list",
    "idalib_current",
    "idalib_save",
    "idalib_health",
    "idalib_warmup",
}
IDALIB_HIDDEN_PLUGIN_TOOLS = {"list_instances", "select_instance"}


def _import_zeromcp():
    """Import vendored zeromcp without importing ida_mcp/__init__.py."""
    import http.server  # noqa: F401 - prevent local http.py shadowing stdlib

    pkg_dir = Path(__file__).resolve().parent / "ida_mcp"
    sys.path.insert(0, str(pkg_dir))
    try:
        from zeromcp import McpServer  # type: ignore
    finally:
        sys.path.remove(str(pkg_dir))
    return McpServer


McpServer = _import_zeromcp()


def _import_rpc_name():
    """Import MCP_SERVER_NAME from ida_mcp.rpc without triggering full plugin load."""
    pkg_dir = Path(__file__).resolve().parent / "ida_mcp"
    sys.path.insert(0, str(pkg_dir))
    try:
        from rpc import MCP_SERVER_NAME  # type: ignore
    except ImportError:
        MCP_SERVER_NAME = "synapse-mcp"
    finally:
        sys.path.remove(str(pkg_dir))
    return MCP_SERVER_NAME


def _import_discovery():
    """Import pure-Python GUI instance discovery without importing ida_mcp."""
    path = Path(__file__).resolve().parent / "ida_mcp" / "discovery.py"
    spec = importlib.util.spec_from_file_location("ida_pro_mcp_idalib_supervisor_discovery", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not import discovery module from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_discovery = _import_discovery()


MCP_SERVER_NAME = _import_rpc_name()


class IdalibContextFields(TypedDict):
    context_id: NotRequired[str]
    transport_context_id: NotRequired[str | None]
    isolated_contexts: NotRequired[bool]


class IdalibSessionInfo(TypedDict):
    session_id: str
    input_path: str
    filename: str
    created_at: str
    last_accessed: str
    is_analyzing: bool
    metadata: dict[str, Any]


class IdalibSessionListInfo(IdalibSessionInfo, total=False):
    is_active: bool
    is_current_context: bool
    bound_contexts: int
    backend: str
    owned: bool
    pid: int | None
    worker_pid: int | None


class IdalibOpenResult(IdalibContextFields, total=False):
    success: bool
    session: IdalibSessionInfo
    message: str
    error: str


class IdalibCloseResult(TypedDict, total=False):
    success: bool
    message: str
    error: str


class IdalibSwitchResult(IdalibContextFields, total=False):
    success: bool
    session: IdalibSessionInfo
    message: str
    error: str


class IdalibUnbindResult(IdalibContextFields, total=False):
    success: bool
    message: str
    error: str


class IdalibListResult(IdalibContextFields, total=False):
    sessions: list[IdalibSessionListInfo]
    count: int
    current_context_session_id: str | None
    error: str


class IdalibCurrentResult(IdalibContextFields, total=False):
    session_id: str
    input_path: str
    filename: str
    created_at: str
    last_accessed: str
    is_analyzing: bool
    metadata: dict[str, Any]
    error: str


class IdalibSaveResult(IdalibContextFields, total=False):
    ok: bool
    path: str
    error: str | None


class IdalibHealthResult(IdalibContextFields, total=False):
    ready: bool
    session: IdalibSessionInfo | None
    health: dict[str, Any] | None
    error: str | None
    pool: NotRequired[dict[str, Any] | None]
    workers: NotRequired[list[dict[str, Any]]]


class IdalibWarmupResult(IdalibContextFields, total=False):
    ready: bool
    session: IdalibSessionInfo | None
    warmup: dict[str, Any] | None
    error: str | None


@dataclass
class WorkerSession:
    session_id: str
    input_path: str
    filename: str
    created_at: datetime = field(default_factory=datetime.now)
    last_accessed: datetime = field(default_factory=datetime.now)
    is_analyzing: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)
    host: str = "127.0.0.1"
    port: int = 0
    process: subprocess.Popen | None = None
    backend: str = "worker"
    owned: bool = True
    pid: int | None = None
    stdin: Any | None = None  # subprocess.PIPE for stdio workers
    stdout: Any | None = None

    def to_dict(self) -> IdalibSessionInfo:
        return {
            "session_id": self.session_id,
            "input_path": self.input_path,
            "filename": self.filename,
            "created_at": self.created_at.isoformat(),
            "last_accessed": self.last_accessed.isoformat(),
            "is_analyzing": self.is_analyzing,
            "metadata": self.metadata,
        }

    def to_list_dict(self, *, current: bool, bound_contexts: int) -> IdalibSessionListInfo:
        return {
            **self.to_dict(),
            "is_active": self.is_alive(),
            "is_current_context": current,
            "bound_contexts": bound_contexts,
            "backend": self.backend,
            "owned": self.owned,
            "pid": self.pid if self.pid is not None else (self.process.pid if self.process is not None else None),
            "worker_pid": self.process.pid if self.process is not None else None,
        }

    def is_alive(self) -> bool:
        if self.backend == "gui":
            try:
                return bool(_discovery.probe_instance(self.host, self.port, timeout=0.5))
            except Exception:
                return False
        return self.process is not None and self.process.poll() is None


class IdalibSupervisor:
    def __init__(
        self,
        mcp: Any,
        *,
        isolated_contexts: bool = False,
        max_workers: int = 4,
        worker_args: list[str] | None = None,
    ):
        self.mcp = mcp
        self.isolated_contexts = isolated_contexts
        self.max_workers = max_workers
        self.worker_args = worker_args or []
        self.sessions: dict[str, WorkerSession] = {}
        self.path_to_session: dict[str, str] = {}
        self.context_bindings: dict[str, str] = {}
        self._schema_worker: WorkerSession | None = None
        self._tools_cache: dict[tuple[str, ...], list[dict]] = {}
        self._resources_cache: dict[str, list[dict]] = {}
        self._lock = RLock()
        self._stop_event = Event()
        self._death_watcher: Thread | None = None
        self._bootstrap_completed = False
        if _IDLE_TIMEOUT_S > 0 or True:
            self._start_death_watcher()

    # ------------------------------------------------------------------
    # Death watcher + idle timeout
    # ------------------------------------------------------------------

    def _start_death_watcher(self) -> None:
        if self._death_watcher is not None and self._death_watcher.is_alive():
            return
        self._stop_event.clear()
        self._death_watcher = Thread(target=self._watcher_loop, daemon=True, name="idalib-watcher")
        self._death_watcher.start()

    def _stop_death_watcher(self) -> None:
        self._stop_event.set()
        if self._death_watcher is not None and self._death_watcher.is_alive():
            self._death_watcher.join(timeout=2.0)

    def _watcher_loop(self) -> None:
        """Background daemon: poll workers every _DEATH_WATCH_INTERVAL_S seconds.
        
        Detects crashed workers (process died) and idle workers (past their
        timeout) and cleans them up. Crashing a worker during a tool call
        returns a clean error instead of hanging the proxy indefinitely.
        """
        idle_cleanup_ticks = 0
        while not self._stop_event.wait(_DEATH_WATCH_INTERVAL_S):
            try:
                with self._lock:
                    dead = [
                        s.session_id
                        for s in self.sessions.values()
                        if s.backend == "worker" and s.owned and not s.is_alive()
                    ]
                    if self._schema_worker is not None and not self._schema_worker.is_alive():
                        self._schema_worker = None
                for session_id in dead:
                    logger.warning("Worker for session %s died — cleaning up", session_id)
                    with self._lock:
                        session = self.sessions.pop(session_id, None)
                        if session is not None:
                            self._unregister_session_locked(session_id)
                            try:
                                session.process.wait(timeout=1)
                            except Exception:
                                pass
            except Exception:
                logger.debug("Death watcher iteration failed", exc_info=True)

            # Idle timeout cleanup: every 6 death-watch cycles (~30s)
            idle_cleanup_ticks += 1
            if _IDLE_TIMEOUT_S > 0 and idle_cleanup_ticks >= 6:
                idle_cleanup_ticks = 0
                self._idle_cleanup()

    def _idle_cleanup(self) -> None:
        """Kill workers that have been idle past _IDLE_TIMEOUT_S."""
        if _IDLE_TIMEOUT_S <= 0:
            return
        cutoff = datetime.now().timestamp() - _IDLE_TIMEOUT_S
        with self._lock:
            idle_sessions = [
                s for s in self.sessions.values()
                if s.backend == "worker" and s.owned
                and s.is_alive() and s.last_accessed.timestamp() < cutoff
            ]
        for session in idle_sessions:
            logger.info(
                "Idle timeout (%ss): killing worker for session %s (%s)",
                _IDLE_TIMEOUT_S, session.session_id, session.filename or session.input_path,
            )
            with self._lock:
                if session.session_id in self.sessions:
                    self._unregister_session_locked(session.session_id)
            self._terminate_worker(session)

    def _touch_worker(self, worker: WorkerSession) -> None:
        worker.last_accessed = datetime.now()

    def resolve_context_id(self) -> str:
        transport_context_id = self.mcp.get_current_transport_session_id()
        if self.isolated_contexts:
            if transport_context_id is None:
                raise RuntimeError(
                    "No MCP transport context is active for this request. "
                    "Use MCP initialize and send Mcp-Session-Id on /mcp requests."
                )
            return transport_context_id
        return SHARED_FALLBACK_CONTEXT_ID

    def context_fields(self, context_id: str) -> IdalibContextFields:
        return {
            "context_id": context_id,
            "transport_context_id": self.mcp.get_current_transport_session_id(),
            "isolated_contexts": self.isolated_contexts,
        }

    def bind_context(self, context_id: str, session_id: str) -> None:
        self.context_bindings[context_id] = session_id

    def unbind_context(self, context_id: str) -> bool:
        return self.context_bindings.pop(context_id, None) is not None

    # ------------------------------------------------------------------
    # Worker process lifecycle
    # ------------------------------------------------------------------

    def _spawn_worker(self) -> WorkerSession:
        cmd = [
            sys.executable,
            "-m",
            "ida_pro_mcp.idalib_server",
            *self.worker_args,
        ]
        env = dict(os.environ)
        if "IDADIR" not in env:
            for candidate in (
                os.environ.get("IDADIR", ""),
                r"C:\Program Files\IDA Professional 9.3",
                r"C:\Program Files\IDA Pro 9.3",
            ):
                if candidate and Path(candidate).is_dir():
                    env["IDADIR"] = str(Path(candidate))
                    break
        logger.info("Spawning idalib worker (IDADIR=%s)", env.get("IDADIR", "unset"))
        log_path = self._worker_log_path()
        stderr_file = open(log_path, "w") if log_path else None
        process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=stderr_file or subprocess.DEVNULL,
            env=env,
        )
        if stderr_file:
            stderr_file.close()
        worker = WorkerSession(
            session_id=f"__worker_schema_{uuid.uuid4().hex[:8]}",
            input_path="",
            filename="",
            host="127.0.0.1",
            port=0,
            process=process,
            backend="worker",
            owned=True,
            pid=process.pid,
            stdin=process.stdin,
            stdout=process.stdout,
        )
        if log_path:
            worker.metadata["stderr_log"] = log_path
        try:
            self._wait_worker_ready(worker)
        except Exception:
            self._terminate_worker(worker)
            raise
        return worker

    def _wait_worker_ready(self, worker: WorkerSession, timeout: float = 120.0) -> None:
        deadline = time.monotonic() + timeout
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            if worker.process is not None and worker.process.poll() is not None:
                raise RuntimeError(
                    f"idalib worker exited early with code {worker.process.returncode}"
                )
            try:
                self._worker_rpc(worker, {"jsonrpc": "2.0", "id": 1, "method": "ping"}, timeout=2.0)
                return
            except Exception as e:
                last_error = e
                time.sleep(0.2)
        raise TimeoutError(f"idalib worker did not become ready: {last_error}")

    def _terminate_worker(self, worker: WorkerSession) -> None:
        if worker.backend != "worker" or not worker.owned:
            return
        proc = worker.process
        if proc is None or proc.poll() is not None:
            return
        try:
            proc.terminate()
            proc.wait(timeout=10)
        except Exception:
            proc.kill()
            proc.wait(timeout=5)

    def _bootstrap_schemas(self) -> None:
        """Spawn a temporary worker at startup to discover tool/resource schemas.
        
        Caches schemas in _tools_cache and _resources_cache so that the first
        get_tools() / list_resources() call returns immediately instead of
        spawning a worker.
        """
        if self._bootstrap_completed:
            return
        logger.info("Bootstrap: spawning temporary worker for schema discovery...")
        worker = self._spawn_worker()
        try:
            tools_resp = self._worker_rpc(worker, {
                "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {},
            })
            tools = (tools_resp.get("result") or {}).get("tools", [])
            if tools:
                ext_data = sorted(getattr(self.mcp._enabled_extensions, "data", set()))
                self._tools_cache[("injected", tuple(ext_data))] = tools
                logger.info("Bootstrap: cached %d tool schemas", len(tools))
            for method in ("resources/list", "resources/templates/list"):
                try:
                    resp = self._worker_rpc(worker, {
                        "jsonrpc": "2.0", "id": 1, "method": method, "params": {},
                    })
                    key = "resources" if "template" not in method else "resourceTemplates"
                    items = (resp.get("result") or {}).get(key, [])
                    if items:
                        self._resources_cache[method] = items
                except Exception:
                    pass
            self._bootstrap_completed = True
            self._schema_worker = worker
            logger.info("Bootstrap: complete — worker ready for reuse")
        except Exception as exc:
            logger.warning("Bootstrap failed: %s — falling back to lazy discovery", exc)
            self._terminate_worker(worker)

    def _worker_log_path(self) -> str | None:
        """Return a path for capturing worker stderr, or None if no log dir is configured.
        
        Uses TMP_DIR or TEMP env var as the base directory, creating a
        ``idalib-worker-logs`` subdirectory if needed. Each worker gets a
        timestamped file.
        """
        log_dir = os.environ.get("IDA_MCP_LOG_DIR") or os.environ.get("TMP") or os.environ.get("TEMP") or tempfile.gettempdir()
        base = Path(log_dir) / "idalib-worker-logs"
        try:
            base.mkdir(parents=True, exist_ok=True)
        except OSError:
            return None
        pid = os.getpid()
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        return str(base / f"worker-{timestamp}-{pid}.stderr")

    def shutdown(self) -> None:
        self._stop_death_watcher()
        with self._lock:
            workers = list(self.sessions.values())
            if self._schema_worker is not None:
                workers.append(self._schema_worker)
            self.sessions.clear()
            self.path_to_session.clear()
            self.context_bindings.clear()
            self._schema_worker = None
        for worker in workers:
            self._terminate_worker(worker)

    def _schema_or_idle_worker(self) -> WorkerSession:
        with self._lock:
            for worker in self.sessions.values():
                if worker.backend == "worker" and worker.is_alive():
                    return worker
            if self._schema_worker is not None and self._schema_worker.is_alive():
                return self._schema_worker
            self._schema_worker = self._spawn_worker()
            return self._schema_worker

    def _take_schema_worker_for_session(self) -> WorkerSession | None:
        if self._schema_worker is not None and self._schema_worker.is_alive():
            worker = self._schema_worker
            self._schema_worker = None
            return worker
        self._schema_worker = None
        return None

    def _prune_dead_worker_sessions_locked(self) -> None:
        stale_session_ids = [
            session.session_id
            for session in self.sessions.values()
            if session.backend == "worker" and session.owned and not session.is_alive()
        ]
        for session_id in stale_session_ids:
            self._unregister_session_locked(session_id)

    def _allocate_worker_locked(self) -> WorkerSession:
        worker = self._take_schema_worker_for_session()
        if worker is not None:
            return worker

        self._prune_dead_worker_sessions_locked()
        owned_workers = sum(
            1
            for session in self.sessions.values()
            if session.backend == "worker" and session.owned and session.is_alive()
        )
        if self.max_workers <= 0 or owned_workers < self.max_workers:
            return self._spawn_worker()

        raise RuntimeError(
            f"Maximum idalib worker count reached ({self.max_workers}). "
            "Close a database with idalib_close or increase --max-workers."
        )

    # ------------------------------------------------------------------
    # JSON-RPC forwarding (stdio-based workers)
    # ------------------------------------------------------------------

    def _worker_rpc(
        self,
        worker: WorkerSession,
        payload: dict[str, Any],
        *,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        """Send a JSON-RPC request to a worker via its stdio pipe and return the response.

        Writes the full JSON payload followed by a newline to the worker's stdin,
        then reads the response line from its stdout. The stdio MCP transport
        writes one JSON-RPC message per line.
        """
        if worker.process is None or worker.process.poll() is not None:
            raise RuntimeError("Worker process is not running")
        if worker.stdin is None or worker.stdout is None:
            raise RuntimeError("Worker stdio pipes not available")

        body = json.dumps(payload)
        deadline = time.monotonic() + (timeout or 60.0)
        try:
            worker.stdin.write((body + "\n").encode("utf-8"))
            worker.stdin.flush()
        except BrokenPipeError as e:
            raise RuntimeError("Worker process closed stdin") from e

        collected = ""
        while time.monotonic() < deadline:
            try:
                line = worker.stdout.readline()
            except Exception as e:
                raise RuntimeError(f"Failed to read from worker: {e}") from e
            if not line:
                raise RuntimeError("Worker process closed stdout")
            collected += line.decode("utf-8")
            stripped = collected.strip()
            if stripped and stripped.startswith("{") and stripped.endswith("}"):
                try:
                    return json.loads(stripped)
                except json.JSONDecodeError:
                    continue  # partial JSON — wait for more data
            # Check if we've accumulated too much without finding a JSON object
            if len(collected) > 1_000_000:
                raise RuntimeError("Worker response exceeded 1MB without producing valid JSON")
        raise TimeoutError(f"Worker RPC timed out after {(timeout or 60.0)}s")

    def forward_raw(self, worker: WorkerSession, request_obj: dict[str, Any]) -> dict[str, Any]:
        return self._worker_rpc(worker, request_obj)

    def call_worker_tool(
        self, worker: WorkerSession, name: str, arguments: dict[str, Any] | None = None
    ) -> Any:
        """Call a tool on a worker and return the structured content."""
        self._touch_worker(worker)
        # For GUI-backend workers, use the old HTTP path
        if worker.backend == "gui":
            return self._gui_call_worker_tool(worker, name, arguments)
        response = self._worker_rpc(
            worker,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments or {}},
            },
        )
        if "error" in response:
            raise RuntimeError(response["error"].get("message", "Unknown worker error"))
        result = response.get("result", {})
        if result.get("isError"):
            content = result.get("content") or []
            message = content[0].get("text", "Unknown worker tool error") if content else "Unknown worker tool error"
            raise RuntimeError(message)
        return result.get("structuredContent")

    def _gui_call_worker_tool(
        self, worker: WorkerSession, name: str, arguments: dict[str, Any] | None = None
    ) -> Any:
        """Call a tool on a GUI-backend worker via HTTP."""
        self._touch_worker(worker)
        body = json.dumps({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": name, "arguments": arguments or {}},
        }).encode("utf-8")
        conn = http.client.HTTPConnection(worker.host, worker.port, timeout=60.0)
        try:
            conn.request("POST", "/mcp", body, {
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            })
            response = conn.getresponse()
            raw = response.read().decode("utf-8")
            if response.status >= 400:
                raise RuntimeError(f"HTTP {response.status} {response.reason}: {raw}")
            resp = json.loads(raw)
        finally:
            conn.close()
        if "error" in resp:
            raise RuntimeError(resp["error"].get("message", "Unknown worker error"))
        result = resp.get("result", {})
        if result.get("isError"):
            content = result.get("content") or []
            message = content[0].get("text", "Unknown worker tool error") if content else "Unknown worker tool error"
            raise RuntimeError(message)
        return result.get("structuredContent")

    # ------------------------------------------------------------------
    # Session management
    # ------------------------------------------------------------------

    def _normalize_input_path(self, input_path: str) -> str:
        path = Path(input_path)
        if not path.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")
        return str(path.resolve())

    def _path_key(self, path: str) -> str:
        return os.path.normcase(str(Path(path).resolve()))

    def _candidate_idb_paths(self, resolved_path: str) -> set[str]:
        path = Path(resolved_path)
        candidates = {self._path_key(str(path))}
        lower_name = path.name.lower()
        if not lower_name.endswith((".i64", ".idb")):
            candidates.add(self._path_key(str(path) + ".i64"))
            candidates.add(self._path_key(str(path) + ".idb"))
        return candidates

    def _find_gui_instance_for_path(self, resolved_path: str) -> dict[str, Any] | None:
        candidates = self._candidate_idb_paths(resolved_path)
        try:
            instances = _discovery.discover_instances()
        except Exception:
            logger.debug("GUI instance discovery failed", exc_info=True)
            return None

        matches = []
        for instance in instances:
            idb_path = str(instance.get("idb_path") or "")
            if not idb_path:
                continue
            try:
                idb_key = self._path_key(idb_path)
            except Exception:
                idb_key = os.path.normcase(idb_path)
            if idb_key in candidates:
                matches.append(instance)

        if len(matches) > 1:
            logger.warning(
                "Multiple GUI IDA instances matched %s; using the first registered instance",
                resolved_path,
            )
        return matches[0] if matches else None

    def _register_session_locked(self, session: WorkerSession, resolved_path: str, context_id: str | None) -> None:
        self.sessions[session.session_id] = session
        for candidate in self._candidate_idb_paths(resolved_path):
            self.path_to_session[candidate] = session.session_id
        if context_id is not None:
            self.bind_context(context_id, session.session_id)

    def _unregister_session_locked(self, session_id: str) -> WorkerSession | None:
        session = self.sessions.pop(session_id, None)
        stale_paths = [
            path_key
            for path_key, bound_session_id in self.path_to_session.items()
            if bound_session_id == session_id
        ]
        for path_key in stale_paths:
            self.path_to_session.pop(path_key, None)
        stale_contexts = [
            context for context, bound in self.context_bindings.items() if bound == session_id
        ]
        for context in stale_contexts:
            self.context_bindings.pop(context, None)
        return session

    def _discard_opened_worker_session(self, worker: WorkerSession, session_id: str) -> None:
        try:
            self.call_worker_tool(worker, "idalib_close", {"session_id": session_id})
        except Exception:
            logger.debug("Worker idalib_close failed for discarded session %s", session_id, exc_info=True)
        self._terminate_worker(worker)

    def _make_gui_session(self, resolved_path: str, session_id: str, instance: dict[str, Any]) -> WorkerSession:
        idb_path = str(instance.get("idb_path") or resolved_path)
        filename = Path(idb_path).name or Path(resolved_path).name
        return WorkerSession(
            session_id=session_id,
            input_path=idb_path,
            filename=filename,
            metadata={"backend": "gui", "requested_path": resolved_path},
            host=str(instance.get("host") or "127.0.0.1"),
            port=int(instance.get("port") or 0),
            process=None,
            backend="gui",
            owned=False,
            pid=int(instance["pid"]) if instance.get("pid") is not None else None,
        )

    def open_session(
        self,
        input_path: str,
        *,
        run_auto_analysis: bool = True,
        session_id: str | None = None,
        context_id: str | None = None,
    ) -> WorkerSession:
        resolved = self._normalize_input_path(input_path)
        requested_session_id = session_id
        with self._lock:
            existing = self.path_to_session.get(self._path_key(resolved))
            if existing is not None:
                session = self.sessions.get(existing)
                if session is not None and session.is_alive():
                    if requested_session_id is not None and requested_session_id != existing:
                        raise ValueError(
                            f"Binary already open as session '{existing}', cannot reuse "
                            f"different session_id '{requested_session_id}'."
                        )
                    session.last_accessed = datetime.now()
                    if context_id is not None:
                        self.bind_context(context_id, existing)
                    return session
                self._unregister_session_locked(existing)

            if session_id is None:
                session_id = str(uuid.uuid4())[:8]
            elif session_id in self.sessions:
                raise ValueError(f"Session already exists: {session_id}")

            gui_instance = self._find_gui_instance_for_path(resolved)
            if gui_instance is not None:
                session = self._make_gui_session(resolved, session_id, gui_instance)
                self._register_session_locked(session, resolved, context_id)
                logger.info(
                    "Using GUI IDA instance %s:%s for %s",
                    session.host,
                    session.port,
                    resolved,
                )
                return session

            worker = self._allocate_worker_locked()

        try:
            opened = self.call_worker_tool(
                worker,
                "idalib_open",
                {
                    "input_path": resolved,
                    "run_auto_analysis": run_auto_analysis,
                    "session_id": session_id,
                },
            )
            if isinstance(opened, dict) and opened.get("error"):
                raise RuntimeError(str(opened["error"]))
        except Exception:
            self._terminate_worker(worker)
            raise

        worker_session = opened.get("session", {}) if isinstance(opened, dict) else {}
        session = WorkerSession(
            session_id=session_id,
            input_path=str(worker_session.get("input_path") or resolved),
            filename=str(worker_session.get("filename") or Path(resolved).name),
            is_analyzing=bool(worker_session.get("is_analyzing", False)),
            metadata=dict(worker_session.get("metadata") or {}),
            host=worker.host,
            port=worker.port,
            process=worker.process,
            backend="worker",
            owned=True,
            pid=worker.process.pid if worker.process is not None else None,
            stdin=worker.stdin,
            stdout=worker.stdout,
        )
        with self._lock:
            existing = self.path_to_session.get(self._path_key(resolved))
            if existing is not None:
                existing_session = self.sessions.get(existing)
                if existing_session is not None and existing_session.is_alive():
                    existing_session.last_accessed = datetime.now()
                    if context_id is not None:
                        self.bind_context(context_id, existing)
                    collision_error = None
                    if requested_session_id is not None and requested_session_id != existing:
                        collision_error = ValueError(
                            f"Binary already open as session '{existing}', cannot reuse "
                            f"different session_id '{requested_session_id}'."
                        )
                else:
                    self._unregister_session_locked(existing)
                    existing_session = None
                    collision_error = None
            else:
                existing_session = None
                collision_error = None

            session_collision_error = None
            if existing_session is None:
                existing_by_id = self.sessions.get(session_id)
                if existing_by_id is not None:
                    if existing_by_id.is_alive():
                        existing_by_id.last_accessed = datetime.now()
                        session_collision_error = ValueError(f"Session already exists: {session_id}")
                    else:
                        self._unregister_session_locked(session_id)

            if existing_session is None and session_collision_error is None:
                self._register_session_locked(session, resolved, context_id)
                return session

        self._discard_opened_worker_session(worker, session_id)
        if collision_error is not None:
            raise collision_error
        if session_collision_error is not None:
            raise session_collision_error
        return existing_session

    def close_session(self, session_id: str) -> bool:
        with self._lock:
            session = self._unregister_session_locked(session_id)
            if session is None:
                return False
        if session.backend == "worker":
            try:
                self.call_worker_tool(session, "idalib_close", {"session_id": session_id})
            except Exception:
                logger.debug("Worker idalib_close failed for %s", session_id, exc_info=True)
        self._terminate_worker(session)
        return True

    def _resolve_gui_fallback_path(self, session: WorkerSession) -> str:
        candidates = [session.input_path]
        requested_path = session.metadata.get("requested_path")
        if isinstance(requested_path, str) and requested_path and requested_path not in candidates:
            candidates.append(requested_path)

        errors = []
        for candidate in candidates:
            try:
                return self._normalize_input_path(candidate)
            except FileNotFoundError as e:
                errors.append(str(e))

        raise FileNotFoundError(
            "Could not reopen GUI-backed session headlessly. Tried: "
            + ", ".join(candidates)
            + (f" ({'; '.join(errors)})" if errors else "")
        )

    def _reopen_gui_session_headless(self, session: WorkerSession) -> WorkerSession:
        logger.info(
            "GUI IDA backend for session %s is unavailable; reopening headless",
            session.session_id,
        )
        resolved = self._resolve_gui_fallback_path(session)
        with self._lock:
            worker = self._allocate_worker_locked()
        try:
            opened = self.call_worker_tool(
                worker,
                "idalib_open",
                {
                    "input_path": resolved,
                    "run_auto_analysis": False,
                    "session_id": session.session_id,
                },
            )
            if isinstance(opened, dict) and opened.get("error"):
                raise RuntimeError(str(opened["error"]))
        except Exception:
            self._terminate_worker(worker)
            raise

        worker_session = opened.get("session", {}) if isinstance(opened, dict) else {}
        replacement = WorkerSession(
            session_id=session.session_id,
            input_path=str(worker_session.get("input_path") or resolved),
            filename=str(worker_session.get("filename") or Path(resolved).name),
            is_analyzing=bool(worker_session.get("is_analyzing", False)),
            metadata={**session.metadata, **dict(worker_session.get("metadata") or {}), "fallback_from_gui": True},
            host=worker.host,
            port=worker.port,
            process=worker.process,
            backend="worker",
            owned=True,
            pid=worker.process.pid if worker.process is not None else None,
        )
        with self._lock:
            current = self.sessions.get(session.session_id)
            if current is session:
                self._register_session_locked(replacement, resolved, None)
                return replacement
            if current is not None and current.is_alive():
                current.last_accessed = datetime.now()
                replacement_session = current
                reopen_error = None
            else:
                if current is not None:
                    self._unregister_session_locked(session.session_id)
                replacement_session = None
                reopen_error = RuntimeError(
                    f"Session '{session.session_id}' was closed or replaced while reopening headlessly"
                )

        self._discard_opened_worker_session(worker, session.session_id)
        if replacement_session is not None:
            return replacement_session
        if reopen_error is not None:
            raise reopen_error
        raise RuntimeError(f"Session '{session.session_id}' changed while reopening headlessly")

    def resolve_session(self, database: str | None = None) -> WorkerSession:
        with self._lock:
            session_id: str | None = None
            if database:
                matches: list[str] = [database] if database in self.sessions else []
                if not matches:
                    try:
                        mapped = self.path_to_session.get(self._path_key(database))
                    except Exception:
                        mapped = self.path_to_session.get(os.path.normcase(database))
                    if mapped is not None:
                        matches = [mapped]
                if not matches:
                    matches = [
                        s.session_id
                        for s in self.sessions.values()
                        if database in {s.session_id, s.filename, s.input_path}
                        or os.path.normcase(database) == os.path.normcase(s.input_path)
                    ]
                if not matches:
                    # Try resolved path match without requiring it to exist now.
                    try:
                        normalized = os.path.normcase(str(Path(database).resolve()))
                    except Exception:
                        normalized = os.path.normcase(database)
                    matches = [
                        s.session_id
                        for s in self.sessions.values()
                        if os.path.normcase(s.input_path) == normalized
                    ]
                if len(matches) > 1:
                    raise RuntimeError(f"Database selector is ambiguous: {database}")
                if not matches:
                    raise RuntimeError(f"Database/session not found: {database}")
                session_id = matches[0]
            else:
                context_id = self.resolve_context_id()
                session_id = self.context_bindings.get(context_id)
                if session_id is None and not self.isolated_contexts:
                    session_id = self.context_bindings.get(SHARED_FALLBACK_CONTEXT_ID)
                if session_id is None:
                    raise RuntimeError(
                        "No database bound for this context. Use idalib_open(...), "
                        "idalib_switch(session_id), or pass database=..."
                    )
            session = self.sessions.get(session_id)
            if session is None:
                raise RuntimeError(f"Session is stale or missing: {session_id}")
            session.last_accessed = datetime.now()

        if session.is_alive():
            return session
        if session.backend == "gui":
            return self._reopen_gui_session_headless(session)
        raise RuntimeError(f"Worker for session '{session_id}' is not running")

    def list_sessions(self, context_id: str) -> list[IdalibSessionListInfo]:
        with self._lock:
            current = self.context_bindings.get(context_id)
            binding_counts: dict[str, int] = {}
            for bound in self.context_bindings.values():
                binding_counts[bound] = binding_counts.get(bound, 0) + 1
            return [
                session.to_list_dict(
                    current=session.session_id == current,
                    bound_contexts=binding_counts.get(session.session_id, 0),
                )
                for session in self.sessions.values()
            ]

    # ------------------------------------------------------------------
    # Schema/resource forwarding
    # ------------------------------------------------------------------

    def worker_tools(self) -> list[dict]:
        cache_key = tuple(sorted(getattr(self.mcp._enabled_extensions, "data", set())))
        with self._lock:
            cached = self._tools_cache.get(cache_key)
            if cached is not None:
                return copy.deepcopy(cached)
        worker = self._schema_or_idle_worker()
        response = self._worker_rpc(worker, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        tools = response.get("result", {}).get("tools", [])
        hidden_tools = IDALIB_MANAGEMENT_TOOLS | IDALIB_HIDDEN_PLUGIN_TOOLS
        filtered = [t for t in tools if t.get("name") not in hidden_tools]
        injected = [self._inject_database_arg(t) for t in filtered]
        with self._lock:
            self._tools_cache[cache_key] = injected
        return copy.deepcopy(injected)

    def _inject_database_arg(self, tool: dict) -> dict:
        tool = copy.deepcopy(tool)
        schema = tool.setdefault("inputSchema", {"type": "object", "properties": {}})
        schema.setdefault("type", "object")
        props = schema.setdefault("properties", {})
        props.setdefault(_DATABASE_ARG, _DATABASE_ARG_SCHEMA)
        required = schema.setdefault("required", [])
        if _DATABASE_ARG in required:
            required.remove(_DATABASE_ARG)
        return tool

    def worker_resources(self, method: str) -> list[dict]:
        with self._lock:
            cached = self._resources_cache.get(method)
            if cached is not None:
                return copy.deepcopy(cached)
        worker = self._schema_or_idle_worker()
        response = self._worker_rpc(worker, {"jsonrpc": "2.0", "id": 1, "method": method})
        key = "resources" if method == "resources/list" else "resourceTemplates"
        items = response.get("result", {}).get(key, [])
        with self._lock:
            self._resources_cache[method] = items
        return copy.deepcopy(items)


mcp = McpServer(MCP_SERVER_NAME)
supervisor: IdalibSupervisor | None = None
_original_dispatch = mcp.registry.dispatch


def _require_supervisor() -> IdalibSupervisor:
    if supervisor is None:
        raise RuntimeError("idalib supervisor not initialized")
    return supervisor


def _call_tool_result(result: Any, *, is_error: bool = False) -> dict:
    response: dict[str, Any] = {
        "content": [{"type": "text", "text": json.dumps(result, separators=(",", ":"))}],
        "isError": is_error,
    }
    if not is_error:
        response["structuredContent"] = result if isinstance(result, dict) else {"result": result}
    return response


def _jsonrpc_result(request_id: Any, result: Any) -> dict:
    return {"jsonrpc": "2.0", "result": result, "id": request_id}


def _jsonrpc_error(request_id: Any, code: int, message: str) -> dict | None:
    if request_id is None:
        return None
    return {"jsonrpc": "2.0", "error": {"code": code, "message": message}, "id": request_id}


@mcp.tool
def idalib_open(
    input_path: Annotated[str, "Path to the binary file to analyze"],
    run_auto_analysis: Annotated[bool, "Run automatic analysis on the binary"] = True,
    session_id: Annotated[
        Optional[str], "Custom session ID (auto-generated if not provided)"
    ] = None,
) -> IdalibOpenResult:
    """Open a binary in its own idalib worker process and bind it to this context."""
    sup = _require_supervisor()
    try:
        context_id = sup.resolve_context_id()
        session = sup.open_session(
            input_path,
            run_auto_analysis=run_auto_analysis,
            session_id=session_id,
            context_id=context_id,
        )
        return {
            "success": True,
            **sup.context_fields(context_id),
            "session": session.to_dict(),
            "message": f"Binary opened and bound to context: {session.filename} ({session.session_id})",
        }
    except Exception as e:
        return {"error": str(e)}


@mcp.tool
def idalib_close(session_id: Annotated[str, "Session ID to close"]) -> IdalibCloseResult:
    """Close a database worker and remove all context bindings targeting it."""
    sup = _require_supervisor()
    try:
        if sup.close_session(session_id):
            return {"success": True, "message": f"Session closed: {session_id}"}
        return {"success": False, "error": f"Session not found: {session_id}"}
    except Exception as e:
        return {"error": f"Failed to close session: {e}"}


@mcp.tool
def idalib_switch(session_id: Annotated[str, "Session ID to bind to active context"]) -> IdalibSwitchResult:
    """Bind the active idalib context to an existing database worker."""
    sup = _require_supervisor()
    try:
        context_id = sup.resolve_context_id()
        session = sup.resolve_session(session_id)
        sup.bind_context(context_id, session.session_id)
        return {
            "success": True,
            **sup.context_fields(context_id),
            "session": session.to_dict(),
            "message": f"Bound context to session: {session.session_id} ({session.filename})",
        }
    except Exception as e:
        return {"error": str(e)}


@mcp.tool
def idalib_unbind() -> IdalibUnbindResult:
    """Unbind the active idalib context from any database."""
    sup = _require_supervisor()
    try:
        context_id = sup.resolve_context_id()
        if sup.unbind_context(context_id):
            return {
                "success": True,
                **sup.context_fields(context_id),
                "message": "Context unbound successfully.",
            }
        return {
            "success": False,
            **sup.context_fields(context_id),
            "error": "No bound session for this context.",
        }
    except Exception as e:
        return {"error": f"Failed to unbind context: {e}"}


@mcp.tool
def idalib_list() -> IdalibListResult:
    """List database workers with context-binding metadata."""
    sup = _require_supervisor()
    try:
        context_id = sup.resolve_context_id()
        sessions = sup.list_sessions(context_id)
        return {
            "sessions": sessions,
            "count": len(sessions),
            **sup.context_fields(context_id),
            "current_context_session_id": sup.context_bindings.get(context_id),
        }
    except Exception as e:
        return {"error": f"Failed to list sessions: {e}"}


@mcp.tool
def idalib_current() -> IdalibCurrentResult:
    """Return the database bound to the active idalib context."""
    sup = _require_supervisor()
    try:
        context_id = sup.resolve_context_id()
        session_id = sup.context_bindings.get(context_id)
        if session_id is None:
            return {
                "error": "No session bound for this context. Use idalib_open(...) or idalib_switch(session_id) first.",
                **sup.context_fields(context_id),
            }
        session = sup.resolve_session(session_id)
        return {**session.to_dict(), **sup.context_fields(context_id)}
    except Exception as e:
        return {"error": f"Failed to get current session: {e}"}


@mcp.tool
def idalib_save(
    path: Annotated[str, "Optional destination path (default: current IDB path)"] = "",
    session_id: Annotated[Optional[str], "Optional session to save"] = None,
) -> IdalibSaveResult:
    """Save the selected database worker's IDB."""
    sup = _require_supervisor()
    try:
        context_id = sup.resolve_context_id()
        session = sup.resolve_session(session_id)
        if session_id:
            sup.bind_context(context_id, session.session_id)
        tool_name = "idb_save" if session.backend == "gui" else "idalib_save"
        result = sup.call_worker_tool(session, tool_name, {"path": path})
        if isinstance(result, dict):
            return {**result, **sup.context_fields(context_id)}
        return {"ok": False, **sup.context_fields(context_id), "error": "Unexpected save result"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@mcp.tool
def idalib_health(
    session_id: Annotated[Optional[str], "Optional session to probe"] = None,
) -> IdalibHealthResult:
    """Health/ready probe for a database worker or the full worker pool.
    
    Without session_id: returns pool-level status (worker count, alive count,
    max workers, idle timeout, per-worker details).
    With session_id: probes that specific worker."""
    sup = _require_supervisor()
    try:
        context_id = sup.resolve_context_id()
        if not session_id:
            alive = []
            dead_detail = []
            with sup._lock:
                for s in sup.sessions.values():
                    detail = {
                        "session_id": s.session_id,
                        "pid": s.process.pid if s.process else s.pid,
                        "alive": s.is_alive(),
                        "backend": s.backend,
                        "filename": s.filename,
                        "owned": s.owned,
                        "last_accessed_sec_ago": (datetime.now() - s.last_accessed).total_seconds(),
                        "stderr_log": s.metadata.get("stderr_log"),
                    }
                    if s.is_alive():
                        alive.append(detail)
                    else:
                        dead_detail.append(detail)
                total = len(sup.sessions)
                alive_count = len(alive)
            return {
                "ready": alive_count > 0,
                **sup.context_fields(context_id),
                "session": None,
                "health": None,
                "error": None,
                "pool": {
                    "workers_total": total,
                    "workers_alive": alive_count,
                    "workers_dead": len(dead_detail),
                    "max_workers": sup.max_workers,
                    "idle_timeout_s": _IDLE_TIMEOUT_S,
                },
                "workers": alive + dead_detail,
            }
        session = sup.resolve_session(session_id)
        sup.bind_context(context_id, session.session_id)
        if session.backend == "gui":
            health = sup.call_worker_tool(session, "server_health", {})
            return {
                "ready": bool(isinstance(health, dict) and not health.get("error")),
                **sup.context_fields(context_id),
                "session": session.to_dict(),
                "health": health if isinstance(health, dict) else None,
                "error": None,
            }
        result = sup.call_worker_tool(session, "idalib_health", {})
        if isinstance(result, dict):
            return {**result, **sup.context_fields(context_id)}
        return {"ready": False, **sup.context_fields(context_id), "session": None, "health": None, "error": "Unexpected health result"}
    except Exception as e:
        return {"ready": False, "error": str(e)}


@mcp.tool
def idalib_warmup(
    session_id: Annotated[Optional[str], "Optional session to warm up"] = None,
    wait_auto_analysis: Annotated[bool, "Wait for auto analysis queue"] = True,
    build_caches: Annotated[bool, "Build core caches"] = True,
    init_hexrays: Annotated[bool, "Initialize Hex-Rays plugin"] = True,
) -> IdalibWarmupResult:
    """Warm up selected database worker and core subsystems."""
    sup = _require_supervisor()
    try:
        context_id = sup.resolve_context_id()
        session = sup.resolve_session(session_id)
        if session_id:
            sup.bind_context(context_id, session.session_id)
        if session.backend == "gui":
            warmup = sup.call_worker_tool(
                session,
                "server_warmup",
                {
                    "wait_auto_analysis": wait_auto_analysis,
                    "build_caches": build_caches,
                    "init_hexrays": init_hexrays,
                },
            )
            return {
                "ready": bool(isinstance(warmup, dict) and warmup.get("ok")),
                **sup.context_fields(context_id),
                "session": session.to_dict(),
                "warmup": warmup if isinstance(warmup, dict) else None,
                "error": None,
            }
        result = sup.call_worker_tool(
            session,
            "idalib_warmup",
            {
                "wait_auto_analysis": wait_auto_analysis,
                "build_caches": build_caches,
                "init_hexrays": init_hexrays,
            },
        )
        if isinstance(result, dict):
            return {**result, **sup.context_fields(context_id)}
        return {"ready": False, **sup.context_fields(context_id), "session": None, "warmup": None, "error": "Unexpected warmup result"}
    except Exception as e:
        return {"ready": False, "error": str(e)}


@mcp.resource("ida://databases")
def databases_resource() -> dict:
    """List open idalib worker databases."""
    sup = _require_supervisor()
    context_id = sup.resolve_context_id()
    return {
        "databases": sup.list_sessions(context_id),
        "count": len(sup.sessions),
        **sup.context_fields(context_id),
    }


def _handle_tools_list(request_obj: dict[str, Any]) -> dict[str, Any]:
    sup = _require_supervisor()
    local_tools = mcp._mcp_tools_list().get("tools", [])
    worker_tools = sup.worker_tools()
    return _jsonrpc_result(request_obj.get("id"), {"tools": worker_tools + local_tools})


def _handle_tools_call(request_obj: dict[str, Any]) -> dict[str, Any] | None:
    sup = _require_supervisor()
    params = request_obj.get("params") or {}
    tool_name = params.get("name", "")
    request_id = request_obj.get("id")

    if tool_name in IDALIB_MANAGEMENT_TOOLS:
        return _original_dispatch(request_obj)
    if tool_name in IDALIB_HIDDEN_PLUGIN_TOOLS:
        return _jsonrpc_result(
            request_id,
            _call_tool_result(
                {
                    "error": (
                        f"{tool_name} is a GUI-plugin routing tool and is not "
                        "available through idalib-mcp. Use idalib_list or "
                        "idalib_switch instead."
                    )
                },
                is_error=True,
            ),
        )

    arguments = copy.deepcopy(params.get("arguments") or {})
    database = arguments.pop(_DATABASE_ARG, None)
    try:
        session = sup.resolve_session(database)
    except Exception as e:
        return _jsonrpc_result(request_id, _call_tool_result({"error": str(e)}, is_error=True))

    forwarded = copy.deepcopy(request_obj)
    forwarded.setdefault("params", {})["arguments"] = arguments
    try:
        return sup.forward_raw(session, forwarded)
    except Exception as e:
        return _jsonrpc_result(request_id, _call_tool_result({"error": str(e)}, is_error=True))


def _handle_resources_list(request_obj: dict[str, Any]) -> dict[str, Any]:
    sup = _require_supervisor()
    local = mcp._mcp_resources_list().get("resources", [])
    worker = sup.worker_resources("resources/list")
    return _jsonrpc_result(request_obj.get("id"), {"resources": local + worker})


def _handle_resource_templates_list(request_obj: dict[str, Any]) -> dict[str, Any]:
    sup = _require_supervisor()
    local = mcp._mcp_resource_templates_list().get("resourceTemplates", [])
    worker = sup.worker_resources("resources/templates/list")
    return _jsonrpc_result(request_obj.get("id"), {"resourceTemplates": local + worker})


def _handle_resources_read(request_obj: dict[str, Any]) -> dict[str, Any] | None:
    sup = _require_supervisor()
    uri = (request_obj.get("params") or {}).get("uri", "")
    if uri == "ida://databases":
        return _original_dispatch(request_obj)
    try:
        session = sup.resolve_session(None)
        return sup.forward_raw(session, request_obj)
    except Exception as e:
        return _jsonrpc_error(request_obj.get("id"), -32001, str(e))


def dispatch_supervisor(request: dict | str | bytes | bytearray) -> dict | None:
    if not isinstance(request, dict):
        try:
            request_obj = json.loads(request)
        except Exception:
            return _original_dispatch(request)
    else:
        request_obj = request

    method = request_obj.get("method", "")
    if method in {"initialize", "ping"} or method.startswith("notifications/"):
        return _original_dispatch(request)
    if method == "tools/list":
        return _handle_tools_list(request_obj)
    if method == "tools/call":
        return _handle_tools_call(request_obj)
    if method == "resources/list":
        return _handle_resources_list(request_obj)
    if method == "resources/templates/list":
        return _handle_resource_templates_list(request_obj)
    if method == "resources/read":
        return _handle_resources_read(request_obj)
    if method in {"prompts/list", "prompts/get"}:
        return _original_dispatch(request_obj)

    try:
        session = _require_supervisor().resolve_session(None)
    except Exception as e:
        return _jsonrpc_error(request_obj.get("id"), -32001, str(e))
    return _require_supervisor().forward_raw(session, request_obj)


def main() -> None:
    parser = argparse.ArgumentParser(description="MCP supervisor for IDA Pro via idalib")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show debug messages")
    parser.add_argument("--stdio", action="store_true", help="Serve MCP over stdio instead of HTTP")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="HTTP host, default: 127.0.0.1")
    parser.add_argument("--port", type=int, default=8745, help="HTTP port, default: 8745")
    parser.add_argument(
        "--isolated-contexts",
        action="store_true",
        help="Enable strict per-transport database binding isolation.",
    )
    parser.add_argument("--unsafe", action="store_true", help="Enable unsafe worker tools (DANGEROUS)")
    parser.add_argument(
        "--profile",
        type=Path,
        default=None,
        metavar="PATH",
        help="Restrict worker tools to names listed in a profile file.",
    )
    parser.add_argument(
        "--max-workers",
        type=int,
        default=int(os.environ.get("IDA_MCP_MAX_WORKERS", "4")),
        help="Maximum simultaneous idalib worker databases (0 = unlimited, default: 4).",
    )
    parser.add_argument("input_path", type=Path, nargs="?", help="Optional binary to open on startup.")
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO)

    worker_args: list[str] = []
    if args.verbose:
        worker_args.append("--verbose")
    if args.unsafe:
        worker_args.append("--unsafe")
    if args.profile is not None:
        worker_args.extend(["--profile", str(args.profile)])

    global supervisor
    supervisor = IdalibSupervisor(
        mcp,
        isolated_contexts=args.isolated_contexts,
        max_workers=args.max_workers,
        worker_args=worker_args,
    )
    mcp.registry.dispatch = dispatch_supervisor
    mcp.require_streamable_http_session = args.isolated_contexts

    # Bootstrap: spawn a temporary worker to discover tool/resource schemas
    # so the first get_tools() call returns instantly.
    supervisor._bootstrap_schemas()

    if args.input_path is not None:
        startup_context_id = STDIO_DEFAULT_CONTEXT_ID if args.isolated_contexts else SHARED_FALLBACK_CONTEXT_ID
        try:
            supervisor.open_session(str(args.input_path), context_id=startup_context_id)
        except Exception as e:
            raise SystemExit(f"Failed to open initial binary: {e}")

    def cleanup_and_exit(signum, frame):
        logger.info("Shutting down idalib supervisor...")
        if supervisor is not None:
            supervisor.shutdown()
        raise SystemExit(0)

    signal.signal(signal.SIGINT, cleanup_and_exit)
    signal.signal(signal.SIGTERM, cleanup_and_exit)

    try:
        if args.stdio:
            mcp.stdio()
        else:
            mcp.serve(host=args.host, port=args.port, background=False)
    finally:
        if supervisor is not None:
            supervisor.shutdown()


if __name__ == "__main__":
    main()
