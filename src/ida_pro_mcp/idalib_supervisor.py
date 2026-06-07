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
from threading import RLock, Thread, Event, Lock, Condition
from typing import Annotated, Any, Callable, NotRequired, Optional, TypedDict


logger = logging.getLogger(__name__)

_DEATH_WATCH_INTERVAL_S = 5.0
_IDLE_TIMEOUT_S = int(os.environ.get("IDA_MCP_IDALIB_IDLE_TIMEOUT_SEC", "1800"))
_BOOTSTRAP_DISCOVER_TIMEOUT_S = 30.0
# Stuck-open watchdog: if a worker makes no CPU progress for
# _OPEN_STALL_NO_PROGRESS_SEC after an initial _OPEN_STALL_GRACE_SEC window,
# the open is considered wedged (OOM/page-thrash or a stale IDB lock) and the
# worker is terminated. Requires psutil for CPU sampling; otherwise the bounded
# RPC timeout is the only backstop.
_OPEN_STALL_GRACE_SEC = float(os.environ.get("IDA_MCP_OPEN_STALL_GRACE_SEC", "90"))
_OPEN_STALL_NO_PROGRESS_SEC = float(os.environ.get("IDA_MCP_OPEN_STALL_SEC", "150"))
# Persist a worker's IDB before the idle timeout kills it, so an expensive
# analysis isn't lost. Disable with IDA_MCP_IDALIB_SAVE_ON_IDLE=0.
_SAVE_ON_IDLE = os.environ.get("IDA_MCP_IDALIB_SAVE_ON_IDLE", "1") not in ("0", "false", "False", "")

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
    "idalib_cleanup_zombies",
    "idalib_task_poll",
    "idalib_cancel_task",
    "idalib_start_analysis",
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


def _estimate_analysis_time(size_mb: float) -> int:
    """Estimate auto-analysis time in seconds based on file size.

    Calibrated against a large PE binary (~343 MB, ~35 min / 2100 s).
    Piecewise linear model with conservative (high) estimates:
      - <= 10 MB : 30 + size_mb * 3  (~1 min for 10 MB)
      - 10-100 MB: 60 + size_mb * 5  (~5 min for 50 MB, ~9 min for 100 MB)
      - > 100 MB : 60 + size_mb * 6  (~35 min for 343 MB)
    """
    if size_mb <= 10:
        return int(30 + size_mb * 3)
    elif size_mb <= 100:
        return int(60 + size_mb * 5)
    else:
        return int(60 + size_mb * 6)


def _available_memory_mb() -> float | None:
    """Return available physical RAM in MB, or None if it can't be determined.

    Prefers psutil (cross-platform); falls back to GlobalMemoryStatusEx on
    Windows so the precheck works without an extra hard dependency.
    """
    try:
        import psutil  # type: ignore
        return psutil.virtual_memory().available / (1024 * 1024)
    except Exception:
        pass
    if os.name == "nt":
        try:
            import ctypes

            class _MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]

            stat = _MEMORYSTATUSEX()
            stat.dwLength = ctypes.sizeof(_MEMORYSTATUSEX)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
                return stat.ullAvailPhys / (1024 * 1024)
        except Exception:
            pass
    return None


def _estimate_required_memory_mb(size_mb: float, is_idb: bool) -> float:
    """Rough peak-RAM estimate for opening a binary or pre-analyzed IDB.

    - IDB (.i64/.idb): IDA maps most of the database in, so ~1.3x its size
      plus a ~1.5 GB baseline for Hex-Rays/type system.
    - Raw binary: auto-analysis expands well beyond the file; ~3x plus baseline.
    """
    if is_idb:
        return size_mb * 1.3 + 1536
    return max(size_mb * 3.0, 1536) + 512


def _is_idb_path(path: Path) -> bool:
    return path.suffix.lower() in (".i64", ".idb")


class WorkerCrashedError(RuntimeError):
    """Raised by _worker_rpc when the worker subprocess died mid-call.

    Subclasses RuntimeError so existing ``except Exception`` / ``except
    RuntimeError`` handlers keep working, but lets dispatch handlers catch
    a crash specifically to prune the dead worker and surface its stderr.
    """

    def __init__(self, worker: "WorkerSession", message: str = "Worker process closed stdout"):
        super().__init__(message)
        self.worker = worker


_WORKER_CMDLINE_MARKER = "ida_pro_mcp.idalib_server"


def _select_orphan_worker_pids(
    procs: list[dict[str, Any]],
    *,
    protected: set[int],
    alive_pids: set[int],
) -> list[int]:
    """Pick idalib_server worker pids whose supervisor parent is gone.

    An orphaned worker keeps an OS file lock on its .i64 (blocking new opens
    AND the IDA GUI) and occupies a pool slot forever — this is the Case-3
    "stuck worker poisons everything / IDB read-only" failure. Pure/testable:
    *procs* is a list of {"pid","ppid","cmdline"} dicts.

    Only true orphans (parent pid not currently alive) are selected, so a
    concurrently-running supervisor's live workers are never touched.
    """
    victims: list[int] = []
    for p in procs:
        cmdline = p.get("cmdline") or []
        if _WORKER_CMDLINE_MARKER not in " ".join(cmdline):
            continue
        pid = p.get("pid")
        if pid is None or pid in protected:
            continue
        ppid = p.get("ppid")
        if ppid is None or ppid not in alive_pids:
            victims.append(pid)
    return victims


def _kill_pid_tree(pid: int) -> bool:
    """Best-effort hard-kill of a pid and its children (releases file locks)."""
    try:
        import psutil  # type: ignore
    except Exception:
        try:
            os.kill(pid, 9)
            return True
        except OSError:
            return False
    try:
        proc = psutil.Process(pid)
    except Exception:
        return False
    targets = []
    try:
        targets = proc.children(recursive=True)
    except Exception:
        pass
    targets.append(proc)
    killed = False
    for t in targets:
        try:
            t.kill()
            killed = True
        except Exception:
            pass
    return killed


def _sweep_orphan_workers(protected_pids: set[int]) -> list[int]:
    """Kill leaked idalib_server workers whose supervisor parent has exited.

    Run at startup so a restart auto-recovers from a prior crash that left
    workers holding .i64 locks. Safe: only parent-dead orphans are killed.
    """
    try:
        import psutil  # type: ignore
    except Exception:
        return []
    procs: list[dict[str, Any]] = []
    alive: set[int] = set()
    for p in psutil.process_iter(["pid", "ppid", "cmdline"]):
        try:
            info = p.info
            alive.add(info["pid"])
            procs.append({"pid": info["pid"], "ppid": info.get("ppid"), "cmdline": info.get("cmdline")})
        except Exception:
            continue
    victims = _select_orphan_worker_pids(procs, protected=protected_pids, alive_pids=alive)
    killed = [pid for pid in victims if _kill_pid_tree(pid)]
    if killed:
        logger.warning(
            "Swept %d orphaned idalib worker(s) holding stale locks: %s", len(killed), killed
        )
    return killed


def _parse_mem_limit_bytes() -> int | None:
    """Committed-memory cap per worker pool, from IDA_MCP_IDALIB_MEM_LIMIT_GB.

    When set, the Job Object enforces a hard cap on total committed memory across
    all workers — this is what backs ``pagefile.sys``, so it bounds pagefile
    growth. Unset/0 → no cap. Too-low a cap will make IDA fail to load large
    IDBs (allocations error out instead of ballooning), so it's opt-in.
    """
    raw = os.environ.get("IDA_MCP_IDALIB_MEM_LIMIT_GB", "").strip()
    if not raw:
        return None
    try:
        gb = float(raw)
    except ValueError:
        return None
    return int(gb * (1024 ** 3)) if gb > 0 else None


class _WorkerJob:
    """Windows Job Object that owns every idalib worker process.

    Solves two things at once for ``pagefile.sys`` blowup:

    * **KILL_ON_JOB_CLOSE** — when the supervisor process exits for ANY reason
      (clean shutdown, crash, taskkill, parent death, lost console), Windows
      terminates every worker still in the job. No orphaned workers survive, so
      their committed memory (pagefile) is freed and their ``.i64`` locks are
      released immediately — "clean up no matter what happens".
    * **JOB_MEMORY limit (opt-in)** — caps total committed memory across all
      workers (``IDA_MCP_IDALIB_MEM_LIMIT_GB``), bounding how far pagefile can
      grow.

    No-op on non-Windows; posix uses a PR_SET_PDEATHSIG preexec instead.
    """

    def __init__(self, mem_limit_bytes: int | None = None):
        self._handle = None
        self._kernel32 = None
        self.mem_limit_bytes = mem_limit_bytes
        if os.name != "nt":
            return
        try:
            self._init_windows(mem_limit_bytes)
        except Exception:
            logger.debug("Job Object setup failed; relying on orphan sweep", exc_info=True)

    def _init_windows(self, mem_limit_bytes: int | None) -> None:
        import ctypes
        from ctypes import wintypes

        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
        JOB_OBJECT_LIMIT_JOB_MEMORY = 0x00000200
        JobObjectExtendedLimitInformation = 9

        class _BASIC(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_int64),
                ("PerJobUserTimeLimit", ctypes.c_int64),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            ]

        class _IO(ctypes.Structure):
            _fields_ = [(n, ctypes.c_uint64) for n in (
                "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                "ReadTransferCount", "WriteTransferCount", "OtherTransferCount",
            )]

        class _EXTENDED(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", _BASIC),
                ("IoInfo", _IO),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        k = ctypes.WinDLL("kernel32", use_last_error=True)
        k.CreateJobObjectW.restype = wintypes.HANDLE
        k.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
        k.SetInformationJobObject.restype = wintypes.BOOL
        k.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD]
        k.AssignProcessToJobObject.restype = wintypes.BOOL
        k.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        k.CloseHandle.argtypes = [wintypes.HANDLE]

        job = k.CreateJobObjectW(None, None)
        if not job:
            return
        info = _EXTENDED()
        flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if mem_limit_bytes and mem_limit_bytes > 0:
            flags |= JOB_OBJECT_LIMIT_JOB_MEMORY
            info.JobMemoryLimit = mem_limit_bytes
        info.BasicLimitInformation.LimitFlags = flags
        if not k.SetInformationJobObject(
            job, JobObjectExtendedLimitInformation, ctypes.byref(info), ctypes.sizeof(info)
        ):
            k.CloseHandle(job)
            return
        self._handle = job
        self._kernel32 = k
        cap = f", commit cap {mem_limit_bytes // (1024 ** 2)} MB" if mem_limit_bytes else ""
        logger.info("Worker Job Object active (kill-on-close%s)", cap)

    @property
    def active(self) -> bool:
        return self._handle is not None

    def assign(self, process: Any) -> None:
        """Add a freshly-spawned worker to the job so it dies with us."""
        if self._handle is None or process is None:
            return
        try:
            handle = int(process._handle)  # subprocess.Popen Windows process handle
        except Exception:
            return
        try:
            if not self._kernel32.AssignProcessToJobObject(self._handle, handle):
                import ctypes
                logger.debug("AssignProcessToJobObject failed (err=%s)", ctypes.get_last_error())
        except Exception:
            logger.debug("AssignProcessToJobObject raised", exc_info=True)

    def close(self) -> None:
        """Close the job handle — kills all remaining workers (KILL_ON_JOB_CLOSE)."""
        if self._handle is not None and self._kernel32 is not None:
            try:
                self._kernel32.CloseHandle(self._handle)
            except Exception:
                pass
        self._handle = None


def _worker_pdeathsig_preexec() -> None:
    """posix preexec: ask the kernel to SIGKILL this worker if the supervisor dies."""
    try:
        import ctypes
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        PR_SET_PDEATHSIG = 1
        libc.prctl(PR_SET_PDEATHSIG, signal.SIGKILL)
    except Exception:
        pass


_SUPERVISOR_LOCK_NAME = "synapse-idalib-supervisor.lock"


def _supervisor_lock_path() -> str:
    return os.path.join(tempfile.gettempdir(), _SUPERVISOR_LOCK_NAME)


def _enforce_supervisor_singleton() -> list[int]:
    """Kill a stale *prior* idalib supervisor + its workers, then claim the lock.

    A stdio supervisor whose client disconnected should exit on stdin EOF; when a
    prior one lingers (crash / blocked main thread / relaunch) it keeps workers
    that hold `.i64` locks and causes the multi-daemon routing chaos seen in the
    stress reports. On startup we kill the previously-recorded supervisor (only if
    it's verifiably an idalib supervisor) and its worker tree, then record our pid.
    Mirrors server.py's proxy singleton. Opt out: ``IDA_MCP_IDALIB_SINGLETON=0``.
    """
    if os.environ.get("IDA_MCP_IDALIB_SINGLETON", "1") in ("0", "false", "False", ""):
        return []
    lock = _supervisor_lock_path()
    our_pid = os.getpid()
    killed: list[int] = []
    prior_pid: int | None = None
    try:
        if os.path.exists(lock):
            with open(lock, "r", encoding="utf-8") as f:
                prior_pid = int((json.load(f) or {}).get("pid"))
    except Exception:
        prior_pid = None

    if prior_pid and prior_pid != our_pid:
        try:
            import psutil  # type: ignore
            if psutil.pid_exists(prior_pid):
                proc = psutil.Process(prior_pid)
                cmd = " ".join(proc.cmdline() or [])
                name = (proc.name() or "").lower()
                # Only kill if it's genuinely an idalib supervisor (guard pid reuse).
                if "idalib_supervisor" in cmd or "idalib-mcp" in cmd or "idalib-mcp" in name:
                    for child in proc.children(recursive=True):
                        if _kill_pid_tree(child.pid):
                            killed.append(child.pid)
                    if _kill_pid_tree(prior_pid):
                        killed.append(prior_pid)
                    logger.warning(
                        "Singleton: killed stale prior supervisor %s and its workers %s",
                        prior_pid, killed,
                    )
        except Exception:
            logger.debug("Supervisor singleton check failed", exc_info=True)

    try:
        with open(lock, "w", encoding="utf-8") as f:
            json.dump({"pid": our_pid, "started": time.time()}, f)
    except Exception:
        pass
    return killed


def _read_stderr_tail(log_path: str | None, *, max_lines: int = 25, max_bytes: int = 4000) -> str | None:
    """Return the tail of a worker stderr-capture file, or None.

    Workers capture raw stderr (incl. C-level crash output IDA prints before
    Python logging is up) to a per-worker file. On a crash this is usually the
    only place the real cause (bad processor, OOM, license, corrupt IDB) shows.
    """
    if not log_path:
        return None
    try:
        with open(log_path, "r", encoding="utf-8", errors="replace") as f:
            data = f.read()
    except OSError:
        return None
    data = data.strip()
    if not data:
        return None
    tail = "\n".join(data.splitlines()[-max_lines:])
    return tail[-max_bytes:]


def _format_duration(seconds: int) -> str:
    """Format seconds into a human-readable duration string."""
    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:
        return f"{seconds // 60}m {seconds % 60}s"
    else:
        return f"{seconds // 3600}h {(seconds % 3600) // 60}m"


class _WorkerChannel:
    """Per-process stdio JSON-RPC channel.

    Keyed by worker pid and shared across every WorkerSession that wraps the
    same process (e.g. lief-only sessions that piggyback on the schema worker),
    so exactly one reader thread ever drains a given pipe. A single reader
    routes responses by id into ``responses``; senders wait on ``cond`` with a
    deadline, so a silent/wedged worker can never block the caller.
    """

    def __init__(self, stdin: Any, stdout: Any, process: Any) -> None:
        self.stdin = stdin
        self.stdout = stdout
        self.process = process
        self.lock = Lock()           # serializes request writes + id allocation
        self.request_id = 0
        self.responses: dict[int, dict[str, Any]] = {}
        self.cond = Condition()
        self.reader_thread: Thread | None = None
        self.reader_eof = False


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
    active_calls: int = 0  # in-flight tool calls to this worker (for health/state)

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
        # pid -> _WorkerChannel, shared across WorkerSession copies of one process.
        self._channels: dict[int, _WorkerChannel] = {}
        self._channels_lock = Lock()
        # pid -> stderr-capture path, so a crash diagnostic can find the log
        # even for a session whose own metadata doesn't carry it.
        self._worker_logs: dict[int, str] = {}
        # All workers join this Job Object: they're force-killed when the
        # supervisor exits (any reason), freeing committed memory (pagefile) and
        # releasing .i64 locks. Optional commit cap bounds pagefile growth.
        self._job = _WorkerJob(_parse_mem_limit_bytes())
        self._tools_cache: dict[tuple[str, ...], list[dict]] = {}
        self._resources_cache: dict[str, list[dict]] = {}
        self._lock = RLock()
        self._stop_event = Event()
        self._death_watcher: Thread | None = None
        self._bootstrap_completed = False
        self._open_tasks: dict[str, dict[str, Any]] = {}
        self._open_task_threads: dict[str, tuple[Thread, WorkerSession | None]] = {}
        # task_id -> {"cpu": last_cpu_seconds, "ts": last_progress_time} for the
        # stuck-open watchdog.
        self._open_worker_progress: dict[str, dict[str, float]] = {}
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

            try:
                self._check_stuck_opens()
            except Exception:
                logger.debug("Stuck-open check failed", exc_info=True)

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
            # Preserve analysis: persist the IDB before the idle kill so an
            # expensive (multi-minute) analysis isn't silently discarded.
            if _SAVE_ON_IDLE:
                self._save_session_best_effort(session)
            with self._lock:
                if session.session_id in self.sessions:
                    self._unregister_session_locked(session.session_id)
            self._terminate_worker(session)

    def _check_stuck_opens(self) -> None:
        """Detect background opens whose worker is making no CPU progress.

        A worker that sits at ~0 CPU well past the initial load window is
        wedged — typically OOM/page-thrash or a hidden 'database already open'
        prompt from a stale IDB lock. We fail the task with a diagnostic and
        terminate the worker so the agent gets a clear error in seconds-to-
        minutes instead of waiting out the full RPC timeout. CPU sampling needs
        psutil; without it we silently rely on the bounded RPC timeout.
        """
        if not self._open_task_threads:
            return
        try:
            import psutil  # type: ignore
        except Exception:
            return

        now = time.time()
        for task_id, (_thread, worker) in list(self._open_task_threads.items()):
            task = self._open_tasks.get(task_id)
            if task is None or task.get("status") != "loading" or worker is None:
                continue
            proc = worker.process
            if proc is None or proc.poll() is not None:
                continue
            if now - task.get("started_at", now) < _OPEN_STALL_GRACE_SEC:
                continue
            try:
                cpu_times = psutil.Process(proc.pid).cpu_times()
                cpu_total = float(cpu_times.user + cpu_times.system)
            except Exception:
                continue

            state = self._open_worker_progress.setdefault(
                task_id, {"cpu": cpu_total, "ts": now}
            )
            if cpu_total > state["cpu"] + 0.5:
                state["cpu"] = cpu_total
                state["ts"] = now
                continue
            stalled_for = now - state["ts"]
            if stalled_for < _OPEN_STALL_NO_PROGRESS_SEC:
                continue

            size_mb = task.get("size_mb", "?")
            logger.warning(
                "Open task %s wedged: no CPU progress for %.0fs (%.0f MB) — terminating worker %s",
                task_id, stalled_for, size_mb if isinstance(size_mb, (int, float)) else 0, proc.pid,
            )
            self._open_tasks[task_id] = {
                "status": "failed",
                "stage": "stuck_no_progress",
                "error": (
                    f"Worker made no CPU progress for {int(stalled_for)}s while opening "
                    f"{size_mb} MB and was terminated. Likely causes: insufficient RAM "
                    f"(page-thrash) or a stale IDA lock (.lck) / 'database already open' "
                    f"state. Free memory, remove stale lock files next to the .i64, or retry."
                ),
                "error_type": "StuckWorker",
                "size_mb": size_mb,
                "started_at": task.get("started_at", now),
                "elapsed_seconds": int(now - task.get("started_at", now)),
            }
            self._terminate_worker(worker)
            self._open_task_threads.pop(task_id, None)
            self._open_worker_progress.pop(task_id, None)

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
        popen_kwargs: dict[str, Any] = dict(
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=stderr_file or subprocess.DEVNULL,
            env=env,
        )
        if os.name == "nt":
            # CREATE_NEW_PROCESS_GROUP isolates the worker in its own process
            # group so force-killing the worker never crashes the parent daemon.
            popen_kwargs["creationflags"] = getattr(
                subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200
            )
        else:
            # posix: SIGKILL the worker if the supervisor dies (parent-death).
            popen_kwargs["preexec_fn"] = _worker_pdeathsig_preexec
        process = subprocess.Popen(cmd, **popen_kwargs)
        if stderr_file:
            stderr_file.close()
        # Join the Job Object ASAP so the worker is force-killed if we die
        # (Windows); frees its committed memory and releases .i64 locks.
        self._job.assign(process)
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
            self._worker_logs[process.pid] = log_path
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
            self._drop_channel(worker)
            return
        pid = proc.pid
        self._drop_channel(worker)
        try:
            proc.terminate()
            proc.wait(timeout=8)
            return
        except Exception:
            pass
        # A wedged worker may ignore terminate() or hold child handles that keep
        # its pipes alive. Kill the whole process tree so it can't linger.
        if os.name == "nt" and pid:
            try:
                subprocess.run(
                    ["taskkill", "/T", "/F", "/PID", str(pid)],
                    capture_output=True,
                    timeout=10,
                )
            except Exception:
                pass
        try:
            proc.kill()
            proc.wait(timeout=5)
        except Exception:
            logger.debug("Failed to reap worker pid %s", pid, exc_info=True)

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
        # Closing the job handle force-kills any worker that somehow survived
        # termination (KILL_ON_JOB_CLOSE) — frees committed memory + locks.
        self._job.close()

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

    def _get_channel(self, worker: WorkerSession) -> _WorkerChannel:
        """Return the shared RPC channel for this worker's process (by pid)."""
        proc = worker.process
        if proc is None:
            raise RuntimeError("Worker stdio pipes not available")
        pid = proc.pid
        with self._channels_lock:
            chan = self._channels.get(pid)
            if chan is None or chan.process is not proc:
                chan = _WorkerChannel(worker.stdin, worker.stdout, proc)
                self._channels[pid] = chan
            return chan

    def _drop_channel(self, worker: WorkerSession) -> None:
        proc = worker.process
        if proc is None:
            return
        with self._channels_lock:
            chan = self._channels.get(proc.pid)
            if chan is not None and chan.process is proc:
                self._channels.pop(proc.pid, None)
        self._worker_logs.pop(proc.pid, None)

    def _reader_loop(self, chan: _WorkerChannel) -> None:
        """Drain a channel's stdout, routing JSON-RPC responses by id.

        Runs as a daemon thread so a silent/wedged worker never blocks a caller:
        the blocking readline lives here, while senders wait on the condition
        with a deadline. On EOF (worker exit/kill) we flag reader_eof and wake
        all waiters so they fail fast instead of hanging.
        """
        stdout = chan.stdout
        try:
            while True:
                try:
                    line = stdout.readline()
                except Exception:
                    break
                if not line:
                    break  # EOF — worker closed stdout / exited
                text = line.decode("utf-8", errors="replace").strip()
                if not text or not text.startswith("{"):
                    continue
                try:
                    msg = json.loads(text)
                except json.JSONDecodeError:
                    continue
                if msg.get("id") is None:
                    continue  # notification — no correlation id
                with chan.cond:
                    chan.responses[msg["id"]] = msg
                    chan.cond.notify_all()
        finally:
            with chan.cond:
                chan.reader_eof = True
                chan.cond.notify_all()

    def _ensure_reader(self, chan: _WorkerChannel) -> None:
        # Guard against two concurrent RPCs starting two readers on one pipe.
        with chan.lock:
            if chan.reader_thread is not None and chan.reader_thread.is_alive():
                return
            chan.reader_eof = False
            thread = Thread(
                target=self._reader_loop,
                args=(chan,),
                daemon=True,
                name=f"worker-reader-{chan.process.pid}",
            )
            chan.reader_thread = thread
            thread.start()

    def _worker_rpc(
        self,
        worker: WorkerSession,
        payload: dict[str, Any],
        *,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        """Send a JSON-RPC request to a worker and wait for its response.

        Time-bounded and worker-death aware: the caller waits on the channel
        condition and re-checks the deadline and ``process.poll()`` at least
        once per second, so a worker that goes silent inside ``open_database()``
        can never block this thread (or the supervisor's main MCP loop) forever.
        """
        if worker.process is None or worker.process.poll() is not None:
            raise WorkerCrashedError(worker, "Worker process is not running")
        if worker.stdin is None or worker.stdout is None:
            raise RuntimeError("Worker stdio pipes not available")

        chan = self._get_channel(worker)
        self._ensure_reader(chan)

        with chan.lock:
            chan.request_id += 1
            request_id = chan.request_id
            body = json.dumps({**payload, "id": request_id})
            try:
                chan.stdin.write((body + "\n").encode("utf-8"))
                chan.stdin.flush()
            except (BrokenPipeError, OSError) as e:
                raise WorkerCrashedError(worker, "Worker process closed stdin") from e

        deadline = time.monotonic() + (timeout or 60.0)
        with chan.cond:
            while True:
                msg = chan.responses.pop(request_id, None)
                if msg is not None:
                    return msg
                if chan.reader_eof or (
                    chan.process is not None and chan.process.poll() is not None
                ):
                    raise WorkerCrashedError(worker, "Worker process closed stdout")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(
                        f"Worker RPC timed out after {(timeout or 60.0)}s"
                    )
                chan.cond.wait(timeout=min(remaining, 1.0))

    def forward_raw(self, worker: WorkerSession, request_obj: dict[str, Any]) -> dict[str, Any]:
        worker.active_calls += 1
        try:
            return self._worker_rpc(worker, request_obj)
        finally:
            worker.active_calls = max(0, worker.active_calls - 1)

    def _worker_crash_diagnostic(self, worker: WorkerSession, *, action: str) -> dict[str, Any]:
        """Structured 'worker_crashed' error enriched with the worker's stderr.

        Turns an opaque transport failure into the actual cause (bad processor,
        OOM, license, corrupt IDB) by attaching the worker's captured stderr.
        """
        info: dict[str, Any] = {
            "error": "worker_crashed",
            "error_type": "WorkerCrashed",
            "message": f"The idalib worker for this database crashed during {action}.",
        }
        proc = worker.process
        if proc is not None and proc.poll() is not None and proc.returncode is not None:
            info["exit_code"] = proc.returncode
        log_path = worker.metadata.get("stderr_log") or (
            self._worker_logs.get(proc.pid) if proc is not None else None
        )
        if log_path:
            info["stderr_log"] = log_path
            tail = _read_stderr_tail(log_path)
            if tail:
                info["stderr_tail"] = tail
        info["recommendation"] = (
            "Reopen the database (idalib_open). If it keeps crashing, check stderr_tail "
            "for the real cause (OOM, bad processor, corrupt/locked IDB) and consider "
            "mode='lief-only' for static metadata."
        )
        return info

    def handle_worker_crash(self, worker: WorkerSession, *, action: str = "an operation") -> dict[str, Any]:
        """Prune every session backed by *worker*'s process, then diagnose.

        Fails fast: the dead worker is removed from the pool immediately so the
        next call returns a clean error instead of waiting for the death watcher.
        """
        diagnostic = self._worker_crash_diagnostic(worker, action=action)
        proc = worker.process
        with self._lock:
            dead_ids = [
                sid for sid, s in self.sessions.items()
                if s is worker or (proc is not None and s.process is proc)
            ]
            for sid in dead_ids:
                self._unregister_session_locked(sid)
            if self._schema_worker is worker or (
                self._schema_worker is not None and proc is not None
                and self._schema_worker.process is proc
            ):
                self._schema_worker = None
        self._terminate_worker(worker)
        return diagnostic

    def _active_analysis_task_for(self, session_id: str) -> str | None:
        """Return the task_id of an in-flight analysis for *session_id*, if any."""
        for task_id, task in self._open_tasks.items():
            if (
                task_id.startswith("analysis_")
                and task.get("status") == "loading"
                and task.get("session_id") == session_id
            ):
                return task_id
        return None

    def session_state(self, session: WorkerSession) -> str:
        """Coarse lifecycle state for health reporting."""
        if not session.is_alive():
            return "dead"
        if self._active_analysis_task_for(session.session_id):
            return "analyzing"
        return "busy" if session.active_calls > 0 else "idle"

    def call_worker_tool(
        self, worker: WorkerSession, name: str, arguments: dict[str, Any] | None = None,
        tool_timeout: float | None = None,
    ) -> Any:
        """Call a tool on a worker and return the structured content."""
        self._touch_worker(worker)
        # For GUI-backend workers, use the old HTTP path
        if worker.backend == "gui":
            return self._gui_call_worker_tool(worker, name, arguments, tool_timeout=tool_timeout)
        worker.active_calls += 1
        try:
            response = self._worker_rpc(
                worker,
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": name, "arguments": arguments or {}},
                },
                timeout=tool_timeout,
            )
        finally:
            worker.active_calls = max(0, worker.active_calls - 1)
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
        open_timeout: float | None = None,
        processor: str | None = None,
        worker_sink: Callable[[WorkerSession], None] | None = None,
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

        # Expose the worker to the caller (async-open watchdog / cancel) as soon
        # as it exists, before the potentially long idalib_open RPC below.
        if worker_sink is not None:
            try:
                worker_sink(worker)
            except Exception:
                logger.debug("worker_sink callback failed", exc_info=True)

        try:
            open_args = {
                "input_path": resolved,
                "run_auto_analysis": run_auto_analysis,
                "session_id": session_id,
            }
            if processor:
                open_args["processor"] = processor
            opened = self.call_worker_tool(
                worker,
                "idalib_open",
                open_args,
                tool_timeout=open_timeout,
            )
            if isinstance(opened, dict) and opened.get("error"):
                raise RuntimeError(str(opened["error"]))
        except Exception:
            self._terminate_worker(worker)
            raise

        worker_session = opened.get("session", {}) if isinstance(opened, dict) else {}
        session_meta = dict(worker_session.get("metadata") or {})
        # Carry the worker's stderr-capture path onto the session so health and
        # crash diagnostics can find it (the worker's own metadata doesn't have it).
        if worker.metadata.get("stderr_log") and "stderr_log" not in session_meta:
            session_meta["stderr_log"] = worker.metadata["stderr_log"]
        # Carry the worker's honest post-open stats (function_count, warning, ...)
        # so callers can see an empty/failed analysis instead of a bare "success".
        if isinstance(opened, dict):
            open_stats = {
                k: opened[k]
                for k in ("function_count", "segment_count", "imagebase", "analysis_warning")
                if k in opened
            }
            if open_stats:
                session_meta["open_stats"] = open_stats
        session = WorkerSession(
            session_id=session_id,
            input_path=str(worker_session.get("input_path") or resolved),
            filename=str(worker_session.get("filename") or Path(resolved).name),
            is_analyzing=bool(worker_session.get("is_analyzing", False)),
            metadata=session_meta,
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

    def _save_session_best_effort(self, session: WorkerSession) -> bool:
        """Persist a worker's IDB before it is torn down. Best-effort.

        Skips lief-only sessions (no IDB) and temp-redirected DBs (cleaned up on
        close anyway). Returns True if a save was attempted and succeeded.
        """
        if session.backend != "worker" or not session.is_alive():
            return False
        if session.metadata.get("mode") == "lief-only":
            return False
        try:
            size_mb = 0.0
            try:
                size_mb = os.path.getsize(session.input_path) / (1024 * 1024)
            except OSError:
                pass
            timeout = min(120 + size_mb * 2, 1800)
            result = self.call_worker_tool(session, "idalib_save", {"path": ""}, tool_timeout=timeout)
            ok = bool(isinstance(result, dict) and result.get("ok"))
            if ok:
                logger.info("Saved IDB for session %s before teardown", session.session_id)
            return ok
        except Exception:
            logger.debug("Save-before-teardown failed for %s", session.session_id, exc_info=True)
            return False

    def close_session(self, session_id: str, *, save: bool = False) -> bool:
        with self._lock:
            session = self.sessions.get(session_id)
            if session is None:
                return False
        if save:
            self._save_session_best_effort(session)
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
            stdin=worker.stdin,
            stdout=worker.stdout,
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
    open_timeout_sec: Annotated[Optional[float], "Timeout in seconds (default: auto-scaled by size; increase for large binaries)"] = None,
    mode: Annotated[Optional[str], "Open mode: 'full' (default, IDA load) or 'lief-only' (static metadata, instant)"] = None,
    processor: Annotated[Optional[str], "IDA processor module short name (e.g. 'mipsr5900l', 'ppcvle', 'sh4l', 'tricore'). Auto-detected if omitted."] = None,
    force: Annotated[bool, "Skip the free-RAM precheck and open even if memory looks insufficient"] = False,
) -> dict:
    """Open a binary in its own idalib worker process and bind it to this context.

    Pass a pre-analyzed IDA database (.i64/.idb) directly to reopen it: the
    worker skips re-analysis, sweeps stale .lck locks, and never redirects
    output onto the database itself. This is the fast path for large saved IDBs.

    ANALYSIS TIME GUIDE (run_auto_analysis=True, raw binary):
    - Files <10 MB  : ~30s–2min
    - Files 10-50 MB: ~2–8min
    - Files 50-100 MB: ~8–15min
    - Files >100 MB : ~15–45min+ (a 343 MB DLL ≈ ~35min)

    For large binaries, set run_auto_analysis=False to open instantly
    (metadata only), then call idalib_start_analysis() later when full
    decompilation is needed. Use mode='lief-only' for instant static
    metadata without IDA loading.

    Before opening, free RAM is checked against an estimate (IDB ≈ 1.2x its
    size; raw binary ≈ 3x). If it looks insufficient the call returns
    error='insufficient_memory' instead of spawning a worker that would
    page-thrash; pass force=true to override.

    For binaries >10 MB, the open runs in a background thread and a
    task_id is returned immediately. Poll with idalib_task_poll(task_id).
    Use idalib_cancel_task(task_id) to abort a long-running open.

    PROCESSOR MODULES (use 'processor' param for raw binaries or when
    auto-detection fails):
    - x86/x64     : metapc (auto-detected for PE/ELF)
    - ARM LE      : arm, aarch64
    - ARM BE      : armb
    - MIPS LE     : mipsl, mipsr5900l (PS2)
    - MIPS BE     : mipsb
    - PowerPC     : ppc, ppcvle (Wii/automotive)
    - SuperH      : sh4l (Dreamcast)
    - TriCore     : tricore (car ECUs)
    - m68k        : m68k (Genesis/Amiga)
    - 6502        : 6502 (NES/Atari)
    - Z80         : z80 (Game Boy)
    - Xtensa      : xtensa (ESP8266/ESP32)
    - AVR         : avr (Arduino)
    - RISC-V      : riscv, riscv64
    - Hexagon     : hexagon (Qualcomm)
    - SPU         : spu (PS3 Cell)
    - V850/RH850  : v850, rh850 (Renesas auto)
    - STM8        : stm8
    - MSP430      : msp430
    - TMS320C6    : tms320c6
    - 8051        : i51
    - Dalvik      : dalvik
    - WebAssembly : wasm
    """

    sup = _require_supervisor()
    try:
        context_id = sup.resolve_context_id()
    except Exception:
        context_id = "shared:fallback"

    actual_mode = (mode or "full").lower()
    path = Path(input_path)
    is_idb = _is_idb_path(path)
    try:
        file_size_mb = round(path.stat().st_size / (1024 * 1024), 2)
    except Exception:
        file_size_mb = 0.0

    # A saved IDB is already analyzed — reopening only loads it, so analysis is
    # effectively off no matter what the caller requested.
    effective_analysis = run_auto_analysis and not is_idb

    # Auto-scale open timeout. IDB reopen only loads (no analysis) so it gets a
    # tighter bound; raw binaries with analysis get the larger budget.
    if open_timeout_sec is None:
        if is_idb:
            open_timeout_sec = min(180 + file_size_mb * 2, 1800)
        else:
            open_timeout_sec = min(300 + file_size_mb * 5, 3600)

    # Memory precheck (skipped for lief-only, which never loads IDA).
    if actual_mode != "lief-only" and not force:
        available_mb = _available_memory_mb()
        required_mb = _estimate_required_memory_mb(file_size_mb, is_idb)
        if available_mb is not None and available_mb < required_mb:
            return {
                "success": False,
                "error": "insufficient_memory",
                "required_mb": round(required_mb),
                "available_mb": round(available_mb),
                "size_mb": file_size_mb,
                "is_idb": is_idb,
                "recommendation": (
                    f"Opening this {'IDB' if is_idb else 'binary'} needs ~{round(required_mb)} MB free "
                    f"but only {round(available_mb)} MB is available. Close other apps and retry, "
                    f"pass force=true to override, or use mode='lief-only' for static metadata."
                ),
                **sup.context_fields(context_id),
            }

    # LIEF-only mode — return metadata + register lightweight session
    if actual_mode == "lief-only":
        info: dict[str, Any] = {"format": "unknown", "sections": []}
        try:
            import lief
            binary = lief.parse(str(path))
            if binary:
                info["format"] = str(binary.format).replace("FORMAT.", "").lower()
                if hasattr(binary, "optional_header") and binary.optional_header:
                    info["image_base"] = hex(binary.optional_header.imagebase)
                    info["entry_point"] = hex(binary.optional_header.addressof_entrypoint)
                for sec in binary.sections:
                    info["sections"].append({"name": sec.name, "virtual_size": sec.virtual_size, "entropy": round(sec.entropy, 2)})
        except Exception:
            pass
        if session_id is None:
            session_id = str(uuid.uuid4())[:8]
        # Create a lightweight worker session backed by the schema worker
        worker = sup._schema_or_idle_worker()
        if worker is not None:
            lief_session = WorkerSession(
                session_id=session_id,
                input_path=str(path),
                filename=path.name,
                metadata={"mode": "lief-only", "lief_metadata": info},
                host=worker.host, port=worker.port,
                process=worker.process, backend="worker",
                owned=worker.owned, pid=worker.pid,
                stdin=worker.stdin, stdout=worker.stdout,
            )
            with sup._lock:
                sup.sessions[session_id] = lief_session
                sup.path_to_session[sup._path_key(str(path))] = session_id
                if context_id:
                    sup.bind_context(context_id, session_id)
        return {
            "success": True, **sup.context_fields(context_id),
            "session": {"session_id": session_id, "filename": path.name, "mode": "lief-only"},
            "size_mb": file_size_mb, "lief_metadata": info,
            "message": f"LIEF-only session for {path.name} ({file_size_mb} MB). Use idalib_lief_* tools with file_path=...",
        }

    # Large file — async open with task tracking
    _LARGE_FILE_THRESHOLD_MB = 10.0
    estimated_total_sec = (
        _estimate_analysis_time(file_size_mb)
        if effective_analysis
        else int(30 + file_size_mb * 0.3)
    )

    if file_size_mb > _LARGE_FILE_THRESHOLD_MB:
        task_id = f"open_{uuid.uuid4().hex[:8]}"
        sup._open_tasks[task_id] = {
            "status": "loading",
            "stage": "spawning_worker",
            "file_path": str(path),
            "size_mb": file_size_mb,
            "started_at": time.time(),
            "estimated_total_seconds": estimated_total_sec,
        }

        def _record_worker(w: WorkerSession) -> None:
            thread_info = sup._open_task_threads.get(task_id)
            existing_thread = thread_info[0] if thread_info else None
            sup._open_task_threads[task_id] = (existing_thread, w)
            task = sup._open_tasks.get(task_id)
            if task is not None and task.get("status") == "loading":
                task["worker_pid"] = w.pid or (w.process.pid if w.process else None)

        def _open_worker_thread():
            try:
                sup._open_tasks[task_id]["stage"] = "loading_database"
                session = sup.open_session(
                    str(path),
                    run_auto_analysis=run_auto_analysis,
                    session_id=session_id,
                    context_id=context_id,
                    open_timeout=open_timeout_sec,
                    processor=processor,
                    worker_sink=_record_worker,
                )
                open_stats = session.metadata.get("open_stats") or {}
                sup._open_tasks[task_id] = {
                    "status": "done",
                    "stage": "done",
                    "session_id": session.session_id,
                    "filename": session.filename,
                    "size_mb": file_size_mb,
                    "started_at": sup._open_tasks[task_id].get("started_at", time.time()),
                    "estimated_total_seconds": estimated_total_sec,
                    **open_stats,
                }
            except Exception as exc:
                # Don't clobber a terminal state the watchdog or cancel set.
                current = sup._open_tasks.get(task_id, {})
                if current.get("status") in ("failed", "cancelled"):
                    return
                sup._open_tasks[task_id] = {
                    "status": "failed",
                    "stage": "failed",
                    "error": str(exc),
                    "error_type": type(exc).__name__,
                    "size_mb": file_size_mb,
                    "started_at": sup._open_tasks[task_id].get("started_at", time.time()),
                    "estimated_total_seconds": estimated_total_sec,
                }
            finally:
                sup._open_worker_progress.pop(task_id, None)

        thread = Thread(target=_open_worker_thread, daemon=True, name=f"open-{task_id}")
        sup._open_task_threads[task_id] = (thread, None)
        thread.start()

        # Build warning / recommendation message
        warning_parts = []
        if effective_analysis and file_size_mb > 50:
            warning_parts.append(
                f"Auto-analysis on {file_size_mb} MB binaries typically takes {_format_duration(estimated_total_sec)}. "
                f"Consider run_auto_analysis=False for instant metadata, then idalib_start_analysis() later."
            )

        return {
            "success": True,
            "status": "loading",
            "task_id": task_id,
            "size_mb": file_size_mb,
            "estimated_sec": estimated_total_sec,
            **sup.context_fields(context_id),
            "message": f"Large binary ({file_size_mb} MB) — opening in background. Poll with idalib_task_poll('{task_id}').",
            **({"analysis_time_warning": " ".join(warning_parts)} if warning_parts else {}),
        }

    # Small file — synchronous open
    try:
        session = sup.open_session(
            str(path),
            run_auto_analysis=run_auto_analysis,
            session_id=session_id,
            context_id=context_id,
            open_timeout=open_timeout_sec,
            processor=processor,
        )
        open_stats = session.metadata.get("open_stats") or {}
        return {
            "success": True,
            **sup.context_fields(context_id),
            "session": session.to_dict(),
            **open_stats,
            "message": f"Binary opened and bound to context: {session.filename} ({session.session_id})",
        }
    except Exception as e:
        try:
            return {"error": str(e), **sup.context_fields(context_id)}
        except Exception:
            return {"error": str(e)}


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
        return {"error": str(e)}


@mcp.tool
def idalib_close(
    session_id: Annotated[str, "Session ID to close"],
    save: Annotated[bool, "Save the IDB to disk before closing (preserves analysis)"] = False,
) -> IdalibCloseResult:
    """Close a database worker and remove all context bindings targeting it.

    Pass save=True to persist the IDB first — important after a long analysis,
    so the work isn't discarded when the worker is torn down."""
    sup = _require_supervisor()
    try:
        if sup.close_session(session_id, save=save):
            saved = " (saved)" if save else ""
            return {"success": True, "message": f"Session closed: {session_id}{saved}"}
        return {"success": False, "error": f"Session not found: {session_id}"}
    except Exception as e:
        return {"error": f"Failed to close session: {e}"}


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
            analyzing_count = 0
            busy_count = 0
            with sup._lock:
                for s in sup.sessions.values():
                    state = sup.session_state(s)
                    analysis_task = sup._active_analysis_task_for(s.session_id)
                    detail = {
                        "session_id": s.session_id,
                        "pid": s.process.pid if s.process else s.pid,
                        "alive": s.is_alive(),
                        "state": state,
                        "active_calls": s.active_calls,
                        "backend": s.backend,
                        "filename": s.filename,
                        "owned": s.owned,
                        "age_sec": round((datetime.now() - s.created_at).total_seconds(), 1),
                        "last_accessed_sec_ago": round((datetime.now() - s.last_accessed).total_seconds(), 1),
                        "stderr_log": s.metadata.get("stderr_log"),
                    }
                    if analysis_task:
                        detail["analysis_task"] = analysis_task
                    if state == "analyzing":
                        analyzing_count += 1
                    elif state == "busy":
                        busy_count += 1
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
                    "workers_analyzing": analyzing_count,
                    "workers_busy": busy_count,
                    "max_workers": sup.max_workers,
                    "idle_timeout_s": _IDLE_TIMEOUT_S,
                    "save_on_idle": _SAVE_ON_IDLE,
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
        # Bound the health probe so a wedged worker yields a structured
        # "unresponsive" answer (with its stderr) instead of hanging the client
        # until its own transport timeout (the report's "2nd health aborts").
        try:
            result = sup.call_worker_tool(session, "idalib_health", {}, tool_timeout=20.0)
        except WorkerCrashedError as e:
            diag = sup.handle_worker_crash(e.worker, action="health probe")
            return {"ready": False, **sup.context_fields(context_id), "session": session.to_dict(), "health": None, **diag}
        except TimeoutError:
            return {
                "ready": False,
                **sup.context_fields(context_id),
                "session": session.to_dict(),
                "health": None,
                "error": "worker_unresponsive",
                "message": (
                    f"Worker for '{session.session_id}' did not answer a health probe in 20s "
                    "(busy with a long op, or wedged). Check stderr_log, or idalib_cancel_task / "
                    "idalib_close it."
                ),
                "stderr_log": session.metadata.get("stderr_log"),
            }
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


@mcp.tool
def idalib_task_poll(
    task_id: Annotated[str, "Task ID returned by idalib_open or idalib_start_analysis"],
) -> dict:
    """Poll the status of an async idalib task.

    Returns elapsed time, estimated total time, completion percentage,
    and current stage so agents can report progress to users instead of
    polling blindly."""
    sup = _require_supervisor()
    if not task_id.startswith("open_") and not task_id.startswith("analysis_"):
        return _call_tool_result(
            {"error": f"Task '{task_id}' not found (expired or invalid ID)"},
            is_error=True,
        )
    if task_id not in sup._open_tasks:
        return _call_tool_result(
            {"error": f"Task '{task_id}' not found (expired or invalid ID)"},
            is_error=True,
        )

    task = sup._open_tasks[task_id].copy()
    started_at = task.get("started_at", time.time())
    elapsed = int(time.time() - started_at)
    estimated_total = task.get("estimated_total_seconds", 60)

    task["elapsed_seconds"] = elapsed
    task["estimated_total_seconds"] = estimated_total
    task["percent_complete"] = min(99, int((elapsed / max(estimated_total, 1)) * 100))

    if task.get("status") == "loading":
        remaining = max(0, estimated_total - elapsed)
        task["message"] = (
            f"{task.get('stage', 'loading')} in progress — "
            f"{_format_duration(elapsed)} elapsed, ~{_format_duration(remaining)} remaining"
        )
    elif task.get("status") == "done":
        task["message"] = f"Completed in {_format_duration(elapsed)}"
        task["percent_complete"] = 100
    elif task.get("status") == "failed":
        task["message"] = f"Failed after {_format_duration(elapsed)}"

    return _call_tool_result(task)


@mcp.tool
def idalib_cancel_task(
    task_id: Annotated[str, "Task ID to cancel (from idalib_open or idalib_start_analysis)"],
) -> dict:
    """Cancel an async idalib task and clean up its worker.

    Terminates the background thread and worker process, then removes
    any temp IDB files created for the task. Returns the final status
    of the task before cancellation."""
    sup = _require_supervisor()
    if task_id not in sup._open_tasks:
        return _call_tool_result(
            {"error": f"Task '{task_id}' not found (expired or invalid ID)"},
            is_error=True,
        )

    task = sup._open_tasks[task_id]
    file_path = task.get("file_path", "")

    # Terminate worker if tracked (worker is recorded via worker_sink as soon
    # as it's allocated, so a hung open can actually be cancelled).
    thread_info = sup._open_task_threads.pop(task_id, None)
    sup._open_worker_progress.pop(task_id, None)
    if thread_info:
        thread, worker = thread_info
        if worker is not None:
            sup._terminate_worker(worker)

    # Clean up IDA sidecars ONLY if they live under the temp dir — never touch
    # files next to the user's original input. Swap the final extension so
    # multi-dot names (foo.dll.i64) resolve correctly.
    if file_path:
        try:
            p = Path(file_path)
            if str(p).startswith(str(Path(tempfile.gettempdir()))):
                targets = {p}
                for ext in (".i64", ".idb", ".id0", ".id1", ".id2", ".nam", ".til"):
                    targets.add(p.with_suffix(ext))
                for f in targets:
                    if f.exists():
                        try:
                            f.unlink()
                        except OSError:
                            pass
        except Exception:
            pass

    # Mark as cancelled
    elapsed = int(time.time() - task.get("started_at", time.time()))
    sup._open_tasks[task_id] = {
        "status": "cancelled",
        "stage": "cancelled",
        "file_path": file_path,
        "size_mb": task.get("size_mb", 0),
        "started_at": task.get("started_at", time.time()),
        "elapsed_seconds": elapsed,
        "message": f"Cancelled after {_format_duration(elapsed)}",
    }

    return _call_tool_result(sup._open_tasks[task_id])


@mcp.tool
def idalib_start_analysis(
    session_id: Annotated[str, "Session ID of an open database to analyze"],
) -> dict:
    """Trigger auto-analysis on an already-open database.

    Use this after idalib_open(run_auto_analysis=False) to start full
    auto-analysis as a background task. Returns a task_id immediately;
    poll with idalib_task_poll(). Cancel with idalib_cancel_task().

    Analysis time guide:
    - Files <10 MB  : ~30s–2min
    - Files 10-50 MB: ~2–8min
    - Files 50-100 MB: ~8–15min
    - Files >100 MB : ~15–45min+"""
    sup = _require_supervisor()
    try:
        session = sup.resolve_session(session_id)
    except Exception as e:
        return _call_tool_result(
            {"error": f"Session not found: {e}"},
            is_error=True,
        )

    # Estimate analysis time from file size
    file_size_mb = 0.0
    try:
        file_size_mb = round(os.path.getsize(session.input_path) / (1024 * 1024), 2)
    except Exception:
        pass
    estimated_total_sec = _estimate_analysis_time(file_size_mb)

    task_id = f"analysis_{uuid.uuid4().hex[:8]}"
    started_at = time.time()
    sup._open_tasks[task_id] = {
        "status": "loading",
        "stage": "auto_analysis",
        "session_id": session_id,
        "file_path": session.input_path,
        "size_mb": file_size_mb,
        "started_at": started_at,
        "estimated_total_seconds": estimated_total_sec,
    }

    def _analysis_worker_thread():
        try:
            sup._open_tasks[task_id]["stage"] = "auto_analysis"
            result = sup.call_worker_tool(
                session,
                "idalib_warmup",
                {
                    "wait_auto_analysis": True,
                    "build_caches": True,
                    "init_hexrays": False,
                },
                tool_timeout=estimated_total_sec + 120,
            )
            elapsed = int(time.time() - started_at)
            sup._open_tasks[task_id] = {
                "status": "done",
                "stage": "done",
                "session_id": session_id,
                "file_path": session.input_path,
                "size_mb": file_size_mb,
                "started_at": started_at,
                "elapsed_seconds": elapsed,
                "estimated_total_seconds": estimated_total_sec,
                "warmup": result if isinstance(result, dict) else None,
            }
        except Exception as exc:
            elapsed = int(time.time() - started_at)
            sup._open_tasks[task_id] = {
                "status": "failed",
                "stage": "failed",
                "error": str(exc),
                "error_type": type(exc).__name__,
                "session_id": session_id,
                "file_path": session.input_path,
                "size_mb": file_size_mb,
                "started_at": started_at,
                "elapsed_seconds": elapsed,
                "estimated_total_seconds": estimated_total_sec,
            }

    thread = Thread(target=_analysis_worker_thread, daemon=True, name=f"analysis-{task_id}")
    sup._open_task_threads[task_id] = (thread, session)
    thread.start()

    return _call_tool_result({
        "success": True,
        "status": "loading",
        "task_id": task_id,
        "session_id": session_id,
        "size_mb": file_size_mb,
        "estimated_sec": estimated_total_sec,
        **sup.context_fields(sup.resolve_context_id()),
        "message": (
            f"Auto-analysis started for {session.filename} ({file_size_mb} MB). "
            f"Estimated time: {_format_duration(estimated_total_sec)}. "
            f"Poll with idalib_task_poll('{task_id}')."
        ),
    })


@mcp.tool
def idalib_cleanup_zombies(
    max_age_minutes: Annotated[Optional[int], "Reap foreign idalib_server workers / ida.exe older than N minutes"] = 30,
    include_foreign_workers: Annotated[bool, "Also reap idalib_server workers from OTHER supervisors older than max_age"] = True,
) -> dict:
    """Kill stuck/orphaned idalib worker processes (the real lock-holders).

    The headless workers that hold OS file locks on .i64 databases — blocking
    new opens AND the IDA GUI — are ``python -m ida_pro_mcp.idalib_server``
    processes, NOT ``ida.exe``. This reaps:
      - **orphaned** idalib_server workers (their supervisor parent is gone) — any age;
      - **foreign** idalib_server workers (another live supervisor) older than
        max_age_minutes, when include_foreign_workers=True;
      - stale ``ida.exe`` GUI instances older than max_age_minutes.
    Workers owned by THIS supervisor (and their children) are always protected.
    Returns the pids killed, with the reason, so you can see what was reclaimed.
    """
    sup = _require_supervisor()
    supervisor_pids: set[int] = set()
    with sup._lock:
        for s in sup.sessions.values():
            if s.process is not None and s.process.pid is not None:
                supervisor_pids.add(s.process.pid)
            if s.pid is not None:
                supervisor_pids.add(s.pid)
        if sup._schema_worker is not None and sup._schema_worker.process is not None:
            supervisor_pids.add(sup._schema_worker.process.pid)
        if sup._schema_worker is not None and sup._schema_worker.pid is not None:
            supervisor_pids.add(sup._schema_worker.pid)
    supervisor_pids.add(os.getpid())

    try:
        import psutil  # type: ignore
    except Exception:
        return {
            "killed": 0,
            "killed_pids": [],
            "errors": 0,
            "remaining_managed": len(supervisor_pids),
            "error": "psutil unavailable — cannot enumerate processes",
        }

    # Protect managed workers and their descendants (idalib may spawn helpers).
    protected: set[int] = set(supervisor_pids)
    for pid in list(supervisor_pids):
        try:
            for child in psutil.Process(pid).children(recursive=True):
                protected.add(child.pid)
        except Exception:
            pass

    procs = list(psutil.process_iter(["pid", "ppid", "name", "cmdline", "create_time"]))
    alive = {p.info["pid"] for p in procs if p.info.get("pid") is not None}
    now = time.time()
    cutoff_age = (max_age_minutes or 0) * 60
    killed: list[dict[str, Any]] = []
    errors = 0

    for proc in procs:
        try:
            info = proc.info
            pid = info["pid"]
            if pid in protected:
                continue
            cmdline = info.get("cmdline") or []
            name = (info.get("name") or "").lower()
            age = now - (info.get("create_time") or now)
            is_worker = _WORKER_CMDLINE_MARKER in " ".join(cmdline)
            reason = None
            if is_worker:
                ppid = info.get("ppid")
                if ppid is None or ppid not in alive:
                    reason = "orphan"  # supervisor parent gone — always reap
                elif include_foreign_workers and age >= cutoff_age:
                    reason = "foreign_stale"
            elif name in ("ida.exe", "ida64.exe", "ida", "ida64") and age >= cutoff_age:
                reason = "gui_zombie"
            if reason is None:
                continue
            if _kill_pid_tree(pid):
                killed.append({"pid": pid, "reason": reason, "age_sec": round(age)})
            else:
                errors += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            errors += 1
        except Exception:
            errors += 1

    return {
        "killed": len(killed),
        "killed_pids": [k["pid"] for k in killed],
        "killed_detail": killed,
        "errors": errors,
        "remaining_managed": len(supervisor_pids),
    }


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

    # *_status probes report library availability/version and need no IDB at
    # all. Route them to the schema/idle worker so they work before any database
    # is opened (was: "no database bound for this context").
    if tool_name.endswith("_status"):
        try:
            worker = sup.resolve_session(database)
        except Exception:
            worker = sup._schema_or_idle_worker()
        if worker is not None:
            forwarded = copy.deepcopy(request_obj)
            forwarded.setdefault("params", {})["arguments"] = arguments
            try:
                return sup.forward_raw(worker, forwarded)
            except WorkerCrashedError as e:
                diag = sup.handle_worker_crash(e.worker, action=f"tool '{tool_name}'")
                return _jsonrpc_result(request_id, _call_tool_result(diag, is_error=True))
            except Exception as e:
                return _jsonrpc_result(request_id, _call_tool_result({"error": str(e)}, is_error=True))

    # LIEF, ELF, and memmap tools with file_path don't need an IDB
    # session. Route to the schema worker directly so the tool can
    # use LIEF/numpy on the raw file without requiring a bound session.
    _TOOLS_ACCEPTING_FILE_PATH = ("lief_", "elf_", "numpy_memmap_", "construct_")
    file_path = arguments.get("file_path", "")

    # If a file-analysis tool is called without file_path, inject the
    # bound LIEF-only session's input_path so the tool can operate on
    # the raw file even though the worker has no open IDA database.
    if not file_path and any(tool_name.startswith(p) for p in _TOOLS_ACCEPTING_FILE_PATH):
        try:
            bound_session = sup.resolve_session(database)
            if bound_session and bound_session.metadata.get("mode") == "lief-only":
                file_path = bound_session.input_path
                arguments = {**arguments, "file_path": file_path}
        except Exception:
            pass

    if file_path and any(tool_name.startswith(p) for p in _TOOLS_ACCEPTING_FILE_PATH):
        try:
            session = sup.resolve_session(database)
        except Exception:
            worker = sup._schema_or_idle_worker()
            if worker is not None:
                forwarded = copy.deepcopy(request_obj)
                forwarded.setdefault("params", {})["arguments"] = arguments
                try:
                    return sup.forward_raw(worker, forwarded)
                except WorkerCrashedError as e:
                    diag = sup.handle_worker_crash(e.worker, action=f"tool '{tool_name}'")
                    return _jsonrpc_result(request_id, _call_tool_result(diag, is_error=True))
                except Exception as e:
                    return _jsonrpc_result(request_id, _call_tool_result({"error": str(e)}, is_error=True))
            return _jsonrpc_result(request_id, _call_tool_result({"error": "No worker available for file-analysis tool. Open a session first."}, is_error=True))

    try:
        session = sup.resolve_session(database)
    except Exception as e:
        return _jsonrpc_result(request_id, _call_tool_result({"error": str(e)}, is_error=True))

    # Gate non-management tools while a background analysis occupies the worker's
    # single thread — otherwise the call silently blocks on the pipe for the
    # whole analysis. Give the agent a fast, clear "poll the task" instead.
    analysis_task = sup._active_analysis_task_for(session.session_id)
    if analysis_task is not None:
        return _jsonrpc_result(request_id, _call_tool_result({
            "error": "analysis_in_progress",
            "error_type": "AnalysisInProgress",
            "message": (
                f"Database '{session.session_id}' is being analyzed in the background. "
                f"Tools are blocked until it finishes — poll idalib_task_poll('{analysis_task}') "
                "until status='done', then retry."
            ),
            "task_id": analysis_task,
        }, is_error=True))

    forwarded = copy.deepcopy(request_obj)
    forwarded.setdefault("params", {})["arguments"] = arguments
    try:
        return sup.forward_raw(session, forwarded)
    except WorkerCrashedError as e:
        diag = sup.handle_worker_crash(e.worker, action=f"tool '{tool_name}'")
        return _jsonrpc_result(request_id, _call_tool_result(diag, is_error=True))
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
    except WorkerCrashedError as e:
        sup.handle_worker_crash(e.worker, action="a resource read")
        return _jsonrpc_error(request_obj.get("id"), -32001, "worker_crashed: the idalib worker died; reopen the database")
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

    sup = _require_supervisor()
    try:
        session = sup.resolve_session(None)
    except Exception as e:
        return _jsonrpc_error(request_obj.get("id"), -32001, str(e))
    try:
        return sup.forward_raw(session, request_obj)
    except WorkerCrashedError as e:
        sup.handle_worker_crash(e.worker, action="an operation")
        return _jsonrpc_error(request_obj.get("id"), -32001, "worker_crashed: the idalib worker died; reopen the database")
    except Exception as e:
        return _jsonrpc_error(request_obj.get("id"), -32001, str(e))


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

    # Kill a stale prior supervisor + its workers (the multi-daemon root cause),
    # then recover from any crash that left leaked workers holding .i64 locks.
    try:
        _enforce_supervisor_singleton()
    except Exception:
        logger.debug("Supervisor singleton enforcement failed", exc_info=True)
    try:
        _sweep_orphan_workers(protected_pids=set())
    except Exception:
        logger.debug("Startup orphan-worker sweep failed", exc_info=True)

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
