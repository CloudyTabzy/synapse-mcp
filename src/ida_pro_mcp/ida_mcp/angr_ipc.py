"""angr_ipc — parent-side supervisor for the out-of-process angr worker.

Runs angr in a dedicated **child process** so it never touches IDA's process:

  * IDA's main thread is never blocked by angr's GIL-holding native code.
  * A runaway computation is force-killed on timeout (``proc.kill()``) — a thing
    a Python thread stuck in native code can never be.
  * Only plain dicts cross the boundary, so the ``_cffi_backend._CDataBase``
    pickle error that broke V2 is impossible by construction.

Transport: ``subprocess.Popen`` + a localhost TCP socket with length-prefixed
pickle framing (``angr_worker.send_msg``/``recv_msg``). We deliberately avoid
``multiprocessing`` because in an embedded interpreter (IDA) its spawn machinery
is unreliable — ``sys.executable`` is ``ida.exe``, the semaphore tracker and
``__main__`` re-import don't behave, etc. Popen + socket gives us:

  * Explicit control of WHICH python runs the child (never relaunches IDA).
  * The child loaded from angr_worker.py BY PATH, so no package import, no
    sys.path pollution, no http.py shadowing.
  * A socket whose EOF tells the child the parent died → the worker self-exits,
    so it never lingers in the background after IDA closes.

Reliability properties (verify against this list when inspecting):
  1. Lazy, single-flight spawn guarded by a lock; auto-respawn if the child died.
  2. accept()/handshake are bounded by timeouts — a child that never connects
     can't hang IDA; it's killed and reported.
  3. Every request has a wall-clock recv timeout; on expiry the child is killed
     and respawned, and a structured ``timeout`` error is returned.
  4. Authkey handshake rejects stray localhost connections.
  5. The listen socket binds to 127.0.0.1 only and is closed right after accept.
  6. shutdown()/atexit kill the child; socket EOF is the backstop watchdog.
"""
from __future__ import annotations

import logging
import os
import secrets
import socket
import subprocess
import sys
import threading

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = 120.0
_SPAWN_TIMEOUT = 30.0       # seconds to wait for the child to connect back
_HANDSHAKE_TIMEOUT = 10.0   # seconds to wait for the authkey message

# The child bootstrap loads angr_worker.py BY PATH (no package import) and hands
# control to connect_and_serve. Kept as a one-liner so -c parsing is trivial.
_BOOTSTRAP = (
    "import os,importlib.util as u;"
    "p=os.environ['ANGR_WORKER_PATH'];"
    "s=u.spec_from_file_location('angr_worker',p);"
    "m=u.module_from_spec(s);s.loader.exec_module(m);"
    "m.connect_and_serve(os.environ['ANGR_WORKER_HOST'],"
    "os.environ['ANGR_WORKER_PORT'],os.environ['ANGR_WORKER_AUTHKEY'])"
)


def _find_python_executable() -> str | None:
    """Discover a real python.exe to host the child.

    Inside IDA sys.executable is ida.exe, so we must look harder: a python-named
    current executable, sys._base_executable, python next to (base_)prefix, then
    PATH.
    """
    candidates: list[str] = []
    exe = sys.executable or ""
    if os.path.basename(exe).lower().startswith("python"):
        candidates.append(exe)
    base_exe = getattr(sys, "_base_executable", "") or ""
    if base_exe:
        candidates.append(base_exe)
    for prefix in (getattr(sys, "base_prefix", ""), sys.prefix):
        if not prefix:
            continue
        for name in ("python.exe", "python3.exe", "python"):
            candidates.append(os.path.join(prefix, name))
            candidates.append(os.path.join(prefix, "bin", name))
    import shutil
    for name in ("python3", "python"):
        found = shutil.which(name)
        if found:
            candidates.append(found)
    seen: set[str] = set()
    for c in candidates:
        if not c or c in seen:
            continue
        seen.add(c)
        if os.path.exists(c) and "python" in os.path.basename(c).lower():
            return c
    return None


def _worker_script_path() -> str:
    from . import angr_worker
    return os.path.abspath(angr_worker.__file__)


def _worker_log_path() -> str:
    import tempfile
    return os.path.join(tempfile.gettempdir(), "synapse_angr_worker.log")


class AngrWorker:
    """Lazily-spawned, auto-restarting supervisor for one angr child process."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._proc: subprocess.Popen | None = None
        self._conn: socket.socket | None = None
        self._authkey: str = ""
        self._req_id = 0
        self._spawn_error: str | None = None
        self._log = None

    # -- lifecycle ---------------------------------------------------------

    def _start_locked(self) -> bool:
        """Spawn the child and complete the handshake. Caller holds the lock."""
        from . import angr_worker  # for send_msg/recv_msg framing

        py = _find_python_executable()
        if py is None:
            self._spawn_error = (
                "No python.exe found to host the angr worker. angr tools require "
                "an out-of-process worker; set one on PATH or in the IDA prefix."
            )
            logger.error(self._spawn_error)
            return False

        worker_path = _worker_script_path()
        if not os.path.exists(worker_path):
            self._spawn_error = f"angr_worker.py not found at {worker_path!r}"
            logger.error(self._spawn_error)
            return False

        # Bind a loopback-only listener on an ephemeral port and wait (bounded)
        # for the child to connect back.
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            srv.bind(("127.0.0.1", 0))
            srv.listen(1)
            srv.settimeout(_SPAWN_TIMEOUT)
            host, port = srv.getsockname()[0], srv.getsockname()[1]

            authkey = secrets.token_hex(16)
            env = os.environ.copy()
            env["ANGR_WORKER_PATH"] = worker_path
            env["ANGR_WORKER_HOST"] = host
            env["ANGR_WORKER_PORT"] = str(port)
            env["ANGR_WORKER_AUTHKEY"] = authkey

            creationflags = 0
            if os.name == "nt":
                creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)

            try:
                self._log = open(_worker_log_path(), "ab", buffering=0)
            except Exception:
                self._log = None
            stdio = self._log if self._log is not None else subprocess.DEVNULL

            try:
                proc = subprocess.Popen(
                    [py, "-c", _BOOTSTRAP],
                    env=env,
                    stdin=subprocess.DEVNULL,
                    stdout=stdio,
                    stderr=stdio,
                    creationflags=creationflags,
                    close_fds=True,
                )
            except Exception as e:
                self._spawn_error = f"Failed to launch angr worker process: {e}"
                logger.error(self._spawn_error)
                return False

            try:
                conn, _addr = srv.accept()
            except socket.timeout:
                self._spawn_error = (
                    f"angr worker did not connect back within {_SPAWN_TIMEOUT:.0f}s "
                    f"(see {_worker_log_path()})."
                )
                logger.error(self._spawn_error)
                self._terminate_proc(proc)
                return False
        finally:
            try:
                srv.close()
            except Exception:
                pass

        # Authenticate the connection.
        conn.settimeout(_HANDSHAKE_TIMEOUT)
        try:
            hello = angr_worker.recv_msg(conn)
        except Exception:
            hello = None
        if not isinstance(hello, dict) or hello.get("authkey") != authkey:
            self._spawn_error = "angr worker failed authkey handshake."
            logger.error(self._spawn_error)
            try:
                conn.close()
            except Exception:
                pass
            self._terminate_proc(proc)
            return False
        conn.settimeout(None)

        self._proc = proc
        self._conn = conn
        self._authkey = authkey
        self._spawn_error = None
        logger.info("angr worker started (pid=%s, port=%s)", proc.pid, port)
        return True

    def _is_alive(self) -> bool:
        return (
            self._proc is not None
            and self._proc.poll() is None
            and self._conn is not None
        )

    @staticmethod
    def _terminate_proc(proc: subprocess.Popen | None) -> None:
        if proc is None:
            return
        try:
            proc.kill()
        except Exception:
            pass
        try:
            proc.wait(timeout=3.0)
        except Exception:
            pass

    def _kill_locked(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:
                pass
        self._terminate_proc(self._proc)
        if self._log is not None:
            try:
                self._log.close()
            except Exception:
                pass
        self._proc = None
        self._conn = None
        self._log = None

    # -- request -----------------------------------------------------------

    def request(self, op: str, payload: dict | None = None,
                timeout: float = _DEFAULT_TIMEOUT) -> dict:
        """Send one op to the worker and return its result dict.

        On timeout the worker is force-killed (and respawns on the next call),
        guaranteeing IDA is never held hostage by a runaway angr computation.
        """
        from . import angr_worker

        with self._lock:
            if not self._is_alive():
                self._kill_locked()
                if not self._start_locked():
                    return {
                        "ok": False,
                        "error": self._spawn_error or "angr worker unavailable",
                        "error_type": "internal_error",
                        "hint": ("The out-of-process angr worker could not start. "
                                 f"Worker log: {_worker_log_path()}"),
                    }

            self._req_id += 1
            req_id = self._req_id

            try:
                self._conn.settimeout(None)
                angr_worker.send_msg(self._conn, {"op": op, "req_id": req_id,
                                                  "payload": payload or {}})
            except Exception as e:
                self._kill_locked()
                return {"ok": False, "error": f"worker send failed: {e}",
                        "error_type": "internal_error",
                        "hint": "The angr worker died; it will respawn on retry."}

            try:
                self._conn.settimeout(timeout if timeout and timeout > 0 else None)
                msg = angr_worker.recv_msg(self._conn)
            except socket.timeout:
                self._kill_locked()
                return {
                    "ok": False,
                    "error": f"angr operation timed out after {timeout:.0f}s",
                    "error_type": "timeout",
                    "hint": ("Worker killed to keep IDA responsive. Retry with a "
                             "larger timeout / tighter char_constraint / smaller "
                             "input_size, or submit via task_submit and poll."),
                }
            except Exception as e:
                self._kill_locked()
                return {"ok": False, "error": f"worker recv failed: {e}",
                        "error_type": "internal_error",
                        "hint": "The angr worker died mid-operation; it will respawn."}
            finally:
                try:
                    if self._conn is not None:
                        self._conn.settimeout(None)
                except Exception:
                    pass

            if msg is None:
                self._kill_locked()
                return {"ok": False, "error": "angr worker closed the connection",
                        "error_type": "internal_error",
                        "hint": "The worker exited unexpectedly; it will respawn."}
            if not isinstance(msg, dict):
                return {"ok": False, "error": "malformed worker response",
                        "error_type": "internal_error"}
            return msg.get("result") or {"ok": False, "error": "empty worker result",
                                         "error_type": "internal_error"}

    def ping(self, timeout: float = 15.0) -> dict:
        """Health check: confirms the process spawned and the socket works,
        without paying angr's import cost."""
        return self.request("__ping__", {}, timeout=timeout)

    def shutdown(self) -> None:
        with self._lock:
            if self._is_alive():
                try:
                    from . import angr_worker
                    angr_worker.send_msg(self._conn, {"op": "__shutdown__"})
                except Exception:
                    pass
            self._kill_locked()


# Module-global singleton + registration for clean process exit.
_WORKER: AngrWorker | None = None
_WORKER_LOCK = threading.Lock()


def get_worker() -> AngrWorker:
    global _WORKER
    with _WORKER_LOCK:
        if _WORKER is None:
            _WORKER = AngrWorker()
            import atexit
            atexit.register(_WORKER.shutdown)
        return _WORKER
