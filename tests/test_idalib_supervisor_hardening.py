"""Gate tests for the idalib heavy-IDB hardening (2026-06-06).

These exercise the *real* supervisor RPC path (unlike test_idalib_supervisor.py,
which stubs ``_worker_rpc``), plus the new memory precheck and IDB helpers. No
IDA/idalib is required — workers are simulated with real OS pipes so the blocking
``readline`` / deadline / worker-death semantics match production exactly.

Run:  uv run pytest tests/test_idalib_supervisor_hardening.py -q

The IDA-dependent half (.i64 reopen, stale-lock sweep, real worker load) cannot
run without IDA + a saved IDB; see devdocs/idalib-heavy-idb-gate-tests.md for the
agent-driven checklist that covers it.
"""

import itertools
import json
import os
import threading
import time
from pathlib import Path

import pytest

from ida_pro_mcp import idalib_supervisor as supmod
from ida_pro_mcp.idalib_supervisor import IdalibSupervisor


_pid_counter = itertools.count(start=90000)


class _FakeWorkerProc:
    """Stand-in for subprocess.Popen with controllable liveness."""

    def __init__(self, pid: int):
        self.pid = pid
        self._alive = True
        self.returncode = None

    def poll(self):
        return None if self._alive else (self.returncode if self.returncode is not None else 0)

    def terminate(self):
        self._alive = False
        self.returncode = 0

    def kill(self):
        self._alive = False
        self.returncode = -9

    def wait(self, timeout=None):
        return self.returncode if self.returncode is not None else 0


class _FakeWorker:
    """A WorkerSession backed by real OS pipes and a controllable responder.

    mode="echo"   -> replies to every request with {"echo": <method>}
    mode="hang"   -> reads requests but never replies (simulates a wedged worker)
    """

    def __init__(self, mode: str = "echo"):
        r_out, w_out = os.pipe()  # supervisor reads worker stdout
        r_in, w_in = os.pipe()    # supervisor writes worker stdin
        self._sup_stdout = os.fdopen(r_out, "rb")
        self._sup_stdin = os.fdopen(w_in, "wb")
        self._worker_read = os.fdopen(r_in, "rb")
        self._worker_write = os.fdopen(w_out, "wb")
        self.proc = _FakeWorkerProc(next(_pid_counter))
        self.mode = mode
        self._stop = False
        self.session = supmod.WorkerSession(
            session_id="fake",
            input_path="",
            filename="",
            process=self.proc,
            backend="worker",
            owned=True,
            pid=self.proc.pid,
            stdin=self._sup_stdin,
            stdout=self._sup_stdout,
        )
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def copy_session(self, session_id: str = "copy") -> supmod.WorkerSession:
        """A second WorkerSession wrapping the SAME process (like lief-only)."""
        return supmod.WorkerSession(
            session_id=session_id,
            input_path="",
            filename="",
            process=self.proc,
            backend="worker",
            owned=True,
            pid=self.proc.pid,
            stdin=self._sup_stdin,
            stdout=self._sup_stdout,
        )

    def _run(self):
        while not self._stop:
            try:
                line = self._worker_read.readline()
            except Exception:
                break
            if not line:
                break
            if self.mode == "hang":
                continue
            try:
                msg = json.loads(line.decode())
            except Exception:
                continue
            resp = {"jsonrpc": "2.0", "id": msg.get("id"), "result": {"echo": msg.get("method")}}
            try:
                self._worker_write.write((json.dumps(resp) + "\n").encode())
                self._worker_write.flush()
            except Exception:
                break

    def die(self):
        """Simulate a force-kill: process dead + stdout EOF."""
        self.proc.kill()
        self._stop = True
        try:
            self._worker_write.close()
        except Exception:
            pass

    def close(self):
        self._stop = True
        for f in (self._worker_write, self._sup_stdin, self._sup_stdout, self._worker_read):
            try:
                f.close()
            except Exception:
                pass


@pytest.fixture
def supervisor():
    sup = IdalibSupervisor(supmod.McpServer("test"))
    yield sup
    sup.shutdown()


# ---------------------------------------------------------------------------
# Core hang fix: bounded, worker-death-aware RPC over real pipes
# ---------------------------------------------------------------------------

def test_worker_rpc_roundtrip(supervisor):
    fw = _FakeWorker("echo")
    try:
        resp = supervisor._worker_rpc(fw.session, {"jsonrpc": "2.0", "method": "ping"}, timeout=5)
        assert resp["result"]["echo"] == "ping"
    finally:
        fw.close()


def test_worker_rpc_times_out_on_silent_worker(supervisor):
    """REGRESSION: a worker that goes silent must NOT block the caller forever.

    This is the exact failure from IDALIB_HEAVY_IDB_REPORT — the old blocking
    readline ignored the deadline. The call must raise TimeoutError promptly.
    """
    fw = _FakeWorker("hang")
    try:
        start = time.monotonic()
        with pytest.raises(TimeoutError):
            supervisor._worker_rpc(fw.session, {"jsonrpc": "2.0", "method": "ping"}, timeout=1.0)
        elapsed = time.monotonic() - start
        assert elapsed < 3.0, f"timeout took {elapsed:.1f}s — deadline not honored"
    finally:
        fw.die()
        fw.close()


def test_worker_rpc_detects_worker_death(supervisor):
    """A worker killed mid-call must wake the waiter with an error, not hang."""
    fw = _FakeWorker("hang")
    result: dict = {}

    def call():
        try:
            supervisor._worker_rpc(fw.session, {"jsonrpc": "2.0", "method": "ping"}, timeout=30)
        except Exception as e:  # noqa: BLE001
            result["err"] = e

    t = threading.Thread(target=call)
    t.start()
    time.sleep(0.3)  # let the call block in the wait loop
    fw.die()
    t.join(timeout=5)
    assert not t.is_alive(), "caller did not wake after worker death"
    assert isinstance(result.get("err"), RuntimeError)
    fw.close()


def test_shared_channel_across_worker_copies(supervisor):
    """Two WorkerSessions over one process share ONE channel + ONE reader.

    Guards the lief-only session, which piggybacks the schema worker's pipe.
    """
    fw = _FakeWorker("echo")
    try:
        copy = fw.copy_session()
        chan1 = supervisor._get_channel(fw.session)
        chan2 = supervisor._get_channel(copy)
        assert chan1 is chan2

        r1 = supervisor._worker_rpc(fw.session, {"jsonrpc": "2.0", "method": "a"}, timeout=5)
        r2 = supervisor._worker_rpc(copy, {"jsonrpc": "2.0", "method": "b"}, timeout=5)
        assert r1["result"]["echo"] == "a"
        assert r2["result"]["echo"] == "b"

        readers = [t for t in threading.enumerate() if t.name == f"worker-reader-{fw.proc.pid}"]
        assert len(readers) == 1, f"expected exactly one reader, found {len(readers)}"
    finally:
        fw.close()


def test_concurrent_rpc_id_routing(supervisor):
    """Many concurrent RPCs on one worker each get their own correlated reply."""
    fw = _FakeWorker("echo")
    errors: list = []

    def call(method):
        try:
            r = supervisor._worker_rpc(fw.session, {"jsonrpc": "2.0", "method": method}, timeout=10)
            if r["result"]["echo"] != method:
                errors.append((method, r))
        except Exception as e:  # noqa: BLE001
            errors.append((method, e))

    threads = [threading.Thread(target=call, args=(f"m{i}",)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=15)
    try:
        assert not errors, errors
    finally:
        fw.close()


# ---------------------------------------------------------------------------
# IDB detection + memory estimate helpers
# ---------------------------------------------------------------------------

def test_is_idb_path():
    assert supmod._is_idb_path(Path("x.i64"))
    assert supmod._is_idb_path(Path("x.idb"))
    assert supmod._is_idb_path(Path("sample.dll.i64"))  # multi-dot name
    assert not supmod._is_idb_path(Path("x.dll"))
    assert not supmod._is_idb_path(Path("x.exe"))


def test_memory_estimate_idb_vs_raw_and_scaling():
    idb = supmod._estimate_required_memory_mb(4000, True)
    raw = supmod._estimate_required_memory_mb(4000, False)
    assert idb > 4000          # at least the IDB size + baseline
    assert raw > idb           # raw auto-analysis estimate is larger
    assert supmod._estimate_required_memory_mb(8000, True) > idb  # scales with size


def test_available_memory_is_sane():
    mb = supmod._available_memory_mb()
    assert mb is None or mb > 0


# ---------------------------------------------------------------------------
# Memory precheck wired into idalib_open
# ---------------------------------------------------------------------------

def test_idalib_open_blocks_when_memory_insufficient(tmp_path, monkeypatch):
    f = tmp_path / "small.bin"
    f.write_bytes(b"x" * 1024)
    sup = IdalibSupervisor(supmod.McpServer("test"))
    monkeypatch.setattr(supmod, "supervisor", sup)
    monkeypatch.setattr(supmod, "_available_memory_mb", lambda: 1.0)
    try:
        res = supmod.idalib_open(str(f), mode="full")
        assert res.get("error") == "insufficient_memory"
        assert res["required_mb"] > res["available_mb"]
        assert "force=true" in res["recommendation"]
    finally:
        sup.shutdown()


def test_idalib_open_force_bypasses_memory_check(tmp_path, monkeypatch):
    f = tmp_path / "small.bin"
    f.write_bytes(b"x" * 1024)
    sup = IdalibSupervisor(supmod.McpServer("test"))
    fake_session = supmod.WorkerSession(
        session_id="s", input_path=str(f), filename="small.bin",
        process=_FakeWorkerProc(next(_pid_counter)), pid=1,
    )
    monkeypatch.setattr(sup, "open_session", lambda *a, **k: fake_session)
    monkeypatch.setattr(supmod, "supervisor", sup)
    monkeypatch.setattr(supmod, "_available_memory_mb", lambda: 1.0)
    try:
        res = supmod.idalib_open(str(f), mode="full", force=True)
        assert res.get("error") != "insufficient_memory"
        assert res.get("success") is True
    finally:
        sup.shutdown()
