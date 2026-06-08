import logging
import queue
import functools
import os
import sys
import threading
import time
import idaapi
import idc
from .rpc import McpToolError
from .zeromcp.jsonrpc import get_current_cancel_event, RequestCancelledError

# ============================================================================
# IDA Synchronization & Error Handling
# ============================================================================

# Lazily-computed IDA kernel version.  Computing it at import time fails on
# IDA 9.3+ because get_kernel_version() may only be called from the main IDA
# thread (via execute_sync).  The HTTP server's accept thread imports this
# module before any tool request arrives, so we defer the call.
_ida_version_cache: tuple[int, int] | None = None


def _get_ida_version() -> tuple[int, int]:
    global _ida_version_cache
    if _ida_version_cache is None:
        _ida_version_cache = tuple(map(int, idaapi.get_kernel_version().split(".")))
    return _ida_version_cache


ida_major: int
ida_minor: int

_version_initialized = False


def _ensure_version() -> None:
    """Ensure ida_major/ida_minor are populated. Safe to call from any thread."""
    global _version_initialized
    if not _version_initialized:
        maj, min_ = _get_ida_version()
        globals()["ida_major"] = maj
        globals()["ida_minor"] = min_
        _version_initialized = True


class _VersionShim:
    """Shim that defers ida_major/ida_minor resolution until first access."""

    def __get__(self, obj, objtype=None) -> tuple[int, int]:
        _ensure_version()
        return (ida_major, ida_minor)


def __getattr__(name: str):
    """Module-level __getattr__ to handle ida_major/ida_minor shim until initialized."""
    if name in ("ida_major", "ida_minor"):
        _ensure_version()
        return globals()[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


class IDAError(McpToolError):
    def __init__(self, message: str):
        super().__init__(message)

    @property
    def message(self) -> str:
        return self.args[0]


class IDASyncError(Exception):
    pass


class CancelledError(RequestCancelledError):
    """Raised when a request is cancelled via notifications/cancelled."""

    pass


logger = logging.getLogger(__name__)
_TOOL_TIMEOUT_ENV = "IDA_MCP_TOOL_TIMEOUT_SEC"
_DEFAULT_TOOL_TIMEOUT_SEC = 60.0


def _get_tool_timeout_seconds() -> float:
    value = os.getenv(_TOOL_TIMEOUT_ENV, "").strip()
    if value == "":
        return _DEFAULT_TOOL_TIMEOUT_SEC
    try:
        return float(value)
    except ValueError:
        return _DEFAULT_TOOL_TIMEOUT_SEC


call_stack = queue.LifoQueue()

# Thread-local: while a synchronized tool body is running, holds the batch
# value that was in effect *before* the sync wrapper bumped it to 1. Tools
# decorated with @keep_batch read this via get_pre_call_batch() so they can
# restore the caller's original state — not assume a hard-coded default.
_sync_state = threading.local()


def get_pre_call_batch() -> int | None:
    """Return the pre-call batch state, or None if not inside a sync body.

    Only meaningful inside a @idasync function body — outside of that the
    sync wrapper isn't tracking anything. Tools using @keep_batch should
    read this and pass it to whatever asynchronous restorer they install,
    so the original batch state is preserved across the deferred work.
    """
    return getattr(_sync_state, "pre_call_batch", None)


def _sync_wrapper(ff, keep_batch=False):
    """Call a function ff with a specific IDA safety_mode.

    If keep_batch=True and ff() returns successfully, batch mode is left on
    after the wrapper exits. The decorated function is responsible for
    arranging restoration (typically via a DBG_Hooks callback) so that any
    asynchronous work scheduled by ff() — e.g. start_process triggering a
    "matching executable names" dialog after we exit execute_sync — runs
    while batch mode is still on. On exception, batch mode is always
    restored before re-raising.

    The pre-call batch state is exposed to ff() via get_pre_call_batch()
    so tools can capture it (typically at hook-install time) and restore
    the caller's original state instead of hard-coding a default.
    """

    res_container = queue.Queue()

    def runned():
        if not call_stack.empty():
            # Non-blocking: a concurrent reentrant @idasync call from
            # within another tool's ff() on the same main thread may
            # have drained the queue between empty() and get().
            try:
                last_func_name = call_stack.get_nowait()
            except queue.Empty:
                last_func_name = "<empty>"
            error_str = f"Call stack is not empty while calling the function {ff.__name__} from {last_func_name}"
            raise IDASyncError(error_str)

        call_stack.put((ff.__name__))
        # Enable batch mode for all synchronized operations
        old_batch = idc.batch(1)
        prev_pre_call = getattr(_sync_state, "pre_call_batch", None)
        _sync_state.pre_call_batch = old_batch
        completed = False
        try:
            res_container.put(ff())
            completed = True
        except Exception as x:
            res_container.put(x)
        finally:
            if not (completed and keep_batch):
                idc.batch(old_batch)
            _sync_state.pre_call_batch = prev_pre_call
            # Non-blocking: a reentrant @idasync invoked synchronously
            # inside ff() may have already popped our entry. Default
            # block=True would freeze the IDA main thread on an empty
            # queue and hang every subsequent @idasync call.
            try:
                call_stack.get_nowait()
            except queue.Empty:
                pass

    if _idalib_executor is not None:
        # Headless idalib mode: dispatch through the MainThreadExecutor instead
        # of idaapi.execute_sync().  The main thread is free (running
        # executor.run_forever()), so the submit picks up the work
        # immediately on the main OS thread.
        submit = getattr(_idalib_executor, "submit")
        submit(runned)
    else:
        idaapi.execute_sync(runned, idaapi.MFF_WRITE)
    res = res_container.get()
    if isinstance(res, Exception):
        raise res
    return res


# ── idalib executor integration ──────────────────────────────────────────────
# In headless idalib mode, the MCP stdio server runs on a background thread and
# the main OS thread is idled so it can service execute_sync() requests.  The
# idalib server's MainThreadExecutor is registered here at startup.  When set,
# all @idasync calls dispatch through it instead of using the native
# idaapi.execute_sync(), which would block forever because the main thread is
# occupied by the stdio read loop.

_idalib_executor: object | None = None


def _set_executor(executor: object) -> None:
    """Register a MainThreadExecutor for headless idalib mode."""
    global _idalib_executor  # noqa: PLW0603
    _idalib_executor = executor


def _normalize_timeout(value: object) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def sync_wrapper(
    ff, timeout_override: float | None = None, keep_batch: bool = False
):
    """Wrapper to enable timeout and cancellation during IDA synchronization.

    Note: Batch mode is now handled in _sync_wrapper to ensure it's always
    applied consistently for all synchronized operations. Pass keep_batch=True
    to opt out of the post-call batch restore (see _sync_wrapper docstring).
    """
    # Capture cancel event from thread-local before execute_sync
    cancel_event = get_current_cancel_event()

    timeout = timeout_override
    if timeout is None:
        timeout = _get_tool_timeout_seconds()
    if timeout > 0 or cancel_event is not None:

        def timed_ff():
            # Calculate deadline when execution starts on IDA main thread,
            # not when the request was queued (avoids stale deadlines)
            deadline = time.monotonic() + timeout if timeout > 0 else None

            def profilefunc(frame, event, arg):
                # Check cancellation first (higher priority)
                if cancel_event is not None and cancel_event.is_set():
                    raise CancelledError("Request was cancelled")
                if deadline is not None and time.monotonic() >= deadline:
                    raise IDASyncError(f"Tool timed out after {timeout:.2f}s")

            old_profile = sys.getprofile()
            sys.setprofile(profilefunc)
            try:
                return ff()
            finally:
                sys.setprofile(old_profile)

        timed_ff.__name__ = ff.__name__
        return _sync_wrapper(timed_ff, keep_batch=keep_batch)
    return _sync_wrapper(ff, keep_batch=keep_batch)


def idasync(f):
    """Run the function on the IDA main thread in write mode.

    This is the unified decorator for all IDA synchronization.
    Previously there were separate @idaread and @idawrite decorators,
    but since read-only operations in IDA might actually require write
    access (e.g., decompilation), we now use a single decorator.
    """

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        ff = functools.partial(f, *args, **kwargs)
        ff.__name__ = f.__name__
        timeout_override = _normalize_timeout(
            getattr(f, "__ida_mcp_timeout_sec__", None)
        )
        keep_batch = bool(getattr(f, "__ida_mcp_keep_batch__", False))
        return sync_wrapper(ff, timeout_override, keep_batch=keep_batch)

    return wrapper


def tool_timeout(seconds: float, prefer_async: bool = False):
    """Decorator to override per-tool timeout (seconds) and optionally auto-async.

    IMPORTANT: Must be applied BEFORE @idasync (i.e., listed AFTER it)
    so the attribute exists when it captures the function in closure.

    Correct order:
        @tool
        @idasync
        @tool_timeout(90.0, prefer_async=True)  # innermost
        def my_func(...):

    When prefer_async=True, the tools/call dispatcher in rpc.py automatically
    submits the tool as a background task instead of executing synchronously.
    The caller immediately receives a task_id and polls with task_poll().
    This eliminates the trial-and-error loop where agents must discover which
    tools are slow enough to need task_submit.
    """

    def decorator(func):
        setattr(func, "__ida_mcp_timeout_sec__", seconds)
        if prefer_async:
            setattr(func, "__ida_mcp_prefer_async__", True)
        return func

    return decorator


def keep_batch(func):
    """Decorator to skip the sync wrapper's post-call batch-mode restore.

    Apply when the tool schedules asynchronous work that runs on the IDA
    main thread *after* execute_sync exits (e.g. start_process, which
    triggers the "matching executable names" dialog later). The decorated
    function MUST arrange batch-mode restoration itself, typically via a
    DBG_Hooks callback that fires once the asynchronous work has completed,
    so batch mode is not left on indefinitely.

    Same ordering rule as tool_timeout: place AFTER @idasync (innermost).

        @tool
        @idasync
        @keep_batch
        def my_func(...):
    """

    setattr(func, "__ida_mcp_keep_batch__", True)
    return func


def is_window_active():
    """Returns whether IDA is currently active."""
    # Source: https://github.com/OALabs/hexcopy-ida/blob/8b0b2a3021d7dc9010c01821b65a80c47d491b61/hexcopy.py#L30
    # Use _ida_version_shim to avoid eagerly calling get_kernel_version() from the HTTP accept thread
    maj, min_ = _ida_version_shim
    using_pyside6 = (maj > 9) or (maj == 9 and min_ >= 2)

    if using_pyside6:
        from PySide6 import QtWidgets
    else:
        from PyQt5 import QtWidgets

    app = QtWidgets.QApplication.instance()
    if app is None:
        return False
    return app.activeWindow() is not None
