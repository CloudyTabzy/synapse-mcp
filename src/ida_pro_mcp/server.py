import argparse
import atexit
import copy
import http.client
import json
import os
import re
import signal
import socket
import sys
import tempfile
import threading
import time
import traceback
from collections import OrderedDict
from typing import Annotated, TYPE_CHECKING, TypedDict
from urllib.parse import parse_qs, urlparse

try:
    from .ida_mcp.toon_encode import (
        TOON_AVAILABLE as _TOON_AVAILABLE,
        TOON_ENABLED as _TOON_ENABLED,
        TOON_MIN_ROWS as _TOON_MIN_ROWS,
        maybe_toon_encode_result as _maybe_toon_encode_result,
    )
except ImportError:
    try:
        from ida_mcp.toon_encode import (
            TOON_AVAILABLE as _TOON_AVAILABLE,
            TOON_ENABLED as _TOON_ENABLED,
            TOON_MIN_ROWS as _TOON_MIN_ROWS,
            maybe_toon_encode_result as _maybe_toon_encode_result,
        )
    except ImportError:
        _TOON_AVAILABLE = False
        _TOON_ENABLED = False
        _TOON_MIN_ROWS = 20
        def _maybe_toon_encode_result(_data):
            return None

if TYPE_CHECKING:
    from ida_pro_mcp.ida_mcp.zeromcp import (
        EXTERNAL_BASE_HEADER,
        McpHttpRequestHandler,
        McpServer,
        get_current_request_external_base_url,
    )
    from ida_pro_mcp.ida_mcp.zeromcp.jsonrpc import JsonRpcRequest, JsonRpcResponse
else:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "ida_mcp"))
    from zeromcp import (
        EXTERNAL_BASE_HEADER,
        McpHttpRequestHandler,
        McpServer,
        get_current_request_external_base_url,
    )
    from zeromcp.jsonrpc import JsonRpcRequest, JsonRpcResponse

    sys.path.pop(0)

try:
    from .installer import (
        list_available_clients,
        print_mcp_config,
        run_install_command,
        run_install_deps_command,
        set_ida_rpc,
    )
except ImportError:
    from installer import (
        list_available_clients,
        print_mcp_config,
        run_install_command,
        run_install_deps_command,
        set_ida_rpc,
    )

try:
    from .ida_mcp.discovery import discover_instances, probe_instance
except ImportError:
    try:
        from ida_mcp.discovery import discover_instances, probe_instance
    except ImportError:
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "ida_mcp"))
        from discovery import discover_instances, probe_instance

        sys.path.pop(0)

try:
    from .ida_mcp.cross_ref import run_compare_instances, run_invoke_on_instance
except ImportError:
    try:
        from ida_mcp.cross_ref import run_compare_instances, run_invoke_on_instance
    except ImportError:
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "ida_mcp"))
        from cross_ref import run_compare_instances, run_invoke_on_instance

        sys.path.pop(0)

try:
    from .ida_mcp.rpc import MCP_SERVER_NAME, get_tool_group
except ImportError:
    try:
        from ida_mcp.rpc import MCP_SERVER_NAME, get_tool_group
    except ImportError:
        MCP_SERVER_NAME = "synapse-mcp"
        def get_tool_group(name: str) -> str:
            return "core"

class ProxyInstanceInfo(TypedDict, total=False):
    host: str
    port: int
    pid: int
    binary: str
    idb_path: str
    started_at: str
    reachable: bool
    active: bool


class ProxySelectResult(TypedDict, total=False):
    success: bool
    host: str
    port: int
    message: str
    error: str


DEFAULT_IDA_HOST = "127.0.0.1"
DEFAULT_IDA_PORT = 13337
IDA_HOST = DEFAULT_IDA_HOST
IDA_PORT = DEFAULT_IDA_PORT

# ---------------------------------------------------------------------------
# Proxy singleton lock file — prevents zombie proxy accumulation across
# session restarts. On startup, any stale proxy holding the same lock is
# killed before this process claims the lock. Cleaned up on normal exit.
# ---------------------------------------------------------------------------
_PROXY_LOCK_PATH = os.path.join(tempfile.gettempdir(), "synapse-mcp-proxy.lock")
_PROXY_LOCK_FD = None


def _acquire_proxy_lock(port: int) -> bool:
    """Acquire the singleton proxy lock, killing any stale previous owner.
    
    Returns True if the lock was acquired (or if locking is unsupported).
    """
    global _PROXY_LOCK_FD
    try:
        # If a previous lock file exists, check if that process is still alive
        if os.path.exists(_PROXY_LOCK_PATH):
            try:
                with open(_PROXY_LOCK_PATH, "r") as f:
                    old_data = json.load(f)
                old_pid = old_data.get("pid", 0)
                old_port = old_data.get("port", 0)
                if old_pid and old_port == port:
                    try:
                        os.kill(old_pid, 0)
                        # Process is alive — kill it
                        print(
                            f"[MCP] Killing stale proxy PID {old_pid} (port {old_port})",
                            file=sys.stderr,
                        )
                        os.kill(old_pid, signal.SIGTERM)
                        time.sleep(0.5)
                    except OSError:
                        pass  # Already dead
            except (json.JSONDecodeError, KeyError, FileNotFoundError):
                pass  # Corrupt lock file — overwrite it

        _PROXY_LOCK_FD = open(_PROXY_LOCK_PATH, "w")
        json.dump({"pid": os.getpid(), "port": port, "started": time.time()}, _PROXY_LOCK_FD)
        _PROXY_LOCK_FD.flush()
        atexit.register(_release_proxy_lock)
        return True
    except OSError:
        return False  # Non-critical — don't block startup


def _release_proxy_lock() -> None:
    """Remove the proxy lock file on clean exit."""
    global _PROXY_LOCK_FD
    try:
        if _PROXY_LOCK_FD is not None:
            _PROXY_LOCK_FD.close()
            _PROXY_LOCK_FD = None
        if os.path.exists(_PROXY_LOCK_PATH):
            os.remove(_PROXY_LOCK_PATH)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Heartbeat thread — maintains a lightweight health-check connection to
# the IDA plugin. Detects dead connections before they waste agent time.
# ---------------------------------------------------------------------------
_HEARTBEAT_INTERVAL_SEC = 15.0
_HEARTBEAT_MAX_MISSED = 4
_heartbeat_thread: threading.Thread | None = None
_heartbeat_running = False
_heartbeat_alive = True  # default: assume alive (tests may not start heartbeat)
_heartbeat_last_ok = time.monotonic()  # set on module load so check_heartbeat works before start
_heartbeat_failures = 0
_heartbeat_lock = threading.Lock()
# Cache the last successful health payload so the proxy can compute adaptive
# timeouts without calling IDA on every dispatch.
_heartbeat_payload: dict | None = None


def _heartbeat_loop(host: str, port: int) -> None:
    """Background thread: ping IDA every _HEARTBEAT_INTERVAL_SEC seconds."""
    global _heartbeat_alive, _heartbeat_last_ok, _heartbeat_failures, _heartbeat_payload
    while _heartbeat_running:
        try:
            conn = http.client.HTTPConnection(host, port, timeout=5.0)
            conn.request("POST", "/mcp", json.dumps({
                "jsonrpc": "2.0", "id": "hb", "method": "server_health", "params": {}
            }), {"Content-Type": "application/json"})
            resp = conn.getresponse()
            body = resp.read()
            conn.close()
            if resp.status == 200 and b'"result"' in body:
                with _heartbeat_lock:
                    _heartbeat_alive = True
                    _heartbeat_last_ok = time.monotonic()
                    _heartbeat_failures = 0
                try:
                    parsed = json.loads(body.decode("utf-8"))
                    if isinstance(parsed.get("result"), dict):
                        _heartbeat_payload = parsed["result"]
                except Exception:
                    pass
            else:
                _record_heartbeat_failure()
        except Exception:
            _record_heartbeat_failure()
        time.sleep(_HEARTBEAT_INTERVAL_SEC)


def _record_heartbeat_failure() -> None:
    global _heartbeat_failures, _heartbeat_alive
    with _heartbeat_lock:
        _heartbeat_failures += 1
        if _heartbeat_failures >= _HEARTBEAT_MAX_MISSED:
            _heartbeat_alive = False
            # Try reconnection before giving up entirely
            _try_reconnect()

def _try_reconnect() -> bool:
    """Attempt a fresh probe to IDA. Returns True on success."""
    global _heartbeat_alive, _heartbeat_failures, _heartbeat_last_ok, IDA_HOST, IDA_PORT
    print("[MCP] Heartbeat lost — attempting reconnection...", file=sys.stderr)
    try:
        probe_resp = _proxy_to_instance(IDA_HOST, IDA_PORT, {
            "jsonrpc": "2.0", "id": "rc", "method": "server_health", "params": {}
        })
        if probe_resp and "result" in probe_resp:
            with _heartbeat_lock:
                _heartbeat_alive = True
                _heartbeat_last_ok = time.monotonic()
                _heartbeat_failures = 0
            print(f"[MCP] Reconnected to {IDA_HOST}:{IDA_PORT}", file=sys.stderr)
            return True
    except Exception as e:
        print(f"[MCP] Reconnection failed: {e}", file=sys.stderr)
    return False


def _start_heartbeat(host: str, port: int) -> None:
    """Start the background heartbeat thread."""
    global _heartbeat_running, _heartbeat_thread, _heartbeat_alive, _heartbeat_last_ok, _heartbeat_failures
    with _heartbeat_lock:
        _heartbeat_running = True
        _heartbeat_alive = True
        _heartbeat_last_ok = time.monotonic()
        _heartbeat_failures = 0
    _heartbeat_thread = threading.Thread(target=_heartbeat_loop, args=(host, port), daemon=True)
    _heartbeat_thread.start()


def _stop_heartbeat() -> None:
    """Stop the heartbeat thread."""
    global _heartbeat_running
    _heartbeat_running = False


def _check_heartbeat(timeout: float = 5.0) -> bool:
    """Return True if the last heartbeat was successful within the given timeout window.
    
    Also performs an immediate synchronous health check if the heartbeat is stale,
    since a single failed ping shouldn't abort the entire session. If all checks
    fail, attempts reconnection before returning False.
    """
    with _heartbeat_lock:
        alive = _heartbeat_alive
        last_ok = _heartbeat_last_ok
    if alive:
        return True
    # Heartbeat is marked dead — try one synchronous probe
    ago = time.monotonic() - last_ok
    if ago > _HEARTBEAT_INTERVAL_SEC:
        host, port = _get_active_ida_target()
        try:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
            conn.request("POST", "/mcp", json.dumps({
                "jsonrpc": "2.0", "id": "hb-sync", "method": "server_health", "params": {}
            }), {"Content-Type": "application/json"})
            resp = conn.getresponse()
            body = resp.read()
            conn.close()
            if resp.status == 200 and b'"result"' in body:
                with _heartbeat_lock:
                    _heartbeat_alive = True
                    _heartbeat_last_ok = time.monotonic()
                    _heartbeat_failures = 0
                return True
        except Exception:
            pass
    # Last resort: try reconnection
    return _try_reconnect()


# ---------------------------------------------------------------------------
# Adaptive timeouts — per-tool timeout hints based on binary size.
# The heartbeat caches the server_health payload, so we know binary_mb
# before every dispatch without an extra round-trip to IDA.
# ---------------------------------------------------------------------------

# Timeout calculator: (scalar_per_mb, fixed_overhead, absolute_max)
# scalar_per_mb: multiplied by binary_mb to get the variable portion
# fixed_overhead: added to the variable portion (covers IDA dispatch + serde)
# absolute_max: hard ceiling even for very large binaries
_ADAPTIVE_TIMEOUT_PROFILES: dict[str, tuple[float, float, float]] = {
    # --- Search tools — linear in data size ---
    "find_regex":          (8.0,  10.0,  300.0),
    "search_text":         (12.0, 15.0,  300.0),
    "find_bytes":          (5.0,   5.0,  120.0),
    "scan_signature":      (5.0,   5.0,  120.0),
    "insn_query":          (7.0,   5.0,  180.0),
    # --- Analysis tools — linear in function count/BB size ---
    "decompile":           (1.0,   5.0,  120.0),
    "decompile_batch":     (3.0,  10.0,  300.0),
    "disasm":              (1.0,   5.0,  120.0),
    "disasm_batch":        (3.0,  10.0,  300.0),
    "analyze_function":    (2.0,   8.0,  180.0),
    "analyze_batch":       (4.0,  10.0,  300.0),
    "find_similar_functions": (10.0, 15.0, 300.0),
    "callgraph":           (6.0,  10.0,  300.0),
    "func_profile":        (2.0,   5.0,  120.0),
    # --- Graph/NX — expensive on large binaries ---
    "nx_call_graph":       (8.0,  15.0,  300.0),
    "nx_central_functions": (8.0, 15.0, 300.0),
    "nx_communities":      (8.0,  15.0,  300.0),
    "workflow_reveng_overview": (10.0, 20.0, 300.0),
    # --- Symbolic engines — heavy, give generous time ---
    "angr_cfg_fast":       (5.0,  20.0,  300.0),
    "angr_find_paths":     (5.0,  20.0,  300.0),
    "triton_process_function": (3.0, 10.0, 180.0),
    "triton_analyze_function": (5.0, 15.0, 300.0),
    "miasm_lift_function": (2.0,   8.0,  180.0),
    # --- Data extraction — modest ---
    "export_funcs":        (3.0,   8.0,  180.0),
    "get_bulk_function_hashes": (3.0, 8.0, 180.0),
    "batch_analyze_completeness": (3.0, 8.0, 180.0),
    # --- py_eval / py_exec — unbounded execution time ---
    "py_eval":             (5.0,  60.0, 600.0),
    "py_exec_file":        (5.0,  60.0, 600.0),
}


def _get_adaptive_timeout(tool_name: str) -> float:
    """Compute a per-tool HTTP socket timeout based on binary size.

    Uses the cached heartbeat health payload (binary_size_mb). Falls back
    to the global _proxy_timeout_seconds() when no cache is available.
    """
    profile = _ADAPTIVE_TIMEOUT_PROFILES.get(tool_name)
    if profile is None:
        return _proxy_timeout_seconds()

    scalar_per_mb, fixed_overhead, absolute_max = profile
    binary_mb: float = 50.0  # conservative default if cache is empty

    payload = _heartbeat_payload
    if payload is not None and isinstance(payload.get("binary_size_mb"), (int, float)):
        binary_mb = max(1.0, float(payload["binary_size_mb"]))

    adaptive = scalar_per_mb * binary_mb + fixed_overhead
    base = _proxy_timeout_seconds()

    # The larger of: adaptive calculation, global proxy timeout, with an
    # upper bound at absolute_max.
    return max(base, min(adaptive, absolute_max))


def _proxy_to_instance_with_timeout(
    host: str, port: int, payload: bytes | str | dict, timeout: float | None = None
) -> dict:
    """Like _proxy_to_instance but accepts an explicit socket timeout."""
    if isinstance(payload, dict):
        payload = json.dumps(payload)
    elif isinstance(payload, str):
        payload = payload.encode("utf-8")

    effective = timeout if timeout is not None else _proxy_timeout_seconds()
    conn = http.client.HTTPConnection(host, port, timeout=effective)
    try:
        conn.request(
            "POST",
            _get_proxy_request_path(),
            payload,
            _get_proxy_request_headers(),
        )
        response = conn.getresponse()
        raw_data = response.read().decode()
        if response.status >= 400:
            raise RuntimeError(
                f"HTTP {response.status} {response.reason}: {raw_data}"
            )
        parsed = json.loads(raw_data)
        _remember_output_proxy_target_from_response(host, port, parsed)
        return parsed
    finally:
        conn.close()

# How long the stdio proxy waits on a single synchronous tool call to IDA before
# giving up. The old hardcoded 30 s was the V3 "proxy timeout" that dropped heavy
# angr/CFG operations mid-flight. Heavy tools should still prefer async_mode
# (submit + poll, each call fast), but this raises the synchronous ceiling so
# moderately-long ops complete and their output is actually returned. Override
# with IDA_MCP_PROXY_TIMEOUT_SEC; the fast submit/poll calls are unaffected since
# the value is a ceiling, not a fixed wait.
def _proxy_timeout_seconds() -> float:
    try:
        return max(5.0, float(os.environ.get("IDA_MCP_PROXY_TIMEOUT_SEC", "180")))
    except (TypeError, ValueError):
        return 180.0

mcp = McpServer(MCP_SERVER_NAME)
dispatch_original = mcp.registry.dispatch

LOCAL_TOOLS = {"list_instances", "select_instance", "invoke_on_instance", "compare_instances"}

# ---------------------------------------------------------------------------
# Backward-compat argument aliases
# Applied before every tools/call proxy so old agent prompts keep working
# after parameter renames. Maps old_name → new_name.
# ---------------------------------------------------------------------------
# Global aliases applied to every tool call.
# Most tools use `address` (singular) and `addrs` (plural) as canonical names.
# Per-tool overrides below handle the two outliers (decompile, disasm) that use `addr`,
# and the two tools (decompile_batch, triton_replay_instructions) that use `addresses`.
# Alias tables and normalization logic live in ida_mcp/arg_aliases.py so the
# IDA plugin (rpc.py) and this proxy share a single source of truth.
# The plugin applies normalization inside its tools/call handler so aliases
# fire for every MCP transport (HTTP, SSE, stdio).  The proxy applies it
# here as well as a second pass — the operation is idempotent.
try:
    from .ida_mcp.arg_aliases import (
        _GLOBAL_ARG_ALIASES,
        _TOOL_ARG_ALIASES,
        normalize_tool_args as _normalize_tool_args,
    )
except ImportError:
    from ida_mcp.arg_aliases import (  # type: ignore[no-redef]
        _GLOBAL_ARG_ALIASES,
        _TOOL_ARG_ALIASES,
        normalize_tool_args as _normalize_tool_args,
    )
LAZY_TOOLS = {"list_modules", "list_tools", "describe_tool", "invoke_tool"}
LAZY_MODE = False

# Cache for IDA tools/list response so meta-tools don't call IDA on every invocation.
_lazy_tools_cache: list[dict] | None = None
_lazy_module_cache: dict[str, list[dict]] | None = None
_lazy_tools_cache_lock = threading.Lock()

OUTPUT_PROXY_CACHE_MAX_SIZE = 100
_OUTPUT_PATH_RE = re.compile(r"^/output/([a-f0-9-]+)\.(\w+)$")
_output_proxy_targets: OrderedDict[str, tuple[str, int]] = OrderedDict()
_output_proxy_lock = threading.Lock()
SESSION_PROXY_TARGET_TTL_SEC = 24 * 60 * 60
SESSION_PROXY_TARGET_MAX_SIZE = 4096
_session_proxy_targets: OrderedDict[str, tuple[str, int]] = OrderedDict()
_session_proxy_last_seen: dict[str, float] = {}
_session_proxy_lock = threading.Lock()


def _get_proxy_session_key() -> str | None:
    """Return the active MCP transport session id, if one is available."""
    return mcp.get_current_transport_session_id()


def _prune_session_proxy_targets_locked(now: float | None = None) -> None:
    """Remove expired or excess per-session IDA target selections."""
    now = time.monotonic() if now is None else now

    # Tests and older callers may mutate _session_proxy_targets directly. Treat
    # entries without metadata as live, then include them in normal pruning.
    for session_key in list(_session_proxy_targets):
        _session_proxy_last_seen.setdefault(session_key, now)

    if SESSION_PROXY_TARGET_TTL_SEC > 0:
        cutoff = now - SESSION_PROXY_TARGET_TTL_SEC
        for session_key, last_seen in list(_session_proxy_last_seen.items()):
            if last_seen < cutoff:
                _session_proxy_targets.pop(session_key, None)
                _session_proxy_last_seen.pop(session_key, None)

    for session_key in list(_session_proxy_last_seen):
        if session_key not in _session_proxy_targets:
            _session_proxy_last_seen.pop(session_key, None)

    if SESSION_PROXY_TARGET_MAX_SIZE > 0:
        while len(_session_proxy_targets) > SESSION_PROXY_TARGET_MAX_SIZE:
            session_key, _ = _session_proxy_targets.popitem(last=False)
            _session_proxy_last_seen.pop(session_key, None)


def _get_active_ida_target() -> tuple[str, int]:
    """Return the IDA target selected for this MCP transport session."""
    session_key = _get_proxy_session_key()
    if session_key is not None:
        now = time.monotonic()
        with _session_proxy_lock:
            _prune_session_proxy_targets_locked(now)
            target = _session_proxy_targets.get(session_key)
            if target is not None:
                _session_proxy_targets.move_to_end(session_key)
                _session_proxy_last_seen[session_key] = now
                return target
    return IDA_HOST, IDA_PORT


def _set_active_ida_target(host: str, port: int) -> None:
    """Select an IDA target for the current session, falling back to process-wide state."""
    global IDA_HOST, IDA_PORT
    session_key = _get_proxy_session_key()
    if session_key is not None:
        now = time.monotonic()
        with _session_proxy_lock:
            _session_proxy_targets.pop(session_key, None)
            _session_proxy_targets[session_key] = (host, port)
            _session_proxy_last_seen[session_key] = now
            _prune_session_proxy_targets_locked(now)
        return
    IDA_HOST = host
    IDA_PORT = port
    set_ida_rpc(IDA_HOST, IDA_PORT)


def _clear_active_ida_target() -> tuple[str, int]:
    """Clear the current session's target selection and return the default target."""
    global IDA_HOST, IDA_PORT
    session_key = _get_proxy_session_key()
    if session_key is not None:
        with _session_proxy_lock:
            _session_proxy_targets.pop(session_key, None)
            _session_proxy_last_seen.pop(session_key, None)
        return IDA_HOST, IDA_PORT
    IDA_HOST = DEFAULT_IDA_HOST
    IDA_PORT = DEFAULT_IDA_PORT
    set_ida_rpc(IDA_HOST, IDA_PORT)
    return IDA_HOST, IDA_PORT


def _extract_output_id(response: dict) -> str | None:
    result = response.get("result")
    if not isinstance(result, dict):
        return None
    meta = result.get("_meta")
    if not isinstance(meta, dict):
        return None
    ida_meta = meta.get("ida_mcp")
    if not isinstance(ida_meta, dict):
        return None
    output_id = ida_meta.get("output_id")
    return output_id if isinstance(output_id, str) else None


def _remember_output_proxy_target(output_id: str, host: str, port: int) -> None:
    with _output_proxy_lock:
        _output_proxy_targets.pop(output_id, None)
        _output_proxy_targets[output_id] = (host, port)
        while len(_output_proxy_targets) > OUTPUT_PROXY_CACHE_MAX_SIZE:
            _output_proxy_targets.popitem(last=False)


def _get_output_proxy_target(output_id: str) -> tuple[str, int] | None:
    with _output_proxy_lock:
        target = _output_proxy_targets.get(output_id)
        if target is None:
            return None
        _output_proxy_targets.move_to_end(output_id)
        return target


def _remember_output_proxy_target_from_response(host: str, port: int, response: dict) -> None:
    output_id = _extract_output_id(response)
    if output_id:
        _remember_output_proxy_target(output_id, host, port)


def _get_proxy_request_path() -> str:
    """Build the proxied MCP path, preserving enabled extensions."""
    enabled = sorted(getattr(mcp._enabled_extensions, "data", set()))
    if enabled:
        return f"/mcp?ext={','.join(enabled)}"
    return "/mcp"


def _get_proxy_request_headers() -> dict[str, str]:
    """Build proxy request headers, preserving HTTP MCP session identity."""
    headers = {"Content-Type": "application/json"}
    transport_session_id = mcp.get_current_transport_session_id()
    if transport_session_id and transport_session_id.startswith("http:"):
        session_id = transport_session_id.split(":", 1)[1]
        if session_id and session_id != "anonymous":
            headers["Mcp-Session-Id"] = session_id
    external_base_url = get_current_request_external_base_url()
    if external_base_url:
        headers[EXTERNAL_BASE_HEADER] = external_base_url
    return headers


def _proxy_to_instance(host: str, port: int, payload: bytes | str | dict) -> dict:
    """Send a JSON-RPC request to a specific IDA instance and return the response."""
    if isinstance(payload, dict):
        payload = json.dumps(payload)
    elif isinstance(payload, str):
        payload = payload.encode("utf-8")

    conn = http.client.HTTPConnection(host, port, timeout=_proxy_timeout_seconds())
    try:
        conn.request(
            "POST",
            _get_proxy_request_path(),
            payload,
            _get_proxy_request_headers(),
        )
        response = conn.getresponse()
        raw_data = response.read().decode()
        if response.status >= 400:
            raise RuntimeError(
                f"HTTP {response.status} {response.reason}: {raw_data}"
            )
        parsed = json.loads(raw_data)
        _remember_output_proxy_target_from_response(host, port, parsed)
        return parsed
    finally:
        conn.close()


def _proxy_output_download(host: str, port: int, path: str) -> tuple[int, str, list[tuple[str, str]], bytes]:
    """Proxy a raw output download from a specific IDA instance."""
    conn = http.client.HTTPConnection(host, port, timeout=_proxy_timeout_seconds())
    try:
        conn.request("GET", path)
        response = conn.getresponse()
        return response.status, response.reason, response.getheaders(), response.read()
    finally:
        conn.close()


def _get_lazy_tools_cache() -> list[dict]:
    """Return cached IDA tools list, fetching from IDA if not yet populated."""
    global _lazy_tools_cache, _lazy_module_cache
    with _lazy_tools_cache_lock:
        if _lazy_tools_cache is not None:
            return _lazy_tools_cache
    try:
        resp = _proxy_to_instance(*_get_active_ida_target(), {
            "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}
        })
        tools = resp.get("result", {}).get("tools", []) if resp else []
    except Exception:
        tools = []
    with _lazy_tools_cache_lock:
        _lazy_tools_cache = tools
        _lazy_module_cache = None
    return tools


def _get_lazy_module_cache() -> dict[str, list[dict]]:
    """Return cached per-module tool slices, building on first use."""
    global _lazy_module_cache
    with _lazy_tools_cache_lock:
        if _lazy_module_cache is not None:
            return _lazy_module_cache
    tools = _get_lazy_tools_cache()
    modules: dict[str, list[dict]] = {}
    for t in tools:
        mod = _tool_module(t["name"])
        modules.setdefault(mod, []).append(t)
    with _lazy_tools_cache_lock:
        _lazy_module_cache = modules
    return modules


# Representative tools shown per group in the embedded list_modules directory.
# These are hardcoded so the description is useful even before IDA connects.
_GROUP_REPRESENTATIVE_TOOLS: dict[str, list[str]] = {
    "analysis": [
        "survey_binary",
        "decompile",
        "decompile_batch",
        "disasm",
        "xrefs_to",
        "trace_data_chain",
        "find_similar_functions",
        "func_profile",
        "callgraph",
        "analyze_function",
        "find_bytes",
    ],
    "core":     [
        "survey_binary",
        "server_health",
        "list_funcs",
        "find_regex",
        "imports",
        "entity_query",
        "search_text",
        "read_mcp_output",
    ],
    "formats":  ["lief_info", "yara_scan", "lief_checksec", "yara_generate_rule", "construct_parse"],
    "modify":   ["rename", "set_comments", "patch_asm", "declare_type", "define_func", "analyze_range"],
    "recon":    ["nx_central_functions", "workflow_reveng_overview", "apply_flirt_sig", "list_sections"],
    "symbolic": [
        "hybrid_analyze_function",
        "triton_init",
        "miasm_lift",
        "angr_find_paths",
        "workflow_solve_crackme",
        "triton_taint",
    ],
}

# Prefix-based module mapping for _tool_module().
# Known core tools; used by _validate_groups() to avoid false-positive warnings.
_CORE_TOOL_NAMES: frozenset[str] = frozenset({
    "server_health", "server_warmup", "lookup_funcs", "int_convert",
    "list_funcs", "func_query", "list_globals", "list_strings", "entity_query",
    "imports", "imports_query", "idb_save", "find_regex", "search_text",
    "read_mcp_output", "list_instances", "select_instance", "get_active_instance",
    "find_instance", "invoke_on_instance", "compare_instances",
    "task_submit", "task_cancel", "task_list", "task_poll",
    "idalib_open", "idalib_close", "idalib_switch", "idalib_unbind",
    "idalib_list", "idalib_current", "idalib_save", "idalib_health", "idalib_warmup",
})


def _tool_module(name: str) -> str:
    """Map a tool name to a logical module group for list_modules grouping."""
    return get_tool_group(name)


def _proxy_to_ida(payload: bytes | str | dict, timeout: float | None = None) -> dict:
    """Send a JSON-RPC request to the active IDA instance and return the response.

    timeout: per-call socket timeout override (seconds). If None, uses the
    global _proxy_timeout_seconds(). If provided, uses the given value.
    """
    host, port = _get_active_ida_target()
    if timeout is not None:
        return _proxy_to_instance_with_timeout(host, port, payload, timeout)
    return _proxy_to_instance(host, port, payload)


# ---------------------------------------------------------------------------
# TOON response post-processor (stdio-proxy path)
# Auto-encodes tool results that contain large uniform flat arrays into the
# compact TOON tabular format, reducing agent context usage by ~40%.
#
# This is the fallback for the stdio proxy. The IDA plugin applies the same
# encoding directly (see ida_mcp/rpc.py); when it already did, the text here is
# TOON (not JSON), json.loads fails, and we return the response unchanged.
# Qualification + encoding logic lives in ida_mcp/toon_encode.py (single source).
# Requires: pip install toon_format  (optional — falls back silently)
# ---------------------------------------------------------------------------


def _maybe_toon_encode_response(response: dict | None) -> dict | None:
    """TOON-encode the text content of a tools/call JSON-RPC response.

    Fires only when toon_format is installed, the result is a successful
    (ok: true) dict, and it contains an array of >=20 uniform flat objects.
    On success content[0].text becomes the compact TOON string while
    structuredContent is preserved for schema validation — dropping it
    would cause -32600 on schema-enforcing clients. Falls back to the
    original response on any error.
    """
    if not _TOON_AVAILABLE or response is None:
        return response
    try:
        result_obj = response.get("result", {})
        content_list = result_obj.get("content", [])
        if not content_list or content_list[0].get("type") != "text":
            return response
        text = content_list[0].get("text", "")
        data = json.loads(text)
        if not isinstance(data, dict) or not data.get("ok"):
            return response
        toon_text = _maybe_toon_encode_result(data)
        if toon_text is None:
            return response
        encoded = copy.deepcopy(response)
        encoded["result"]["content"][0]["text"] = toon_text
        # structuredContent is intentionally kept: schema-enforcing clients
        # require it when outputSchema is declared (MCP spec). The model reads
        # content (TOON), the client framework validates structuredContent (JSON).
        return encoded
    except Exception:
        return response


def dispatch_proxy(request: dict | str | bytes | bytearray) -> JsonRpcResponse | None:
    """Dispatch JSON-RPC requests to the MCP server registry."""
    if not isinstance(request, dict):
        request_obj: JsonRpcRequest = json.loads(request)
    else:
        request_obj: JsonRpcRequest = request  # type: ignore

    if request_obj["method"] == "initialize":
        return dispatch_original(request)
    if request_obj["method"].startswith("notifications/"):
        return dispatch_original(request)

    # Handle local tools (instance discovery + lazy meta-tools) without proxying to IDA
    if request_obj["method"] == "tools/call":
        params = request_obj.get("params", {})
        tool_name = params.get("name", "")
        if tool_name in LOCAL_TOOLS:
            return dispatch_original(request)
        if LAZY_MODE and tool_name in LAZY_TOOLS:
            # invoke_tool forwards to IDA and returns the inner tool result directly —
            # run TOON post-processing here so lazy-mode callers also get compression.
            return _maybe_toon_encode_response(dispatch_original(request))

    # Handle tools/list: in lazy mode expose only 4 meta-tools; otherwise merge local + IDA
    if request_obj["method"] == "tools/list":
        local_result = dispatch_original(request)
        if LAZY_MODE:
            # Filter local tools down to just the 4 lazy meta-tools
            if local_result and "result" in local_result:
                local_result["result"]["tools"] = [
                    t for t in local_result["result"].get("tools", [])
                    if t.get("name") in LAZY_TOOLS
                ]
            return local_result
        local_tool_names = (
            {t["name"] for t in local_result.get("result", {}).get("tools", [])}
            if local_result
            else set()
        )
        # In normal mode, hide lazy meta-tools — they're only useful in --lazy mode
        if local_result and "result" in local_result:
            local_result["result"]["tools"] = [
                t for t in local_result["result"].get("tools", [])
                if t.get("name") not in LAZY_TOOLS
            ]
            local_tool_names -= LAZY_TOOLS
        # Try to get IDA tools and merge them in
        try:
            ida_result = _proxy_to_ida(request)
            if ida_result and "result" in ida_result:
                # Filter out IDA tools that duplicate local tools (e.g. select_instance)
                ida_tools = [
                    t
                    for t in ida_result["result"].get("tools", [])
                    if t.get("name") not in local_tool_names
                ]
                if local_result and "result" in local_result:
                    local_result["result"]["tools"] = (
                        ida_tools + local_result["result"].get("tools", [])
                    )
        except Exception:
            pass  # IDA unreachable — local tools still work
        return local_result

    request_id = request_obj.get("id")
    tool_name = request_obj.get("params", {}).get("name", "<unknown>")
    shortcut = "Ctrl+Option+M" if sys.platform == "darwin" else "Ctrl+Alt+M"

    # Normalize deprecated/variant argument names before forwarding.
    if request_obj.get("method") == "tools/call":
        raw_args = request_obj.get("params", {}).get("arguments", {})
        normalized = _normalize_tool_args(tool_name, raw_args)
        if normalized is not raw_args:
            request_obj = copy.deepcopy(request_obj)
            request_obj["params"]["arguments"] = normalized
            request = request_obj

    try:
        # Pre-flight: check heartbeat before every tools/call dispatch.
        # If the IDA connection is known dead, fail fast instead of waiting
        # for the HTTP socket timeout (180s).
        if not _check_heartbeat(timeout=3.0):
            return JsonRpcResponse({
                "jsonrpc": "2.0",
                "error": {
                    "code": -32000,
                    "message": (
                        "IDA Pro connection is dead (heartbeat lost). "
                        "The proxy cannot reach the IDA plugin. Restart the MCP plugin "
                        f"in IDA or restart the proxy process. Last successful heartbeat: "
                        f"{time.monotonic() - _heartbeat_last_ok:.0f}s ago."
                    ),
                },
                "id": request_obj.get("id"),
            })

        # Compute per-tool adaptive timeout based on binary size
        adaptive_timeout = _get_adaptive_timeout(tool_name) if tool_name else None
        result = _proxy_to_ida(request, timeout=adaptive_timeout)
        if request_obj.get("method") == "tools/call":
            result = _maybe_toon_encode_response(result)
        return result

    except (TimeoutError, socket.timeout) as e:
        # IDA is reachable but not responding — main thread is almost certainly blocked.
        if request_id is None:
            return None
        return JsonRpcResponse(
            {
                "jsonrpc": "2.0",
                "error": {
                    "code": -32000,
                    "message": (
                        f"IDA Pro timed out on tool '{tool_name}' (30 s limit exceeded). "
                        "The IDA main thread is blocked and cannot process new requests. "
                        "Common causes: a py_eval/py_exec script that is still running "
                        "(e.g. pip install, a long loop), or a previous heavy tool that has "
                        "not finished yet. "
                        "What to do: wait ~30 s and retry once — if still unresponsive, "
                        "interrupt or restart IDA. "
                        "Do NOT retry mutating tools (rename, patch, define_func) until you "
                        "have confirmed IDA state, as the previous call may have partially "
                        "completed."
                    ),
                    "data": str(e),
                },
                "id": request_id,
            }
        )

    except (ConnectionRefusedError, ConnectionResetError) as e:
        # IDA server is not running or was killed mid-request.
        if request_id is None:
            return None
        return JsonRpcResponse(
            {
                "jsonrpc": "2.0",
                "error": {
                    "code": -32000,
                    "message": (
                        f"Cannot reach IDA Pro for tool '{tool_name}': {e}. "
                        f"Start the MCP plugin via Edit → Plugins → MCP ({shortcut}), "
                        "then retry."
                    ),
                    "data": str(e),
                },
                "id": request_id,
            }
        )

    except Exception as e:
        full_info = traceback.format_exc()
        if request_id is None:
            return None
        return JsonRpcResponse(
            {
                "jsonrpc": "2.0",
                "error": {
                    "code": -32000,
                    "message": (
                        f"Unexpected error proxying tool '{tool_name}' to IDA Pro. "
                        "The request was not retried automatically. "
                        "If this was a mutating operation, verify IDA state before retrying.\n"
                        f"{full_info}"
                    ),
                    "data": str(e),
                },
                "id": request_id,
            }
        )


mcp.registry.dispatch = dispatch_proxy


class ProxyHttpRequestHandler(McpHttpRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        output_match = _OUTPUT_PATH_RE.match(parsed.path)
        if output_match:
            if not self._check_api_request():
                return
            output_id = output_match.group(1)
            target = _get_output_proxy_target(output_id)
            if target is None:
                self.send_error(404, "Output not found or expired")
                return
            try:
                status, _, response_headers, body = _proxy_output_download(
                    target[0], target[1], parsed.path
                )
            except Exception as e:
                self.send_error(502, f"Failed to proxy output download: {e}")
                return

            self.send_response(status)
            for header, value in response_headers:
                if header.lower() == "transfer-encoding":
                    continue
                self.send_header(header, value)
            self.send_cors_headers()
            self.end_headers()
            self.wfile.write(body)
            return

        # MCP Streamable HTTP: GET /mcp is an optional SSE pre-connect check.
        # Returning 405 (as zeromcp does) causes some MCP clients (Kilo, Cursor)
        # to treat the connection as failed instead of falling through to POST.
        # Per the MCP spec, an empty SSE stream signals "no events, use POST only".
        if parsed.path == "/mcp" or parsed.path.rstrip("/") == "/mcp":
            if not self._check_api_request():
                return
            self.send_response(200)
            self.send_cors_headers()
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            self.wfile.flush()
            return

        super().do_GET()


def _validate_groups() -> None:
    """In lazy mode, warn about tools that fall through to 'core' unexpectedly.

    This is a dev-time check: it logs warnings but never blocks startup.
    """
    tools = _get_lazy_tools_cache()
    warned: set[str] = set()
    for t in tools:
        name = t["name"]
        mod = _tool_module(name)
        if mod == "core" and name not in _CORE_TOOL_NAMES and name not in warned:
            warned.add(name)
            print(
                f"[MCP] Warning: tool '{name}' fell through to 'core' module. "
                "If it belongs elsewhere, update _tool_module() in server.py.",
                file=sys.stderr,
            )


def _build_lazy_directory_description() -> str:
    """Build the embedded group directory for list_modules' description.

    Called at startup and on cache reset so agents see live counts in tools/list.
    Falls back to static representative tools + '?' counts if IDA is unreachable.
    """
    modules = _get_lazy_module_cache()
    all_groups = sorted(set(list(modules.keys()) + list(_GROUP_REPRESENTATIVE_TOOLS.keys())))
    group_lines = []
    for grp in all_groups:
        count = len(modules.get(grp, []))
        count_str = str(count) if count else "?"
        top = _GROUP_REPRESENTATIVE_TOOLS.get(grp, [])
        top_str = ", ".join(top) if top else "(see list_tools)"
        group_lines.append(f"  {grp:<10} ({count_str:>3}) — {top_str}")

    groups_block = "\n".join(group_lines)
    return (
        "[lazy-mode] List available tool groups with live counts.\n"
        "\n"
        "Groups — invoke_tool directly if you know the name:\n"
        f"{groups_block}\n"
        "\n"
        "Shortcuts:\n"
        "  invoke_tool(tool='NAME', args={...})   direct call, no prior discovery needed\n"
        "  list_tools(search='keyword')           search names+descriptions by keyword\n"
        "  list_tools(module='GROUP')             full tool list for one group\n"
        "  list_tools(module='GROUP', limit=20)   paginate large groups (symbolic has 60+)"
    )


# ============================================================================
# Local tools (handled by the proxy, not forwarded to IDA)
# ============================================================================


@mcp.tool
def list_instances() -> list[ProxyInstanceInfo]:
    """List discovered IDA Pro instances and indicate which one is active."""
    active_host, active_port = _get_active_ida_target()
    result = []
    for inst in discover_instances():
        reachable = probe_instance(inst["host"], inst["port"])
        result.append(
            {
                **inst,
                "reachable": reachable,
                "active": inst["host"] == active_host and inst["port"] == active_port,
            }
        )
    return result


@mcp.tool
def select_instance(
    port: Annotated[int, "Port number of the IDA instance to connect to"],
    host: Annotated[str, "Host address of the IDA instance"] = "127.0.0.1",
) -> ProxySelectResult:
    """Switch this MCP server to proxy requests to a different IDA Pro instance.

    Use list_instances first to see available instances, then select one by port.
    All subsequent tool calls will be routed to the selected instance.
    """
    if port == 0:
        default_host, default_port = _clear_active_ida_target()
        return {
            "success": True,
            "host": default_host,
            "port": default_port,
            "message": "Reset to default IDA target",
        }
    if not probe_instance(host, port):
        return {"success": False, "error": f"Instance at {host}:{port} is not reachable"}
    _set_active_ida_target(host, port)
    return {"success": True, "host": host, "port": port}


@mcp.tool
def invoke_on_instance(
    instance: Annotated[
        str,
        "Target instance: a binary name like 'Engine.dll' (case-insensitive, "
        "stable across restarts) or a port number. Use list_instances to see options.",
    ],
    tool: Annotated[str, "Name of the analysis tool to run on that instance (e.g. 'lief_exports', 'decompile')."],
    args: Annotated[
        dict | None,
        "Tool arguments as a flat dict, exactly as you would pass to the tool directly. "
        "CORRECT: invoke_on_instance(instance='Engine.dll', tool='decompile', args={'address': 'main'}).",
    ] = None,
) -> dict:
    """Run a single tool against one specific IDA instance without changing the active session target.

    Unlike select_instance (which redirects ALL later calls), this is a stateless one-off:
    it targets the named instance for this call only. Ideal for pulling the same datum from
    a second binary to verify a finding, without losing your current instance context.

    Returns {ok, instance, host, port, result} on success, or a structured error with
    error_type ('no_instances' | 'binary_not_found' | 'port_not_found' | 'ambiguous' |
    'unreachable' | 'tool_error' | 'proxy_error') and the list of available instances.
    """
    return run_invoke_on_instance(_proxy_to_instance, instance, tool, args)


@mcp.tool
def compare_instances(
    tool: Annotated[str, "Name of the analysis tool to run on every targeted instance (e.g. 'lief_info', 'get_function_hash')."],
    args: Annotated[
        dict | None,
        "Tool arguments as a flat dict, applied identically to each instance.",
    ] = None,
    instances: Annotated[
        list[str] | None,
        "Instances to target, each a binary name or port. Omit to fan out to ALL "
        "currently registered instances.",
    ] = None,
) -> dict:
    """Run the same tool across two or more IDA instances and return labeled, side-by-side results.

    IMPORTANT — ok semantics: the top-level 'ok: true' means AT LEAST ONE instance succeeded,
    NOT that all did. Always check each entry's individual 'ok' field in the 'results' list
    before acting on any entry's data. Partial success (some ok, some failed) is normal and
    expected when instances have different binary layouts or different analysis state.

    This is the primary cross-reference primitive: compare or verify the same query across
    multiple open binaries in one call (e.g. diff exports between Engine.dll and a patched
    variant, confirm function hashes match across builds, or cross-check vtable layouts).

    Returns {ok, tool, count, success_count, fail_count, results}, where each entry in
    'results' is {instance, host, port, ok, result|error, error_type}. Per-instance failures
    do not abort the others. Omit 'instances' to fan out to ALL registered instances.
    """
    return run_compare_instances(_proxy_to_instance, tool, args, instances)


# ============================================================================
# Lazy meta-tools — only exposed when --lazy flag is active
# ============================================================================


@mcp.tool
def list_modules() -> list[dict]:
    """[lazy-mode] List available tool groups. Call list_tools(module=...) to see tools per group.
    Use list_tools(search='keyword') to find a tool by keyword without browsing groups."""
    modules = _get_lazy_module_cache()
    return [{"module": m, "tool_count": len(v)} for m, v in sorted(modules.items())]


@mcp.tool
def list_tools(
    module: Annotated[str | None, "Module group: 'core', 'analysis', 'modify', 'symbolic', 'formats', 'recon'. Omit for all."] = None,
    search: Annotated[str | None, "Keyword to search tool names and descriptions (case-insensitive). Faster than browsing a full group — e.g. search='xref' or search='decompile'."] = None,
    limit: Annotated[int, "Max results to return (default 50, use 0 for unlimited)."] = 50,
    offset: Annotated[int, "Results to skip for pagination (default 0)."] = 0,
) -> dict:
    """[lazy-mode] List tools with one-line descriptions.

    Use search= to find tools by keyword across all groups — e.g. list_tools(search='decompile').
    Use module= to browse all tools in one group — e.g. list_tools(module='analysis').
    Combine both to narrow a group by keyword.
    Results include module name so you can route follow-up calls correctly."""
    if module:
        tools = _get_lazy_module_cache().get(module, [])
    else:
        tools = _get_lazy_tools_cache()
    result = []
    for t in tools:
        desc = t.get("description", "")
        short_desc = desc.split("\n")[0][:150] if desc else ""
        result.append({"name": t["name"], "module": _tool_module(t["name"]), "description": short_desc})
    if not module:
        result.sort(key=lambda x: (x["module"], x["name"]))
    if search:
        kw = search.lower()
        result = [t for t in result if kw in t["name"].lower() or kw in t["description"].lower()]
    total = len(result)
    paginated = result[offset:offset + limit] if limit > 0 else result[offset:]
    return {
        "tools": paginated,
        "total": total,
        "offset": offset,
        "has_more": (offset + len(paginated)) < total,
    }


@mcp.tool
def describe_tool(
    name: Annotated[str, "Exact tool name (from list_tools)"],
) -> dict:
    """[lazy-mode] Get the full input schema for a specific tool before invoking it."""
    tools = _get_lazy_tools_cache()
    for t in tools:
        if t["name"] == name:
            t = dict(t)
            t["module"] = _tool_module(name)
            return t
    return {
        "ok": False,
        "error": f"Tool '{name}' not found.",
        "hint": "Call list_modules() to see available groups, then list_tools(module=...) to find the right tool name.",
    }


def _unpack_call_result(call_result: dict) -> object:
    """Extract the actual tool output from a zeromcp tools/call result envelope."""
    structured = call_result.get("structuredContent")
    if structured is not None:
        return structured
    content = call_result.get("content", [])
    if content:
        try:
            return json.loads(content[0].get("text", "null"))
        except (json.JSONDecodeError, KeyError):
            return content[0].get("text")
    return None


def _invoke_tool_async(tool: str, args: dict | None, host: str, port: int) -> object:
    """Submit tool as a background task and poll until done, then return the result.

    Keeps no open HTTP connection during execution — safe for operations that
    take 30 s–5 min on the IDA main thread.
    """
    submit_resp = _proxy_to_instance(host, port, {
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "task_submit", "arguments": {"tool_name": tool, "arguments": args or {}}},
    })
    if submit_resp is None or "error" in submit_resp:
        err = (submit_resp or {}).get("error", {}).get("message", "no response")
        return {"ok": False, "error": f"task_submit failed: {err}", "hint": "Retry without async_mode=True for a direct synchronous call."}

    submit_result = _unpack_call_result(submit_resp.get("result", {}))
    if not isinstance(submit_result, dict) or not submit_result.get("ok"):
        err = submit_result.get("error", "unknown") if isinstance(submit_result, dict) else "submit failed"
        return {"ok": False, "error": f"task_submit error: {err}"}

    task_id = submit_result.get("task_id")
    if not task_id:
        return {"ok": False, "error": "task_submit returned no task_id"}

    poll_interval = 2.0
    max_wait = 300.0
    waited = 0.0
    while waited < max_wait:
        time.sleep(poll_interval)
        waited += poll_interval
        poll_resp = _proxy_to_instance(host, port, {
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "task_poll", "arguments": {"task_id": task_id}},
        })
        if poll_resp is None or "error" in poll_resp:
            continue
        poll_data = _unpack_call_result(poll_resp.get("result", {}))
        if not isinstance(poll_data, dict):
            continue
        status = poll_data.get("status")
        if status == "done":
            inner = poll_data.get("result")
            if isinstance(inner, dict):
                return _unpack_call_result(inner) or inner
            return inner
        if status == "error":
            return {"ok": False, "error": poll_data.get("error", "task failed"), "task_id": task_id}
        if status == "cancelled":
            return {"ok": False, "error": "Task was cancelled", "task_id": task_id}

    return {
        "ok": False,
        "error": f"Async task '{task_id}' did not complete within {int(max_wait)}s.",
        "task_id": task_id,
        "hint": "Call task_poll(task_id=...) manually to check if it finished, or task_cancel to abort.",
    }


@mcp.tool
def invoke_tool(
    tool: Annotated[str, "Tool name to invoke (from list_tools or list_modules directory)"],
    args: Annotated[dict | None, "Tool arguments as a flat dict. ALL tool inputs go here — never at the top level alongside 'tool'. CORRECT: invoke_tool(tool='decompile', args={'address': 'main'}). WRONG: invoke_tool(tool='decompile', address='main')."] = None,
    async_mode: Annotated[bool | str, "Submit as a background task to avoid proxy timeout. Values: False (sync, default), True (submit + poll up to 300s, BLOCKS — VSCode's 60s client limit still applies!), 'task' (submit immediately, return task_id — agent polls separately). 'task' is RECOMMENDED for all heavy tools. ALWAYS use async_mode=True or 'task' for: angr_find_paths, angr_cfg_fast, angr_backward_slice, angr_cfg_emulated, angr_enumerate_reachable, angr_diff_cfg, hybrid_angr_*.",] = False,
) -> object:
    """[lazy-mode] Invoke any IDA tool by name.

    Put all tool arguments inside args={...}. Do NOT place tool inputs beside 'tool' at the top level.
      CORRECT:   invoke_tool(tool='decompile', args={'address': 'main'})
      INCORRECT: invoke_tool(tool='decompile', address='main')

    **CRITICAL for angr/heavy tools:** use async_mode='task'.
    Heavy tools (angr_find_paths, angr_cfg_fast, angr_backward_slice, etc.) take
    60-300+ seconds. async_mode='task' returns a task_id IMMEDIATELY (1 s),
    avoiding any client timeout. Then poll with:
        invoke_tool(tool='task_poll', args={'task_id': task_id})
    Each poll completes in <1 s — VSCode's 60s client timeout is never hit.
    When the task finishes, task_poll returns the tool's actual result.

    async_mode=True (blocking poll) also works but may hit VSCode's 60s client
    limit for very long operations. Prefer async_mode='task' for angr tools.

    If you know the tool name, call directly without discovery."""
    global _lazy_tools_cache, _lazy_module_cache
    if tool == "__reset_cache__":
        with _lazy_tools_cache_lock:
            _lazy_tools_cache = None
            _lazy_module_cache = None
        try:
            list_modules.__doc__ = _build_lazy_directory_description()
        except Exception:
            pass
        return {"ok": True, "message": "Tool cache cleared and directory refreshed."}

    host, port = _get_active_ida_target()

    # ── Auto-async for known-heavy tools ──────────────────────────────────
    _HEAVY_TOOL_PREFIXES = (
        "angr_find_paths", "angr_cfg_fast", "angr_cfg_emulated",
        "angr_backward_slice", "angr_enumerate_reachable",
        "angr_diff_cfg", "angr_stdin_fuzz",
        "hybrid_angr_", "hybrid_nx_angr_",
        "angr_snapshot_save", "angr_snapshot_restore",
    )
    _auto_async = not async_mode and any(tool.startswith(p) for p in _HEAVY_TOOL_PREFIXES)
    _use_task_mode = async_mode == "task" or _auto_async

    # ── Task mode: submit immediately, return task_id — no blocking ──────
    if _use_task_mode:
        submit_resp = _proxy_to_instance(host, port, {
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "task_submit", "arguments": {"tool_name": tool, "arguments": args or {}}},
        })
        if submit_resp is None or "error" in submit_resp:
            err = (submit_resp or {}).get("error", {}).get("message", "no response")
            return {"ok": False, "error": f"task_submit failed: {err}"}
        submit_result = _unpack_call_result(submit_resp.get("result", {}))
        if not isinstance(submit_result, dict) or not submit_result.get("ok"):
            err = submit_result.get("error", "submit failed") if isinstance(submit_result, dict) else "submit failed"
            return {"ok": False, "error": f"task_submit error: {err}"}
        task_id = submit_result.get("task_id")
        if not task_id:
            return {"ok": False, "error": "task_submit returned no task_id"}
        return {
            "ok": True,
            "stage": "submitted",
            "task_id": task_id,
            "tool": tool,
            "auto_async": _auto_async,
            "hint": (
                f"Task submitted as '{task_id}'. Poll with: "
                f"invoke_tool(tool='task_poll', args={{'task_id': '{task_id}'}}). "
                "The task runs in IDA's background task queue — you can check progress "
                "by passing the task_id to task_poll at any time."
            ),
        }

    # ── Blocking async mode (True): submit + poll in a loop ──────────────
    if async_mode is True:
        result = _invoke_tool_async(tool, args, host, port)
        if isinstance(result, dict):
            if not result.get("ok") and result.get("error"):
                return result
            return result
        return {"ok": True, "result": result}

    # ── Synchronous path (lightweight tools only) ─────────────────────────
    for attempt in range(2):
        try:
            resp = _proxy_to_instance(host, port, {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": tool, "arguments": args or {}},
            })
        except (socket.timeout, TimeoutError, ConnectionError,
                ConnectionRefusedError, ConnectionResetError, OSError,
                http.client.HTTPException) as e:
            # Socket/HTTP-layer timeout — almost certainly a heavy tool
            # that exceeded the proxy timeout (180 s). Return a structured
            # error with the exact fix the agent needs to retry immediately.
            return {
                "ok": False,
                "error": f"Proxy connection to IDA lost ({type(e).__name__}: {e})",
                "hint": (
                    f"This tool ({tool}) likely exceeded the {_proxy_timeout_seconds():.0f}s proxy timeout. "
                    "RETRY IMMEDIATELY with async_mode=True: "
                    f"invoke_tool(tool='{tool}', args=<same_args>, async_mode=True). "
                    "async_mode submits a background task via task_submit, then polls "
                    "every 2 s until completion (max 300 s). The proxy never drops "
                    "because each poll completes in < 1 s."
                ),
                "tool": tool,
                "retry_with_async": True,
            }
        if resp is None:
            return {
                "ok": False,
                "error": "No response from IDA",
                "hint": "Ensure the IDA Pro MCP plugin is running and the target instance is reachable.",
            }
        def _contextual_hint(error_msg: str) -> str:
            em = error_msg.lower()
            if any(w in em for w in ("timed out", "timeout", "deadline", "took too long")):
                return (
                    "IDA main thread may be blocked. "
                    "For heavy tools use async_mode='task' or reduce scope (limit, max_depth). "
                    "If the tool is genuinely slow, increase the timeout or run via task_submit + task_poll."
                )
            if any(w in em for w in ("decompilation failed", "hex-rays unavailable", "no decompiler", "decompile")):
                return (
                    "Decompiler error. Use disasm(addr='...') for assembly fallback, "
                    "or analyze_function(addr='...') for a compact overview without full decompilation."
                )
            if any(w in em for w in ("not found", "no function", "badaddr", "not mapped")):
                return (
                    "Address or name not resolved. Use find_regex(pattern='...') "
                    "or entity_query(kind='functions', filter='...') to locate the correct address."
                )
            if "not available" in em and "install" in em:
                return "Optional dependency missing. Install it with pip as described in the error."
            if "not found" in em or "method" in em:
                return "Call list_modules() to see available groups, then list_tools(module=...) to find the right tool name."
            return "Call list_modules() to see available groups, then list_tools(module=...) to find the right tool name."

        if "error" in resp:
            msg = resp["error"].get("message", "IDA error")
            if attempt == 0 and ("not found" in msg.lower() or "method" in msg.lower()):
                with _lazy_tools_cache_lock:
                    _lazy_tools_cache = None
                    _lazy_module_cache = None
                continue
            return {
                "ok": False,
                "error": msg,
                "hint": _contextual_hint(msg),
            }
        call_result = resp.get("result", {})
        if call_result.get("isError"):
            content = call_result.get("content", [])
            msg = content[0].get("text", "tool error") if content else "tool error"
            if attempt == 0 and ("not found" in msg.lower() or "method" in msg.lower()):
                with _lazy_tools_cache_lock:
                    _lazy_tools_cache = None
                    _lazy_module_cache = None
                continue
            return {
                "ok": False,
                "error": msg,
                "hint": _contextual_hint(msg),
            }
        return _unpack_call_result(call_result)


@mcp.tool
def task_wait(
    tool: Annotated[str, "Tool name to run (e.g. 'angr_find_paths')"],
    args: Annotated[dict | None, "Tool arguments dict"] = None,
    task_id: Annotated[str | None, "Existing task_id from a previous task_wait call. Omit on first call (submits new task); pass on subsequent calls (polls for completion)."] = None,
    max_wait: Annotated[int, "Max seconds to wait on THIS poll call before returning 'running' (default: 5). Pass 0 for immediate status check. Does NOT limit total task time — the task runs until done on IDA."] = 5,
) -> object:
    """Submit a heavy tool as a background task and poll for completion.

    **Calling pattern (never hits VSCode 60s client timeout):**
    Call 1: task_wait(tool='angr_find_paths', args={...})       → {stage:'submitted', task_id:'abc'}
    Call 2: task_wait(task_id='abc')                             → {stage:'running', elapsed: 4s}
    Call 3: task_wait(task_id='abc')                             → {stage:'running', elapsed: 12s}
    ...
    Call N: task_wait(task_id='abc')                             → {stage:'done', result:{...}}

    Each call completes in < 1 s. The task runs independently on IDA.
    """
    host, port = _get_active_ida_target()

    # ── Submit new task (first call) ─────────────────────────────────────
    if not task_id:
        submit_resp = _proxy_to_instance(host, port, {
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "task_submit", "arguments": {"tool_name": tool, "arguments": args or {}}},
        })
        if submit_resp is None or "error" in submit_resp:
            err = (submit_resp or {}).get("error", {}).get("message", "no response")
            return {"ok": False, "error": f"task_submit failed: {err}"}
        submit_result = _unpack_call_result(submit_resp.get("result", {}))
        if not isinstance(submit_result, dict) or not submit_result.get("ok"):
            err = submit_result.get("error", "submit failed") if isinstance(submit_result, dict) else "submit failed"
            return {"ok": False, "error": f"task_submit error: {err}"}
        new_task_id = submit_result.get("task_id")
        if not new_task_id:
            return {"ok": False, "error": "task_submit returned no task_id"}
        return {
            "ok": True,
            "stage": "submitted",
            "task_id": new_task_id,
            "tool": tool,
            "hint": f"Poll: task_wait(task_id='{new_task_id}'). Each call completes in <1 s.",
        }

    # ── Poll existing task ────────────────────────────────────────────────
    deadline = time.monotonic() + max(max_wait, 0.1)
    while time.monotonic() < deadline:
        poll_resp = _proxy_to_instance(host, port, {
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "task_poll", "arguments": {"task_id": task_id}},
        })
        if poll_resp is None or "error" in poll_resp:
            time.sleep(0.5)
            continue
        poll_data = _unpack_call_result(poll_resp.get("result", {}))
        if not isinstance(poll_data, dict):
            continue
        status = poll_data.get("status")
        if status == "done":
            inner = poll_data.get("result")
            result = _unpack_call_result(inner) if isinstance(inner, dict) else inner
            return {"ok": True, "stage": "done", "task_id": task_id, "result": result}
        if status == "error":
            return {"ok": False, "stage": "error", "task_id": task_id, "error": poll_data.get("error", "task failed")}
        if status == "cancelled":
            return {"ok": False, "stage": "cancelled", "task_id": task_id, "error": "Task was cancelled"}
        if status == "running":
            elapsed = poll_data.get("elapsed_seconds", 0)
            return {"ok": True, "stage": "running", "task_id": task_id, "elapsed_seconds": round(elapsed, 1)}
        time.sleep(0.5)

    return {"ok": True, "stage": "running", "task_id": task_id, "hint": "Task still running. Poll again."}


# ============================================================================

DEFAULT_IDA_RPC = f"http://{IDA_HOST}:{IDA_PORT}"


def _resolve_ida_rpc(args) -> None:
    """Resolve the IDA RPC target: explicit --ida-rpc, or auto-discovery."""
    global IDA_HOST, IDA_PORT

    if args.ida_rpc is not None:
        # Explicit --ida-rpc: use directly (backwards compatible)
        ida_rpc = urlparse(args.ida_rpc)
        if ida_rpc.hostname is None or ida_rpc.port is None:
            raise Exception(f"Invalid IDA RPC server: {args.ida_rpc}")
        IDA_HOST = ida_rpc.hostname
        IDA_PORT = ida_rpc.port

        # Preserve ?ext= query param so proxy requests include the extensions
        ext_value = parse_qs(ida_rpc.query).get("ext", [""])[0]
        if ext_value:
            mcp._enabled_extensions.data = set(ext_value.split(","))

        set_ida_rpc(IDA_HOST, IDA_PORT)
        return

    # Auto-discover running IDA instances
    instances = discover_instances()
    if len(instances) == 0:
        print(
            f"[MCP] No IDA instances discovered, using default {IDA_HOST}:{IDA_PORT}",
            file=sys.stderr,
        )
    elif len(instances) == 1:
        inst = instances[0]
        IDA_HOST = inst["host"]
        IDA_PORT = inst["port"]
        print(
            f"[MCP] Auto-connected to: {inst['binary']} at {IDA_HOST}:{IDA_PORT}",
            file=sys.stderr,
        )
    else:
        print(f"[MCP] Found {len(instances)} IDA instances:", file=sys.stderr)
        for i, inst in enumerate(instances):
            print(f"  [{i}] {inst['binary']} at {inst['host']}:{inst['port']}", file=sys.stderr)
        inst = instances[0]
        IDA_HOST = inst["host"]
        IDA_PORT = inst["port"]
        print(
            f"[MCP] Auto-selected: {inst['binary']}. "
            "Use select_instance tool to switch.",
            file=sys.stderr,
        )

    set_ida_rpc(IDA_HOST, IDA_PORT)


def main():
    global IDA_HOST, IDA_PORT

    parser = argparse.ArgumentParser(description="IDA Pro MCP Server")
    parser.add_argument(
        "--install",
        nargs="?",
        const="",
        default=None,
        metavar="TARGETS",
        help="Install the MCP Server and IDA plugin. "
        "The IDA plugin is installed immediately. "
        "Optionally specify comma-separated client targets (e.g., 'claude,cursor'). "
        "Without targets, an interactive selector is shown.",
    )
    parser.add_argument(
        "--uninstall",
        nargs="?",
        const="",
        default=None,
        metavar="TARGETS",
        help="Uninstall the MCP Server and IDA plugin. "
        "The IDA plugin is uninstalled immediately. "
        "Optionally specify comma-separated client targets. "
        "Without targets, an interactive selector is shown.",
    )
    parser.add_argument(
        "--allow-ida-free",
        action="store_true",
        help="Allow installation despite IDA Free being installed",
    )
    parser.add_argument(
        "--transport",
        type=str,
        default=None,
        help="MCP transport for install: 'streamable-http' (default), 'stdio', or 'sse'. "
        "For running: use stdio (default) or pass a URL (e.g., http://127.0.0.1:8744[/mcp|/sse])",
    )
    parser.add_argument(
        "--scope",
        type=str,
        choices=["global", "project", "export"],
        default=None,
        help="Installation scope: 'project' (current directory, default), 'global' (user-level), or 'export' (write JSON configs to project folder for manual copy)",
    )
    parser.add_argument(
        "--ida-rpc",
        type=str,
        default=None,
        help=f"IDA RPC server (default: auto-discover, fallback: {DEFAULT_IDA_RPC})",
    )
    parser.add_argument(
        "--config", action="store_true", help="Generate MCP config JSON"
    )
    parser.add_argument(
        "--list-clients",
        action="store_true",
        help="List all available MCP client targets",
    )
    parser.add_argument(
        "--install-deps",
        nargs="?",
        const="all",
        default=None,
        metavar="PACKAGES",
        help="Install optional analysis engines into IDA's Python. "
        "Comma-separated names: 'triton', 'miasm', or 'all' (default when flag given without value). "
        "Example: --install-deps triton,miasm",
    )
    parser.add_argument(
        "--python",
        type=str,
        default=None,
        metavar="PATH",
        help="Explicit Python executable to use for --install-deps "
        "(e.g. C:\\Program Files\\IDA Pro 9.3\\python311\\python.exe). "
        "Auto-detected from registry/IDADIR when omitted.",
    )
    lazy_group = parser.add_mutually_exclusive_group()
    lazy_group.add_argument(
        "--lazy",
        action="store_true",
        default=False,
        help="Expose only 4 meta-tools (list_modules, list_tools, describe_tool, invoke_tool) "
        "instead of all 160+ tools. Reduces agent context usage by ~95%%. "
        "Tools are discovered and invoked on demand through the meta-tools.",
    )
    lazy_group.add_argument(
        "--no-lazy",
        action="store_true",
        default=False,
        help="Force all tools to be exposed upfront, overriding --lazy if it is present "
        "in a saved config. Useful for debugging or clients with very large context windows.",
    )
    args = parser.parse_args()

    # Handle --list-clients independently
    if args.list_clients:
        list_available_clients()
        return

    # Handle --install-deps independently (no IDA RPC needed)
    if args.install_deps is not None:
        packages = [p.strip() for p in args.install_deps.split(",") if p.strip()]
        run_install_deps_command(packages, args)
        return

    # Enable lazy mode before resolving IDA RPC (so dispatch is ready)
    global LAZY_MODE
    if args.lazy and not args.no_lazy:
        LAZY_MODE = True
        print("[MCP] Lazy mode enabled — exposing 4 meta-tools instead of all tools", file=sys.stderr)
    elif args.no_lazy:
        LAZY_MODE = False
        print("[MCP] Normal mode forced — exposing all tools upfront", file=sys.stderr)

    if _TOON_ENABLED and _TOON_AVAILABLE:
        print(
            f"[MCP] TOON encoding active — uniform arrays ≥{_TOON_MIN_ROWS} rows "
            "auto-compressed; structuredContent preserved for schema validation",
            file=sys.stderr,
        )
    elif _TOON_ENABLED and not _TOON_AVAILABLE:
        print(
            "[MCP] TOON encoding inactive (pip install toon_format to enable ~40% token savings)",
            file=sys.stderr,
        )
    else:
        print(
            "[MCP] TOON encoding disabled (SYNAPSE_MCP_TOON=0)",
            file=sys.stderr,
        )

    # Resolve IDA RPC target (explicit or auto-discovery)
    _resolve_ida_rpc(args)

    # Acquire the singleton lock so only one proxy runs per IDA port.
    _acquire_proxy_lock(IDA_PORT)

    # Start background heartbeat so we detect dead connections proactively.
    _start_heartbeat(IDA_HOST, IDA_PORT)

    if LAZY_MODE:
        try:
            _validate_groups()
            list_modules.__doc__ = _build_lazy_directory_description()
            print("[MCP] Lazy directory embedded in list_modules description.", file=sys.stderr)
        except Exception:
            pass

    is_install = args.install is not None
    is_uninstall = args.uninstall is not None

    # Validate flag combinations
    if args.scope and not (is_install or is_uninstall):
        print("--scope requires --install or --uninstall")
        return

    if is_install and is_uninstall:
        print("Cannot install and uninstall at the same time")
        return

    if is_install or is_uninstall:
        run_install_command(
            uninstall=is_uninstall,
            targets_str=args.install if is_install else args.uninstall,
            args=args,
        )
        return

    if args.config:
        print_mcp_config(lazy=args.lazy)
        return

    try:
        transport = args.transport or "stdio"
        if transport == "stdio":
            mcp.stdio()
        else:
            url = urlparse(transport)
            if url.hostname is None or url.port is None:
                raise Exception(f"Invalid transport URL: {args.transport}")
            # NOTE: npx -y @modelcontextprotocol/inspector for debugging
            mcp.serve(url.hostname, url.port, request_handler=ProxyHttpRequestHandler)
            input("Server is running, press Enter or Ctrl+C to stop.")
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        _stop_heartbeat()
        _release_proxy_lock()


if __name__ == "__main__":
    main()
