import argparse
import http.client
import json
import os
import re
import sys
import threading
import time
import traceback
from collections import OrderedDict
from typing import Annotated, TYPE_CHECKING, TypedDict
from urllib.parse import parse_qs, urlparse

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
    from .ida_mcp.rpc import MCP_SERVER_NAME
except ImportError:
    try:
        from ida_mcp.rpc import MCP_SERVER_NAME
    except ImportError:
        MCP_SERVER_NAME = "synapse-mcp"

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

mcp = McpServer(MCP_SERVER_NAME)
dispatch_original = mcp.registry.dispatch

LOCAL_TOOLS = {"list_instances", "select_instance"}
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

    conn = http.client.HTTPConnection(host, port, timeout=30)
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
    conn = http.client.HTTPConnection(host, port, timeout=30)
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


# Prefix-based module mapping for _tool_module().
_TOOL_MODULE_PREFIXES: tuple[tuple[str, str], ...] = (
    ("triton_", "symbolic"),
    ("miasm_", "symbolic"),
    ("angr_", "symbolic"),
    ("lief_", "formats"),
    ("yara_", "formats"),
    ("construct_", "formats"),
    ("cstruct_", "formats"),
    ("filetype_", "formats"),
    ("nx_", "recon"),
    ("flirt_", "recon"),
    ("sig_", "recon"),
    ("recon_", "recon"),
    ("dbg_", "recon"),
)

# Tools without a distinctive prefix that belong to a specific module.
_TOOL_MODULE_EXACT: dict[str, str] = {
    # analysis
    "decompile": "analysis",
    "disasm": "analysis",
    "func_profile": "analysis",
    "analyze_batch": "analysis",
    "xrefs_to": "analysis",
    "xref_query": "analysis",
    "xrefs_to_field": "analysis",
    "callees": "analysis",
    "find_bytes": "analysis",
    "basic_blocks": "analysis",
    "find": "analysis",
    "insn_query": "analysis",
    "export_funcs": "analysis",
    "callgraph": "analysis",
    "get_cfg_dot": "analysis",
    "find_similar_functions": "analysis",
    "trace_data_chain": "analysis",
    "get_bytes": "analysis",
    "read_local_file": "analysis",
    "get_int": "analysis",
    "get_string": "analysis",
    "get_global_value": "analysis",
    "patch": "analysis",
    "put_int": "analysis",
    "survey_binary": "analysis",
    # modify
    "set_comments": "modify",
    "append_comments": "modify",
    "patch_asm": "modify",
    "rename": "modify",
    "define_func": "modify",
    "analyze_range": "modify",
    "scan_and_define_funcs": "modify",
    "add_xref": "modify",
    "define_code": "modify",
    "undefine": "modify",
    "remove_type": "modify",
    "declare_type": "modify",
    "enum_upsert": "modify",
    "read_struct": "modify",
    "search_structs": "modify",
    "type_query": "modify",
    "type_inspect": "modify",
    "set_type": "modify",
    "type_apply_batch": "modify",
    "infer_types": "modify",
    "analyze_constructor": "modify",
    "type_propagate": "modify",
    "stack_frame": "modify",
    "declare_stack": "modify",
    "delete_stack": "modify",
    # recon
    "get_binary_sections": "recon",
    "find_global_writers": "recon",
    "find_vtable_candidates": "recon",
    "list_functions_in_range": "recon",
    "find_indirect_calls": "recon",
    "identify_vtable_call": "recon",
    "analyze_cleanup_function": "recon",
    "find_function_prologues": "recon",
    "apply_flirt_signature": "recon",
    "load_type_library": "recon",
    "list_type_libraries": "recon",
    "sig_suggest_candidates": "recon",
    "make_signature": "recon",
    "make_signature_for_function": "recon",
    "make_signature_for_range": "recon",
    "find_xref_signatures": "recon",
    "scan_signature": "recon",
    "sync_debugger_to_idb": "recon",
    "list_breakpoints": "recon",
    "py_eval": "recon",
    "py_exec_file": "recon",
    # symbolic (composite tools without distinctive prefixes)
    "analyze_function": "symbolic",
    "analyze_component": "symbolic",
    "diff_before_after": "symbolic",
    "trace_data_flow": "symbolic",
    "hybrid_analyze_function": "symbolic",
    "hybrid_deobfuscate_and_patch": "symbolic",
    "hybrid_iterative_deobfuscate": "symbolic",
    "deobfuscate_segment": "symbolic",
    # formats (hybrid format tools)
    "hybrid_lief_checksec_exploit_assess": "formats",
    "hybrid_lief_sync_symbols": "formats",
    "hybrid_lief_yara_section_scan": "formats",
    "hybrid_nx_lief_import_graph": "formats",
    "hybrid_yara_lief_profile": "formats",
    "hybrid_yara_miasm_deobfuscate": "symbolic",
    "hybrid_yara_triton_verify_crypto": "symbolic",
    "hybrid_nx_angr_target_ranking": "symbolic",
    "hybrid_nx_triton_taint_graph": "symbolic",
    "hybrid_nx_yara_cluster_detection": "formats",
    "hybrid_angr_miasm_path": "symbolic",
    "hybrid_angr_stdin_fuzz": "symbolic",
    "hybrid_angr_triton_decompile": "symbolic",
    "hybrid_angr_triton_solve": "symbolic",
    "hybrid_angr_z3_formula": "symbolic",
    # recon workflows
    "workflow_binary_diff_summary": "recon",
    "workflow_find_critical_paths": "recon",
    "workflow_reveng_overview": "recon",
}

# Known core tools; used by _validate_groups() to avoid false-positive warnings.
_CORE_TOOL_NAMES: frozenset[str] = frozenset({
    "server_health", "server_warmup", "lookup_funcs", "int_convert",
    "list_funcs", "func_query", "list_globals", "entity_query",
    "imports", "imports_query", "idb_save", "find_regex", "search_text",
    "read_mcp_output", "list_instances", "select_instance", "get_active_instance",
    "task_submit", "task_cancel", "task_list", "task_poll",
    "idalib_open", "idalib_close", "idalib_switch", "idalib_unbind",
    "idalib_list", "idalib_current", "idalib_save", "idalib_health", "idalib_warmup",
})


def _tool_module(name: str) -> str:
    """Map a tool name to a logical module group for list_modules grouping."""
    if name in _TOOL_MODULE_EXACT:
        return _TOOL_MODULE_EXACT[name]
    for prefix, module in _TOOL_MODULE_PREFIXES:
        if name.startswith(prefix):
            return module
    if name.startswith("hybrid_"):
        if any(x in name for x in ("triton", "miasm", "angr")):
            return "symbolic"
        if any(x in name for x in ("lief", "yara", "construct", "cstruct")):
            return "formats"
        return "core"
    if name.startswith("workflow_"):
        return "symbolic"
    return "core"


def _proxy_to_ida(payload: bytes | str | dict) -> dict:
    """Send a JSON-RPC request to the active IDA instance and return the response."""
    host, port = _get_active_ida_target()
    return _proxy_to_instance(host, port, payload)


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
            return dispatch_original(request)

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

    try:
        return _proxy_to_ida(request)
    except Exception as e:
        full_info = traceback.format_exc()
        request_id = request_obj.get("id")
        if request_id is None:
            return None  # Notification, no response needed

        shortcut = "Ctrl+Option+M" if sys.platform == "darwin" else "Ctrl+Alt+M"
        return JsonRpcResponse(
            {
                "jsonrpc": "2.0",
                "error": {
                    "code": -32000,
                    "message": (
                        "Failed to complete request to IDA Pro. "
                        f"Did you run Edit -> Plugins -> MCP ({shortcut}) to start the server?\n"
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


# ============================================================================
# Lazy meta-tools — only exposed when --lazy flag is active
# ============================================================================


@mcp.tool
def list_modules() -> list[dict]:
    """[lazy-mode] List available tool groups. Call list_tools(module=...) to see tools per group."""
    modules = _get_lazy_module_cache()
    return [{"module": m, "tool_count": len(v)} for m, v in sorted(modules.items())]


@mcp.tool
def list_tools(
    module: Annotated[str | None, "Module group to filter by: 'core', 'analysis', 'modify', 'symbolic', 'formats', 'recon'. Omit for all tools."] = None,
    limit: Annotated[int, "Maximum number of tools to return (default 50)."] = 50,
    offset: Annotated[int, "Number of tools to skip for pagination (default 0)."] = 0,
) -> dict:
    """[lazy-mode] List available tools with one-line descriptions. Filter by module group or omit for all tools."""
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


@mcp.tool
def invoke_tool(
    tool: Annotated[str, "Tool name to invoke (from list_tools)"],
    args: Annotated[dict | None, "Tool arguments as a dict. Use describe_tool first to see required fields."] = None,
) -> object:
    """[lazy-mode] Invoke any IDA tool by name. Use list_tools() to discover tools, describe_tool() to get schemas."""
    global _lazy_tools_cache, _lazy_module_cache
    if tool == "__reset_cache__":
        with _lazy_tools_cache_lock:
            _lazy_tools_cache = None
            _lazy_module_cache = None
        return {"ok": True, "message": "Tool cache cleared."}
    host, port = _get_active_ida_target()
    for attempt in range(2):
        resp = _proxy_to_instance(host, port, {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": tool, "arguments": args or {}},
        })
        if resp is None:
            return {
                "ok": False,
                "error": "No response from IDA",
                "hint": "Ensure the IDA Pro MCP plugin is running and the target instance is reachable.",
            }
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
                "hint": "Call list_modules() to see available groups, then list_tools(module=...) to find the right tool name.",
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
                "hint": "Call list_modules() to see available groups, then list_tools(module=...) to find the right tool name.",
            }
        # Prefer structuredContent (already a dict); fall back to parsing the text content
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

    # Resolve IDA RPC target (explicit or auto-discovery)
    _resolve_ida_rpc(args)

    if LAZY_MODE:
        try:
            _validate_groups()
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


if __name__ == "__main__":
    main()
