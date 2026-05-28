"""Cross-instance targeting and fan-out for multi-binary analysis.

The MCP server already supports stateful session routing via
``select_instance`` — once selected, every subsequent call goes to that
instance. That is poor for cross-referencing two or more open binaries,
which requires running the *same* query against several instances and
comparing the results without losing track of which IDB is active.

This module provides the stateless primitives both routing layers
(``server.py`` proxy and ``api_discovery.py`` IDA-side redirect) wire up as
tools:

- ``run_invoke_on_instance`` — call one tool against one explicitly named
  instance, without changing the session's active target.
- ``run_compare_instances`` — fan one tool out across several (or all)
  instances and return labeled, side-by-side results.

Instances are addressed by *binary name* (stable across restarts) or by
*port* (unambiguous). Every failure mode returns a structured error with an
``error_type`` and, where useful, the list of currently available instances
so an agent can self-correct.
"""

import json
import os
from typing import Callable, TypedDict

# Resilient import: as a package submodule (inside IDA) the relative import
# works; when server.py loads this as a bare top-level module (outside IDA,
# where ida_mcp/__init__.py's idaapi import fails), fall back to the flat name
# with the ida_mcp dir already on sys.path.
try:
    from .discovery import discover_instances, probe_instance
except ImportError:
    from discovery import discover_instances, probe_instance

# Tools that must never be fanned out / nested — doing so would recurse the
# routing layer back onto itself.
_NON_FANOUT_TOOLS = frozenset(
    {"invoke_on_instance", "compare_instances", "select_instance"}
)

# proxy_fn(host, port, payload_bytes) -> JSON-RPC response dict.
ProxyFn = Callable[[str, int, bytes], dict]


class InstanceRef(TypedDict, total=False):
    binary: str
    port: int
    host: str


class InstanceResolution(TypedDict, total=False):
    ok: bool
    host: str
    port: int
    binary: str
    error: str
    error_type: str
    available: list[InstanceRef]


class InstanceCallResult(TypedDict, total=False):
    instance: str
    host: str
    port: int
    ok: bool
    result: object
    error: str
    error_type: str


class CompareInstancesResult(TypedDict, total=False):
    ok: bool
    tool: str
    count: int
    success_count: int
    fail_count: int
    results: list[InstanceCallResult]
    error: str
    error_type: str


def _inst_display_name(inst: dict) -> str:
    """Best human-readable label for an instance (for error messages)."""
    binary = (inst.get("binary") or "").strip()
    if binary:
        return os.path.basename(binary)
    idb = (inst.get("idb_path") or "").strip()
    if idb:
        return os.path.basename(idb)
    return f"port:{inst.get('port', '?')}"


def _inst_match_tokens(inst: dict) -> tuple[set[str], list[str]]:
    """Return (exact_set, substring_list) for case-insensitive name matching.

    exact_set  — lowercased names where an exact equality match should succeed:
                 binary basename (with ext), idb_path basename (with ext),
                 idb_path stem (without ext).
    substring_list — lowercased strings to search for a substring match:
                     binary full path, idb full path.

    Covering both the binary field and the idb_path guards against IDA instances
    that register with an empty/null binary name but a populated idb_path, and
    against callers who pass a name like "engine" (no extension) that would not
    exactly match "engine.dll" but does exactly match the idb stem "engine".
    """
    exact: set[str] = set()
    substr: list[str] = []
    binary = (inst.get("binary") or "").strip()
    if binary:
        bname = os.path.basename(binary).lower()
        exact.add(bname)          # "engine.dll"
        substr.append(binary.lower())  # full path substring fallback
    idb = (inst.get("idb_path") or "").strip()
    if idb:
        ibase = os.path.basename(idb).lower()  # "engine.i64" / "engine.idb"
        exact.add(ibase)
        exact.add(os.path.splitext(ibase)[0])  # "engine" (extension-free)
        substr.append(idb.lower())
    return exact, substr


def _available_refs(instances: list[dict]) -> list[InstanceRef]:
    return [
        {
            "binary": _inst_display_name(i),
            "port": i.get("port"),
            "host": i.get("host"),
        }
        for i in instances
    ]


def resolve_instance(selector: "str | int") -> InstanceResolution:
    """Resolve a binary-name-or-port selector to a concrete (host, port).

    ``selector`` may be a port (int or numeric string) or a binary name
    (case-insensitive). Matching order:
      1. Exact basename match against binary field, idb basename, and idb stem
         (so both 'Engine.dll' and 'Engine' resolve correctly).
      2. Substring match against the full binary path and idb path.
    Returns a structured error — including the list of available instances —
    when resolution fails or is ambiguous.
    """
    instances = discover_instances()
    available = _available_refs(instances)
    if not instances:
        return {
            "ok": False,
            "error_type": "no_instances",
            "error": (
                "No IDA instances are currently registered. Open the target "
                "binary in IDA Pro with the MCP plugin running, then retry."
            ),
            "available": [],
        }

    # Port selector (int or numeric string).
    port: int | None = None
    if isinstance(selector, int):
        port = selector
    elif isinstance(selector, str) and selector.strip().isdigit():
        port = int(selector.strip())
    if port is not None:
        for inst in instances:
            if inst.get("port") == port:
                return {
                    "ok": True,
                    "host": inst["host"],
                    "port": inst["port"],
                    "binary": _inst_display_name(inst),
                }
        return {
            "ok": False,
            "error_type": "port_not_found",
            "error": f"No IDA instance is listening on port {port}.",
            "available": available,
        }

    # Binary-name selector (case-insensitive).
    name = str(selector).strip().lower()
    if not name:
        return {
            "ok": False,
            "error_type": "empty_selector",
            "error": "Instance selector was empty. Pass a binary name (e.g. 'Engine.dll') or a port.",
            "available": available,
        }

    # Pass 1: exact match (basename / idb-stem equality).
    exact = [inst for inst in instances if name in _inst_match_tokens(inst)[0]]
    # Pass 2: substring match across full binary/idb paths.
    matches = exact or [
        inst for inst in instances if any(name in h for h in _inst_match_tokens(inst)[1])
    ]
    if not matches:
        return {
            "ok": False,
            "error_type": "binary_not_found",
            "error": f"No open IDA instance matches '{selector}'.",
            "available": available,
        }
    if len(matches) > 1:
        return {
            "ok": False,
            "error_type": "ambiguous",
            "error": (
                f"'{selector}' matches {len(matches)} open instances. "
                "Disambiguate by passing the exact port instead."
            ),
            "available": _available_refs(matches),
        }
    inst = matches[0]
    return {
        "ok": True,
        "host": inst["host"],
        "port": inst["port"],
        "binary": _inst_display_name(inst),
    }


def _unpack_response(resp: dict | None) -> "tuple[bool, object, str | None]":
    """Unpack a JSON-RPC tools/call response into (ok, result, error)."""
    if resp is None:
        return False, None, "No response from instance."
    if "error" in resp:
        err = resp.get("error") or {}
        return False, None, err.get("message", "RPC error") if isinstance(err, dict) else str(err)
    call_result = resp.get("result", {})
    if not isinstance(call_result, dict):
        return True, call_result, None
    if call_result.get("isError"):
        content = call_result.get("content", [])
        msg = content[0].get("text", "tool error") if content else "tool error"
        return False, None, msg
    structured = call_result.get("structuredContent")
    if structured is not None:
        return True, structured, None
    content = call_result.get("content", [])
    if content:
        try:
            return True, json.loads(content[0].get("text", "null")), None
        except (json.JSONDecodeError, KeyError, AttributeError):
            return True, content[0].get("text"), None
    return True, None, None


def _invoke_resolved(
    proxy_fn: ProxyFn, host: str, port: int, binary: str, tool: str, args: dict | None
) -> InstanceCallResult:
    """Run one tool against an already-resolved (host, port)."""
    if not probe_instance(host, port):
        return {
            "instance": binary,
            "host": host,
            "port": port,
            "ok": False,
            "error_type": "unreachable",
            "error": (
                f"Instance '{binary}' at {host}:{port} is registered but not "
                "reachable. It may have been closed — call list_instances to refresh."
            ),
        }
    payload = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": tool, "arguments": args or {}},
        }
    ).encode("utf-8")
    try:
        resp = proxy_fn(host, port, payload)
    except Exception as e:  # noqa: BLE001 — surface any transport error to the agent
        return {
            "instance": binary,
            "host": host,
            "port": port,
            "ok": False,
            "error_type": "proxy_error",
            "error": f"Failed to call '{tool}' on '{binary}' ({host}:{port}): {e}",
        }
    ok, result, err = _unpack_response(resp)
    if not ok:
        return {
            "instance": binary,
            "host": host,
            "port": port,
            "ok": False,
            "error_type": "tool_error",
            "error": err or "Tool reported an error.",
        }
    return {
        "instance": binary,
        "host": host,
        "port": port,
        "ok": True,
        "result": result,
    }


def _reject_nested_tool(tool: str) -> "dict | None":
    if tool in _NON_FANOUT_TOOLS:
        return {
            "ok": False,
            "error_type": "invalid_tool",
            "error": (
                f"'{tool}' cannot be invoked across instances — it is a routing "
                "tool and would recurse. Pass an analysis tool name (e.g. "
                "'lief_exports', 'decompile', 'get_function_hash')."
            ),
        }
    return None


def run_invoke_on_instance(
    proxy_fn: ProxyFn,
    instance: "str | int",
    tool: str,
    args: dict | None = None,
) -> InstanceCallResult:
    """Resolve ``instance`` and run ``tool`` against it once (stateless)."""
    rejected = _reject_nested_tool(tool)
    if rejected is not None:
        return rejected  # type: ignore[return-value]
    res = resolve_instance(instance)
    if not res.get("ok"):
        return res  # type: ignore[return-value]
    return _invoke_resolved(
        proxy_fn, res["host"], res["port"], res.get("binary", ""), tool, args
    )


def run_compare_instances(
    proxy_fn: ProxyFn,
    tool: str,
    args: dict | None = None,
    instances: "list[str | int] | None" = None,
) -> CompareInstancesResult:
    """Fan ``tool`` out across the named instances (or all if omitted)."""
    rejected = _reject_nested_tool(tool)
    if rejected is not None:
        return rejected  # type: ignore[return-value]

    discovered = discover_instances()
    if not discovered:
        return {
            "ok": False,
            "tool": tool,
            "error_type": "no_instances",
            "error": (
                "No IDA instances are currently registered. Open at least two "
                "binaries in IDA Pro with the MCP plugin running to cross-reference them."
            ),
            "results": [],
            "count": 0,
            "success_count": 0,
            "fail_count": 0,
        }

    results: list[InstanceCallResult] = []
    if instances:
        for sel in instances:
            res = resolve_instance(sel)
            if not res.get("ok"):
                results.append(
                    {
                        "instance": str(sel),
                        "ok": False,
                        "error_type": res.get("error_type"),
                        "error": res.get("error"),
                    }
                )
                continue
            results.append(
                _invoke_resolved(
                    proxy_fn,
                    res["host"],
                    res["port"],
                    res.get("binary", ""),
                    tool,
                    args,
                )
            )
    else:
        for inst in discovered:
            results.append(
                _invoke_resolved(
                    proxy_fn,
                    inst["host"],
                    inst["port"],
                    os.path.basename(inst.get("binary", "") or ""),
                    tool,
                    args,
                )
            )

    success = sum(1 for r in results if r.get("ok"))
    return {
        "ok": success > 0,
        "tool": tool,
        "count": len(results),
        "success_count": success,
        "fail_count": len(results) - success,
        "results": results,
    }
