import inspect
import json
import os
import threading
from typing import Any, Optional
from .arg_aliases import normalize_tool_args


def _tool_param_names(fn) -> "set[str] | None":
    """Return the set of a tool's declared parameter names, or None if it cannot
    be determined reliably (e.g. the function accepts **kwargs). None disables
    the schema-aware alias reversal and falls back to blind normalization.
    """
    if fn is None:
        return None
    try:
        sig = inspect.signature(fn)
    except (ValueError, TypeError):
        return None
    names: set[str] = set()
    for p in sig.parameters.values():
        if p.kind in (p.VAR_POSITIONAL, p.VAR_KEYWORD):
            return None  # *args/**kwargs — real params unknowable
        names.add(p.name)
    return names or None
from .zeromcp import (
    McpRpcRegistry,
    McpServer,
    McpToolError,
    McpHttpRequestHandler,
    get_current_request_external_base_url,
)

MCP_SERVER_NAME = "synapse-mcp"
MCP_UNSAFE: set[str] = set()
MCP_EXTENSIONS: dict[str, set[str]] = {}  # group -> set of function names
MCP_SERVER = McpServer(MCP_SERVER_NAME, extensions=MCP_EXTENSIONS)

# Optionally compress uniform-array responses into TOON tabular form for the
# direct-HTTP transport (client → IDA plugin). DISABLED BY DEFAULT: TOON drops
# structuredContent, which breaks schema-enforcing MCP clients (and saves them
# nothing). The post-processor self-gates on SYNAPSE_MCP_TOON; see toon_encode.py.
try:
    from .toon_encode import TOON_AVAILABLE as _TOON_AVAILABLE
    from .toon_encode import TOON_ENABLED as _TOON_ENABLED
    from .toon_encode import maybe_toon_encode_result as _maybe_toon

    MCP_SERVER.result_post_processor = lambda _name, result: _maybe_toon(result)
    if _TOON_ENABLED and _TOON_AVAILABLE:
        print("[synapse-mcp] TOON response compression active (threshold: 20 rows) — structuredContent preserved")
    elif _TOON_ENABLED and not _TOON_AVAILABLE:
        print("[synapse-mcp] TOON inactive — install toon_format in IDA's Python to enable")
    else:
        print("[synapse-mcp] TOON disabled — set SYNAPSE_MCP_TOON=0 to disable, unset to re-enable")
except Exception as _toon_init_err:
    print(f"[synapse-mcp] TOON init error: {_toon_init_err}")

# ============================================================================
# Tool Grouping and Profiles
# ============================================================================

_TOOL_MODULE_PREFIXES: tuple[tuple[str, str], ...] = (
    ("triton_", "symbolic"),
    ("miasm_", "symbolic"),
    ("angr_", "symbolic"),
    ("unicorn_", "symbolic"),
    ("lief_", "formats"),
    ("yara_", "formats"),
    ("construct_", "formats"),
    ("cstruct_", "formats"),
    ("filetype_", "formats"),
    ("elf_", "formats"),
    ("nx_", "recon"),
    ("flirt_", "recon"),
    ("sig_", "recon"),
    ("recon_", "recon"),
    ("dbg_", "recon"),
    ("numpy_", "analysis"),
    ("xor_", "analysis"),
)

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
    "find_xor_pattern": "analysis",
    "xor_invert": "analysis",
    "check_constraint_type": "analysis",
    "find_alphabet_encoder": "analysis",
    "static_invert_xor_with_constraints": "analysis",
    "bf_analyze": "analysis",
    "get_bytes": "analysis",
    "read_local_file": "analysis",
    "get_int": "analysis",
    "get_string": "analysis",
    "get_global_value": "analysis",
    "patch": "analysis",
    "put_int": "analysis",
    "survey_binary": "analysis",
    "analyze_function_full": "analysis",
    # enhanced analysis tools
    "list_functions_enhanced": "analysis",
    "list_classes": "analysis",
    "decompile_batch": "analysis",
    "get_function_callers": "analysis",
    "get_function_signature": "analysis",
    "get_function_jump_targets": "analysis",
    "get_function_hash": "analysis",
    "get_bulk_function_hashes": "analysis",
    "analyze_function_completeness": "analysis",
    "batch_analyze_completeness": "analysis",
    "diff_functions": "analysis",
    "demangle_names": "analysis",
    "analysis_status": "analysis",
    "decompile_range": "analysis",
    "disasm_batch": "analysis",
    "find_functions_by_string": "analysis",
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
    "struct_recovery": "modify",
    "mark_functions_as_stubs": "modify",
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
    "dump_vtable": "recon",
    "resolve_com_vtable": "recon",
    "find_render_loop": "recon",
    "find_dll_by_purpose": "recon",
    "py_eval": "recon",
    "py_exec_file": "recon",
    # composite / analysis tools without distinctive prefixes
    "find_callers_of_import": "analysis",
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
    "hybrid_angr_unicorn_concrete": "symbolic",
    "hybrid_unicorn_triton_analyze": "symbolic",
    "hybrid_unicorn_miasm_hot_blocks": "symbolic",
    "hybrid_unicorn_networkx_exec_graph": "symbolic",
    "workflow_unicorn_decrypt_analyze": "symbolic",
    # recon workflows
    "workflow_binary_diff_summary": "recon",
    "workflow_find_critical_paths": "recon",
    "workflow_reveng_overview": "recon",
}


def get_tool_group(name: str) -> str:
    """Map a tool name to a logical module group for profile/lazy-mode grouping."""
    if name in _TOOL_MODULE_EXACT:
        return _TOOL_MODULE_EXACT[name]
    for prefix, module in _TOOL_MODULE_PREFIXES:
        if name.startswith(prefix):
            return module
    if name.startswith("hybrid_"):
        if any(x in name for x in ("triton", "miasm", "angr")):
            return "symbolic"
        if any(x in name for x in ("lief", "yara", "construct", "cstruct", "elf")):
            return "formats"
        return "core"
    if name.startswith("workflow_"):
        return "symbolic"
    return "core"


# Profile registry: profile_name -> frozenset of tool names included in that profile.
# Built lazily after all api_*.py modules load. "all" is always registered.
MCP_PROFILES: dict[str, frozenset[str]] = {}
MCP_DEFAULT_PROFILE: str | None = None  # None = expose all tools (backward compat)


def register_profile(name: str, tools: set[str]) -> None:
    """Register a named tool profile. Called during module init."""
    MCP_PROFILES[name] = frozenset(tools)


def get_profile_tools(profile: str | None) -> frozenset[str] | None:
    """Return tool name set for a profile, or None if all tools should be shown."""
    if profile is None or profile == "all":
        return None
    return MCP_PROFILES.get(profile)

# ============================================================================
# Output Size Limiting
# ============================================================================

OUTPUT_LIMIT_MAX_CHARS = 50000
OUTPUT_CACHE_MAX_SIZE = 100
_output_cache: dict[str, Any] = {}
_download_base_url: str = os.environ.get("IDA_MCP_URL", "http://127.0.0.1:13337")


def set_download_base_url(url: str) -> None:
    global _download_base_url
    _download_base_url = url.rstrip("/")


def get_download_base_url() -> str:
    return get_current_request_external_base_url() or _download_base_url


def get_current_transport_session_id() -> str | None:
    return MCP_SERVER.get_current_transport_session_id()


def _generate_output_id() -> str:
    import uuid

    return str(uuid.uuid4())


OUTPUT_LIMIT_PREVIEW_ITEMS = 10
OUTPUT_LIMIT_PREVIEW_STR_LEN = 1000


def _truncate_value(value: Any, depth: int = 0) -> Any:
    if depth > 5:
        return value

    if isinstance(value, str) and len(value) > OUTPUT_LIMIT_PREVIEW_STR_LEN:
        return value[:OUTPUT_LIMIT_PREVIEW_STR_LEN] + f"... [{len(value)} chars total]"

    if isinstance(value, list):
        # IMPORTANT: Do not inject sentinel objects like {"_truncated": "..."} into lists.
        # Many tool schemas constrain list item shapes (additionalProperties: false),
        # so sentinels can break structured output validation. Truncation is reported
        # via _meta.ida_mcp and the download_hint content.
        return [
            _truncate_value(item, depth + 1)
            for item in value[:OUTPUT_LIMIT_PREVIEW_ITEMS]
        ]

    if isinstance(value, dict):
        return {k: _truncate_value(v, depth + 1) for k, v in value.items()}

    return value


def _build_download_meta(output_id: str, total_chars: int) -> dict:
    download_url = f"{get_download_base_url()}/output/{output_id}.json"
    return {
        "output_truncated": True,
        "total_chars": total_chars,
        "output_id": output_id,
        "download_url": download_url,
        "download_hint": (
            f"Output truncated ({total_chars} chars). "
            f"Retrieve with: read_mcp_output(output_id='{output_id}'). "
            f"Or via HTTP: {download_url}"
        ),
    }


def get_cached_output(output_id: str) -> Optional[Any]:
    return _output_cache.get(output_id)


def _cache_output(output_id: str, data: Any) -> None:
    if len(_output_cache) >= OUTPUT_CACHE_MAX_SIZE:
        oldest_key = next(iter(_output_cache))
        del _output_cache[oldest_key]
    _output_cache[output_id] = data


def _install_tools_call_patch() -> None:
    original = MCP_SERVER.registry.methods["tools/call"]
    # Thread-local re-entry guard: the task worker dispatches tools through
    # tools/call internally, so we must not re-submit a prefer_async tool
    # when execution originates from _execute_task().
    _reentry = threading.local()

    def patched(
        name: str, arguments: Optional[dict] = None, _meta: Optional[dict] = None
    ) -> dict:
        tool_fn = MCP_SERVER.tools.methods.get(name)

        # Normalize arg aliases before dispatch so every MCP transport
        # (HTTP, SSE, stdio proxy) benefits — not just proxy-routed calls.
        # Pass the tool's real parameter names so the schema-aware reversal can
        # restore canonical names (addr, max_results, …) that a blind global
        # rename would otherwise leave the tool unable to accept.
        if arguments:
            arguments = normalize_tool_args(
                name, arguments, valid_params=_tool_param_names(tool_fn)
            )

        # === auto-async: if the tool has prefer_async=True, auto-submit
        # as a background task so the agent never times out waiting ===
        if (tool_fn is not None
                and getattr(tool_fn, "__ida_mcp_prefer_async__", False)
                and not getattr(_reentry, "active", False)):
            task_submit_fn = MCP_SERVER.tools.methods.get("task_submit")
            if task_submit_fn is not None:
                try:
                    result = task_submit_fn(tool_name=name, arguments=arguments or {})
                    if result.get("task_id"):
                        return {
                            "structuredContent": result,
                            "content": [{
                                "type": "text",
                                "text": json.dumps(result, separators=(",", ":")),
                            }],
                            "isError": False,
                            "_meta": {"ida_mcp": {"async_submit": True}},
                        }
                except Exception:
                    pass  # fall through to synchronous execution

        # === Strict guard for very_large binaries ===
        # These tools need enumeration or full-binary traversal, which
        # blocks IDA's non-interruptible main thread and crashes the
        # HTTP plugin. Rather than trying to run them, we reject upfront.
        _HEAVY_TOOLS_VERY_LARGE = frozenset({
            "find_regex", "search_text",        # scan all strings/text
            "survey_binary",                     # enumerates everything
            "imports", "imports_query",          # import enumeration
            "callgraph",                         # full call graph
            "find_similar_functions",            # all-function scan
            "batch_analyze_completeness",        # all-function scan
            "get_bulk_function_hashes",          # all-function scan
            "workflow_reveng_overview",          # composite heavy ops
            "nx_call_graph",                     # full graph build
            "nx_central_functions",              # full graph metrics
            "nx_communities",                    # full graph partitioning
        })
        _HEAVY_ALT = {
            "find_regex": (
                "Use `lief_strings(file_path=...)` for raw file byte scanning "
                "(works outside IDA's string database), "
                "`find_callers_of_import(name=...)` for import tracing, "
                "or `numpy_memmap_scan(file_path=..., pattern_hex=...)` "
                "for hex pattern search."
            ),
            "search_text": (
                "Use `find_regex(pattern=...)` with a narrow pattern instead."
            ),
            "survey_binary": (
                "Use `lief_info()` for binary metadata, "
                "`lief_imports()` for import table, "
                "and `list_functions_enhanced(limit=100)` for function browsing."
            ),
            "imports": (
                "Use `lief_imports()` instead — it reads from the PE file "
                "on disk without blocking the IDA main thread."
            ),
            "imports_query": (
                "Use `lief_imports(library_filter='dllname')` instead."
            ),
            "callgraph": (
                "Decompose into smaller steps: `callees()` and `get_function_callers()` "
                "on individual functions, then assemble the graph client-side."
            ),
            "find_similar_functions": (
                "Limit scope with `scope='.text'` and small max_results (≤5). "
                "On smaller binaries, this tool is safe for binary-wide scan."
            ),
            "batch_analyze_completeness": (
                "Use `analyze_function_completeness(addr='0x...')` on individual "
                "functions instead of batch-scanning the entire binary."
            ),
            "get_bulk_function_hashes": (
                "Use `get_function_hash(addr='0x...')` on individual functions."
            ),
            "workflow_reveng_overview": (
                "Use `quick_mode=True` and limit `top_n` to 20."
            ),
        }
        if (name in _HEAVY_TOOLS_VERY_LARGE
                and not getattr(_reentry, "active", False)):
            from . import api_core as _core
            if not _core._BINARY_CLASS_INITIALIZED:
                _core._ensure_binary_class()
            if _core._BINARY_CLASS == "very_large":
                alt = _HEAVY_ALT.get(name, "Use smaller-scoped alternatives.")
                func_str = (f"{_core._FUNC_COUNT_CACHE // 1000}K functions" 
                             if _core._FUNC_COUNT_CACHE > 0 else "a very large binary")
                error_msg = (
                    f"`{name}` cannot run on this binary ({func_str}). "
                    f"IDA's main thread is non-interruptible and this operation "
                    f"would block or crash the HTTP plugin. {alt}"
                )
                return {
                    "content": [{
                        "type": "text",
                        "text": json.dumps({"ok": False, "error": error_msg}, separators=(",", ":")),
                    }],
                    "isError": True,
                }

        response = original(name, arguments, _meta)

        if response.get("isError"):
            return response

        structured = response.get("structuredContent")
        if structured is None:
            return response

        serialized = json.dumps(structured)
        if len(serialized) <= OUTPUT_LIMIT_MAX_CHARS:
            return response

        output_id = _generate_output_id()
        _cache_output(output_id, structured)

        preview = _truncate_value(structured)
        download_meta = _build_download_meta(output_id, len(serialized))

        content = [{
            "type": "text",
            "text": json.dumps(preview, separators=(",", ":")),
        }, {
            "type": "text",
            "text": download_meta["download_hint"],
        }]

        return {
            "structuredContent": preview,
            "content": content,
            "isError": False,
            "_meta": {"ida_mcp": download_meta},
        }

    MCP_SERVER.registry.methods["tools/call"] = patched
    MCP_SERVER.registry._reentry_guard = _reentry  # expose for task worker


# Install the output limiting patch
_install_tools_call_patch()


# ============================================================================
# Decorators
# ============================================================================


def tool(func):
    return MCP_SERVER.tool(func)


def resource(uri):
    return MCP_SERVER.resource(uri)


def unsafe(func):
    MCP_UNSAFE.add(func.__name__)
    return func


def ext(group: str):
    """Mark a tool as belonging to an extension group.

    Tools in extension groups are hidden by default. Enable via ?ext=group query param.
    Example: @ext("dbg") marks debugger tools that require ?ext=dbg to be visible.
    """

    def decorator(func):
        if group not in MCP_EXTENSIONS:
            MCP_EXTENSIONS[group] = set()
        MCP_EXTENSIONS[group].add(func.__name__)
        return func

    return decorator


__all__ = [
    "McpRpcRegistry",
    "McpServer",
    "McpToolError",
    "McpHttpRequestHandler",
    "MCP_SERVER",
    "MCP_UNSAFE",
    "MCP_EXTENSIONS",
    "MCP_PROFILES",
    "MCP_DEFAULT_PROFILE",
    "tool",
    "unsafe",
    "ext",
    "resource",
    "register_profile",
    "get_profile_tools",
    "get_tool_group",
    "get_cached_output",
    "set_download_base_url",
    "get_download_base_url",
    "get_current_transport_session_id",
]
