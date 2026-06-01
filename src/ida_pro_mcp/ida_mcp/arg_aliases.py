"""
Parameter alias normalization for Synapse MCP.

Defined here (no IDA imports) so both the proxy (server.py) and the
IDA plugin (rpc.py) share a single source of truth.  Changes to any
alias table immediately take effect for every transport: HTTP, SSE, and
the stdio proxy.

How normalization works
-----------------------
Global aliases fire first and rename agent-natural names to canonical
parameter names (e.g. ``addr`` → ``address``).  Per-tool aliases fire
second and handle tools whose real parameter differs from the canonical
name (e.g. ``decompile`` takes ``addr``, not ``address``, so the global
rename must be reversed).

The rule is: only rename when the source key is present AND the target
key is absent.  When both are present the canonical key wins silently.
This makes the operation idempotent — double-normalizing a request is
safe and produces the same result.
"""

# ---------------------------------------------------------------------------
# Global aliases — applied to every tools/call regardless of tool name.
# key   = alias the agent may naturally send
# value = canonical parameter name the tool actually declares
# ---------------------------------------------------------------------------
_GLOBAL_ARG_ALIASES: dict[str, str] = {
    # address / addr — "address" is more natural English;
    # most tools use "addr" so the global renames to "address" and
    # per-tool flip-flops restore "addr" for tools that need it.
    "addr":             "address",
    # plural address variants
    "addresses":        "addrs",
    # limit / count synonyms
    "max_results":      "limit",
    "max_entries":      "limit",
    # range helpers — many agent prompts use start_address / start_ea / src
    "start_address":    "start",
    "end_address":      "end",
    "start_ea":         "start",
    "target_ea":        "end",
    "addr_a":           "start",
    "addr_b":           "end",
    "src":              "start",
    "dst":              "end",
    # misc normalization
    "architecture":     "arch",
    "yara_rules":       "rules",
    "custom_rules":     "rules",
    "segment_name":     "segment",
    "segment_names":    "segment",
    "max_instructions": "max_insns",
    "path":             "file_path",
    "binary_path":      "file_path",
    "output_path":      "file_path",
}

# ---------------------------------------------------------------------------
# Per-tool aliases — applied only when the named tool is being called.
# ---------------------------------------------------------------------------
_TOOL_ARG_ALIASES: dict[str, dict[str, str]] = {
    # -----------------------------------------------------------------------
    # addr/address flip-flops — tools that declare "addr" as their real param.
    # Global addr→address fires first; per-tool reverses it for these tools.
    # -----------------------------------------------------------------------
    "decompile":                  {"address": "addr"},
    # disasm uses max_instructions (not max_insns); reverse the global rename.
    "disasm":                     {"address": "addr", "max_insns": "max_instructions"},
    "analyze_function":           {"address": "addr"},
    "diff_before_after":          {"address": "addr"},
    # trace_data_flow takes a single starting addr; "start" maps to it via
    # the global src→start chain: src→start→addr.
    "trace_data_flow":            {"address": "addr", "start": "addr"},
    "dbg_run_to":                 {"address": "addr"},
    "remove_type":                {"address": "addr"},
    "find_global_writers":        {"address": "addr"},
    "dump_vtable":                {"address": "addr"},
    "analyze_cleanup_function":   {"address": "addr"},
    "analyze_constructor":        {"address": "addr"},
    "type_propagate":             {"address": "addr"},
    # -----------------------------------------------------------------------
    # search_text — cursor is a resume hex-address, not a numeric offset.
    # "start" maps naturally (a start address IS a cursor value).
    # "offset" maps too: offset=0 → cursor=0 which is falsy, so the tool
    # correctly starts from the first segment (same as cursor="").
    # -----------------------------------------------------------------------
    "search_text":                {"start": "cursor", "offset": "cursor"},
    # -----------------------------------------------------------------------
    # Batch tools: real param is "addresses" (not "addrs").
    # Global addresses→addrs fires first; per-tool reverses back.
    # -----------------------------------------------------------------------
    "decompile_batch":            {"addrs": "addresses"},
    # disasm_batch uses max_instructions (not max_insns); reverse global rename.
    "disasm_batch":               {"addrs": "addresses", "max_insns": "max_instructions"},
    "triton_replay_instructions": {"addrs": "addresses"},
    "yara_function_classifier":   {"addrs": "addresses"},
    # -----------------------------------------------------------------------
    # Batch tools: real param is "addrs" (plural) but accepts list[str]|str.
    # Global fires addr→address; per-tool maps address→addrs so a single
    # "addr" or "address" input reaches the tool correctly.
    # -----------------------------------------------------------------------
    # --- cross-reference / call-graph ---
    "xrefs_to":                   {"address": "addrs"},
    "callees":                    {"address": "addrs"},
    "get_function_callers":       {"address": "addrs"},
    # --- analysis / profiling ---
    "basic_blocks":               {"address": "addrs"},
    "export_funcs":               {"address": "addrs"},
    "get_function_signature":     {"address": "addrs"},
    "get_function_jump_targets":  {"address": "addrs"},
    "get_function_hash":          {"address": "addrs"},
    "analyze_function_completeness": {"address": "addrs"},
    "analyze_component":          {"address": "addrs"},
    # --- type / stack ---
    "stack_frame":                {"address": "addrs"},
    "infer_types":                {"address": "addrs"},
    # --- signatures / debug ---
    "make_signature":             {"address": "addrs"},
    "make_signature_for_function": {"address": "addrs"},
    "dbg_add_bp":                 {"address": "addrs"},
    "dbg_delete_bp":              {"address": "addrs"},
    # -----------------------------------------------------------------------
    # Custom name variants
    # -----------------------------------------------------------------------
    "find":                       {"addrs": "targets",  "addresses": "targets"},
    "callgraph":                  {"addrs": "roots",    "addresses": "roots"},
    # -----------------------------------------------------------------------
    # limit / count / top variants
    # -----------------------------------------------------------------------
    # find_similar_functions uses max_results as its REAL param — protect it
    # from the global max_results→limit rename and also accept "limit".
    "find_similar_functions":     {"limit": "max_results"},
    "list_functions_enhanced":    {"limit": "count"},
    "list_classes":               {"limit": "count"},
    "imports":                    {"limit": "count"},
    "get_bulk_function_hashes":   {"limit": "count"},
    "batch_analyze_completeness": {"limit": "count"},
    "construct_parse_ida_struct": {"limit": "count"},
    "construct_batch_parse_array": {"limit": "count"},
    "cstruct_parse_at_address":   {"limit": "count"},
    "find_xref_signatures":       {"limit": "top", "address": "addrs"},
}


def normalize_tool_args(tool_name: str, args: dict) -> dict:
    """Rewrite variant/alias arg names to their canonical equivalents.

    Never drops unrecognised keys.  When both the alias and the canonical
    key are present the canonical key wins and the alias is discarded.
    """
    if not args:
        return args
    result = dict(args)
    for old, new in _GLOBAL_ARG_ALIASES.items():
        if old in result and new not in result:
            result[new] = result.pop(old)
    for old, new in _TOOL_ARG_ALIASES.get(tool_name, {}).items():
        if old in result and new not in result:
            result[new] = result.pop(old)
    return result
