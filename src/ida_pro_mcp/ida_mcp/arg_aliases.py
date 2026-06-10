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

Schema-aware safety net
-----------------------
When the caller passes ``valid_params`` (the set of parameter names the
target tool actually declares), a final reversal pass undoes any global
rename that produced a key the tool does not accept.  Example: the global
``addr`` → ``address`` rename fires, but the tool's real parameter is
``addr``; the reversal restores ``addr``.  This means a tool can never
become unreachable just because it uses a canonical name (``addr``,
``max_results``, …) without a hand-written per-tool reversal entry — which
is exactly the bug class that previously broke new tools.  The reversal is
purely additive: it only acts when a key is present that the tool cannot
accept while its alias-equivalent IS a declared parameter, so it never
changes the result for a tool that is already receiving valid arguments.
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
    # trace_data_flow takes a single starting addr; both start and end map via
    # the global src→start and dst→end chains: src→start→addr, dst→end→addr.
    "trace_data_flow":            {"address": "addr", "start": "addr", "end": "addr"},
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
    # Tools whose REAL param is max_results — protect them from the global
    # max_results→limit rename (which would otherwise produce the handler error
    # "unexpected parameters: ['limit']") and also accept a literal "limit".
    # The global rename fires first (max_results→limit), then these per-tool
    # reversals restore "limit"→max_results. Net effect: max_results passes
    # through unchanged AND a literal "limit" is accepted.
    "find_similar_functions":     {"limit": "max_results"},
    "lief_strings":               {"limit": "max_results"},
    "scan_signature":             {"limit": "max_results"},
    "yara_scan":                  {"limit": "max_results"},
    "sig_suggest_candidates":     {"limit": "max_results"},
    "construct_scan_for_structs": {"limit": "max_results"},
    "angr_backward_slice":        {"limit": "max_results"},
    "nx_strongly_connected":      {"limit": "max_results"},
    "nx_communities":             {"limit": "max_results"},
    "list_functions_enhanced":    {"limit": "count"},
    "list_classes":               {"limit": "count"},
    "imports":                    {"limit": "count"},
    "get_bulk_function_hashes":   {"limit": "count"},
    "batch_analyze_completeness": {"limit": "count"},
    "construct_parse_ida_struct": {"limit": "count"},
    "construct_batch_parse_array": {"limit": "count"},
    "cstruct_parse_at_address":   {"limit": "count"},
    "find_xref_signatures":       {"limit": "top", "address": "addrs"},
    # -----------------------------------------------------------------------
    # Unicorn tools — natural aliases for regs/timeout params.
    # Global max_instructions→max_insns already covers max_insns remapping.
    # -----------------------------------------------------------------------
    # -----------------------------------------------------------------------
    # COM / DirectX vtable tools
    # -----------------------------------------------------------------------
    # resolve_com_vtable: "slot" is a natural alias for the integer "index" param
    "resolve_com_vtable":           {"slot": "index", "iface": "interface", "name": "interface"},
    # find_render_loop: natural names for the "section" and "apis" params
    "find_render_loop":             {"seg": "section", "segment": "section", "api": "apis"},
    # struct_recovery: accept "function" or "address" as aliases for addr
    "struct_recovery":              {"function": "addr", "address": "addr", "min_distinct": "min_fields"},
    # -----------------------------------------------------------------------
    # NumPy numerical-analysis tools.
    # These declare "addr" as their real param; reverse the global addr→address
    # rename so an agent-sent "addr" reaches them. numpy_memmap_scan declares
    # "max_results" (not "limit"); reverse the global max_results→limit rename.
    # numpy_function_similarity / numpy_binary_similarity take func_*/file_*
    # params and need no reversal.
    # -----------------------------------------------------------------------
    "numpy_entropy_map":            {"address": "addr"},
    "numpy_byte_histogram":         {"address": "addr"},
    "numpy_xor_key_recovery":       {"address": "addr"},
    "numpy_opcode_histogram":       {"address": "addr"},
    "numpy_value_scan":             {"address": "addr"},
    "numpy_memmap_scan":            {"limit": "max_results"},
    # -----------------------------------------------------------------------
    # Unicorn tools — natural aliases for regs/timeout params.
    # Global max_instructions→max_insns already covers max_insns remapping.
    # -----------------------------------------------------------------------
    "unicorn_emulate":              {"registers": "regs", "timeout": "timeout_ms"},
    "unicorn_trace":                {"registers": "regs", "timeout": "timeout_ms"},
    "unicorn_call_function":        {"timeout": "timeout_ms"},
    "unicorn_emulate_and_patch":    {"registers": "regs", "timeout": "timeout_ms"},
    "unicorn_diff_memory":          {"registers": "regs", "timeout": "timeout_ms"},
    "unicorn_recover_stackstrings": {"registers": "regs", "timeout": "timeout_ms"},
    "unicorn_find_memory_accesses": {"registers": "regs", "timeout": "timeout_ms"},
    "unicorn_resolve_api_hash":     {"timeout": "timeout_ms"},
    "unicorn_emulate_shellcode":    {"timeout": "timeout_ms"},
    "workflow_unicorn_decrypt_analyze": {"registers": "regs", "timeout": "timeout_ms"},
    "hybrid_unicorn_triton_analyze":    {"registers": "regs", "timeout": "timeout_ms"},
    "hybrid_unicorn_miasm_hot_blocks":  {"registers": "regs", "timeout": "timeout_ms"},
    "hybrid_unicorn_networkx_exec_graph": {"timeout": "timeout_ms"},
}


def normalize_tool_args(
    tool_name: str, args: dict, valid_params: "set[str] | None" = None
) -> dict:
    """Rewrite variant/alias arg names to their canonical equivalents.

    Never drops unrecognised keys.  When both the alias and the canonical
    key are present the canonical key wins and the alias is discarded.

    ``valid_params`` (optional) is the set of parameter names the target tool
    actually declares.  When provided, a final schema-aware reversal undoes any
    global rename that produced a key the tool does not accept — so a tool using
    a canonical name (``addr``, ``max_results``, …) works without needing a
    hand-written per-tool reversal.  Pass ``None`` (the default) to skip the
    reversal, e.g. from a transport that has no access to tool schemas.
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
    # Schema-aware reversal — only when we know the tool's real parameters.
    # Undo a global rename X→Y when the result carries Y but the tool declares
    # X (and not Y).  Strict conditions make this a pure safety net: it never
    # touches a tool that is already receiving a valid argument set.
    if valid_params is not None:
        for old, new in _GLOBAL_ARG_ALIASES.items():
            if (new in result and new not in valid_params
                    and old in valid_params and old not in result):
                result[old] = result.pop(new)
    return result
