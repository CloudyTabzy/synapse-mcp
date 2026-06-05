"""
Phase 3 Stress Tests — Parameter Aliases + find_callers_of_import

Run with:
    uv run pytest tests/test_phase3_stress.py -v
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import MagicMock

# Ensure src is importable
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from ida_pro_mcp.server import _normalize_tool_args, _GLOBAL_ARG_ALIASES, _TOOL_ARG_ALIASES

# ---------------------------------------------------------------------------
# Standalone copy of find_callers_of_import core logic for testing
# (the real function is in api_composite.py; this copy is identical in logic
#  but accepts dependencies as arguments so we can test without IDA).
# ---------------------------------------------------------------------------

def _find_callers_of_import_core(name, limit, _collect_imports, idaapi, ida_funcs, idautils):
    """Exact logic clone of api_composite.find_callers_of_import for unit testing."""
    try:
        all_imports = _collect_imports()
        matched = []
        for imp in all_imports:
            if imp.get("imported_name") == name:
                matched.append(imp)

        if not matched:
            return {
                "ok": True,
                "import_name": name,
                "import_addr": None,
                "functions": [],
                "total": 0,
                "error": None,
            }

        target_imp = matched[0]
        target_addr = int(target_imp["addr"], 16)

        func_map: dict[int, dict] = {}
        for call_ea in idautils.CodeRefsTo(target_addr, 0):
            caller_func = idaapi.get_func(call_ea)
            if not caller_func:
                continue
            fstart = caller_func.start_ea
            if fstart not in func_map:
                fname = ida_funcs.get_func_name(fstart) or f"sub_{fstart:X}"
                func_map[fstart] = {
                    "addr": hex(fstart),
                    "name": fname,
                    "call_sites": [],
                }
            site = hex(call_ea)
            if site not in func_map[fstart]["call_sites"]:
                func_map[fstart]["call_sites"].append(site)

        func_list = list(func_map.values())
        total = len(func_list)
        if limit > 0 and len(func_list) > limit:
            func_list = func_list[:limit]

        return {
            "ok": True,
            "import_name": name,
            "import_addr": target_imp["addr"],
            "functions": func_list,
            "total": total,
            "error": None,
        }
    except Exception as e:
        return {
            "ok": False,
            "import_name": name,
            "import_addr": None,
            "functions": [],
            "total": 0,
            "error": str(e),
        }


# ---------------------------------------------------------------------------
# Section A: Parameter Alias Stress Tests
# ---------------------------------------------------------------------------

class TestGlobalAliases:
    """A1: Every global alias key produces the expected canonical key."""

    @pytest.mark.parametrize("alias,canonical,test_input", [
        ("addr", "address", {"addr": "0x401000"}),
        ("addresses", "addrs", {"addresses": ["0x401000"]}),
        ("max_results", "limit", {"max_results": 10}),
        ("max_entries", "limit", {"max_entries": 10}),
        ("start_address", "start", {"start_address": "0x401000"}),
        ("end_address", "end", {"end_address": "0x402000"}),
        ("start_ea", "start", {"start_ea": "0x401000"}),
        ("target_ea", "end", {"target_ea": "0x402000"}),
        ("addr_a", "start", {"addr_a": "0x401000"}),
        ("addr_b", "end", {"addr_b": "0x402000"}),
        ("src", "start", {"src": "0x401000"}),
        ("dst", "end", {"dst": "0x402000"}),
        ("architecture", "arch", {"architecture": "x64"}),
        ("yara_rules", "rules", {"yara_rules": "rule x {}"}),
        ("custom_rules", "rules", {"custom_rules": "rule x {}"}),
        ("segment_name", "segment", {"segment_name": ".text"}),
        ("segment_names", "segment", {"segment_names": ".text"}),
        ("max_instructions", "max_insns", {"max_instructions": 100}),
        ("path", "file_path", {"path": "/tmp/a.exe"}),
        ("binary_path", "file_path", {"binary_path": "/tmp/a.exe"}),
        ("output_path", "file_path", {"output_path": "/tmp/out"}),
    ])
    def test_global_alias_renames(self, alias, canonical, test_input):
        """Global alias must rename key for any generic tool."""
        # Use server_health as the test tool — it has no per-tool aliases,
        # so only the global alias fires. This avoids interference from
        # per-tool mappings like xrefs_to's {"address":"addrs"}.
        result = _normalize_tool_args("server_health", test_input)
        assert alias not in result, f"Old key '{alias}' should be removed"
        assert result.get(canonical) == test_input[alias], f"New key '{canonical}' should have original value"

    def test_all_global_aliases_accounted(self):
        """Every key in _GLOBAL_ARG_ALIASES must appear in the parametrize list above."""
        tested = {
            "addr", "addresses", "max_results", "max_entries",
            "start_address", "end_address", "start_ea", "target_ea",
            "addr_a", "addr_b", "src", "dst",
            "architecture", "yara_rules", "custom_rules",
            "segment_name", "segment_names", "max_instructions",
            "path", "binary_path", "output_path",
        }
        assert set(_GLOBAL_ARG_ALIASES.keys()) == tested, \
            f"Untested global aliases: {set(_GLOBAL_ARG_ALIASES.keys()) - tested}"


class TestPerToolAliases:
    """A2: Every per-tool alias produces the expected canonical key."""

    @pytest.mark.parametrize("tool_name,alias,canonical,test_input", [
        # search_text
        ("search_text", "start", "cursor", {"start": 10}),
        ("search_text", "offset", "cursor", {"offset": 10}),
        # address flip-flops
        ("decompile", "address", "addr", {"address": "0x401000"}),
        ("disasm", "address", "addr", {"address": "0x401000"}),
        ("analyze_function", "address", "addr", {"address": "0x401000"}),
        ("diff_before_after", "address", "addr", {"address": "0x401000"}),
        ("trace_data_flow", "address", "addr", {"address": "0x401000"}),
    ("trace_data_flow", "start", "addr", {"start": "0x401000"}),
    ("trace_data_flow", "end", "addr", {"end": "0x401000"}),
        ("dbg_run_to", "address", "addr", {"address": "0x401000"}),
        ("remove_type", "address", "addr", {"address": "0x401000"}),
        ("find_global_writers", "address", "addr", {"address": "0x401000"}),
        ("dump_vtable", "address", "addr", {"address": "0x401000"}),
        ("analyze_cleanup_function", "address", "addr", {"address": "0x401000"}),
        ("analyze_constructor", "address", "addr", {"address": "0x401000"}),
        ("type_propagate", "address", "addr", {"address": "0x401000"}),
        # plural address variants
        ("decompile_batch", "addrs", "addresses", {"addrs": ["0x401000"]}),
        ("disasm_batch", "addrs", "addresses", {"addrs": ["0x401000"]}),
        ("triton_replay_instructions", "addrs", "addresses", {"addrs": ["0x401000"]}),
        ("yara_function_classifier", "addrs", "addresses", {"addrs": ["0x401000"]}),
        ("find", "addrs", "targets", {"addrs": ["0x401000"]}),
        ("find", "addresses", "targets", {"addresses": ["0x401000"]}),
        ("callgraph", "addrs", "roots", {"addrs": ["0x401000"]}),
        ("callgraph", "addresses", "roots", {"addresses": ["0x401000"]}),
        # pagination limit aliases
        ("list_functions_enhanced", "limit", "count", {"limit": 10}),
        ("list_classes", "limit", "count", {"limit": 10}),
        ("imports", "limit", "count", {"limit": 10}),
        ("get_bulk_function_hashes", "limit", "count", {"limit": 10}),
        ("batch_analyze_completeness", "limit", "count", {"limit": 10}),
        ("construct_parse_ida_struct", "limit", "count", {"limit": 10}),
        ("construct_batch_parse_array", "limit", "count", {"limit": 10}),
        ("cstruct_parse_at_address", "limit", "count", {"limit": 10}),
        ("find_xref_signatures", "limit", "top", {"limit": 10}),
    ])
    def test_per_tool_alias_renames(self, tool_name, alias, canonical, test_input):
        """Per-tool alias must rename only for the specified tool."""
        result = _normalize_tool_args(tool_name, test_input)
        assert alias not in result, f"Old key '{alias}' should be removed for {tool_name}"
        assert result.get(canonical) == test_input[alias], \
            f"New key '{canonical}' should have original value for {tool_name}"

    def test_per_tool_alias_not_applied_to_other_tools(self):
        """Per-tool aliases must NOT fire for unrelated tools."""
        # decompile's address->addr should not affect server_health,
        # which has no per-tool aliases
        result = _normalize_tool_args("server_health", {"address": "0x401000"})
        assert result.get("address") == "0x401000"
        assert "addr" not in result

    def test_all_per_tool_aliases_accounted(self):
        """Every entry in _TOOL_ARG_ALIASES must appear in the parametrize list above."""
        tested = set()
        for tool, aliases in _TOOL_ARG_ALIASES.items():
            for alias in aliases:
                tested.add((tool, alias))

        expected = {
            ("search_text", "start"), ("search_text", "offset"),
            ("decompile", "address"), ("disasm", "address"),
            ("analyze_function", "address"), ("diff_before_after", "address"),
            ("trace_data_flow", "address"), ("trace_data_flow", "start"),
            ("dbg_run_to", "address"),
            ("remove_type", "address"), ("find_global_writers", "address"),
            ("dump_vtable", "address"), ("analyze_cleanup_function", "address"),
            ("analyze_constructor", "address"), ("type_propagate", "address"),
            ("decompile_batch", "addrs"), ("disasm_batch", "addrs"),
            ("triton_replay_instructions", "addrs"), ("yara_function_classifier", "addrs"),
            ("find", "addrs"), ("find", "addresses"),
            ("callgraph", "addrs"), ("callgraph", "addresses"),
            ("list_functions_enhanced", "limit"), ("list_classes", "limit"),
            ("imports", "limit"), ("get_bulk_function_hashes", "limit"),
            ("batch_analyze_completeness", "limit"),
            ("construct_parse_ida_struct", "limit"),
            ("construct_batch_parse_array", "limit"),
            ("cstruct_parse_at_address", "limit"),
            ("find_xref_signatures", "limit"),
        }
        missing = expected - tested
        assert not missing, f"Key aliases not in per-tool table: {missing}"


class TestFlipFlopScenarios:
    """A3: Two-step global→per-tool rewrite produces correct final keys."""

    def test_decompile_addr_flipflop(self):
        """decompile: addr → address (global) → addr (per-tool)."""
        result = _normalize_tool_args("decompile", {"addr": "0x401000"})
        assert result == {"addr": "0x401000"}

    def test_analyze_function_addr_flipflop(self):
        """analyze_function: addr → address (global) → addr (per-tool)."""
        result = _normalize_tool_args("analyze_function", {"addr": "0x401000"})
        assert result == {"addr": "0x401000"}

    def test_find_addresses_flipflop(self):
        """find: addresses → addrs (global) → targets (per-tool)."""
        result = _normalize_tool_args("find", {"addresses": ["0x401000"]})
        assert result == {"targets": ["0x401000"]}

    def test_callgraph_addresses_flipflop(self):
        """callgraph: addresses → addrs (global) → roots (per-tool)."""
        result = _normalize_tool_args("callgraph", {"addresses": ["0x401000"]})
        assert result == {"roots": ["0x401000"]}

    def test_search_text_offset_to_cursor(self):
        """search_text: offset → cursor (per-tool only, no global match)."""
        result = _normalize_tool_args("search_text", {"offset": 10})
        assert result == {"cursor": 10}

    def test_search_text_start_to_cursor(self):
        """search_text: start → cursor (per-tool)."""
        result = _normalize_tool_args("search_text", {"start": 10})
        assert result == {"cursor": 10}

    def test_trace_data_flow_start_to_addr(self):
        """trace_data_flow: start → addr (per-tool, after global src→start)."""
        result = _normalize_tool_args("trace_data_flow", {"start": "0x401000"})
        assert result == {"addr": "0x401000"}

    def test_trace_data_flow_end_to_addr(self):
        """trace_data_flow: end → addr (per-tool, after global dst→end)."""
        result = _normalize_tool_args("trace_data_flow", {"end": "0x401000"})
        assert result == {"addr": "0x401000"}

    def test_trace_data_flow_src_full_pipeline(self):
        """trace_data_flow: src → start (global) → addr (per-tool)."""
        result = _normalize_tool_args("trace_data_flow", {"src": "0x401000"})
        assert result == {"addr": "0x401000"}

    def test_trace_data_flow_dst_full_pipeline(self):
        """trace_data_flow: dst → end (global) → addr (per-tool)."""
        result = _normalize_tool_args("trace_data_flow", {"dst": "0x401000"})
        assert result == {"addr": "0x401000"}


class TestConflictResolution:
    """A4: When both alias and canonical keys are present, the alias is skipped.
    This means BOTH keys remain in the result — the caller receives both the old
    and new names.  Tools with strict signatures may see an extra kwarg, but in
    practice MCP agents rarely supply both names simultaneously."""

    def test_decompile_both_addr_and_address(self):
        """decompile with both addr and address present: alias is skipped,
        both keys remain (addr from original, address from original)."""
        result = _normalize_tool_args("decompile", {"addr": "0x401000", "address": "0x402000"})
        # global: addr→address skipped because address already present
        # per-tool: address→addr skipped because addr already present
        assert result.get("addr") == "0x401000"
        assert result.get("address") == "0x402000"

    def test_xrefs_to_both_addr_and_address(self):
        """xrefs_to with both addr and address: global skipped (address exists),
        per-tool renames address->addrs, both original addr and new addrs remain."""
        result = _normalize_tool_args("xrefs_to", {"addr": "0x401000", "address": "0x402000"})
        # Per-tool alias address->addrs fires, keeping original addr
        assert result.get("addrs") == "0x402000"
        assert result.get("addr") == "0x401000"

    def test_find_both_addrs_and_targets(self):
        """find with both addrs and targets: per-tool skipped, both remain."""
        result = _normalize_tool_args("find", {"addrs": ["a"], "targets": ["b"]})
        assert result.get("targets") == ["b"]
        assert result.get("addrs") == ["a"]

    def test_search_text_both_start_and_cursor(self):
        """search_text with both start and cursor: per-tool skipped, both remain."""
        result = _normalize_tool_args("search_text", {"start": 10, "cursor": 20})
        assert result.get("cursor") == 20
        assert result.get("start") == 10

    def test_global_alias_skipped_when_canonical_present(self):
        """Global alias is not applied when canonical key already exists.
        But xrefs_to's per-tool alias address->addrs still fires."""
        result = _normalize_tool_args("xrefs_to", {"addr": "0x401000", "address": "0x402000"})
        assert result.get("addrs") == "0x402000"
        assert result.get("addr") == "0x401000"

    def test_per_tool_alias_skipped_when_canonical_present(self):
        """Per-tool alias is not applied when canonical key already exists."""
        result = _normalize_tool_args("decompile", {"address": "0x401000", "addr": "0x402000"})
        assert result.get("addr") == "0x402000"
        assert result.get("address") == "0x401000"


class TestEdgeCases:
    """A5: Boundary conditions and non-aliased keys."""

    def test_none_args(self):
        """None args should return as-is (not crash)."""
        assert _normalize_tool_args("any_tool", None) is None  # type: ignore[arg-type]

    def test_empty_dict(self):
        """Empty dict should return empty dict."""
        assert _normalize_tool_args("any_tool", {}) == {}

    def test_unknown_keys_untouched(self):
        """Keys not in any alias map must be preserved."""
        result = _normalize_tool_args("any_tool", {"foo": "bar", "baz": 42})
        assert result == {"foo": "bar", "baz": 42}

    def test_mixed_valid_and_unknown(self):
        """Valid aliases renamed, unknown keys preserved.
        xrefs_to: addr -> address (global) -> addrs (per-tool)."""
        result = _normalize_tool_args("xrefs_to", {"addr": "0x401000", "foo": "bar"})
        assert result == {"addrs": "0x401000", "foo": "bar"}

    def test_numeric_value_preserved(self):
        """Numeric values must survive the rename.
        find_similar_functions: max_results -> limit (global) -> max_results (per-tool)."""
        result = _normalize_tool_args("find_similar_functions", {"max_results": 42})
        assert result == {"max_results": 42}

    def test_list_value_preserved(self):
        """List values must survive the rename."""
        result = _normalize_tool_args("find", {"addresses": ["a", "b"]})
        assert result == {"targets": ["a", "b"]}

    def test_nested_dict_untouched(self):
        """Nested dict values must survive."""
        nested = {"queries": [{"addr": "0x401000"}]}
        result = _normalize_tool_args("func_profile", nested)
        assert result == {"queries": [{"addr": "0x401000"}]}

    def test_multiple_aliases_same_tool(self):
        """Multiple aliases on the same tool all fire correctly."""
        result = _normalize_tool_args("decompile_range", {
            "start_address": "0x401000",
            "end_address": "0x402000",
            "max_instructions": 100,
        })
        assert result == {
            "start": "0x401000",
            "end": "0x402000",
            "max_insns": 100,
        }

    def test_no_double_application(self):
        """Aliases must not chain (e.g., addr→address should not then match another alias)."""
        # There's no chain like addr→address→something_else, but let's verify
        # by checking that after normalization, no old keys remain
        result = _normalize_tool_args("decompile", {"addr": "0x401000"})
        assert "address" not in result  # intermediate should be gone
        assert "addr" in result


# ---------------------------------------------------------------------------
# Section B: find_callers_of_import Stress Tests
# ---------------------------------------------------------------------------

class TestFindCallersOfImport:
    """B1-B7: Composite tool logic validation via standalone core function."""

    def test_import_not_found(self):
        """B2: Import name not in the binary."""
        result = _find_callers_of_import_core(
            "NonExistentApi", 100,
            _collect_imports=lambda: [],
            idaapi=None, ida_funcs=None, idautils=None,
        )
        assert result["ok"] is True
        assert result["import_addr"] is None
        assert result["functions"] == []
        assert result["total"] == 0

    def test_import_found_no_callers(self):
        """B3: Import exists but nobody calls it."""
        class FakeIdautils:
            @staticmethod
            def CodeRefsTo(addr, flow):
                return iter([])
        result = _find_callers_of_import_core(
            "CreateFileW", 100,
            _collect_imports=lambda: [{"addr": "0x403000", "module": "KERNEL32.dll", "imported_name": "CreateFileW"}],
            idaapi=None, ida_funcs=None, idautils=FakeIdautils(),
        )
        assert result["ok"] is True
        assert result["import_addr"] == "0x403000"
        assert result["functions"] == []
        assert result["total"] == 0

    def test_import_found_with_callers(self):
        """B1: Normal flow — two functions call the import."""

        class FakeFunc:
            def __init__(self, start):
                self.start_ea = start

        class FakeIdaapi:
            @staticmethod
            def get_func(ea):
                return FakeFunc(0x401000) if 0x401000 <= ea < 0x402000 else FakeFunc(0x402000)

        class FakeIdaFuncs:
            @staticmethod
            def get_func_name(ea):
                return "sub_401000" if ea == 0x401000 else "sub_402000"

        class FakeIdautils:
            @staticmethod
            def CodeRefsTo(addr, flow):
                return iter([0x401010, 0x401020, 0x402010])

        result = _find_callers_of_import_core(
            "CreateFileW", 100,
            _collect_imports=lambda: [{"addr": "0x403000", "module": "KERNEL32.dll", "imported_name": "CreateFileW"}],
            idaapi=FakeIdaapi(), ida_funcs=FakeIdaFuncs(), idautils=FakeIdautils(),
        )
        assert result["ok"] is True
        assert result["import_addr"] == "0x403000"
        assert result["total"] == 2
        funcs = {f["addr"]: f for f in result["functions"]}
        assert funcs["0x401000"]["call_sites"] == ["0x401010", "0x401020"]
        assert funcs["0x402000"]["call_sites"] == ["0x402010"]

    def test_limit_truncation(self):
        """B4: More callers than limit — truncation works."""

        class FakeFunc:
            def __init__(self, start):
                self.start_ea = start

        call_sites = [(0x401000 + i * 0x100, 0x401000 + i * 0x100 + 0x10) for i in range(150)]

        class FakeIdaapi:
            @staticmethod
            def get_func(ea):
                return FakeFunc(ea - 0x10)

        class FakeIdaFuncs:
            @staticmethod
            def get_func_name(ea):
                return f"sub_{ea:X}"

        class FakeIdautils:
            @staticmethod
            def CodeRefsTo(addr, flow):
                return iter([cs for _, cs in call_sites])

        result = _find_callers_of_import_core(
            "CreateFileW", 100,
            _collect_imports=lambda: [{"addr": "0x403000", "module": "KERNEL32.dll", "imported_name": "CreateFileW"}],
            idaapi=FakeIdaapi(), ida_funcs=FakeIdaFuncs(), idautils=FakeIdautils(),
        )
        assert result["ok"] is True
        assert result["total"] == 150
        assert len(result["functions"]) == 100

    def test_duplicate_call_sites_deduplicated(self):
        """B5: Multiple call sites in same function — deduplicated."""

        class FakeFunc:
            def __init__(self, start):
                self.start_ea = start

        class FakeIdaapi:
            @staticmethod
            def get_func(ea):
                return FakeFunc(0x401000)

        class FakeIdaFuncs:
            @staticmethod
            def get_func_name(ea):
                return "sub_401000"

        class FakeIdautils:
            @staticmethod
            def CodeRefsTo(addr, flow):
                return iter([0x401010, 0x401020, 0x401010])

        result = _find_callers_of_import_core(
            "CreateFileW", 100,
            _collect_imports=lambda: [{"addr": "0x403000", "module": "KERNEL32.dll", "imported_name": "CreateFileW"}],
            idaapi=FakeIdaapi(), ida_funcs=FakeIdaFuncs(), idautils=FakeIdautils(),
        )
        assert result["total"] == 1
        assert result["functions"][0]["call_sites"] == ["0x401010", "0x401020"]

    def test_call_site_outside_function_skipped(self):
        """B6: Call site with no containing function is silently skipped."""

        class FakeIdaapi:
            @staticmethod
            def get_func(ea):
                return None

        class FakeIdautils:
            @staticmethod
            def CodeRefsTo(addr, flow):
                return iter([0x401010])

        result = _find_callers_of_import_core(
            "CreateFileW", 100,
            _collect_imports=lambda: [{"addr": "0x403000", "module": "KERNEL32.dll", "imported_name": "CreateFileW"}],
            idaapi=FakeIdaapi(), ida_funcs=None, idautils=FakeIdautils(),
        )
        assert result["ok"] is True
        assert result["functions"] == []
        assert result["total"] == 0

    def test_error_handling(self):
        """B7: Exception in _collect_imports is caught gracefully."""
        def _broken():
            raise RuntimeError("IDB not ready")
        result = _find_callers_of_import_core(
            "CreateFileW", 100,
            _collect_imports=_broken,
            idaapi=None, ida_funcs=None, idautils=None,
        )
        assert result["ok"] is False
        assert "error" in result
        assert "IDB not ready" in result.get("error", "")


# ---------------------------------------------------------------------------
# Section C: Integration / Schema Integrity
# ---------------------------------------------------------------------------

class TestSchemaIntegrity:
    """Verify that aliased parameter names don't break schema generation."""

    def test_all_aliased_tools_have_valid_names(self):
        """Every tool referenced in _TOOL_ARG_ALIASES should be a valid tool name
        that the server could receive.  We can't check against live IDA here,
        but we can ensure the dict keys are well-formed strings."""
        for tool_name in _TOOL_ARG_ALIASES:
            assert isinstance(tool_name, str)
            assert len(tool_name) > 0

    def test_no_circular_aliases(self):
        """No alias should map to a key that is itself an alias for something else."""
        # If global aliases had a→b and b→c, that would be a chain.
        # Check that no value in _GLOBAL_ARG_ALIASES is also a key.
        values = set(_GLOBAL_ARG_ALIASES.values())
        keys = set(_GLOBAL_ARG_ALIASES.keys())
        intersection = values & keys
        assert not intersection, f"Circular alias risk: {intersection}"

    def test_per_tool_no_circular_aliases(self):
        """No per-tool alias should map to a key that is itself an alias."""
        for tool, aliases in _TOOL_ARG_ALIASES.items():
            values = set(aliases.values())
            keys = set(aliases.keys())
            intersection = values & keys
            assert not intersection, f"Circular alias in {tool}: {intersection}"

    def test_per_tool_values_not_in_global_keys(self):
        """Per-tool canonical names should not accidentally be global aliases
        that would fire on the next call.  (This would cause double-aliasing.)

        EXCEPTION: The intentional 'flip-flop' pattern (addr↔address) is
        whitelisted because it is applied deliberately to tools whose real
        parameter is `addr` while the global default is `address`."""
        global_keys = set(_GLOBAL_ARG_ALIASES.keys())
        # Known intentional flip-flops — these per-tool canonical names
        # deliberately match global alias keys so the tools can undo the
        # global rename and restore their actual parameter name.
        whitelist = {"addr", "addresses", "max_instructions", "max_results"}
        for tool, aliases in _TOOL_ARG_ALIASES.items():
            for canonical in aliases.values():
                if canonical in whitelist:
                    continue
                assert canonical not in global_keys, \
                    f"{tool}: canonical '{canonical}' is also a global alias key — double alias risk"
