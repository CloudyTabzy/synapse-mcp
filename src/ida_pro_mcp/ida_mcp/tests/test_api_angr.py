"""Tests for api_angr — Angr symbolic execution engine tools.

All tests except the status probe skip gracefully when angr is not installed.
File-based tests use the crackme03.elf fixture (ELF64 Linux binary).
"""

from ..framework import (
    test,
    skip_test,
    assert_ok,
    assert_has_keys,
    assert_is_list,
    get_named_function,
)

try:
    from ..api_angr import (
        angr_status,
        ANGR_AVAILABLE,
    )
    if ANGR_AVAILABLE:
        from ..api_angr import (
            angr_load_segment,
            angr_cfg_fast,
            angr_cfg_from_ida,
            angr_diff_cfg,
            angr_find_paths,
            angr_enumerate_reachable,
            angr_state_evaluate,
            angr_hook_function,
            angr_backward_slice,
            angr_value_set,
            angr_snapshot_save,
            angr_snapshot_restore,
            hybrid_angr_triton_solve,
            hybrid_angr_stdin_fuzz,
            hybrid_angr_z3_formula,
            workflow_solve_crackme,
            workflow_find_gadgets,
        )
except ImportError:
    ANGR_AVAILABLE = False


def _require_angr():
    if not ANGR_AVAILABLE:
        skip_test("angr not installed")


# ---------------------------------------------------------------------------
# Status probe — always runs, even without angr
# ---------------------------------------------------------------------------


@test()
def test_angr_status_probe():
    """angr_status must not crash regardless of whether angr is installed."""
    result = angr_status()
    assert isinstance(result, dict), "angr_status must return a dict"
    assert "available" in result, "angr_status must include 'available' key"
    assert "ok" in result, "angr_status must include 'ok' key"
    assert result.get("ok") is True


@test()
def test_angr_status_version():
    """version and claripy_version are present when angr is available."""
    _require_angr()
    result = angr_status()
    assert result.get("available") is True
    version = result.get("version")
    assert isinstance(version, str) and len(version) > 0, "version must be non-empty"
    claripy = result.get("claripy_version")
    assert isinstance(claripy, str)


@test()
def test_angr_status_engines_dict():
    """engines dict lists supported analysis engines."""
    _require_angr()
    result = angr_status()
    engines = result.get("engines", {})
    assert isinstance(engines, dict)
    assert engines.get("simulation_manager") is True
    assert engines.get("cfg_fast") is True


@test()
def test_angr_status_no_angr_hint():
    """hint field is present when angr is not installed."""
    if ANGR_AVAILABLE:
        skip_test("angr is installed — no-angr path not reachable")
    result = angr_status()
    assert result.get("ok") is True
    assert "hint" in result, "hint must be present when angr is absent"


# ---------------------------------------------------------------------------
# Load segment / project cache
# ---------------------------------------------------------------------------


@test(binary="crackme03.elf")
def test_angr_load_segment_basic():
    """angr_load_segment creates a project from the IDB's input file."""
    _require_angr()
    result = angr_load_segment()
    assert_ok(result, "project_id")
    assert_has_keys(result, "project_id", "binary_path", "arch", "bits",
                    "entry_point", "image_base", "memory_regions")
    assert isinstance(result.get("memory_regions"), list)
    assert result.get("bits") in (32, 64)


@test(binary="crackme03.elf")
def test_angr_load_segment_reuse_same_binary():
    """Loading the same binary twice returns the same project_id (cache hit)."""
    _require_angr()
    first = angr_load_segment()
    assert_ok(first, "project_id")
    pid1 = first["project_id"]

    second = angr_load_segment()
    assert_ok(second, "project_id")
    pid2 = second["project_id"]
    assert pid1 == pid2, f"expected same project_id, got {pid1!r} vs {pid2!r}"
    assert "already cached" in (second.get("note") or "").lower() or \
           "cached" in (second.get("note") or "").lower()


@test(binary="crackme03.elf")
def test_angr_load_segment_explicit_project_id():
    """Explicit project_id is honoured on first load."""
    _require_angr()
    result = angr_load_segment(project_id="my_custom_proj")
    assert_ok(result, "project_id")
    assert result["project_id"] == "my_custom_proj"


# ---------------------------------------------------------------------------
# CFG from IDA
# ---------------------------------------------------------------------------


@test(binary="crackme03.elf")
def test_angr_cfg_from_ida_basic():
    """angr_cfg_from_ida extracts blocks and edges from IDA's FlowChart."""
    _require_angr()
    func = get_named_function("main")
    if not func:
        skip_test("main not found")
    result = angr_cfg_from_ida(function_address=func)
    assert_ok(result, "blocks", "edges")
    assert_is_list(result.get("blocks"), min_length=1)
    assert_is_list(result.get("edges"))
    assert result.get("block_count", 0) >= 1


# ---------------------------------------------------------------------------
# CFGFast
# ---------------------------------------------------------------------------


@test(binary="crackme03.elf")
def test_angr_cfg_fast_basic():
    """angr_cfg_fast builds a static CFG and returns function summaries."""
    _require_angr()
    # Ensure project is loaded
    load_res = angr_load_segment()
    assert_ok(load_res, "project_id")

    result = angr_cfg_fast(timeout_seconds=30)
    assert_ok(result, "functions", "block_count", "edge_count")
    assert_is_list(result.get("functions"), min_length=1)
    assert result.get("function_count", 0) >= 1


# ---------------------------------------------------------------------------
# Diff CFG
# ---------------------------------------------------------------------------


@test(binary="crackme03.elf")
def test_angr_diff_cfg_basic():
    """angr_diff_cfg compares IDA FlowChart vs angr CFGFast for a function."""
    _require_angr()
    func = get_named_function("main")
    if not func:
        skip_test("main not found")
    # Ensure CFG exists
    angr_cfg_fast(timeout_seconds=30)
    result = angr_diff_cfg(function_address=func)
    assert_ok(result)
    assert_has_keys(result, "ida_block_count", "angr_block_count", "shared_blocks")


# ---------------------------------------------------------------------------
# Symbolic execution — find paths
# ---------------------------------------------------------------------------


@test(binary="crackme03.elf")
def test_angr_find_paths_argv_mode():
    """angr_find_paths with argv mode can explore from entry toward main."""
    _require_angr()
    load_res = angr_load_segment()
    assert_ok(load_res, "project_id")

    # Target main itself — it is trivially reachable from entry
    main_addr = get_named_function("main")
    if not main_addr:
        skip_test("main not found")

    result = angr_find_paths(
        target_address=main_addr,
        source_address="entry",
        input_mode="argv",
        input_size=32,
        max_paths=1,
        timeout_seconds=30,
    )
    # We may or may not find a path depending on binary complexity;
    # the important thing is that it returns a structured dict without crashing.
    assert isinstance(result, dict)
    assert "ok" in result
    assert "paths" in result
    assert "timed_out" in result
    assert_is_list(result.get("paths"))


# ---------------------------------------------------------------------------
# State evaluate
# ---------------------------------------------------------------------------


@test(binary="crackme03.elf")
def test_angr_state_evaluate_register():
    """angr_state_evaluate can evaluate a register at a blank state."""
    _require_angr()
    load_res = angr_load_segment()
    assert_ok(load_res, "project_id")

    main_addr = get_named_function("main")
    if not main_addr:
        skip_test("main not found")

    result = angr_state_evaluate(
        at_address=main_addr,
        expression="rax",
        initial_registers={"rax": "0xdeadbeef"},
    )
    assert_ok(result, "result")
    assert result.get("result") == "0xdeadbeef"
    assert result.get("is_symbolic") is False


@test(binary="crackme03.elf")
def test_angr_state_evaluate_memory():
    """angr_state_evaluate supports mem:addr:size syntax."""
    _require_angr()
    load_res = angr_load_segment()
    assert_ok(load_res, "project_id")

    main_addr = get_named_function("main")
    if not main_addr:
        skip_test("main not found")

    result = angr_state_evaluate(
        at_address=main_addr,
        expression="mem:0x1000:8",
    )
    assert_ok(result, "result")
    assert "is_symbolic" in result


# ---------------------------------------------------------------------------
# Hook function
# ---------------------------------------------------------------------------


@test(binary="crackme03.elf")
def test_angr_hook_function_skip_and_unhook():
    """angr_hook_function can install a skip hook and later remove it."""
    _require_angr()
    load_res = angr_load_segment()
    assert_ok(load_res, "project_id")

    check_pw = get_named_function("check_pw")
    if not check_pw:
        skip_test("check_pw not found")

    # Install skip hook
    result = angr_hook_function(
        function_address=check_pw,
        hook_type="skip",
        return_value="0x1",
    )
    assert_ok(result, "hook_id")
    assert result.get("hook_type") == "skip"

    # Remove hook
    unhook = angr_hook_function(
        function_address=check_pw,
        hook_type="unhook",
    )
    assert_ok(unhook)
    assert unhook.get("hook_type") == "unhook"


# ---------------------------------------------------------------------------
# Backward slice
# ---------------------------------------------------------------------------


@test(binary="crackme03.elf")
def test_angr_backward_slice_cfg_only():
    """angr_backward_slice in CFG-only mode returns a list of contributing blocks."""
    _require_angr()
    load_res = angr_load_segment()
    assert_ok(load_res, "project_id")

    main_addr = get_named_function("main")
    if not main_addr:
        skip_test("main not found")

    # Build CFG first
    cfg_res = angr_cfg_fast(timeout_seconds=30)
    assert_ok(cfg_res)

    result = angr_backward_slice(
        target_address=main_addr,
        use_cfg_only=True,
        timeout_seconds=30,
    )
    assert isinstance(result, dict)
    assert "ok" in result
    if result.get("ok"):
        assert_is_list(result.get("contributing_instructions", []))


# ---------------------------------------------------------------------------
# Snapshot save / restore
# ---------------------------------------------------------------------------


@test(binary="crackme03.elf")
def test_angr_snapshot_roundtrip():
    """angr_snapshot_save and angr_snapshot_restore form a round-trip."""
    _require_angr()
    load_res = angr_load_segment()
    assert_ok(load_res, "project_id")

    # Run a trivial find_paths to populate last_found_states
    main_addr = get_named_function("main")
    if not main_addr:
        skip_test("main not found")

    find_res = angr_find_paths(
        target_address=main_addr,
        source_address="entry",
        input_mode="argv",
        max_paths=1,
        timeout_seconds=15,
    )
    # Even if no paths found, we just need the tool not to crash.
    # Snapshot requires last_found_states to exist.
    save_res = angr_snapshot_save(label="test_snap")
    assert isinstance(save_res, dict)
    if not save_res.get("ok"):
        # No states to save — acceptable if find_paths found nothing
        assert "run angr_find_paths first" in (save_res.get("error") or "").lower() or \
               "no state" in (save_res.get("error") or "").lower()
        return

    snap_id = save_res["snapshot_id"]
    restore_res = angr_snapshot_restore(snapshot_id=snap_id)
    assert_ok(restore_res, "snapshot_id")
    assert restore_res["snapshot_id"] == snap_id


# ---------------------------------------------------------------------------
# Hybrid tools
# ---------------------------------------------------------------------------


@test(binary="crackme03.elf")
def test_hybrid_angr_triton_solve_degrades_gracefully():
    """hybrid_angr_triton_solve returns a structured result even without Triton."""
    _require_angr()
    load_res = angr_load_segment()
    assert_ok(load_res, "project_id")

    main_addr = get_named_function("main")
    if not main_addr:
        skip_test("main not found")

    result = hybrid_angr_triton_solve(
        target_address=main_addr,
        source_address="entry",
        input_mode="argv",
        max_paths=1,
        timeout_seconds=15,
    )
    assert isinstance(result, dict)
    assert "ok" in result
    assert "engines_used" in result
    assert "angr" in result.get("engines_used", [])


@test(binary="crackme03.elf")
def test_hybrid_angr_stdin_fuzz_structured_result():
    """hybrid_angr_stdin_fuzz returns a structured result dict."""
    _require_angr()
    load_res = angr_load_segment()
    assert_ok(load_res, "project_id")

    main_addr = get_named_function("main")
    if not main_addr:
        skip_test("main not found")

    result = hybrid_angr_stdin_fuzz(
        target_address=main_addr,
        max_inputs=1,
        timeout_seconds=15,
    )
    assert isinstance(result, dict)
    assert "ok" in result
    assert "inputs" in result


@test(binary="crackme03.elf")
def test_hybrid_angr_z3_formula_requires_paths():
    """hybrid_angr_z3_formula errors gracefully when no paths exist."""
    _require_angr()
    load_res = angr_load_segment()
    assert_ok(load_res, "project_id")

    result = hybrid_angr_z3_formula(path_id=0)
    assert isinstance(result, dict)
    # Should error because no find_paths has been run
    assert result.get("ok") is False or "constraint_count" in result


# ---------------------------------------------------------------------------
# Workflows
# ---------------------------------------------------------------------------


@test(binary="crackme03.elf")
def test_workflow_solve_crackme_explicit_target():
    """workflow_solve_crackme with an explicit target returns a structured result."""
    _require_angr()
    load_res = angr_load_segment()
    assert_ok(load_res, "project_id")

    main_addr = get_named_function("main")
    if not main_addr:
        skip_test("main not found")

    result = workflow_solve_crackme(
        target_address=main_addr,
        input_mode="argv",
        input_size=32,
        max_solutions=1,
        timeout_seconds=15,
    )
    assert isinstance(result, dict)
    assert "ok" in result
    assert "serial_found" in result or "error" in result


@test(binary="crackme03.elf")
def test_workflow_find_gadgets_text_segment():
    """workflow_find_gadgets returns gadget list for the .text segment."""
    _require_angr()
    load_res = angr_load_segment()
    assert_ok(load_res, "project_id")

    result = workflow_find_gadgets(segment_name=".text", max_gadgets=10)
    assert_ok(result, "gadgets")
    assert_is_list(result.get("gadgets"))
    assert result.get("gadget_count", 0) >= 0


# ---------------------------------------------------------------------------
# Enumerate reachable
# ---------------------------------------------------------------------------


@test(binary="crackme03.elf")
def test_angr_enumerate_reachable_basic():
    """angr_enumerate_reachable performs BFS over the CFG."""
    _require_angr()
    load_res = angr_load_segment()
    assert_ok(load_res, "project_id")

    result = angr_enumerate_reachable(
        source_address="entry",
        max_depth=5,
        max_nodes=100,
    )
    assert isinstance(result, dict)
    assert "ok" in result
    if result.get("ok"):
        assert_is_list(result.get("nodes", []))
        assert result.get("reachable_count", 0) >= 0
