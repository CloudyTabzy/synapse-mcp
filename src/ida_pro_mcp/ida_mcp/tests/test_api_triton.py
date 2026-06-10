"""Tests for api_triton — Triton symbolic execution tools.

All tests skip gracefully when triton-library is not installed.
The test binary assumed by address constants is crackme03.elf (x86-64 ELF).
"""

from ..framework import (
    test,
    skip_test,
    assert_non_empty,
    assert_is_list,
    get_any_function,
)

try:
    from ..api_triton import (
        triton_status,
        TRITON_AVAILABLE,
    )
    if TRITON_AVAILABLE:
        from ..api_triton import (
            triton_init,
            triton_reset,
            triton_get_context_info,
            triton_symbolize_register,
            triton_symbolize_memory,
            triton_batch_symbolize_registers,
            triton_set_concrete_register_value,
            triton_get_concrete_register_value,
            triton_set_concrete_memory_value,
            triton_get_concrete_memory_value,
            triton_process_instruction,
            triton_process_function,
            triton_get_symbolic_variables,
            triton_get_symbolic_expressions,
            triton_get_path_constraints,
            triton_taint_register,
            triton_untaint_register,
            triton_taint_memory,
            triton_is_register_tainted,
            triton_is_memory_tainted,
            triton_get_taint_summary,
            triton_solve_path_constraints,
            triton_snapshot_save,
            triton_snapshot_restore,
            triton_snapshot_list,
            triton_snapshot_delete,
            triton_annotate_function,
            triton_highlight_tainted_instructions,
        )
except ImportError:
    TRITON_AVAILABLE = False


def _require_triton():
    if not TRITON_AVAILABLE:
        skip_test("triton-library not installed")


def _init_context():
    """Initialise the default Triton context; skip if not possible."""
    _require_triton()
    result = triton_init()
    assert isinstance(result, dict), f"triton_init should return dict, got {type(result)}"
    assert result.get("ok") is True, f"triton_init failed: {result}"
    return result


# ============================================================================
# Status probe — always runs regardless of Triton availability
# ============================================================================


@test()
def test_triton_status_always_returns_dict():
    """triton_status should always return a dict whether or not triton-library is installed."""
    result = triton_status()
    assert isinstance(result, dict), f"expected dict, got {type(result)}"
    assert "available" in result, f'missing "available" key in {result}'


@test()
def test_triton_status_reports_availability():
    """triton_status dict indicates whether Triton is available or not."""
    result = triton_status()
    assert isinstance(result, dict)
    assert "available" in result, f'missing "available" key in {result}'


# ============================================================================
# Context lifecycle
# ============================================================================


@test()
def test_triton_init_auto_detects_arch():
    """triton_init auto-detects architecture from the loaded binary."""
    _require_triton()
    result = triton_init()
    assert isinstance(result, dict)
    assert result.get("ok") is True, f"triton_init failed: {result}"
    assert "architecture" in result, f"Expected arch in init result, got: {result!r}"


@test()
def test_triton_init_explicit_x86_64():
    """triton_init accepts explicit architecture override."""
    _require_triton()
    result = triton_init("x86_64")
    assert isinstance(result, dict)
    assert result.get("ok") is True, f"triton_init failed: {result}"
    assert result.get("architecture") == "x86_64", f"Expected x86_64 arch: {result}"


@test()
def test_triton_get_context_info_after_init():
    """triton_get_context_info returns a dict with architecture and mode info."""
    _init_context()
    info = triton_get_context_info()
    assert isinstance(info, dict), f"expected dict, got {type(info)}"
    assert "architecture" in info, f"missing 'architecture' key in {info}"


@test()
def test_triton_reset_clears_state():
    """triton_reset returns success and leaves the context ready for reuse."""
    _init_context()
    result = triton_reset()
    assert isinstance(result, dict)
    assert result.get("ok") is True, f"triton_reset failed: {result}"
    # Should still be usable after reset
    info = triton_get_context_info()
    assert isinstance(info, dict)


# ============================================================================
# Symbolization
# ============================================================================


@test()
def test_triton_symbolize_register():
    """triton_symbolize_register marks a register as symbolic."""
    _init_context()
    result = triton_symbolize_register("rax", "test_input")
    assert isinstance(result, dict), f"expected dict, got {type(result)}"
    assert "id" in result or "alias" in result or "variable" in result or "symbolic" in result, (
        f"Missing expected key in {result}"
    )


@test()
def test_triton_symbolize_memory():
    """triton_symbolize_memory marks a memory region as symbolic."""
    _init_context()
    result = triton_symbolize_memory(0x1000, 8, "mem_input")
    assert isinstance(result, dict), f"expected dict, got {type(result)}"


@test()
def test_triton_batch_symbolize_registers():
    """triton_batch_symbolize_registers processes a comma-separated register list."""
    _init_context()
    result = triton_batch_symbolize_registers("rax, rbx, rcx")
    assert isinstance(result, list), f"expected list, got {type(result)}"
    assert len(result) == 3, f"Expected 3 results, got {len(result)}: {result}"
    assert all(isinstance(r, dict) for r in result), f"Expected list of dicts: {result}"


# ============================================================================
# Concrete values
# ============================================================================


@test()
def test_triton_set_get_concrete_register():
    """Setting and getting a concrete register value round-trips correctly."""
    _init_context()
    triton_set_concrete_register_value("rax", "0xdeadbeef")
    result = triton_get_concrete_register_value("rax")
    assert isinstance(result, dict), f"expected dict, got {type(result)}"
    assert "value" in result, f"missing 'value' key in {result}"
    # Value should be 0xdeadbeef
    assert int(result["value"], 16) == 0xDEADBEEF or result["value"] == "0xdeadbeef", (
        f"Unexpected register value: {result['value']}"
    )


@test()
def test_triton_set_get_concrete_memory():
    """Setting and getting concrete memory values round-trips correctly."""
    _init_context()
    triton_set_concrete_memory_value(0x2000, "DEADBEEFCAFEBABE")
    result = triton_get_concrete_memory_value(0x2000, 8)
    assert isinstance(result, dict), f"expected dict, got {type(result)}"
    assert "data" in result or "value" in result or "bytes" in result, (
        f"Missing expected key in {result}"
    )


# ============================================================================
# Instruction processing
# ============================================================================


@test()
def test_triton_process_instruction():
    """triton_process_instruction processes a real instruction from the binary."""
    _init_context()
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")

    result = triton_process_instruction(int(fn_addr, 16))
    assert isinstance(result, dict), f"expected dict, got {type(result)}"
    assert "disasm" in result or "instruction" in result or "mnemonic" in result, (
        f"Missing disasm info in {result}"
    )


@test()
def test_triton_process_function():
    """triton_process_function walks a function and returns processed instruction count."""
    _init_context()
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")

    result = triton_process_function(int(fn_addr, 16), max_insns=20)
    assert isinstance(result, dict), f"expected dict, got {type(result)}"
    assert "processed" in result or "count" in result or "instructions" in result, (
        f"Missing count info in {result}"
    )


# ============================================================================
# Symbolic queries
# ============================================================================


@test()
def test_triton_get_symbolic_variables_after_symbolize():
    """triton_get_symbolic_variables returns the symbolized register."""
    _init_context()
    triton_symbolize_register("rax", "query_test")
    result = triton_get_symbolic_variables()
    assert isinstance(result, dict), f"expected dict, got {type(result)}"
    assert result.get("ok") is True, f"get_symbolic_variables failed: {result}"
    assert result.get("count", 0) >= 1, "Expected at least one symbolic variable"


@test()
def test_triton_get_symbolic_expressions():
    """triton_get_symbolic_expressions returns an empty list on a fresh context."""
    _init_context()
    result = triton_get_symbolic_expressions()
    assert isinstance(result, dict), f"expected dict, got {type(result)}"
    assert result.get("ok") is True, f"get_symbolic_expressions failed: {result}"


@test()
def test_triton_get_path_constraints():
    """triton_get_path_constraints returns a list (empty on a fresh context)."""
    _init_context()
    result = triton_get_path_constraints()
    assert isinstance(result, dict), f"expected dict, got {type(result)}"
    assert result.get("ok") is True, f"get_path_constraints failed: {result}"


# ============================================================================
# Taint
# ============================================================================


@test()
def test_triton_taint_and_untaint_register():
    """Taint/untaint cycle on rax reflects correctly in the taint query."""
    _init_context()
    triton_taint_register("rax")
    status = triton_is_register_tainted("rax")
    assert isinstance(status, dict), f"expected dict, got {type(status)}"
    assert status.get("tainted") is True, f"Expected rax to be tainted: {status}"

    triton_untaint_register("rax")
    status2 = triton_is_register_tainted("rax")
    assert status2.get("tainted") is False, f"Expected rax to be untainted: {status2}"


@test()
def test_triton_taint_and_check_memory():
    """Taint a memory region and verify it's reported as tainted."""
    _init_context()
    triton_taint_memory(0x3000, 4)
    status = triton_is_memory_tainted(0x3000, 4)
    assert isinstance(status, dict), f"expected dict, got {type(status)}"
    assert status.get("tainted") is True, f"Expected memory 0x3000 to be tainted: {status}"


@test()
def test_triton_get_taint_summary():
    """triton_get_taint_summary returns lists of tainted registers and memory."""
    _init_context()
    triton_taint_register("rbx")
    triton_taint_memory(0x4000, 1)
    summary = triton_get_taint_summary()
    assert isinstance(summary, dict), f"expected dict, got {type(summary)}"
    assert "registers" in summary, f"missing 'registers' key in {summary}"
    assert "memory" in summary, f"missing 'memory' key in {summary}"


# ============================================================================
# SMT / solving
# ============================================================================


@test()
def test_triton_solve_path_constraints_no_constraints():
    """triton_solve_path_constraints on an empty path predicate returns a result dict."""
    _init_context()
    result = triton_solve_path_constraints()
    assert isinstance(result, dict), f"expected dict, got {type(result)}"
    assert "sat" in result or "model" in result, (
        f"Missing solve status in {result}"
    )


# ============================================================================
# Snapshots
# ============================================================================


@test()
def test_triton_snapshot_save_list_delete():
    """Snapshot save/list/delete lifecycle works correctly."""
    _init_context()
    triton_symbolize_register("rax", "snap_test")

    save_result = triton_snapshot_save("test_snapshot")
    assert isinstance(save_result, dict), f"expected dict, got {type(save_result)}"
    snap_id = save_result.get("snapshot_id")
    assert snap_id is not None, f"Expected snapshot_id in {save_result}"

    listing = triton_snapshot_list()
    assert isinstance(listing, dict), f"expected dict, got {type(listing)}"
    snaps = listing.get("snapshots", [])
    ids = [s.get("id") for s in snaps]
    assert snap_id in ids, f"Snapshot {snap_id} not found in list: {ids}"

    del_result = triton_snapshot_delete(snap_id)
    assert isinstance(del_result, dict), f"expected dict from delete, got {type(del_result)}"
    assert del_result.get("ok") is True, f"delete failed: {del_result}"


@test()
def test_triton_snapshot_restore():
    """Snapshot restore re-establishes symbolic variables from the saved state."""
    _init_context()
    triton_symbolize_register("rcx", "restore_test")

    save_result = triton_snapshot_save("restore_snap")
    snap_id = save_result.get("snapshot_id")
    assert snap_id is not None

    triton_reset()

    restore_result = triton_snapshot_restore(snap_id)
    assert isinstance(restore_result, dict), f"expected dict, got {type(restore_result)}"
    assert restore_result.get("ok") is True, f"Unexpected restore result: {restore_result}"

    vars_after = triton_get_symbolic_variables()
    assert isinstance(vars_after, dict), f"expected dict, got {type(vars_after)}"
    assert vars_after.get("ok") is True
    assert vars_after.get("count", 0) >= 1, "Expected at least one symbolic variable after restore"


# ============================================================================
# Annotation tools
# ============================================================================


@test()
def test_triton_annotate_function():
    """triton_annotate_function runs and reports annotation count."""
    _init_context()
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")
    result = triton_annotate_function(int(fn_addr, 16), max_insns=20)
    assert isinstance(result, dict), f"expected dict, got {type(result)}"
    assert "annotations_written" in result, f"Missing annotations_written: {result}"


@test()
def test_triton_highlight_tainted_instructions():
    """triton_highlight_tainted_instructions scans and reports highlights."""
    _init_context()
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")
    # Taint a register first so something is highlighted
    triton_taint_register("rax")
    result = triton_highlight_tainted_instructions(int(fn_addr, 16), max_insns=20)
    assert isinstance(result, dict), f"expected dict, got {type(result)}"
    assert "highlighted_count" in result, f"Missing highlighted_count: {result}"

@test()
def test_triton_analyze_function():
    """triton_analyze_function runs the full pipeline and returns a structured report."""
    _require_triton()
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")
    result = triton_analyze_function(fn_addr, max_insns=20)
    assert isinstance(result, dict), f"expected dict, got {type(result)}"
    assert result.get("ok") is True, f"Expected ok=True: {result}"
    assert "instructions_processed" in result, f"Missing instructions_processed: {result}"
    assert "solver" in result, f"Missing solver: {result}"


@test()
def test_triton_find_input_for_branch():
    """triton_find_input_for_branch returns a block path and solver result."""
    _require_triton()
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")
    # Use the function start as target (trivial path)
    result = triton_find_input_for_branch(fn_addr, fn_addr, max_insns=20)
    assert isinstance(result, dict), f"expected dict, got {type(result)}"
    assert result.get("ok") is True, f"Expected ok=True: {result}"
    assert "block_path" in result, f"Missing block_path: {result}"
    assert "solver" in result, f"Missing solver: {result}"

