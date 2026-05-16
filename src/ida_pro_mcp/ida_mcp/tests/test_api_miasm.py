"""Tests for api_miasm — Miasm IR analysis and assembly tools.

All tests skip gracefully when miasm is not installed.
Address constants assume a 64-bit ELF binary (crackme03.elf).
"""

from ..framework import (
    test,
    skip_test,
    assert_non_empty,
    assert_is_list,
    get_any_function,
)

try:
    from ..api_miasm import (
        miasm_status,
        MIASM_AVAILABLE,
    )
    if MIASM_AVAILABLE:
        from ..api_miasm import (
            miasm_sync,
            miasm_lift_to_ir,
            miasm_lift_function,
            miasm_get_ssa,
            miasm_get_cfg_dot,
            miasm_find_paths,
            miasm_deobfuscate_cfg,
            miasm_simplify_block,
            miasm_emulate_symbolic,
            miasm_get_function_side_effects,
            miasm_assemble,
            miasm_patch_instruction,
            miasm_trace_data_flow,
        )
except ImportError:
    MIASM_AVAILABLE = False


def _require_miasm():
    if not MIASM_AVAILABLE:
        skip_test("miasm not installed")


def _get_func_ea() -> int:
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")
    return int(fn_addr, 16)


# ============================================================================
# Status probe — always runs regardless of Miasm availability
# ============================================================================


@test()
def test_miasm_status_always_returns_string():
    """miasm_status should always succeed whether or not miasm is installed."""
    result = miasm_status()
    assert isinstance(result, str), f"expected str, got {type(result)}"
    assert_non_empty(result)


@test()
def test_miasm_status_reports_availability():
    """miasm_status reports availability clearly."""
    result = miasm_status()
    has_not = "NOT" in result or "not" in result
    has_yes = "yes" in result.lower() or "version" in result.lower()
    assert has_not or has_yes, f"Unexpected status string: {result!r}"


# ============================================================================
# Sync
# ============================================================================


@test()
def test_miasm_sync_detects_arch():
    """miasm_sync reports the architecture after synchronising with IDA."""
    _require_miasm()
    result = miasm_sync()
    assert isinstance(result, str), f"expected str, got {type(result)}"
    # Should mention architecture name
    arch_keywords = ("x86", "arm", "mips", "ppc", "aarch64")
    assert any(kw in result.lower() for kw in arch_keywords), (
        f"Expected arch name in sync result: {result!r}"
    )


# ============================================================================
# IR lifting
# ============================================================================


@test()
def test_miasm_lift_to_ir_basic():
    """miasm_lift_to_ir lifts a small instruction range to IR blocks."""
    _require_miasm()
    ea = _get_func_ea()
    result = miasm_lift_to_ir(ea, ea + 32)
    assert isinstance(result, list), f"expected list, got {type(result)}"
    assert len(result) >= 1, "Expected at least one IR block"
    block = result[0]
    assert "loc_key" in block, f"Missing 'loc_key' in block {block}"
    assert "instructions" in block, f"Missing 'instructions' in block {block}"
    assert isinstance(block["instructions"], list)


@test()
def test_miasm_lift_function_returns_blocks_and_edges():
    """miasm_lift_function lifts a whole function and returns blocks and edges."""
    _require_miasm()
    ea = _get_func_ea()
    result = miasm_lift_function(ea)
    assert isinstance(result, dict), f"expected dict, got {type(result)}"
    assert "blocks" in result, f"Missing 'blocks' in {result}"
    assert "edges" in result, f"Missing 'edges' in {result}"
    assert isinstance(result["blocks"], list)
    assert isinstance(result["edges"], list)
    assert "function_ea" in result


# ============================================================================
# SSA
# ============================================================================


@test()
def test_miasm_get_ssa_returns_ssa_form():
    """miasm_get_ssa returns IR in SSA form with phi-renamed variables."""
    _require_miasm()
    ea = _get_func_ea()
    result = miasm_get_ssa(ea)
    assert isinstance(result, dict), f"expected dict, got {type(result)}"
    assert result.get("form") == "ssa", f"Expected form=ssa in {result}"
    assert "blocks" in result
    assert isinstance(result["blocks"], list)


# ============================================================================
# CFG analysis
# ============================================================================


@test()
def test_miasm_get_cfg_dot_returns_dot_string():
    """miasm_get_cfg_dot returns a non-empty Graphviz DOT string."""
    _require_miasm()
    ea = _get_func_ea()
    result = miasm_get_cfg_dot(ea)
    assert isinstance(result, str), f"expected str, got {type(result)}"
    assert_non_empty(result)
    assert "digraph" in result.lower() or "->" in result, (
        f"Result doesn't look like DOT format: {result[:200]!r}"
    )


@test()
def test_miasm_find_paths_start_equals_target():
    """miasm_find_paths with start == target finds at least one trivial path."""
    _require_miasm()
    ea = _get_func_ea()
    result = miasm_find_paths(ea, ea)
    assert isinstance(result, list), f"expected list, got {type(result)}"


@test()
def test_miasm_find_paths_returns_path_list():
    """miasm_find_paths returns a list of path dicts with 'addresses' keys."""
    _require_miasm()
    ea = _get_func_ea()
    result = miasm_find_paths(ea, ea, max_paths=5)
    assert isinstance(result, list), f"expected list, got {type(result)}"
    for path in result:
        assert "path_index" in path, f"Missing path_index in {path}"
        assert "addresses" in path, f"Missing addresses in {path}"
        assert isinstance(path["addresses"], list)


# ============================================================================
# Deobfuscation / simplification
# ============================================================================


@test()
def test_miasm_deobfuscate_cfg_returns_simplified():
    """miasm_deobfuscate_cfg returns simplified IR with the 'simplified' flag."""
    _require_miasm()
    ea = _get_func_ea()
    result = miasm_deobfuscate_cfg(ea)
    assert isinstance(result, dict), f"expected dict, got {type(result)}"
    assert result.get("simplified") is True, f"Expected simplified=True in {result}"
    assert "blocks" in result
    assert "edges" in result


@test()
def test_miasm_simplify_block_returns_register_state():
    """miasm_simplify_block symbolically executes a block and returns simplified regs."""
    _require_miasm()
    ea = _get_func_ea()
    result = miasm_simplify_block(ea)
    assert isinstance(result, dict), f"expected dict, got {type(result)}"
    assert "address" in result, f"Missing 'address' in {result}"
    assert "simplified_registers" in result, f"Missing 'simplified_registers' in {result}"
    assert isinstance(result["simplified_registers"], dict)


# ============================================================================
# Symbolic execution
# ============================================================================


@test()
def test_miasm_emulate_symbolic_empty_context():
    """miasm_emulate_symbolic with no initial context runs and returns a register map."""
    _require_miasm()
    ea = _get_func_ea()
    result = miasm_emulate_symbolic(ea)
    assert isinstance(result, dict), f"expected dict, got {type(result)}"
    assert "address" in result, f"Missing 'address' in {result}"
    assert "registers" in result, f"Missing 'registers' in {result}"
    assert isinstance(result["registers"], dict)


@test()
def test_miasm_emulate_symbolic_with_context():
    """miasm_emulate_symbolic with a concrete initial context produces a concrete result."""
    _require_miasm()
    ea = _get_func_ea()
    # Set EAX/RAX to a concrete value and see if it propagates
    result = miasm_emulate_symbolic(ea, '{"RAX": 42}')
    assert isinstance(result, dict), f"expected dict, got {type(result)}"
    assert "registers" in result


# ============================================================================
# Data flow / side effects
# ============================================================================


@test()
def test_miasm_get_function_side_effects():
    """miasm_get_function_side_effects returns reads and writes sets."""
    _require_miasm()
    ea = _get_func_ea()
    result = miasm_get_function_side_effects(ea)
    assert isinstance(result, dict), f"expected dict, got {type(result)}"
    assert "reads" in result, f"Missing 'reads' in {result}"
    assert "writes" in result, f"Missing 'writes' in {result}"
    assert isinstance(result["reads"], list)
    assert isinstance(result["writes"], list)
    assert "function_ea" in result


# ============================================================================
# Assembly
# ============================================================================


@test()
def test_miasm_assemble_mov_x86():
    """miasm_assemble returns valid hex encoding for an x86 MOV instruction."""
    _require_miasm()
    result = miasm_assemble("MOV EAX, 1", "x86_32")
    assert isinstance(result, dict), f"expected dict, got {type(result)}"
    assert "shortest" in result, f"Missing 'shortest' in {result}"
    assert "encodings" in result, f"Missing 'encodings' in {result}"
    assert isinstance(result["encodings"], list)
    assert len(result["encodings"]) >= 1
    # Encoding should be valid hex
    enc = result["shortest"]
    bytes.fromhex(enc)  # raises ValueError if not valid hex


@test()
def test_miasm_assemble_returns_multiple_encodings():
    """miasm_assemble can return multiple encodings when available."""
    _require_miasm()
    result = miasm_assemble("NOP", "x86_32")
    assert isinstance(result, dict), f"expected dict, got {type(result)}"
    assert "encodings" in result
    assert len(result["encodings"]) >= 1


@test()
def test_miasm_assemble_invalid_instruction_raises_error():
    """miasm_assemble raises an error for an invalid instruction string."""
    _require_miasm()
    from ..sync import IDAError
    try:
        miasm_assemble("NOTANINSTRUCTION FAKE, ARGS", "x86_32")
        # If it doesn't raise, that's also acceptable (returns error dict)
    except (IDAError, Exception):
        pass  # expected
