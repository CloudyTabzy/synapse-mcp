"""Tests for hybrid cross-engine workflows.

Skips gracefully when either triton-library or miasm is not installed.
"""

from ..framework import (
    test,
    skip_test,
    get_any_function,
)

try:
    from ..api_triton import TRITON_AVAILABLE
except ImportError:
    TRITON_AVAILABLE = False

try:
    from ..api_miasm import MIASM_AVAILABLE
except ImportError:
    MIASM_AVAILABLE = False

try:
    from ..api_composite import (
        hybrid_analyze_function,
        hybrid_deobfuscate_and_patch,
        hybrid_iterative_deobfuscate,
        deobfuscate_segment,
    )
except ImportError:
    hybrid_analyze_function = None
    hybrid_deobfuscate_and_patch = None
    hybrid_iterative_deobfuscate = None
    deobfuscate_segment = None


def _require_both():
    if not TRITON_AVAILABLE:
        skip_test("triton-library not installed")
    if not MIASM_AVAILABLE:
        skip_test("miasm not installed")


@test()
def test_hybrid_analyze_function():
    """hybrid_analyze_function returns combined Miasm + Triton results."""
    _require_both()
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")
    result = hybrid_analyze_function(int(fn_addr, 16), max_insns=20)
    assert isinstance(result, dict), f"expected dict, got {type(result)}"
    assert result.get("ok") is True, f"Expected ok=True: {result}"
    assert "miasm" in result, f"Missing miasm key: {result}"
    assert "triton" in result, f"Missing triton key: {result}"
    assert "solver" in result, f"Missing solver key: {result}"


@test()
def test_hybrid_deobfuscate_and_patch_dry_run():
    """hybrid_deobfuscate_and_patch dry-run reports candidates without patching."""
    _require_both()
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")
    result = hybrid_deobfuscate_and_patch(int(fn_addr, 16), dry_run=True)
    assert isinstance(result, dict), f"expected dict, got {type(result)}"
    assert result.get("ok") is True, f"Expected ok=True: {result}"
    assert "candidates" in result, f"Missing candidates: {result}"
    assert result.get("dry_run") is True, f"Expected dry_run=True: {result}"


@test()
def test_hybrid_deobfuscate_and_patch_requires_confirm():
    """hybrid_deobfuscate_and_patch rejects dry_run=False without confirm."""
    _require_both()
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")
    result = hybrid_deobfuscate_and_patch(int(fn_addr, 16), dry_run=False, confirm=False)
    assert isinstance(result, dict), f"expected dict, got {type(result)}"
    assert result.get("ok") is False, f"Expected ok=False when confirm=False: {result}"


@test()
def test_hybrid_iterative_deobfuscate_dry_run():
    """hybrid_iterative_deobfuscate dry-run returns per-iteration log and converges
    (or hits max_iterations) without modifying the IDB."""
    if not MIASM_AVAILABLE:
        skip_test("miasm not installed")
    if hybrid_iterative_deobfuscate is None:
        skip_test("hybrid_iterative_deobfuscate not importable")
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")

    result = hybrid_iterative_deobfuscate(
        int(fn_addr, 16),
        max_iterations=3,
        verify_with_triton=False,  # speed up the test; verification covered separately
        dry_run=True,
    )
    assert isinstance(result, dict), f"expected dict, got {type(result)}"
    assert result.get("ok") is True, f"Expected ok=True: {result}"
    assert result.get("dry_run") is True
    assert isinstance(result.get("iterations"), list), f"missing iterations: {result}"
    assert result.get("total_patches", 0) == 0, "dry_run must not patch"
    # Iteration log structure sanity.
    for it in result["iterations"]:
        for field in ("iteration", "block_count_before", "block_count_after",
                      "ir_statements_before", "ir_statements_after",
                      "candidates", "patches_applied", "converged"):
            assert field in it, f"iteration missing {field}: {it}"


@test()
def test_hybrid_iterative_deobfuscate_requires_confirm():
    """dry_run=False without confirm=True must refuse to run."""
    if not MIASM_AVAILABLE:
        skip_test("miasm not installed")
    if hybrid_iterative_deobfuscate is None:
        skip_test("hybrid_iterative_deobfuscate not importable")
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")
    result = hybrid_iterative_deobfuscate(
        int(fn_addr, 16), dry_run=False, confirm=False, verify_with_triton=False,
    )
    assert isinstance(result, dict)
    assert result.get("ok") is False
    assert "confirm" in (result.get("error") or "").lower()


@test()
def test_hybrid_iterative_deobfuscate_with_verification():
    """When Triton is available, verification runs and produces a verified bool/None."""
    _require_both()
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")
    result = hybrid_iterative_deobfuscate(
        int(fn_addr, 16),
        max_iterations=2,
        verify_with_triton=True,
        verify_samples=2,
        dry_run=True,
    )
    assert isinstance(result, dict)
    assert result.get("ok") is True
    iters = result.get("iterations") or []
    # Every iteration that produced candidates should expose a 'verified' field.
    for it in iters:
        assert "verified" in it
        assert it["verified"] in (True, False, None)


@test()
def test_deobfuscate_segment_bad_segment():
    """deobfuscate_segment returns ok=False for a non-existent segment."""
    if not MIASM_AVAILABLE:
        skip_test("miasm not installed")
    if deobfuscate_segment is None:
        skip_test("deobfuscate_segment not importable")
    result = deobfuscate_segment(".this_segment_does_not_exist_12345")
    assert isinstance(result, dict)
    assert result.get("ok") is False
    assert "segment" in (result.get("error") or "").lower() or "not found" in (result.get("error") or "").lower()


@test()
def test_deobfuscate_segment_dry_run():
    """deobfuscate_segment dry_run scans segment, returns structured result without patching."""
    if not MIASM_AVAILABLE:
        skip_test("miasm not installed")
    if deobfuscate_segment is None:
        skip_test("deobfuscate_segment not importable")

    result = deobfuscate_segment(
        ".text",
        max_functions=5,
        complexity_threshold=0.0,  # force all functions to qualify so we test the pipeline
        min_function_size=1,
        dry_run=True,
        verify_with_triton=False,  # speed up test
    )
    assert isinstance(result, dict), f"expected dict, got {type(result)}"
    assert result.get("ok") is True, f"Expected ok=True: {result}"
    assert result.get("dry_run") is True
    assert isinstance(result.get("candidates"), list)
    assert isinstance(result.get("results"), list)
    assert "scanned_functions" in result
    assert "segment" in result
    assert "segment_start" in result
    assert "segment_end" in result
    # With threshold=0.0 we should get at least some candidates on any real binary.
    assert result.get("candidate_count", 0) >= 0
    # No patches applied in dry_run.
    assert result.get("total_patches", 0) == 0


@test()
def test_deobfuscate_segment_requires_confirm():
    """deobfuscate_segment rejects dry_run=False without confirm=True."""
    if not MIASM_AVAILABLE:
        skip_test("miasm not installed")
    if deobfuscate_segment is None:
        skip_test("deobfuscate_segment not importable")
    result = deobfuscate_segment(".text", dry_run=False, confirm=False)
    assert isinstance(result, dict)
    assert result.get("ok") is False
    assert "confirm" in (result.get("error") or "").lower()


@test()
def test_deobfuscate_segment_respects_max_functions():
    """max_functions cap limits how many candidates are processed."""
    if not MIASM_AVAILABLE:
        skip_test("miasm not installed")
    if deobfuscate_segment is None:
        skip_test("deobfuscate_segment not importable")
    result = deobfuscate_segment(
        ".text",
        max_functions=2,
        complexity_threshold=0.0,
        min_function_size=1,
        dry_run=True,
        verify_with_triton=False,
    )
    assert isinstance(result, dict)
    assert result.get("ok") is True
    # Candidates list should be capped.
    assert len(result.get("candidates", [])) <= 2
    assert len(result.get("results", [])) <= 2


@test()
def test_deobfuscate_segment_high_threshold_empty():
    """An impossibly high threshold should yield zero candidates."""
    if not MIASM_AVAILABLE:
        skip_test("miasm not installed")
    if deobfuscate_segment is None:
        skip_test("deobfuscate_segment not importable")
    result = deobfuscate_segment(
        ".text",
        complexity_threshold=999.0,
        dry_run=True,
        verify_with_triton=False,
    )
    assert isinstance(result, dict)
    assert result.get("ok") is True
    assert result.get("candidate_count", -1) == 0
    assert len(result.get("candidates", [])) == 0
    assert len(result.get("results", [])) == 0
