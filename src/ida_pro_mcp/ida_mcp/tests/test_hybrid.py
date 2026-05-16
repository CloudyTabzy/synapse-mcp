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
    from ..api_composite import hybrid_analyze_function, hybrid_deobfuscate_and_patch
except ImportError:
    hybrid_analyze_function = None
    hybrid_deobfuscate_and_patch = None


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
