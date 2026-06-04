"""Tests for api_numpy — NumPy-accelerated numerical binary analysis.

All tests except the status probe skip gracefully when numpy is not installed.
Region-based tests read bytes from the loaded fixture's first code segment.
"""

from ..framework import test, skip_test

try:
    from ..api_numpy import numpy_status
    from ..numpy_compat import NUMPY_AVAILABLE, np_entropy
    if NUMPY_AVAILABLE:
        from ..api_numpy import numpy_entropy_map, numpy_byte_histogram
except ImportError:
    NUMPY_AVAILABLE = False


def _require_numpy():
    if not NUMPY_AVAILABLE:
        skip_test("numpy not installed")


def _first_code_region(min_size: int = 4096) -> tuple[str, int]:
    """Return (hex_addr, size) of a readable chunk in the first code segment."""
    import ida_bytes
    import ida_segment

    seg = None
    for i in range(ida_segment.get_segm_qty()):
        s = ida_segment.getnseg(i)
        if s and (s.perm & ida_segment.SEGPERM_EXEC):
            seg = s
            break
    if seg is None:
        skip_test("no executable segment in fixture")
    size = min(min_size, int(seg.end_ea - seg.start_ea))
    if size < 256:
        skip_test("executable segment too small")
    data = ida_bytes.get_bytes(seg.start_ea, size)
    if not data:
        skip_test("could not read code segment bytes")
    return hex(seg.start_ea), size


# ---------------------------------------------------------------------------
# Status probe — always runs, even without numpy
# ---------------------------------------------------------------------------


@test()
def test_numpy_status_probe():
    """numpy_status must not crash regardless of whether numpy is installed."""
    result = numpy_status()
    assert isinstance(result, dict), "numpy_status must return a dict"
    assert result.get("ok") is True
    assert "available" in result, "numpy_status must include 'available'"


@test()
def test_numpy_status_version():
    """version is a non-empty string when numpy is available."""
    _require_numpy()
    result = numpy_status()
    assert result.get("available") is True
    version = result.get("version")
    assert isinstance(version, str) and len(version) > 0


# ---------------------------------------------------------------------------
# np_entropy primitive — exact known values
# ---------------------------------------------------------------------------


@test()
def test_np_entropy_uniform_is_eight():
    """All 256 byte values once each => entropy is exactly 8.0 bits/byte."""
    _require_numpy()
    data = bytes(range(256))
    h = np_entropy(data)
    assert abs(h - 8.0) < 1e-9, f"expected 8.0, got {h}"


@test()
def test_np_entropy_constant_is_zero():
    """A single repeated byte => entropy is 0.0."""
    _require_numpy()
    assert np_entropy(b"\x41" * 1024) == 0.0
    assert np_entropy(b"") == 0.0


@test()
def test_np_entropy_two_symbols_is_one():
    """Two equally-frequent byte values => entropy is exactly 1.0 bit/byte."""
    _require_numpy()
    data = (b"\x00\xff") * 512
    h = np_entropy(data)
    assert abs(h - 1.0) < 1e-9, f"expected 1.0, got {h}"


# ---------------------------------------------------------------------------
# numpy_entropy_map
# ---------------------------------------------------------------------------


@test()
def test_entropy_map_basic_shape():
    """entropy_map returns summary + histogram over a real code region."""
    _require_numpy()
    addr, size = _first_code_region(4096)
    result = numpy_entropy_map(addr, size, block_size=256)
    assert result.get("ok") is True, result
    assert result["total_blocks"] >= 1
    assert result["block_size"] == 256
    assert result["step"] == 256  # 0 => non-overlapping default
    assert len(result["entropy_histogram"]) == 16
    summary = result["summary"]
    for key in ("mean_entropy", "median_entropy", "max_entropy", "min_entropy"):
        assert 0.0 <= summary[key] <= 8.0, f"{key}={summary[key]} out of range"
    assert summary["min_entropy"] <= summary["max_entropy"]


@test()
def test_entropy_map_small_region_includes_blocks():
    """A small region (<= 512 blocks) includes the per-block list."""
    _require_numpy()
    addr, size = _first_code_region(4096)
    result = numpy_entropy_map(addr, size, block_size=512)
    assert result.get("ok") is True
    assert "blocks" in result, "small region should inline per-block list"
    for b in result["blocks"]:
        assert 0.0 <= b["entropy"] <= 8.0
        assert b["entropy_class"] in (
            "padding", "data", "code", "compressed", "encrypted",
        )


@test()
def test_entropy_map_rejects_tiny_block():
    """block_size below the minimum is rejected with a clear error."""
    _require_numpy()
    addr, size = _first_code_region(4096)
    result = numpy_entropy_map(addr, size, block_size=8)
    assert result.get("ok") is False
    assert "block_size" in result.get("error", "")


# ---------------------------------------------------------------------------
# numpy_byte_histogram
# ---------------------------------------------------------------------------


@test()
def test_byte_histogram_basic():
    """byte_histogram returns entropy, chi2, and most_common for a code region."""
    _require_numpy()
    addr, size = _first_code_region(4096)
    result = numpy_byte_histogram(addr, size)
    assert result.get("ok") is True, result
    assert 0.0 <= result["entropy"] <= 8.0
    assert result["chi2"] >= 0.0
    assert 1 <= result["unique_byte_count"] <= 256
    assert isinstance(result["most_common"], list)
    assert result["most_common"], "most_common should be non-empty"
    top = result["most_common"][0]
    assert top["count"] >= 1
    assert 0.0 <= top["pct"] <= 100.0


@test()
def test_byte_histogram_counts_optional():
    """The raw 256-bucket counts array is returned only when requested."""
    _require_numpy()
    addr, size = _first_code_region(4096)
    without = numpy_byte_histogram(addr, size, include_counts=False)
    assert "counts" not in without
    with_counts = numpy_byte_histogram(addr, size, include_counts=True)
    assert "counts" in with_counts
    assert len(with_counts["counts"]) == 256
    assert sum(with_counts["counts"]) == with_counts["size_analyzed"]


@test()
def test_byte_histogram_unmapped_address_errors():
    """An unreadable region returns a structured error, not a crash."""
    _require_numpy()
    # BADADDR-ish high address that is not mapped in any fixture.
    result = numpy_byte_histogram("0xffffffffff000000", 256)
    assert result.get("ok") is False
    assert "error" in result
