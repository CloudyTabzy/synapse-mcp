"""Tests for api_numpy — NumPy-accelerated numerical binary analysis.

All tests except the status probe skip gracefully when numpy is not installed.
Region-based tests read bytes from the loaded fixture's first code segment.
"""

from ..framework import test, skip_test

try:
    from ..api_numpy import numpy_status
    from ..numpy_compat import NUMPY_AVAILABLE, np_entropy
    if NUMPY_AVAILABLE:
        from ..api_numpy import (
            numpy_entropy_map,
            numpy_byte_histogram,
            numpy_xor_key_recovery,
            numpy_function_similarity,
        )
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


# ---------------------------------------------------------------------------
# XOR key recovery — helper unit tests on synthetic data (no IDA needed)
# ---------------------------------------------------------------------------


@test()
def test_xor_helpers_recover_4byte_key():
    """Candidate-length detection + key recovery recover a known 4-byte key."""
    _require_numpy()
    import numpy as np
    from ..api_numpy import _xor_candidate_lengths, _recover_xor_key

    plain = (b"The quick brown fox jumps over the lazy dog. " * 120)[:4096]
    pa = np.frombuffer(plain, dtype=np.uint8)
    key = np.frombuffer(bytes([0xDE, 0xAD, 0xBE, 0xEF]), dtype=np.uint8)
    cipher = (pa ^ np.resize(key, pa.size)).astype(np.uint8)

    cand_lengths, top = _xor_candidate_lengths(cipher, 32)
    assert 4 in cand_lengths, f"4 not in candidates {cand_lengths}"
    # Text => dominant plaintext byte is space (0x20).
    rec = _recover_xor_key(cipher, 4, 0x20)
    assert rec.tolist() == [0xDE, 0xAD, 0xBE, 0xEF], rec.tolist()


@test()
def test_xor_helpers_single_byte_key():
    """A single-byte XOR is recovered (entropy is unchanged; relies on freq)."""
    _require_numpy()
    import numpy as np
    from ..api_numpy import _recover_xor_key

    plain = (b"The quick brown fox jumps over the lazy dog. " * 120)[:4096]
    pa = np.frombuffer(plain, dtype=np.uint8)
    cipher = (pa ^ np.uint8(0x5A)).astype(np.uint8)
    rec = _recover_xor_key(cipher, 1, 0x20)
    assert rec.tolist() == [0x5A], rec.tolist()


# ---------------------------------------------------------------------------
# numpy_xor_key_recovery (tool-level)
# ---------------------------------------------------------------------------


@test()
def test_xor_key_recovery_smoke():
    """On a real code region the tool returns ranked candidates without crashing."""
    _require_numpy()
    addr, size = _first_code_region(4096)
    result = numpy_xor_key_recovery(addr, size)
    assert result.get("ok") is True, result
    assert isinstance(result["key_candidates"], list) and result["key_candidates"]
    assert isinstance(result["top_key_length_candidates"], list)
    for c in result["key_candidates"]:
        assert c["confidence"] in ("high", "medium", "low")
        assert c["key_length"] >= 1


@test()
def test_xor_key_recovery_tiny_region_errors():
    """A region below the minimum analysis size returns a structured error."""
    _require_numpy()
    addr, _ = _first_code_region(4096)
    result = numpy_xor_key_recovery(addr, 8)
    assert result.get("ok") is False
    assert "small" in result.get("error", "").lower()


# ---------------------------------------------------------------------------
# numpy_function_similarity
# ---------------------------------------------------------------------------


def _two_functions(min_size: int = 64):
    import idautils
    import idaapi

    funcs = []
    for f in idautils.Functions():
        func = idaapi.get_func(f)
        if func and (func.end_ea - func.start_ea) >= min_size:
            funcs.append(f)
    return funcs


@test()
def test_function_similarity_self_identical():
    """A function compared to itself scores ~1.0 / identical (all methods)."""
    _require_numpy()
    funcs = _two_functions(64)
    if not funcs:
        skip_test("no function >= 64 bytes in fixture")
    ea = hex(funcs[0])
    for method in ("byte_histogram", "byte_entropy_histogram", "ncc"):
        result = numpy_function_similarity(ea, ea, method=method)
        assert result.get("ok") is True, result
        assert result["score"] >= 0.99, f"{method}: {result['score']}"
        assert result["interpretation"] == "identical"


@test()
def test_function_similarity_distinct_in_range():
    """Two distinct functions produce a valid score in [0, 1]."""
    _require_numpy()
    funcs = _two_functions(64)
    if len(funcs) < 2:
        skip_test("need two functions >= 64 bytes")
    result = numpy_function_similarity(hex(funcs[0]), hex(funcs[-1]))
    assert result.get("ok") is True, result
    assert 0.0 <= result["score"] <= 1.0
    assert result["interpretation"] in (
        "identical", "very_similar", "similar", "dissimilar",
    )


@test()
def test_function_similarity_min_bytes_guard():
    """min_bytes larger than the function triggers the too-small guard."""
    _require_numpy()
    import idautils

    f = next(iter(idautils.Functions()), None)
    if f is None:
        skip_test("no functions in fixture")
    result = numpy_function_similarity(hex(f), hex(f), min_bytes=10 ** 9)
    assert result.get("ok") is False
    assert "too small" in result.get("error", "").lower()


@test()
def test_function_similarity_bad_method():
    """An unknown method returns a structured error."""
    _require_numpy()
    funcs = _two_functions(64)
    if not funcs:
        skip_test("no function >= 64 bytes")
    result = numpy_function_similarity(hex(funcs[0]), hex(funcs[0]), method="bogus")
    assert result.get("ok") is False
    assert "method" in result.get("error", "").lower()
