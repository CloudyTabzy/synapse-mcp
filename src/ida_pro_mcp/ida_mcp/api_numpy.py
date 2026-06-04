"""api_numpy — NumPy-accelerated numerical binary analysis for IDA Pro MCP.

Optional module: numerical tools are only registered when ``numpy`` is installed.
Install with: pip install numpy>=2.0.0  (included in --install-deps all)

NumPy's value here is *additive*, not a retrofit of existing small-data paths.
These tools operate on large, agent-chosen byte regions (a multi-megabyte
section → tens of thousands of entropy blocks) where vectorization delivers a
real 10–50× win on data that is actually that big. The existing pure-Python
entropy/similarity helpers in api_lief / api_analysis run on tiny inputs
(a 4 KB overlay, 14-element feature vectors) where IDA's own native calls
dominate — so they are intentionally left alone.

Tool roster (2 tools + 1 always-registered probe):

  Infrastructure
    numpy_status            — availability probe (always registered)

  Numerical analysis
    numpy_entropy_map       — block-level Shannon entropy heatmap with
                              contiguous high-entropy run detection
                              (⭐ packed/encrypted section triage)
    numpy_byte_histogram    — 256-bucket byte distribution + chi-square
                              uniformity test (distinguishes encrypted /
                              compressed / plaintext / code in one call)

Profile: analysis
"""

import logging
from functools import reduce
from math import gcd
from typing import Annotated, TypedDict

import ida_bytes
import ida_funcs

from .rpc import tool
from .sync import idasync, tool_timeout
from .utils import parse_address, tool_error
from .numpy_compat import NUMPY_AVAILABLE, NUMPY_VERSION, np, np_entropy

logger = logging.getLogger(__name__)

# Hard cap on bytes read per call. Protects IDA's process from an accidental
# request to map an enormous region. Callers hitting this get truncated=True.
_MAX_REGION = 64 * 1024 * 1024  # 64 MB

# Cap on per-block entries returned inline. The full statistics (summary,
# contiguous runs, entropy histogram) are always computed over ALL blocks;
# only the verbose per-block list is suppressed above this many blocks so a
# multi-megabyte map doesn't flood the agent's context with 40k+ rows.
_MAX_BLOCKS_INLINE = 512

# Internal chunk size for vectorized block-entropy computation. Bounds peak
# memory to ~CHUNK * 256 * 8 bytes regardless of how large the region is.
_ENTROPY_CHUNK = 8192


# ============================================================================
# TypedDict result types  (defined in dependency order — no forward refs)
# ============================================================================


class EntropyBlock(TypedDict):
    offset: int
    entropy: float
    entropy_class: str


class EntropyRun(TypedDict):
    start_offset: int
    end_offset: int
    block_count: int
    mean_entropy: float


class NumpyEntropyMapResult(TypedDict, total=False):
    ok: bool
    addr: str
    size_analyzed: int
    block_size: int
    step: int
    total_blocks: int
    high_entropy_blocks: int
    low_entropy_blocks: int
    truncated: bool
    blocks: list[EntropyBlock]
    blocks_truncated: bool
    entropy_histogram: list[int]
    summary: dict
    contiguous_high_entropy_runs: list[EntropyRun]
    hint: str
    error: str
    error_type: str


class ByteHit(TypedDict):
    byte: int
    hex: str
    count: int
    pct: float


class NumpyByteHistogramResult(TypedDict, total=False):
    ok: bool
    addr: str
    size_analyzed: int
    truncated: bool
    entropy: float
    entropy_class: str
    chi2: float
    chi2_uniform_ratio: float
    distribution: str
    unique_byte_count: int
    most_common: list[ByteHit]
    least_common_count: int
    counts: list[int]
    interpretation: str
    hint: str
    error: str
    error_type: str


class KeyLengthCandidate(TypedDict):
    key_length: int
    ioc_rate: float


class XorKeyCandidate(TypedDict, total=False):
    key_hex: str
    key_length: int
    assumed_plaintext: str
    plaintext_entropy_after: float
    entropy_reduction: float
    printable_ratio: float
    null_ratio: float
    sample_decrypted_hex: str
    sample_decrypted_ascii: str
    confidence: str


class NumpyXorResult(TypedDict, total=False):
    ok: bool
    addr: str
    size_analyzed: int
    analysis_capped: bool
    ciphertext_entropy: float
    top_key_length_candidates: list[KeyLengthCandidate]
    key_candidates: list[XorKeyCandidate]
    hint: str
    error: str
    error_type: str


class NumpyFunctionSimilarityResult(TypedDict, total=False):
    ok: bool
    func_a: str
    func_b: str
    method: str
    score: float
    interpretation: str
    bytes_a: int
    bytes_b: int
    hint: str
    error: str
    error_type: str


# ============================================================================
# Helpers
# ============================================================================


def _classify_entropy(ent: float) -> str:
    """Map a Shannon entropy value (bits/byte) to a coarse class.

    Thresholds match api_lief._entropy_class for cross-tool consistency, with
    an added 'padding' class for near-zero entropy (NOP/null/alignment runs).
    """
    if ent < 1.0:
        return "padding"
    if ent >= 7.2:
        return "encrypted"
    if ent >= 6.0:
        return "compressed"
    if ent >= 4.5:
        return "code"
    return "data"


def _read_region(addr: str, size: int) -> tuple[int, bytes, bool]:
    """Resolve addr, bulk-read up to _MAX_REGION bytes. Returns (ea, data, truncated).

    Uses ida_bytes.get_bytes (one native bulk read) rather than a per-byte
    Python loop — essential for multi-megabyte regions. Raises ValueError when
    the region cannot be read (e.g. unmapped / BSS).
    """
    ea = parse_address(addr)
    if size <= 0:
        raise ValueError("size must be > 0")
    truncated = False
    if size > _MAX_REGION:
        size = _MAX_REGION
        truncated = True
    data = ida_bytes.get_bytes(ea, size)
    if not data:
        raise ValueError(
            f"Could not read {size} bytes at {hex(ea)} — region may be unmapped "
            "(e.g. BSS or beyond the image). Try a smaller size or a mapped address."
        )
    # get_bytes can return fewer bytes than requested at the image edge.
    if len(data) < size:
        truncated = True
    return ea, data, truncated


def _block_entropies(arr, block_size: int, step: int):
    """Vectorized per-window Shannon entropy over a uint8 array.

    Returns (starts, entropies) as numpy arrays. Processes windows in chunks so
    peak memory stays bounded (~_ENTROPY_CHUNK * 256 floats) regardless of how
    large the region is. Uses the offset-bincount trick to compute a full
    (chunk, 256) histogram matrix in one bincount call, then entropy per row.
    """
    n = arr.size
    if n < block_size:
        return np.empty(0, dtype=np.int64), np.empty(0, dtype=np.float64)
    starts = np.arange(0, n - block_size + 1, step, dtype=np.int64)
    ent_out = np.empty(starts.size, dtype=np.float64)
    win = np.arange(block_size, dtype=np.int64)
    inv_bs = 1.0 / block_size

    for c0 in range(0, starts.size, _ENTROPY_CHUNK):
        cs = starts[c0:c0 + _ENTROPY_CHUNK]
        c = cs.size
        # (c, block_size) matrix of byte values for this chunk's windows.
        blocks = arr[cs[:, None] + win[None, :]].astype(np.int64)
        # Pack each row into its own 256-wide bin range so a single bincount
        # yields per-row histograms: row i occupies bins [i*256, i*256+255].
        offs = (np.arange(c, dtype=np.int64)[:, None] * 256 + blocks).ravel()
        hist = np.bincount(offs, minlength=c * 256).reshape(c, 256).astype(np.float64)
        p = hist * inv_bs
        with np.errstate(divide="ignore", invalid="ignore"):
            logp = np.where(p > 0, np.log2(p), 0.0)
        ent_out[c0:c0 + c] = -np.sum(p * logp, axis=1)

    return starts, ent_out


# --- XOR key recovery helpers -------------------------------------------------

# Statistical analysis is capped at this many bytes — key detection and recovery
# need only a representative prefix, and the IoC scan is O(N) per candidate length.
_XOR_MAX_ANALYZE = 2 * 1024 * 1024  # 2 MB
# Validation window: a recovered key is scored by decrypting up to this many
# bytes. Large enough that a wrong (over-long) key cannot fake a good score.
_XOR_VALIDATE = 4096
# Assumed dominant-plaintext byte for each named assumption.
_XOR_ASSUMPTIONS: dict[str, int] = {"null": 0x00, "space": 0x20, "0xff": 0xFF}


def _divisors(x: int) -> set[int]:
    return {i for i in range(1, x + 1) if x % i == 0}


def _xor_candidate_lengths(arr, cap: int) -> tuple[list[int], list[KeyLengthCandidate]]:
    """Index-of-coincidence key-length detection.

    IoC (rate of equal bytes at distance k) peaks at *every multiple* of the
    true key length with near-equal height, so the maximum is an unreliable
    pick. Instead the candidate set is the GCD of the detected peaks (the
    fundamental period) and the strongest peak, expanded to their divisors,
    plus {1,2,3}. This stays small — no spurious long lengths that would
    overfit the validation window.
    """
    n = arr.size
    rates = np.empty(cap, dtype=np.float64)
    for k in range(1, cap + 1):
        rates[k - 1] = np.count_nonzero(arr[:-k] == arr[k:]) / (n - k)
    ks = np.arange(1, cap + 1)
    baseline = float(np.median(rates))
    peak = float(rates.max())
    thr = baseline + 0.4 * (peak - baseline)
    peaks = ks[rates >= thr].tolist()

    cands: set[int] = {1, 2, 3}
    if peaks:
        cands |= _divisors(reduce(gcd, peaks))
        cands |= _divisors(int(ks[int(np.argmax(rates))]))
    cand_list = sorted(c for c in cands if 1 <= c <= cap)

    order = np.argsort(rates)[::-1][:3]
    top = [
        {"key_length": int(ks[i]), "ioc_rate": round(float(rates[i]), 5)}
        for i in order
    ]
    return cand_list, top


def _recover_xor_key(arr, key_len: int, assumed_byte: int):
    """Per-column frequency analysis: key[pos] = most_common_cipher_byte ^ assumed."""
    key = np.empty(key_len, dtype=np.uint8)
    for pos in range(key_len):
        col = arr[pos::key_len]
        key[pos] = (int(np.argmax(np.bincount(col, minlength=256))) ^ assumed_byte) & 0xFF
    return key


# --- Function similarity helpers ---------------------------------------------

# np.correlate is O(La*Lb); cap function bytes for the NCC method to stay fast.
_NCC_MAX_BYTES = 8192


def _byte_hist_vec(data: bytes):
    return np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256).astype(np.float64)


def _byte_entropy_vec(data: bytes):
    """EMBER-style joint byte-entropy histogram (16 entropy rows × 16 nibble cols).

    Slides a window over the data; for each window computes the upper-nibble
    histogram and its entropy, quantizes the entropy to one of 16 rows, and
    accumulates the nibble histogram into that row. Returns a flat 256-vector.
    """
    arr = np.frombuffer(data, dtype=np.uint8)
    n = arr.size
    window = min(256, n)
    if window < 1:
        return np.zeros(256, dtype=np.float64)
    step = max(1, window // 4)
    acc = np.zeros((16, 16), dtype=np.float64)
    count = 0
    for s in range(0, n - window + 1, step):
        block = arr[s:s + window]
        c = np.bincount(block >> 4, minlength=16).astype(np.float64)
        p = c / window
        nz = p > 0
        h = float(-np.sum(p[nz] * np.log2(p[nz])))  # 0..4 bits (16 bins)
        hbin = min(int(h / 4.0 * 16), 15)
        acc[hbin] += c
        count += 1
    if count == 0:
        c = np.bincount(arr >> 4, minlength=16).astype(np.float64)
        acc[0] += c
    return acc.ravel()


def _cosine(a, b) -> float:
    na = float(np.linalg.norm(a))
    nb = float(np.linalg.norm(b))
    if na == 0.0 or nb == 0.0:
        return 0.0
    return float(np.dot(a, b) / (na * nb))


def _ncc(da: bytes, db: bytes) -> float:
    """Normalized cross-correlation peak — shift-invariant similarity in [0,1]."""
    a = np.frombuffer(da, dtype=np.uint8).astype(np.float64)
    b = np.frombuffer(db, dtype=np.uint8).astype(np.float64)
    a = a - a.mean()
    b = b - b.mean()
    na = float(np.linalg.norm(a))
    nb = float(np.linalg.norm(b))
    if na == 0.0 or nb == 0.0:
        return 0.0
    corr = np.correlate(a, b, mode="full")
    return float(np.max(np.abs(corr)) / (na * nb))


def _interpret_similarity(score: float) -> str:
    if score >= 0.99:
        return "identical"
    if score >= 0.92:
        return "very_similar"
    if score >= 0.80:
        return "similar"
    return "dissimilar"


def _read_func_bytes(spec: str) -> tuple[int, str, bytes]:
    """Resolve a function spec (addr or name) and return (start_ea, name, bytes)."""
    ea = parse_address(spec)
    f = ida_funcs.get_func(ea)
    if not f:
        raise ValueError(f"No function at {spec} ({hex(ea)})")
    data = ida_bytes.get_bytes(f.start_ea, f.end_ea - f.start_ea)
    if not data:
        raise ValueError(f"Could not read bytes for function at {hex(f.start_ea)}")
    name = ida_funcs.get_func_name(f.start_ea) or hex(f.start_ea)
    return f.start_ea, name, data


# ============================================================================
# Status probe — always registered, even without numpy
# ============================================================================


@tool
@idasync
def numpy_status() -> dict:
    """Report NumPy availability and version.

    Always registered regardless of whether numpy is installed. Check this
    before calling other numpy_* tools.

    Profile: analysis
    """
    return {
        "ok": True,
        "available": NUMPY_AVAILABLE,
        "version": NUMPY_VERSION if NUMPY_AVAILABLE else None,
        "hint": None if NUMPY_AVAILABLE else "Install with: pip install numpy>=2.0.0",
    }


if NUMPY_AVAILABLE:

    @tool
    @idasync
    @tool_timeout(120.0)
    def numpy_entropy_map(
        addr: Annotated[str, "Start address (hex or symbol) of the region to analyze"],
        size: Annotated[int, "Number of bytes to analyze (capped at 64 MB)"],
        block_size: Annotated[
            int, "Bytes per entropy measurement window (default: 256)"
        ] = 256,
        step: Annotated[
            int,
            "Window stride in bytes (0 = non-overlapping = block_size). "
            "Set < block_size for overlapping windows (smoother, more output).",
        ] = 0,
        threshold: Annotated[
            float, "Entropy (bits/byte) at/above which a block is 'high entropy' (default: 7.0)"
        ] = 7.0,
    ) -> NumpyEntropyMapResult:
        """Block-level Shannon entropy heatmap of a memory region.

        Splits the region into ``block_size``-byte windows and computes the
        Shannon entropy (0–8 bits/byte) of each, fully vectorized. Where a
        single per-section entropy value (lief_sections) only tells you the
        whole section is "high entropy", this reveals the *internal structure*:
        which blocks are uniformly encrypted vs. which dip into recoverable
        code/headers.

        The full statistics — ``summary``, ``contiguous_high_entropy_runs``,
        and ``entropy_histogram`` — are always computed over every block. The
        verbose per-block ``blocks`` list is included only for small regions
        (≤512 blocks); for larger maps it is omitted (``blocks_truncated: true``)
        and you should rely on the runs + histogram, which pinpoint the
        encrypted segments without flooding context with tens of thousands of rows.

        Note: for small blocks the entropy ceiling is below 8.0 (a 256-byte
        block has at most 256 distinct values), so encrypted data typically
        reads ~7.0–7.4 at block_size=256, not 7.9. The default threshold of 7.0
        accounts for this.

        Typical use — triaging a packed .text section reported as high-entropy:
            numpy_entropy_map(addr='0x140002000', size=0x100000)
        then read ``contiguous_high_entropy_runs`` to locate the encrypted spans
        and the low-entropy gaps between them.

        See also: lief_sections (per-section entropy + class),
        numpy_byte_histogram (distribution shape of one region),
        lief_compare_to_idb (diff packed image vs source).

        Profile: analysis
        """
        try:
            if block_size < 16:
                return {"ok": False, "error": "block_size must be >= 16"}
            if step <= 0:
                step = block_size

            ea, data, truncated = _read_region(addr, size)
            arr = np.frombuffer(data, dtype=np.uint8)

            starts, ents = _block_entropies(arr, block_size, step)
            total_blocks = int(starts.size)
            if total_blocks == 0:
                return {
                    "ok": False,
                    "error": f"Region ({len(data)} bytes) smaller than one block ({block_size}).",
                    "hint": "Reduce block_size or increase size.",
                }

            high_mask = ents >= threshold
            low_mask = ents < 1.0
            high_count = int(np.count_nonzero(high_mask))
            low_count = int(np.count_nonzero(low_mask))

            # Entropy distribution into 16 buckets of width 0.5 over [0, 8].
            hist_counts, _edges = np.histogram(ents, bins=16, range=(0.0, 8.0))
            entropy_histogram = [int(x) for x in hist_counts]

            # Contiguous runs of >=3 high-entropy blocks (the actionable signal).
            runs: list[EntropyRun] = []
            if high_count:
                framed = np.concatenate(([0], high_mask.astype(np.int8), [0]))
                edges = np.diff(framed)
                run_starts = np.where(edges == 1)[0]
                run_ends = np.where(edges == -1)[0]  # exclusive block index
                for rs, re_ in zip(run_starts, run_ends):
                    if re_ - rs >= 3:
                        start_off = int(starts[rs])
                        last_off = int(starts[re_ - 1]) + block_size
                        runs.append({
                            "start_offset": start_off,
                            "end_offset": last_off,
                            "block_count": int(re_ - rs),
                            "mean_entropy": round(float(ents[rs:re_].mean()), 4),
                        })

            summary = {
                "mean_entropy": round(float(ents.mean()), 4),
                "median_entropy": round(float(np.median(ents)), 4),
                "stdev_entropy": round(float(ents.std()), 4),
                "max_entropy": round(float(ents.max()), 4),
                "max_entropy_offset": int(starts[int(np.argmax(ents))]),
                "min_entropy": round(float(ents.min()), 4),
                "min_entropy_offset": int(starts[int(np.argmin(ents))]),
                "p25": round(float(np.percentile(ents, 25)), 4),
                "p75": round(float(np.percentile(ents, 75)), 4),
                "p95": round(float(np.percentile(ents, 95)), 4),
            }

            result: NumpyEntropyMapResult = {
                "ok": True,
                "addr": hex(ea),
                "size_analyzed": int(len(data)),
                "block_size": block_size,
                "step": step,
                "total_blocks": total_blocks,
                "high_entropy_blocks": high_count,
                "low_entropy_blocks": low_count,
                "entropy_histogram": entropy_histogram,
                "summary": summary,
                "contiguous_high_entropy_runs": runs,
            }
            if truncated:
                result["truncated"] = True

            if total_blocks <= _MAX_BLOCKS_INLINE:
                blocks: list[EntropyBlock] = []
                for off, ent in zip(starts.tolist(), ents.tolist()):
                    blocks.append({
                        "offset": int(off),
                        "entropy": round(float(ent), 4),
                        "entropy_class": _classify_entropy(ent),
                    })
                result["blocks"] = blocks
            else:
                result["blocks_truncated"] = True

            frac_high = high_count / total_blocks
            if frac_high > 0.9:
                result["hint"] = (
                    "Region is almost entirely high-entropy (encrypted/compressed). "
                    "Consider unicorn_emulate_and_patch to decrypt it, or "
                    "lief_compare_to_idb to diff the packed image against the source."
                )
            elif runs:
                result["hint"] = (
                    f"{len(runs)} contiguous high-entropy run(s) found — likely "
                    "encrypted/packed segments. Low-entropy gaps between them may "
                    "hold recoverable code or headers; inspect those offsets first."
                )
            else:
                result["hint"] = (
                    "No sustained high-entropy regions — likely normal code/data. "
                    "Mean entropy "
                    f"{summary['mean_entropy']} is consistent with "
                    f"{_classify_entropy(summary['mean_entropy'])}."
                )
            return result
        except ValueError as e:
            return {"ok": False, **tool_error(e, f"numpy_entropy_map at {addr}")}
        except Exception as e:
            return {"ok": False, **tool_error(e, f"numpy_entropy_map at {addr}")}

    @tool
    @idasync
    @tool_timeout(60.0)
    def numpy_byte_histogram(
        addr: Annotated[str, "Start address (hex or symbol) of the region to analyze"],
        size: Annotated[int, "Number of bytes to analyze (capped at 64 MB)"],
        include_counts: Annotated[
            bool, "Include the raw 256-bucket count array in the response (default: false)"
        ] = False,
    ) -> NumpyByteHistogramResult:
        """256-bucket byte frequency distribution with statistical interpretation.

        Computes the full byte histogram of a region plus the analytics an agent
        needs to classify it in a single call:

        - ``entropy`` / ``entropy_class`` — Shannon bits/byte and a coarse label
        - ``chi2`` — chi-square statistic of the distribution vs. a uniform one.
          Direction: a *uniform* (encrypted/random) region produces observed
          counts close to expected, so chi-square is LOW (near the 255 degrees
          of freedom). A *non-uniform* (plaintext/code) region produces a HIGH
          chi-square. ``chi2_uniform_ratio`` = chi2 / 255 is ≈1.0 for uniform
          data and grows large for structured data.
        - ``unique_byte_count`` — 256 (every value present) suggests cipher
          output; a small count suggests sparse/structured data.
        - ``most_common`` — top-5 bytes; a single dominant byte at moderate
          entropy is a classic single-byte-XOR / RLE signature.

        Together these distinguish AES/stream-cipher output (near-uniform,
        entropy ≈ 8, chi2 low) from XOR-obfuscated data (one dominant byte,
        entropy 4–7) from plaintext code (very non-uniform, chi2 high).

        See also: numpy_entropy_map (where in a region the entropy lives),
        yara_scan_builtin_crypto (find crypto constants directly),
        lief_sections (per-section entropy).

        Profile: analysis
        """
        try:
            ea, data, truncated = _read_region(addr, size)
            arr = np.frombuffer(data, dtype=np.uint8)
            n = arr.size

            counts = np.bincount(arr, minlength=256)
            entropy = np_entropy(data)
            unique_byte_count = int(np.count_nonzero(counts))

            expected = n / 256.0
            chi2 = float(np.sum((counts - expected) ** 2 / expected))
            chi2_ratio = chi2 / 255.0  # ≈1.0 uniform, >>1 non-uniform

            order = np.argsort(counts)[::-1][:5]
            most_common: list[ByteHit] = []
            for b in order.tolist():
                cnt = int(counts[b])
                if cnt == 0:
                    continue
                most_common.append({
                    "byte": int(b),
                    "hex": f"0x{int(b):02x}",
                    "count": cnt,
                    "pct": round(cnt / n * 100.0, 3),
                })

            ent_class = _classify_entropy(entropy)

            # Distribution label from entropy + uniformity together.
            if entropy >= 7.5 and unique_byte_count >= 250 and chi2_ratio < 4.0:
                distribution = "near_uniform_encrypted_or_random"
            elif entropy >= 6.5:
                distribution = "high_entropy_compressed_or_encrypted"
            elif most_common and most_common[0]["pct"] > 30.0:
                distribution = "single_byte_dominant_possible_xor_or_rle"
            elif unique_byte_count < 64:
                distribution = "sparse_structured_or_code"
            else:
                distribution = "non_uniform_plaintext_or_code"

            result: NumpyByteHistogramResult = {
                "ok": True,
                "addr": hex(ea),
                "size_analyzed": n,
                "entropy": round(entropy, 4),
                "entropy_class": ent_class,
                "chi2": round(chi2, 2),
                "chi2_uniform_ratio": round(chi2_ratio, 3),
                "distribution": distribution,
                "unique_byte_count": unique_byte_count,
                "most_common": most_common,
                "least_common_count": int(counts.min()),
            }
            if truncated:
                result["truncated"] = True
            if include_counts:
                result["counts"] = [int(x) for x in counts]

            # One-sentence interpretation + a concrete next-step hint.
            if distribution == "near_uniform_encrypted_or_random":
                result["interpretation"] = (
                    "Byte distribution is near-uniform — consistent with encrypted "
                    "or compressed data (AES/stream cipher, zlib, etc.)."
                )
                result["hint"] = (
                    "Use numpy_entropy_map to locate any low-entropy gaps, or "
                    "unicorn_emulate_and_patch if a runtime decryptor exists."
                )
            elif distribution == "single_byte_dominant_possible_xor_or_rle":
                dom = most_common[0]
                result["interpretation"] = (
                    f"Byte {dom['hex']} dominates ({dom['pct']}%) at moderate entropy — "
                    "a classic single-byte XOR or run-length pattern."
                )
                result["hint"] = (
                    f"The XOR key byte is likely {dom['hex']} ^ 0x00. Try decrypting "
                    "with get_bytes + XOR, or yara_scan_builtin_crypto for known constants."
                )
            elif distribution == "high_entropy_compressed_or_encrypted":
                result["interpretation"] = (
                    "High but not perfectly uniform entropy — likely compressed, or "
                    "encrypted data with some structure."
                )
                result["hint"] = "Use numpy_entropy_map for the block-level picture."
            else:
                result["interpretation"] = (
                    f"Non-uniform distribution (entropy {round(entropy, 2)}, "
                    f"{unique_byte_count} distinct bytes) — consistent with "
                    f"{ent_class}."
                )
                result["hint"] = (
                    "Looks like normal code/data; decompile or disasm to analyze."
                )
            return result
        except ValueError as e:
            return {"ok": False, **tool_error(e, f"numpy_byte_histogram at {addr}")}
        except Exception as e:
            return {"ok": False, **tool_error(e, f"numpy_byte_histogram at {addr}")}

    @tool
    @idasync
    @tool_timeout(120.0)
    def numpy_xor_key_recovery(
        addr: Annotated[str, "Start address (hex or symbol) of the XOR-obfuscated region"],
        size: Annotated[int, "Number of bytes to analyze (statistical analysis capped at 2 MB)"],
        max_key_length: Annotated[
            int, "Maximum XOR key length to consider (default: 32)"
        ] = 32,
        assumed_plaintext: Annotated[
            str,
            "Dominant plaintext byte assumption: 'auto' (try null/space/0xff and "
            "rank), 'null' (binary/struct padding), 'space' (ASCII text), or '0xff'.",
        ] = "auto",
        top_candidates: Annotated[
            int, "Number of ranked key candidates to return (default: 5)"
        ] = 5,
    ) -> NumpyXorResult:
        """Recover a repeating-XOR key from an obfuscated region via statistics.

        Two-stage classical attack, fully vectorized:

        1. **Key-length detection** — index of coincidence (rate of equal bytes
           at each distance k). Because IoC peaks at every multiple of the true
           length, the candidate lengths are taken from the GCD of the detected
           peaks and their divisors (the fundamental period), never an arbitrary
           maximum.
        2. **Key-byte recovery** — for each candidate length, the most common
           byte in each key-aligned column is assumed to be the dominant
           plaintext byte XOR the key byte. Each candidate is then validated by
           decrypting a 4 KB window and scoring it (printable-ASCII ratio for
           text, null-run ratio for binary, plus entropy reduction).

        Candidates are ranked by that composite score, ties broken toward the
        shortest key. Note a single-byte XOR does not change entropy at all (it
        is a byte permutation), so the printable/null signal — not entropy — is
        what identifies it. The ``key`` and ``key ^ 0x20`` solutions are
        genuinely ambiguous for some data; inspect ``sample_decrypted_ascii`` of
        the top candidates to confirm which plaintext assumption is right.

        Typical use — an obfuscated C2 string or config blob:
            numpy_xor_key_recovery(addr='0x140089000', size=0x400)

        See also: numpy_byte_histogram (is this even XOR? look for a dominant
        byte), yara_scan_builtin_crypto (known crypto constants).

        Profile: analysis
        """
        try:
            if max_key_length < 1:
                return {"ok": False, "error": "max_key_length must be >= 1"}
            analyze = min(size, _XOR_MAX_ANALYZE)
            ea, data, _trunc = _read_region(addr, analyze)
            arr = np.frombuffer(data, dtype=np.uint8)
            n = arr.size
            if n < 16:
                return {
                    "ok": False,
                    "error": "Region too small for XOR analysis (need >= 16 bytes).",
                }

            cap = max(1, min(max_key_length, 64, n // 4))
            cand_lengths, top_lengths = _xor_candidate_lengths(arr, cap)

            if assumed_plaintext == "auto":
                assumptions = ["null", "space", "0xff"]
            elif assumed_plaintext in _XOR_ASSUMPTIONS:
                assumptions = [assumed_plaintext]
            else:
                return {
                    "ok": False,
                    "error": f"Unknown assumed_plaintext: {assumed_plaintext!r} "
                             "(use auto | null | space | 0xff).",
                }

            cipher_entropy = np_entropy(data)
            vlen = min(n, _XOR_VALIDATE)
            vwin = arr[:vlen]

            cands: list[XorKeyCandidate] = []
            for L in cand_lengths:
                if L > n // 2:
                    continue
                for asm in assumptions:
                    P = _XOR_ASSUMPTIONS[asm]
                    key = _recover_xor_key(arr, L, P)
                    dec = (vwin ^ np.resize(key, vlen)).astype(np.uint8)
                    de = np_entropy(dec.tobytes())
                    printable = float(np.count_nonzero((dec >= 0x20) & (dec < 0x7F)) / vlen)
                    null_ratio = float(np.count_nonzero(dec == 0) / vlen)
                    reduction = max(0.0, cipher_entropy - de)
                    score = max(printable, 1.2 * null_ratio) + 0.5 * reduction
                    if score > 2.4 and (printable > 0.85 or null_ratio > 0.5):
                        conf = "high"
                    elif score > 1.2:
                        conf = "medium"
                    else:
                        conf = "low"
                    dec_bytes = dec.tobytes()
                    cands.append({
                        "key_hex": " ".join(f"0x{b:02x}" for b in key.tolist()),
                        "key_length": int(L),
                        "assumed_plaintext": asm,
                        "plaintext_entropy_after": round(de, 4),
                        "entropy_reduction": round(reduction, 4),
                        "printable_ratio": round(printable, 3),
                        "null_ratio": round(null_ratio, 3),
                        "sample_decrypted_hex": dec_bytes[:64].hex(" ", 1),
                        "sample_decrypted_ascii": dec_bytes[:64].decode("ascii", errors="replace"),
                        "confidence": conf,
                        "_score": round(score, 4),  # internal sort key, popped below
                    })

            # Pick the winner with the verified near-tie rule (within 0.02 of the
            # best score, prefer the shortest key — a longer key that ties only
            # because it is the true key repeated should not outrank the
            # fundamental). Rank the remainder by score.
            if cands:
                smax = max(c["_score"] for c in cands)
                best = min(
                    (c for c in cands if c["_score"] >= smax - 0.02),
                    key=lambda c: c["key_length"],
                )
                rest = sorted(
                    (c for c in cands if c is not best),
                    key=lambda c: c["_score"],
                    reverse=True,
                )
                cands = [best] + rest
            for c in cands:
                c.pop("_score", None)
            cands = cands[:max(1, top_candidates)]

            result: NumpyXorResult = {
                "ok": True,
                "addr": hex(ea),
                "size_analyzed": n,
                "ciphertext_entropy": round(cipher_entropy, 4),
                "top_key_length_candidates": top_lengths,
                "key_candidates": cands,
            }
            if size > _XOR_MAX_ANALYZE:
                result["analysis_capped"] = True

            best = cands[0] if cands else None
            if best and best["confidence"] != "low":
                result["hint"] = (
                    f"Best candidate: {best['key_length']}-byte key "
                    f"({best['confidence']} confidence, assumed plaintext "
                    f"'{best['assumed_plaintext']}'). Key = {best['key_hex']}. "
                    "Verify via sample_decrypted_ascii, then decrypt with get_bytes + XOR."
                )
            else:
                result["hint"] = (
                    "No high-confidence key found — the region may use multi-layer "
                    "or non-XOR encryption, or a key longer than max_key_length. "
                    "Run numpy_byte_histogram first to confirm a XOR-like distribution."
                )
            return result
        except ValueError as e:
            return {"ok": False, **tool_error(e, f"numpy_xor_key_recovery at {addr}")}
        except Exception as e:
            return {"ok": False, **tool_error(e, f"numpy_xor_key_recovery at {addr}")}

    @tool
    @idasync
    @tool_timeout(60.0)
    def numpy_function_similarity(
        func_a: Annotated[str, "First function (address or name)"],
        func_b: Annotated[str, "Second function (address or name)"],
        method: Annotated[
            str,
            "Comparison method: 'byte_histogram' (256-bucket cosine, default), "
            "'byte_entropy_histogram' (EMBER 16×16 joint), or 'ncc' "
            "(shift-invariant normalized cross-correlation).",
        ] = "byte_histogram",
        min_bytes: Annotated[
            int, "Minimum function size for a reliable comparison (default: 32)"
        ] = 32,
    ) -> NumpyFunctionSimilarityResult:
        """Bytecode-level similarity between two functions.

        Complements ``find_similar_functions`` (which uses semantic CFG/feature
        similarity) by comparing the raw bytes — catching clones that semantic
        features miss, e.g. the same routine compiled into two binaries, or a
        function duplicated under different names. Score is 0.0 (unrelated) to
        1.0 (identical bytes).

        Methods:
        - ``byte_histogram`` — cosine of 256-bucket frequency vectors. Fast,
          format-independent, works on stripped binaries. The proven baseline.
        - ``byte_entropy_histogram`` — EMBER-style 16×16 joint histogram; more
          discriminative for telling apart structurally-similar functions.
        - ``ncc`` — normalized cross-correlation; shift-invariant, best when two
          functions differ only by alignment/padding (slowest).

        Interpretation: ≥0.99 identical · ≥0.92 very_similar · ≥0.80 similar.

        See also: find_similar_functions (semantic search across the IDB),
        diff_functions (decompiled-output diff), get_function_hash (exact match).

        Profile: analysis
        """
        try:
            _ea_a, name_a, da = _read_func_bytes(func_a)
            _ea_b, name_b, db = _read_func_bytes(func_b)
            if len(da) < min_bytes or len(db) < min_bytes:
                return {
                    "ok": False,
                    "func_a": name_a,
                    "func_b": name_b,
                    "bytes_a": len(da),
                    "bytes_b": len(db),
                    "error": (
                        f"Function too small for reliable byte similarity "
                        f"(min {min_bytes} bytes; got {len(da)} and {len(db)}). "
                        "Use diff_functions or get_function_hash instead."
                    ),
                }

            m = method.lower().strip()
            if m == "byte_histogram":
                score = _cosine(_byte_hist_vec(da), _byte_hist_vec(db))
            elif m == "byte_entropy_histogram":
                score = _cosine(_byte_entropy_vec(da), _byte_entropy_vec(db))
            elif m == "ncc":
                score = _ncc(da[:_NCC_MAX_BYTES], db[:_NCC_MAX_BYTES])
            else:
                return {
                    "ok": False,
                    "error": f"Unknown method: {method!r} "
                             "(use byte_histogram | byte_entropy_histogram | ncc).",
                }

            score = min(1.0, max(0.0, score))
            interp = _interpret_similarity(score)
            result: NumpyFunctionSimilarityResult = {
                "ok": True,
                "func_a": name_a,
                "func_b": name_b,
                "method": m,
                "score": round(score, 4),
                "interpretation": interp,
                "bytes_a": len(da),
                "bytes_b": len(db),
            }
            if interp == "identical":
                result["hint"] = (
                    "Byte profiles are identical — almost certainly the same "
                    "function (clone, duplicated, or statically linked twice)."
                )
            elif interp in ("very_similar", "similar"):
                result["hint"] = (
                    "Closely related — same algorithm or a recompiled/patched "
                    "variant. Confirm with diff_functions on the decompiled output."
                )
            else:
                result["hint"] = (
                    "Byte profiles differ substantially — probably unrelated. "
                    "Try method='ncc' if they may differ only by alignment/padding."
                )
            return result
        except ValueError as e:
            return {"ok": False, **tool_error(e, "numpy_function_similarity")}
        except Exception as e:
            return {"ok": False, **tool_error(e, "numpy_function_similarity")}
