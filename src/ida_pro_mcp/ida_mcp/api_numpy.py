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
from typing import Annotated, TypedDict

import ida_bytes

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
