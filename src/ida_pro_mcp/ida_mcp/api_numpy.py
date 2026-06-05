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
import mmap
import os
from functools import reduce
from math import gcd
from typing import Annotated, TypedDict

import ida_bytes
import ida_funcs
import ida_ua
import idaapi
import idautils

from . import compat
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
    column_stats: dict
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


class MnemonicHit(TypedDict):
    mnemonic: str
    count: int
    ratio: float


class NumpyOpcodeHistogramResult(TypedDict, total=False):
    ok: bool
    addr: str
    mode: str
    instruction_count: int
    unique_mnemonics: int
    distribution_entropy: float
    top_mnemonics: list[MnemonicHit]
    ratios: dict
    anomalies: list[str]
    hint: str
    error: str
    error_type: str


class MemmapMatch(TypedDict, total=False):
    file_offset: int
    matched_hex: str
    context_before_hex: str
    context_after_hex: str


class NumpyMemmapScanResult(TypedDict, total=False):
    ok: bool
    file_path: str
    file_size: int
    pattern: str
    pattern_length: int
    match_count: int
    matches: list[MemmapMatch]
    truncated: bool
    next_offset: int
    hint: str
    error: str
    error_type: str


class NumpyBinarySimilarityResult(TypedDict, total=False):
    ok: bool
    file_a: str
    file_b: str
    method: str
    score: float
    interpretation: str
    size_a: int
    size_b: int
    entropy_a: float
    entropy_b: float
    sampled: bool
    hint: str
    error: str
    error_type: str


class NumpyValueScanResult(TypedDict, total=False):
    ok: bool
    addr: str
    dtype: str
    endian: str
    value_count: int
    bytes_analyzed: int
    unique_values: int
    zero_ratio: float
    min_value: str
    max_value: str
    pointer_candidate_ratio: float
    pointer_target_image_range: list[str]
    classification: str
    is_monotonic_increasing: bool
    longest_constant_run: int
    sample_values: list[str]
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


# --- Opcode histogram helpers -------------------------------------------------

_OPC_BRANCH = frozenset({
    "jmp", "je", "jne", "jz", "jnz", "jg", "jge", "jl", "jle", "ja", "jb",
    "jae", "jbe", "jo", "jno", "js", "jns", "jc", "jnc", "jp", "jnp",
    "loop", "loope", "loopne",
})
_OPC_CALL = frozenset({"call"})
_OPC_RET = frozenset({"ret", "retn", "retf", "iret", "iretd"})
_OPC_ARITH = frozenset({
    "add", "sub", "mul", "imul", "div", "idiv", "inc", "dec", "neg", "sal",
    "and", "or", "xor", "not", "shl", "shr", "sar", "rol", "ror", "adc", "sbb",
})
_OPC_DATA = frozenset({"mov", "movzx", "movsx", "movsxd", "lea", "movabs", "xchg"})
_OPC_STACK = frozenset({"push", "pop", "pusha", "popa", "pushf", "popf", "pushfd", "popfd"})
_OPC_NOP = frozenset({"nop", "fnop"})


def _collect_mnemonics(start: int, end: int, func) -> list[str]:
    """Collect lowercase instruction mnemonics over a function or raw range."""
    mnems: list[str] = []
    if func is not None:
        for item_ea in idautils.FuncItems(func.start_ea):
            insn = ida_ua.insn_t()
            if ida_ua.decode_insn(insn, item_ea) > 0:
                mnems.append(insn.get_canon_mnem().lower())
        return mnems
    cur = start
    while cur < end and cur != idaapi.BADADDR:
        insn = ida_ua.insn_t()
        length = ida_ua.decode_insn(insn, cur)
        if length <= 0:
            break
        mnems.append(insn.get_canon_mnem().lower())
        cur += insn.size
    return mnems


# --- Memmap pattern-scan helpers ---------------------------------------------


def _parse_byte_pattern(pattern_hex: str) -> tuple[bytes, list[bool]]:
    """Parse an IDA-style hex pattern into (bytes, fixed_mask).

    Accepts space-separated hex bytes with '??' or '?' wildcards, e.g.
    "48 8B 05 ?? ?? ?? ??". fixed_mask[i] is True for a concrete byte.
    """
    tokens = pattern_hex.replace(",", " ").split()
    if not tokens:
        raise ValueError("Empty pattern")
    pat = bytearray()
    mask: list[bool] = []
    for tok in tokens:
        if tok in ("??", "?", "*"):
            pat.append(0)
            mask.append(False)
        else:
            try:
                pat.append(int(tok, 16) & 0xFF)
            except ValueError:
                raise ValueError(f"Invalid pattern token: {tok!r}")
            mask.append(True)
    return bytes(pat), mask


def _longest_fixed_run(mask: list[bool]) -> tuple[int, int]:
    """Return (offset, length) of the longest run of fixed (non-wildcard) bytes."""
    best_off = best_len = 0
    cur_off = run = 0
    for i, fixed in enumerate(mask):
        if fixed:
            if run == 0:
                cur_off = i
            run += 1
            if run > best_len:
                best_len, best_off = run, cur_off
        else:
            run = 0
    return best_off, best_len


# --- Whole-file similarity helpers -------------------------------------------

# Cap for the byte-histogram pass and the (heavier) byte-entropy pass. The flat
# histogram is cheap so its cap is generous; the sliding-window entropy histogram
# is sampled from a smaller prefix to stay fast on large files.
_SIM_HIST_CAP = 64 * 1024 * 1024
_SIM_ENTROPY_CAP = 16 * 1024 * 1024


def _read_file_prefix(path: str, cap: int) -> tuple[bytes, bool]:
    """Read up to `cap` bytes from a file. Returns (data, sampled)."""
    size = os.path.getsize(path)
    with open(path, "rb") as fh:
        data = fh.read(cap)
    return data, size > cap


# --- Typed value-scan helpers ------------------------------------------------

# Accepted dtype codes → (numpy base code, item size, is_integer).
_VALUE_DTYPES: dict[str, tuple[str, int, bool]] = {
    "u1": ("u1", 1, True), "u2": ("u2", 2, True), "u4": ("u4", 4, True), "u8": ("u8", 8, True),
    "i1": ("i1", 1, True), "i2": ("i2", 2, True), "i4": ("i4", 4, True), "i8": ("i8", 8, True),
    "f4": ("f4", 4, False), "f8": ("f8", 8, False),
}


def _image_ea_range() -> tuple[int, int]:
    """Return (min_ea, max_ea) of the loaded database, version-safe."""
    return compat.inf_get_min_ea(), compat.inf_get_max_ea()


def _longest_run_len(arr) -> int:
    """Length of the longest run of equal consecutive values in a 1-D array."""
    if arr.size == 0:
        return 0
    # Boundaries where the value changes.
    change = np.nonzero(np.diff(arr))[0]
    if change.size == 0:
        return int(arr.size)
    bounds = np.concatenate(([-1], change, [arr.size - 1]))
    return int(np.max(np.diff(bounds)))


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
        include_column_stats: Annotated[
            bool,
            "Also report per-byte-offset variance across non-overlapping blocks "
            "(reveals fixed/aligned columns — repeating headers, struct fields). "
            "Default: false.",
        ] = False,
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

            # Optional per-byte-offset variance across non-overlapping blocks.
            # Columns with near-zero variance are fixed positions across every
            # block — repeating headers, alignment padding, or struct fields.
            if include_column_stats:
                n_full = arr.size // block_size
                if n_full >= 2:
                    mat = arr[:n_full * block_size].reshape(n_full, block_size).astype(np.float64)
                    col_var = mat.var(axis=0)
                    near_const = int(np.count_nonzero(col_var < 1.0))
                    result["column_stats"] = {
                        "full_blocks": int(n_full),
                        "near_constant_columns": near_const,
                        "near_constant_ratio": round(near_const / block_size, 4),
                        "mean_column_variance": round(float(col_var.mean()), 4),
                        "max_column_variance": round(float(col_var.max()), 4),
                    }
                else:
                    result["column_stats"] = {
                        "full_blocks": int(n_full),
                        "note": "Need >= 2 full blocks for column variance.",
                    }

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

    @tool
    @idasync
    @tool_timeout(60.0)
    def numpy_opcode_histogram(
        addr: Annotated[str, "Function address/name, or start of a raw range (with size)"],
        size: Annotated[
            int,
            "0 = treat addr as a function (default). >0 = decode this many bytes "
            "as a raw instruction range.",
        ] = 0,
        top_n: Annotated[int, "Number of most-frequent mnemonics to return (default: 20)"] = 20,
    ) -> NumpyOpcodeHistogramResult:
        """Instruction mnemonic frequency profile of a function or range.

        Surfaces obfuscation/profiling signals that no other tool exposes
        directly:
        - ``ratios`` — branch / call / ret / arith / data_move / stack / nop
          fractions of all instructions.
        - ``distribution_entropy`` — Shannon entropy (bits) of the mnemonic
          distribution. Low diversity (a few opcodes dominating) is typical of
          junk-instruction obfuscation or unrolled stubs; high diversity is
          typical of normal compiled code.
        - ``anomalies`` — heuristic flags (high nop ratio, low diversity, a
          single dominant mnemonic).

        Use it to triage whether a function is real code worth decompiling or a
        junk/obfuscation stub, without paying for a full decompile.

        See also: find_similar_functions (semantic similarity),
        numpy_function_similarity (byte-level), analyze_function (full analysis).

        Profile: analysis
        """
        try:
            ea = parse_address(addr)
            func = ida_funcs.get_func(ea)
            mode = "function"
            if size > 0:
                mode = "range"
                mnems = _collect_mnemonics(ea, ea + size, None)
            elif func is not None:
                mnems = _collect_mnemonics(func.start_ea, func.end_ea, func)
            else:
                return {
                    "ok": False,
                    "error": f"No function at {addr}. Pass size>0 to scan a raw range.",
                }

            total = len(mnems)
            if total == 0:
                return {"ok": False, "error": "No instructions decoded in the target."}

            counts: dict[str, int] = {}
            for m in mnems:
                counts[m] = counts.get(m, 0) + 1

            # Distribution entropy over the mnemonic frequency vector.
            cvals = np.array(list(counts.values()), dtype=np.float64)
            p = cvals / total
            dist_entropy = float(-np.sum(p * np.log2(p)))

            def _grp(group) -> int:
                return sum(counts.get(m, 0) for m in group)

            ratios = {
                "branch": round(_grp(_OPC_BRANCH) / total, 4),
                "call": round(_grp(_OPC_CALL) / total, 4),
                "ret": round(_grp(_OPC_RET) / total, 4),
                "arith": round(_grp(_OPC_ARITH) / total, 4),
                "data_move": round(_grp(_OPC_DATA) / total, 4),
                "stack": round(_grp(_OPC_STACK) / total, 4),
                "nop": round(_grp(_OPC_NOP) / total, 4),
            }

            ordered = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)
            top_mnemonics: list[MnemonicHit] = [
                {"mnemonic": m, "count": c, "ratio": round(c / total, 4)}
                for m, c in ordered[:max(1, top_n)]
            ]

            anomalies: list[str] = []
            if ratios["nop"] > 0.15:
                anomalies.append(
                    f"High nop ratio ({ratios['nop']}) — junk/padding or anti-disassembly."
                )
            if total >= 20 and dist_entropy < 1.5:
                anomalies.append(
                    f"Low mnemonic diversity (entropy {round(dist_entropy, 2)}) — "
                    "repetitive/unrolled or obfuscated code."
                )
            if top_mnemonics and top_mnemonics[0]["ratio"] > 0.5:
                anomalies.append(
                    f"Single mnemonic '{top_mnemonics[0]['mnemonic']}' dominates "
                    f"({top_mnemonics[0]['ratio']}) — likely a stub or junk filler."
                )

            result: NumpyOpcodeHistogramResult = {
                "ok": True,
                "addr": hex(func.start_ea if (func is not None and size <= 0) else ea),
                "mode": mode,
                "instruction_count": total,
                "unique_mnemonics": len(counts),
                "distribution_entropy": round(dist_entropy, 4),
                "top_mnemonics": top_mnemonics,
                "ratios": ratios,
                "anomalies": anomalies,
            }
            if anomalies:
                result["hint"] = (
                    "Anomalies detected — this may be junk/obfuscation rather than "
                    "real logic; verify with disasm before investing in decompilation."
                )
            else:
                result["hint"] = (
                    "Mnemonic profile looks like normal compiled code "
                    f"(diversity entropy {round(dist_entropy, 2)})."
                )
            return result
        except ValueError as e:
            return {"ok": False, **tool_error(e, f"numpy_opcode_histogram at {addr}")}
        except Exception as e:
            return {"ok": False, **tool_error(e, f"numpy_opcode_histogram at {addr}")}

    @tool
    @tool_timeout(60.0)
    def numpy_memmap_scan(
        file_path: Annotated[str, "Path to the file to scan (read via memory map)"],
        pattern_hex: Annotated[
            str,
            "Byte pattern in IDA style with '??' wildcards, e.g. '48 8B 05 ?? ?? ?? ??'. "
            "A fully fixed pattern works as an exact byte search.",
        ],
        max_results: Annotated[int, "Maximum matches to return (default: 100)"] = 100,
        context_bytes: Annotated[
            int, "Bytes of surrounding context (hex) to include per match (default: 16)"
        ] = 16,
        start_offset: Annotated[
            int,
            "File offset to begin scanning from (default: 0). When a previous call "
            "returned truncated=true, pass its next_offset here to page through "
            "the rest of the matches.",
        ] = 0,
    ) -> NumpyMemmapScanResult:
        """Memory-mapped byte-pattern search over a file on disk.

        Scans a file (any size — memory-mapped, constant RAM) for a byte pattern
        with optional ``??`` wildcards. Unlike IDA's find_bytes (which only sees
        the loaded IDB), this works on files not loaded into IDA and on files too
        large to hold in memory — e.g. a 200 MB sibling DLL.

        Anchors on the longest fixed run in the pattern (fast C-level substring
        search), then verifies the full masked pattern at each hit with a
        vectorized comparison. Not IDA-bound, so it does not run on the IDA
        main thread.

        Paging: when more than ``max_results`` matches exist the result has
        ``truncated: true`` and a ``next_offset``. Call again with
        ``start_offset=next_offset`` to continue from where it left off.

        See also: find_bytes (loaded IDB), find_dll_by_purpose (keyword search
        across many DLLs), lief_strings (raw string extraction).

        Profile: analysis
        """
        try:
            if not os.path.isfile(file_path):
                return {"ok": False, "error": f"File not found: {file_path}"}
            pat, mask = _parse_byte_pattern(pattern_hex)
            plen = len(pat)
            if not any(mask):
                return {
                    "ok": False,
                    "error": "Pattern is all wildcards — provide at least one fixed byte.",
                }

            run_off, run_len = _longest_fixed_run(mask)
            anchor = bytes(pat[run_off:run_off + run_len])
            pat_arr = np.frombuffer(pat, dtype=np.uint8)
            mask_arr = np.array(mask, dtype=bool)

            matches: list[MemmapMatch] = []
            truncated = False
            file_size = os.path.getsize(file_path)

            with open(file_path, "rb") as fh:
                if file_size == 0:
                    return {
                        "ok": True, "file_path": file_path, "file_size": 0,
                        "pattern": pattern_hex, "pattern_length": plen,
                        "match_count": 0, "matches": [],
                    }
                mm = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
                next_offset = 0
                try:
                    pos = max(0, int(start_offset))
                    while True:
                        idx = mm.find(anchor, pos)
                        if idx < 0:
                            break
                        start = idx - run_off
                        if start >= 0 and start + plen <= file_size:
                            window = np.frombuffer(mm[start:start + plen], dtype=np.uint8)
                            if bool(np.all((window == pat_arr) | ~mask_arr)):
                                cb = max(0, start - context_bytes)
                                ca = min(file_size, start + plen + context_bytes)
                                matches.append({
                                    "file_offset": int(start),
                                    "matched_hex": bytes(mm[start:start + plen]).hex(" ", 1),
                                    "context_before_hex": bytes(mm[cb:start]).hex(" ", 1),
                                    "context_after_hex": bytes(mm[start + plen:ca]).hex(" ", 1),
                                })
                                if len(matches) >= max_results:
                                    truncated = True
                                    next_offset = idx + 1
                                    break
                        pos = idx + 1
                finally:
                    mm.close()

            result: NumpyMemmapScanResult = {
                "ok": True,
                "file_path": file_path,
                "file_size": file_size,
                "pattern": pattern_hex,
                "pattern_length": plen,
                "match_count": len(matches),
                "matches": matches,
            }
            if truncated:
                result["truncated"] = True
                result["next_offset"] = next_offset
                result["hint"] = (
                    f"Stopped at max_results={max_results}; more matches may exist. "
                    f"Call again with start_offset={next_offset} to continue, or "
                    "raise max_results / narrow the pattern."
                )
            return result
        except ValueError as e:
            return {"ok": False, **tool_error(e, "numpy_memmap_scan")}
        except Exception as e:
            return {"ok": False, **tool_error(e, "numpy_memmap_scan")}

    @tool
    @idasync
    @tool_timeout(120.0)
    def numpy_binary_similarity(
        file_a: Annotated[str, "First binary file path. Empty = the active IDB's source file."] = "",
        file_b: Annotated[str, "Second binary file path. Empty = the active IDB's source file."] = "",
        method: Annotated[
            str,
            "Comparison: 'byte_histogram' (256-bucket cosine, default) or "
            "'byte_entropy_histogram' (EMBER 16×16 joint — more discriminative).",
        ] = "byte_histogram",
    ) -> NumpyBinarySimilarityResult:
        """Whole-file byte-distribution similarity between two binaries.

        Compares two files on disk by their byte statistics — the proven EMBER
        feature representation. The per-function ``numpy_function_similarity``
        answers "are these two functions the same?"; this answers "are these two
        *files* variants of each other?":

        - Is a dropped/unpacked payload a variant of the parent sample?
        - Are two sibling DLLs in an install dir built from the same code?
        - Did a binary's byte profile change between versions?

        Either path may be omitted to use the active IDB's source file, so you
        can compare the binary you are analyzing against any file on disk without
        loading it into IDA. Score is 0.0 (unrelated) to 1.0 (identical
        distribution).

        Note: a high score means similar byte *distributions*, not identical code
        — packing/encryption raises entropy of both files and can inflate the
        score. Cross-check with entropy_a/entropy_b and, for code, with
        numpy_function_similarity on specific functions.

        See also: numpy_function_similarity (per-function), lief_rich_header
        (compiler fingerprint), lief_compare_to_idb (packed image vs source).

        Profile: analysis
        """
        try:
            pa = file_a or (idaapi.get_input_file_path() or "")
            pb = file_b or (idaapi.get_input_file_path() or "")
            if not pa or not pb:
                return {"ok": False, "error": "Need two file paths (or an active IDB source file)."}
            for p in (pa, pb):
                if not os.path.isfile(p):
                    return {"ok": False, "error": f"File not found: {p}"}

            m = method.lower().strip()
            if m == "byte_histogram":
                da, sa = _read_file_prefix(pa, _SIM_HIST_CAP)
                db, sb = _read_file_prefix(pb, _SIM_HIST_CAP)
                score = _cosine(_byte_hist_vec(da), _byte_hist_vec(db))
            elif m == "byte_entropy_histogram":
                da, sa = _read_file_prefix(pa, _SIM_ENTROPY_CAP)
                db, sb = _read_file_prefix(pb, _SIM_ENTROPY_CAP)
                score = _cosine(_byte_entropy_vec(da), _byte_entropy_vec(db))
            else:
                return {
                    "ok": False,
                    "error": f"Unknown method: {method!r} "
                             "(use byte_histogram | byte_entropy_histogram).",
                }

            score = min(1.0, max(0.0, score))
            interp = _interpret_similarity(score)
            result: NumpyBinarySimilarityResult = {
                "ok": True,
                "file_a": pa,
                "file_b": pb,
                "method": m,
                "score": round(score, 4),
                "interpretation": interp,
                "size_a": os.path.getsize(pa),
                "size_b": os.path.getsize(pb),
                "entropy_a": round(np_entropy(da), 4),
                "entropy_b": round(np_entropy(db), 4),
            }
            if sa or sb:
                result["sampled"] = True
            if interp in ("identical", "very_similar"):
                result["hint"] = (
                    "Byte distributions are very close — likely the same family or "
                    "a minor variant. Confirm with numpy_function_similarity on a "
                    "couple of key functions, since packing alone can inflate this."
                )
            elif interp == "similar":
                result["hint"] = "Related distributions — possibly the same toolchain or partial code reuse."
            else:
                result["hint"] = "Distributions differ — probably unrelated files."
            return result
        except ValueError as e:
            return {"ok": False, **tool_error(e, "numpy_binary_similarity")}
        except Exception as e:
            return {"ok": False, **tool_error(e, "numpy_binary_similarity")}

    @tool
    @idasync
    @tool_timeout(60.0)
    def numpy_value_scan(
        addr: Annotated[str, "Start address (hex or symbol) of the data region"],
        size: Annotated[int, "Number of bytes to interpret"],
        dtype: Annotated[
            str,
            "Element type: u1/u2/u4/u8 (unsigned), i1/i2/i4/i8 (signed), f4/f8 "
            "(float). Default: u8 (64-bit — good for pointer tables).",
        ] = "u8",
        endian: Annotated[str, "Byte order: 'little' (default) or 'big'"] = "little",
        max_samples: Annotated[int, "How many leading values to echo back (default: 16)"] = 16,
    ) -> NumpyValueScanResult:
        """Interpret a raw region as a typed array and detect its structure.

        Where cstruct/construct parse *named* structs, this answers "what *is*
        this untyped blob?" — invaluable on regions IDA has not analyzed
        (decrypted/unpacked memory, an unknown data table). It reads the bytes as
        an array of the chosen integer/float type and classifies it:

        - **pointer_table** — most values fall inside the loaded image's address
          range (vtables, import-resolver tables, jump tables, relocation arrays).
        - **counter/sequence** — strictly increasing values.
        - **constant** — all values equal (zero-fill, padding).
        - **mixed_data** — none of the above.

        Reports the value distribution, the fraction of pointer-like values, the
        longest constant run, and a few sample values, so you can decide whether
        to apply a pointer/struct type in IDA.

        Typical use — after decrypting a packed section, check a suspicious table:
            numpy_value_scan(addr='0x1400a0000', size=0x200, dtype='u8')

        See also: find_vtable_candidates / dump_vtable (IDA-analysis-based vtable
        detection), cstruct_parse_at_address (named-struct parsing).

        Profile: analysis
        """
        try:
            spec = _VALUE_DTYPES.get(dtype.lower().strip())
            if spec is None:
                return {
                    "ok": False,
                    "error": f"Unknown dtype {dtype!r} (use u1/u2/u4/u8/i1/i2/i4/i8/f4/f8).",
                }
            code, itemsize, is_int = spec
            prefix = "<" if endian.lower().startswith("l") else ">"

            ea, data, _trunc = _read_region(addr, size)
            usable = (len(data) // itemsize) * itemsize
            if usable < itemsize:
                return {"ok": False, "error": f"Region smaller than one {dtype} element."}
            arr = np.frombuffer(data[:usable], dtype=prefix + code)
            count = int(arr.size)

            uniq = np.unique(arr)
            zero_ratio = float(np.count_nonzero(arr == 0) / count)
            longest_const = _longest_run_len(arr)

            classification = "mixed_data"
            pointer_ratio = 0.0
            ptr_range: list[str] = []
            is_monotonic = False

            if is_int:
                min_ea, max_ea = _image_ea_range()
                ptr_range = [hex(min_ea), hex(max_ea)]
                as_u = arr.astype(np.uint64, copy=False) if "u" in code else arr.astype(np.int64).astype(np.uint64, copy=False)
                in_range = int(np.count_nonzero((as_u >= min_ea) & (as_u < max_ea)))
                pointer_ratio = round(in_range / count, 4)
                if count >= 2:
                    is_monotonic = bool(np.all(np.diff(arr.astype(np.int64)) > 0))

                if uniq.size == 1:
                    classification = "constant"
                elif itemsize in (4, 8) and pointer_ratio >= 0.6:
                    classification = "pointer_table"
                elif is_monotonic:
                    classification = "counter_or_sequence"
                elif zero_ratio > 0.8:
                    classification = "mostly_zero_padding"
            else:
                if uniq.size == 1:
                    classification = "constant"

            def _fmt(v) -> str:
                return hex(int(v)) if is_int else repr(float(v))

            result: NumpyValueScanResult = {
                "ok": True,
                "addr": hex(ea),
                "dtype": dtype,
                "endian": "little" if prefix == "<" else "big",
                "value_count": count,
                "bytes_analyzed": usable,
                "unique_values": int(uniq.size),
                "zero_ratio": round(zero_ratio, 4),
                "min_value": _fmt(arr.min()),
                "max_value": _fmt(arr.max()),
                "classification": classification,
                "is_monotonic_increasing": is_monotonic,
                "longest_constant_run": longest_const,
                "sample_values": [_fmt(v) for v in arr[:max(1, max_samples)].tolist()],
            }
            if is_int:
                result["pointer_candidate_ratio"] = pointer_ratio
                result["pointer_target_image_range"] = ptr_range

            if classification == "pointer_table":
                result["interpretation"] = (
                    f"{int(pointer_ratio * 100)}% of {dtype} values point into the "
                    "image — likely a pointer/vtable/jump table. Consider applying a "
                    "pointer-array type in IDA, or dump_vtable if it is a vtable."
                )
                result["hint"] = "Cross-check with find_vtable_candidates / dump_vtable."
            elif classification == "counter_or_sequence":
                result["interpretation"] = "Strictly increasing values — an index/offset table or counter."
                result["hint"] = "Could be an RVA table or sorted key array."
            elif classification == "constant":
                result["interpretation"] = f"All values equal ({_fmt(arr[0])}) — zero-fill or padding."
                result["hint"] = "Likely uninitialized/aligned space; skip."
            elif classification == "mostly_zero_padding":
                result["interpretation"] = f"Mostly zero ({int(zero_ratio * 100)}%) — sparse table or padding."
                result["hint"] = "Sparse data; inspect the non-zero entries."
            else:
                result["interpretation"] = (
                    f"No strong structure as {dtype}. Try a different dtype/endian, "
                    "or numpy_byte_histogram to characterize it."
                )
                result["hint"] = "If this looks like code, use disasm instead."
            return result
        except ValueError as e:
            return {"ok": False, **tool_error(e, f"numpy_value_scan at {addr}")}
        except Exception as e:
            return {"ok": False, **tool_error(e, f"numpy_value_scan at {addr}")}
