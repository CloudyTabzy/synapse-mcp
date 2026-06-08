"""api_xor — the XOR Swiss Army Knife: a universal XOR cipher solver for IDA Pro MCP.

The classic single-byte / repeating-XOR tools (``xor_invert``,
``numpy_xor_key_recovery``) model XOR as ``ciphertext = plaintext ^ K`` for a
*fixed* key. That model silently fails on the many common-but-slightly-
non-standard XOR variants found in crackmes and malware: keys derived from the
plaintext itself, rolling/chained XOR, position-dependent XOR, prefix-scan XOR,
table lookups, and layered XOR. None of these are *hard* — they are usually a
single unknown byte away from trivial — but the wrong cipher *model* makes them
look unsolvable.

This module models XOR as a **family of cipher templates** and solves for the
one that satisfies the data plus a set of plaintext constraints. It is
**model-driven** (families are equations, not heuristics), **algebraic-first**
(simplify before brute-forcing), **constraint-aware** (printable / prefix /
regex / charset / known-plaintext), and **transparent** (it reports which
family it detected and how the solution was derived).

Tool roster (3 tools — module is always registered; the core solver has no hard
dependency, Z3 only enriches the constraint path):

  Infrastructure
    xor_status                 — availability probe (reports Z3 presence)

  Solving
    xor_solve_universal        — ⭐ the flagship. Enumerate XOR families and
                                 return the one(s) that satisfy the constraints.
                                 algebraic → brute-force → Z3 strategy ladder.
    xor_model_from_disassembly — classify the XOR family from a function's
                                 code (bridges static analysis → cryptanalysis).

The solver engine (everything above the ``# IDA-facing tools`` banner) is pure
Python with no IDA imports, so it is unit-testable in isolation and reusable.

Profile: analysis
"""

import logging
import re
from typing import Annotated, Optional, TypedDict

import ida_bytes
import ida_funcs
import idaapi
import idautils
import idc

from .rpc import tool
from .sync import idasync, tool_timeout
from .utils import parse_address, tool_error

logger = logging.getLogger(__name__)

# Z3 is optional. It is already present transitively via triton/angr in most
# installs; when absent the solver degrades gracefully to algebraic + brute
# force. Install the standalone wheel with:  pip install z3-solver
try:
    import z3 as _z3

    Z3_AVAILABLE = True
    try:
        Z3_VERSION = _z3.get_version_string()
    except Exception:  # pragma: no cover - defensive
        Z3_VERSION = "unknown"
except Exception:  # pragma: no cover - z3 not installed
    _z3 = None  # type: ignore[assignment]
    Z3_AVAILABLE = False
    Z3_VERSION = None

# The canonical list of cipher families the solver understands. Kept in one
# place so xor_status, the tool docstrings, and auto-detection stay in sync.
FAMILIES: tuple[str, ...] = (
    "fixed_single",
    "fixed_multi",
    "self_referential",
    "rolling",
    "position_dependent",
    "two_layer",
    "table_lookup",
    "cumulative",
)

# Safety caps. A wrong family on long input should never spin: statistical /
# brute work runs on a representative prefix only.
_MAX_LENGTH = 1 << 16            # 64 KB ciphertext cap per call
_DEFAULT_READ = 256              # bytes read from an address when length omitted
_BRUTE_CAP_DEFAULT = 1 << 16     # default max_brute_force_keys


# ============================================================================
# Constraint system  (pure Python)
# ============================================================================


class Constraints:
    """Plaintext constraints a candidate solution is scored against.

    Hard constraints (``known_prefix``, ``known_suffix``, ``known_pairs``,
    ``regex``, length bounds, ``char_set`` membership, ``alphanumeric``) must all
    hold for a candidate to be *verified*. ``printable_ascii`` is treated as a
    strong soft constraint: it never disqualifies on its own (so a single bad
    byte does not throw away an otherwise-perfect crib match) but heavily drives
    the score, which is what lets ``family='auto'`` pick the right model when no
    other constraint is given.
    """

    __slots__ = (
        "known_prefix", "known_suffix", "known_pairs", "regex", "_regex_c",
        "printable_ascii", "alphanumeric", "char_set", "_char_mask",
        "min_length", "max_length", "self_consistency",
    )

    def __init__(
        self,
        known_prefix: bytes = b"",
        known_suffix: bytes = b"",
        known_pairs: Optional[list[tuple[int, int]]] = None,
        regex: str = "",
        printable_ascii: bool = False,
        alphanumeric: bool = False,
        char_set: str = "",
        min_length: int = 0,
        max_length: int = 0,
        self_consistency: bool = False,
    ):
        self.known_prefix = known_prefix
        self.known_suffix = known_suffix
        self.known_pairs = known_pairs or []
        self.regex = regex
        self._regex_c = re.compile(regex) if regex else None
        self.printable_ascii = printable_ascii
        self.alphanumeric = alphanumeric
        self.char_set = char_set
        self._char_mask = _charset_to_mask(char_set) if char_set else None
        self.min_length = min_length
        self.max_length = max_length
        self.self_consistency = self_consistency

    # -- predicates ---------------------------------------------------------

    def any_set(self) -> bool:
        """True when at least one constraint was actually provided."""
        return bool(
            self.known_prefix or self.known_suffix or self.known_pairs
            or self.regex or self.printable_ascii or self.alphanumeric
            or self.char_set or self.min_length or self.max_length
        )

    def crib_bytes(self, length: int) -> dict[int, int]:
        """Resolve all known plaintext bytes to absolute offsets in [0, length)."""
        crib: dict[int, int] = {}
        for i, b in enumerate(self.known_prefix):
            if i < length:
                crib[i] = b
        for i, b in enumerate(self.known_suffix):
            off = length - len(self.known_suffix) + i
            if 0 <= off < length:
                crib[off] = b
        for off, b in self.known_pairs:
            real = off if off >= 0 else length + off
            if 0 <= real < length:
                crib[real] = b & 0xFF
        return crib

    def hard_violation(self, pt: bytes) -> Optional[str]:
        """Return a reason string if a hard constraint is violated, else None."""
        n = len(pt)
        if self.min_length and n < self.min_length:
            return f"length {n} < min_length {self.min_length}"
        if self.max_length and n > self.max_length:
            return f"length {n} > max_length {self.max_length}"
        if self.known_prefix and not pt.startswith(self.known_prefix):
            return "known_prefix mismatch"
        if self.known_suffix and not pt.endswith(self.known_suffix):
            return "known_suffix mismatch"
        for off, b in self.known_pairs:
            real = off if off >= 0 else n + off
            if 0 <= real < n and pt[real] != (b & 0xFF):
                return f"known byte at offset {off} mismatch"
        if self._char_mask is not None:
            for b in pt:
                if not self._char_mask[b]:
                    return "char_set violation"
        if self.alphanumeric:
            for b in pt:
                if not (0x30 <= b <= 0x39 or 0x41 <= b <= 0x5A or 0x61 <= b <= 0x7A):
                    return "alphanumeric violation"
        if self._regex_c is not None:
            try:
                text = pt.decode("latin-1")
            except Exception:  # pragma: no cover
                return "regex: undecodable"
            if not self._regex_c.search(text):
                return "regex mismatch"
        return None

    def score(self, pt: bytes) -> float:
        """Soft fitness, higher = more plausible plaintext.

        The decisive signal is the *alphabetic* ratio: XOR-ing a real string by
        the wrong byte rarely yields many letters, so the true key's plaintext
        almost always has the highest letter density. We combine that with the
        printable ratio, a mild reward for common text punctuation/space, and
        penalties for control bytes and unusual printable symbols ('@ ~ ^ | …'
        that seldom appear in passwords/flags/strings). Hard constraints are
        *not* scored here (they gate via hard_violation); this is the
        tie-breaker that lets ``family='auto'`` choose the right model from
        nothing but ``printable_ascii``.
        """
        n = len(pt)
        if n == 0:
            return 0.0
        alpha = printable = control = textpunct = weird = 0
        for b in pt:
            if b in _ALPHA:
                alpha += 1
                printable += 1
            elif 0x20 <= b < 0x7F:
                printable += 1
                if b in _TEXT_PUNCT:
                    textpunct += 1
                elif b not in _DIGIT:
                    weird += 1
            elif b in (0x09, 0x0A, 0x0D):
                textpunct += 1
            else:
                control += 1
        pr, ar = printable / n, alpha / n
        cr, tp, wr = control / n, textpunct / n, weird / n
        score = pr + 1.5 * ar + 0.3 * tp - 1.5 * cr - 0.5 * wr
        if self.printable_ascii and pr >= 0.99:
            score += 1.0
        return score


_PRINTABLE = bytes(range(0x20, 0x7F))
# Character classes for the soft plaintext score.
_ALPHA = frozenset(range(0x41, 0x5B)) | frozenset(range(0x61, 0x7B))
_DIGIT = frozenset(range(0x30, 0x3A))
# Punctuation that plausibly occurs in real text, identifiers, flags, passwords.
_TEXT_PUNCT = frozenset(b" _-.,!?:;'\"(){}[]/")


def _build_english_score() -> list[float]:
    """Per-byte English-likeness table for single-column frequency analysis.

    Space scores highest (it is the single most common byte in English text),
    then the common letters (ETAOIN…), then any letter, then digits/common
    punctuation; unusual printables are mildly negative and control bytes are
    strongly negative. Maximising the column sum of this table is the classic
    'most common byte is a space' attack generalised — it recovers a repeating
    key without an assumed-byte guess and, crucially, does not sacrifice the
    space signal the way pure letter-density maximisation does.
    """
    score = [-3.0] * 256
    for b in range(0x20, 0x7F):
        score[b] = -0.5
    for b in _DIGIT:
        score[b] = 0.3
    for b in _TEXT_PUNCT:
        score[b] = 0.3
    for b in _ALPHA:
        score[b] = 1.0
    for ch in b"etaoinshrdluETAOINSHRDLU":
        score[ch] = 2.0
    score[0x20] = 3.0   # space — most common English byte
    for b in (0x09, 0x0A, 0x0D):
        score[b] = 0.0
    return score


_ENGLISH_SCORE = _build_english_score()


def _charset_to_mask(spec: str) -> list[bool]:
    """Compile a charset spec like 'a-z0-9_' into a 256-entry membership mask."""
    mask = [False] * 256
    i = 0
    s = spec
    while i < len(s):
        if i + 2 < len(s) and s[i + 1] == "-":
            lo, hi = ord(s[i]), ord(s[i + 2])
            for c in range(min(lo, hi), max(lo, hi) + 1):
                if 0 <= c < 256:
                    mask[c] = True
            i += 3
        else:
            c = ord(s[i])
            if 0 <= c < 256:
                mask[c] = True
            i += 1
    return mask


# ============================================================================
# Candidate solution model
# ============================================================================


class Solution:
    """One candidate plaintext recovery from a single cipher family."""

    __slots__ = ("family", "plaintext", "key_repr", "key_derivation", "method")

    def __init__(self, family: str, plaintext: bytes, key_repr: str,
                 key_derivation: str, method: str):
        self.family = family
        self.plaintext = plaintext
        self.key_repr = key_repr
        self.key_derivation = key_derivation
        self.method = method

    def evaluate(self, cons: Constraints) -> tuple[bool, float]:
        """Return (verified, score). verified = no hard constraint violated."""
        verified = cons.hard_violation(self.plaintext) is None
        return verified, cons.score(self.plaintext)


# ============================================================================
# Family solvers  (pure Python — each returns a list[Solution])
# ============================================================================


def _xor_reduce(data: bytes) -> int:
    acc = 0
    for b in data:
        acc ^= b
    return acc


def _solve_fixed_single(ct: bytes, cons: Constraints, brute_cap: int) -> list[Solution]:
    """out[i] = ct[i] ^ K. Crib-derive K when possible, else brute 0..255."""
    out: list[Solution] = []
    crib = cons.crib_bytes(len(ct))
    if crib:
        # Each known byte pins K = ct[off] ^ pt[off]; they must all agree.
        keys = {ct[off] ^ b for off, b in crib.items()}
        if len(keys) == 1:
            k = keys.pop()
            pt = bytes(c ^ k for c in ct)
            out.append(Solution(
                "fixed_single", pt, f"0x{k:02x}",
                "K = ciphertext[i] ^ known_plaintext[i]", "algebraic_crib",
            ))
            return out
        # Inconsistent crib → this family cannot fit; emit nothing.
        return out
    # No crib: enumerate the (tiny) keyspace.
    seen: set[bytes] = set()
    for k in range(256):
        if k > brute_cap:
            break
        pt = bytes(c ^ k for c in ct)
        if pt in seen:
            continue
        seen.add(pt)
        out.append(Solution(
            "fixed_single", pt, f"0x{k:02x}", "brute force K in 0..255",
            "brute_force",
        ))
    return out


def _solve_fixed_multi(ct: bytes, cons: Constraints, key_length: int,
                       brute_cap: int) -> list[Solution]:
    """out[i] = ct[i] ^ K[i % L]. Crib-derive whole columns; else per-column brute.

    Per-column independent solving: for each of the L key columns, choose the key
    byte that (a) is pinned by any crib in that column and (b) otherwise best
    satisfies the column's per-position constraints. A single best key is
    returned; Z3 (when present) can find a globally-consistent multi-byte key
    under regex/charset constraints that this greedy pass cannot.
    """
    n = len(ct)
    if key_length < 1:
        return []
    if key_length > n:
        return []
    crib = cons.crib_bytes(n)
    base_key = bytearray(key_length)
    determined = [False] * key_length
    # Pin columns from the crib.
    for off, b in crib.items():
        col = off % key_length
        kb = ct[off] ^ b
        if determined[col] and base_key[col] != kb:
            return []  # crib forces inconsistent key bytes in one column
        base_key[col] = kb
        determined[col] = True

    if all(determined):
        pt = bytes(ct[i] ^ base_key[i % key_length] for i in range(n))
        return [Solution(
            "fixed_multi", pt,
            " ".join(f"0x{b:02x}" for b in base_key),
            f"per-column key, length {key_length}", "algebraic_crib",
        )]

    # Per-column frequency analysis via the English-likeness table: for each
    # undetermined column pick the key byte that maximises the column's English
    # score. This generalises the classic 'most common byte is a space' attack
    # (space is weighted highest) while also rewarding common letters, so it is
    # more robust on short text than a single assumed-byte guess. We also emit a
    # NUL-assumption variant for binary/struct plaintext and let ranking pick.
    # (For long blobs, numpy_xor_key_recovery's IoC attack is still preferred.)
    columns = [ct[c::key_length] for c in range(key_length)]
    eng_key = bytearray(base_key)
    null_key = bytearray(base_key)
    for col in range(key_length):
        if determined[col]:
            continue
        column = columns[col]
        best_kb, best_val = 0, -1e18
        for kb in range(256):
            val = 0.0
            for c in column:
                val += _ENGLISH_SCORE[c ^ kb]
            if val > best_val:
                best_val, best_kb = val, kb
        eng_key[col] = best_kb
        # NUL-dominant assumption for binary plaintext.
        counts = [0] * 256
        for c in column:
            counts[c] += 1
        null_key[col] = (counts.index(max(counts)) if column else 0)

    out: list[Solution] = []
    seen: set[bytes] = set()
    for key, label in ((eng_key, "English frequency"), (null_key, "NUL-dominant")):
        pt = bytes(ct[i] ^ key[i % key_length] for i in range(n))
        if pt in seen:
            continue
        seen.add(pt)
        out.append(Solution(
            "fixed_multi", pt,
            " ".join(f"0x{b:02x}" for b in key),
            f"column frequency ({label}), length {key_length}",
            "column_frequency",
        ))
    return out


def _solve_self_referential(ct: bytes, cons: Constraints, key_function: str,
                            brute_cap: int) -> list[Solution]:
    """Key is a reduction of the *plaintext* itself.

    Covers two real-world variants under one search over the single unknown
    reduction byte ``r``:

      * direct      : out[i] = ct[i] ^ r           (plain self-key)
      * xor_buffer  : out[i] = ct[i] ^ (XOR(ct) ^ r)  (the classic "selkey"
                      crackme, where the loop folds both the constant buffer and
                      the input into one accumulator)

    For each candidate ``r`` in 0..255 and each derivation mode, build the
    plaintext, then *verify self-consistency*: the reduction actually computed
    over that plaintext must equal the assumed ``r``. Self-consistency reduces
    the whole self-referential problem to at most 256 checks regardless of
    length. When exactly one ``r`` is consistent the answer is algebraically
    unique; when many are (the genuinely free-variable case, e.g. odd-length
    selkey) the constraints disambiguate.
    """
    n = len(ct)
    if n == 0:
        return []
    reduce_fn = _xor_reduce if key_function == "xor_reduce" else (
        lambda d: sum(d) & 0xFF
    )
    bx = _xor_reduce(ct)
    out: list[Solution] = []
    seen: set[bytes] = set()
    consistent_count = 0
    for mode, derive in (
        ("direct", lambda r: r),
        ("xor_buffer", lambda r: bx ^ r),
    ):
        mode_consistent = 0
        for r in range(256):
            k = derive(r)
            pt = bytes(c ^ k for c in ct)
            if reduce_fn(pt) != r:
                continue  # not self-consistent — this r cannot occur
            mode_consistent += 1
            if pt in seen:
                continue
            seen.add(pt)
            kd = (
                "key = reduce(plaintext)" if mode == "direct"
                else "key = XOR(ciphertext) ^ reduce(plaintext)"
            )
            out.append(Solution(
                "self_referential", pt, f"0x{k:02x}",
                f"{kd} [{key_function}, {mode}]", "self_consistency",
            ))
        consistent_count += mode_consistent
    # Tag the method as algebraic when the reduction was uniquely pinned.
    if consistent_count == 1 and out:
        out[0].method = "algebraic_simplification"
    return out


def _solve_rolling(ct: bytes, cons: Constraints, brute_cap: int) -> list[Solution]:
    """Chained XOR. Two common schemes, K seeds the first byte, rest chains.

      * ct_chain : out[i] = ct[i] ^ ct[i-1]   (differential on ciphertext)
      * pt_chain : out[i] = ct[i] ^ out[i-1]   (feedback on plaintext)

    Both leave only the seed key K (for out[0]) unknown → brute 0..255.
    """
    n = len(ct)
    if n == 0:
        return []
    crib = cons.crib_bytes(n)
    # If offset 0 is cribbed, K is pinned directly.
    k_values = [ct[0] ^ crib[0]] if 0 in crib else range(256)
    out: list[Solution] = []
    seen: set[bytes] = set()
    for scheme in ("ct_chain", "pt_chain"):
        for k in k_values:
            if isinstance(k_values, range) and k > brute_cap:
                break
            pt = bytearray(n)
            pt[0] = ct[0] ^ k
            for i in range(1, n):
                prev = ct[i - 1] if scheme == "ct_chain" else pt[i - 1]
                pt[i] = ct[i] ^ prev
            b = bytes(pt)
            if b in seen:
                continue
            seen.add(b)
            method = "algebraic_crib" if 0 in crib else "brute_force"
            out.append(Solution(
                "rolling", b, f"0x{k:02x}",
                f"seed K then chain [{scheme}]", method,
            ))
    return out


def _solve_position_dependent(ct: bytes, cons: Constraints, formula: str,
                              brute_cap: int) -> list[Solution]:
    """out[i] = ct[i] ^ f(K, i). Supported f: key+i, key-i, key^i, i."""
    n = len(ct)
    if n == 0:
        return []
    f = formula.replace(" ", "").lower()
    crib = cons.crib_bytes(n)

    def mask(k: int, i: int) -> int:
        if f == "i":
            return i & 0xFF
        if f in ("key+i", "k+i"):
            return (k + i) & 0xFF
        if f in ("key-i", "k-i"):
            return (k - i) & 0xFF
        if f in ("key^i", "k^i"):
            return (k ^ i) & 0xFF
        return (k + i) & 0xFF  # default

    if f == "i":
        k_values: range | list[int] = [0]
    elif crib:
        # Each crib byte pins K from the formula; they must agree.
        ks: set[int] = set()
        ok = True
        for off, b in crib.items():
            want = ct[off] ^ b  # == f(K, off)
            if f in ("key+i", "k+i"):
                ks.add((want - off) & 0xFF)
            elif f in ("key-i", "k-i"):
                ks.add((want + off) & 0xFF)
            elif f in ("key^i", "k^i"):
                ks.add((want ^ off) & 0xFF)
            else:
                ks.add((want - off) & 0xFF)
        k_values = list(ks) if len(ks) == 1 else []
        if not k_values:
            ok = False
        if not ok:
            return []
    else:
        k_values = range(256)

    out: list[Solution] = []
    seen: set[bytes] = set()
    for k in k_values:
        if isinstance(k_values, range) and k > brute_cap:
            break
        pt = bytes(ct[i] ^ mask(k, i) for i in range(n))
        if pt in seen:
            continue
        seen.add(pt)
        method = "brute_force" if isinstance(k_values, range) else (
            "fixed_formula" if f == "i" else "algebraic_crib"
        )
        out.append(Solution(
            "position_dependent", pt, f"0x{k:02x}",
            f"out[i] = ct[i] ^ ({formula})", method,
        ))
    return out


def _solve_two_layer(ct: bytes, cons: Constraints, brute_cap: int) -> list[Solution]:
    """out[i] = (ct[i] ^ K1) ^ K2 — algebraically a single key K = K1 ^ K2.

    The value of reporting this family separately is the *insight*: two-layer
    constant XOR is never harder than single-byte XOR. We solve as single-byte
    and relabel so the agent learns the layers collapse.
    """
    singles = _solve_fixed_single(ct, cons, brute_cap)
    out: list[Solution] = []
    for s in singles:
        out.append(Solution(
            "two_layer", s.plaintext, s.key_repr,
            "K1 ^ K2 collapses to a single byte K", s.method,
        ))
    return out


def _solve_table_lookup(ct: bytes, cons: Constraints, table: bytes,
                        table_len: int, brute_cap: int) -> list[Solution]:
    """out[i] = ct[i] ^ T[i % len(T)].

    With a known table, decrypt deterministically. With an unknown table of
    given length, this is exactly repeating-XOR → delegate to fixed_multi.
    """
    n = len(ct)
    if n == 0:
        return []
    if table:
        L = len(table)
        pt = bytes(ct[i] ^ table[i % L] for i in range(n))
        return [Solution(
            "table_lookup", pt,
            " ".join(f"0x{b:02x}" for b in table),
            f"known table, length {L}", "known_table",
        )]
    if table_len > 0:
        sols = _solve_fixed_multi(ct, cons, table_len, brute_cap)
        for s in sols:
            s.family = "table_lookup"
            s.key_derivation = f"recovered table, length {table_len}"
        return sols
    return []


def _solve_cumulative(ct: bytes, cons: Constraints, brute_cap: int) -> list[Solution]:
    """Prefix-scan XOR: out[i] = ct[i] ^ (seed ^ ct[0] ^ ... ^ ct[i-1]).

    With seed = 0 this is keyless and deterministic. We also brute the seed (the
    running accumulator's initial value) when a crib does not pin it.
    """
    n = len(ct)
    if n == 0:
        return []
    crib = cons.crib_bytes(n)
    # out[0] = ct[0] ^ seed → seed pinned by a crib at offset 0.
    seeds: range | list[int] = [ct[0] ^ crib[0]] if 0 in crib else range(256)
    out: list[Solution] = []
    seen: set[bytes] = set()
    for seed in seeds:
        if isinstance(seeds, range) and seed > brute_cap:
            break
        pt = bytearray(n)
        acc = seed
        for i in range(n):
            pt[i] = ct[i] ^ acc
            acc ^= ct[i]
        b = bytes(pt)
        if b in seen:
            continue
        seen.add(b)
        method = "algebraic_crib" if 0 in crib else (
            "deterministic" if seed == 0 else "brute_force"
        )
        out.append(Solution(
            "cumulative", b, f"0x{seed:02x}",
            "out[i] = ct[i] ^ running_xor(ct[0..i-1]) ^ seed", method,
        ))
    return out


# ============================================================================
# Z3-backed constraint solver  (optional — only the fixed families benefit)
# ============================================================================


def _solve_z3_fixed(ct: bytes, cons: Constraints, key_length: int) -> list[Solution]:
    """Find a globally-consistent fixed/repeating key under hard constraints.

    Encodes key bytes as 8-bit BitVecs and pt[i] = ct[i] ^ key[i % L], then asks
    Z3 for an assignment satisfying printable / charset / alphanumeric / crib
    constraints simultaneously. This shines for multi-byte keys where the greedy
    per-column pass cannot honour a cross-byte charset/regex requirement. Regex
    is applied as a post-filter (Z3 string theory over a fixed-length byte array
    is not worth the complexity here). Returns [] when unavailable or UNSAT.
    """
    if not Z3_AVAILABLE:
        return []
    n = len(ct)
    L = max(1, key_length)
    if L > n:
        return []
    s = _z3.Solver()
    key = [_z3.BitVec(f"k{i}", 8) for i in range(L)]
    pt = [_z3.BitVecVal(ct[i], 8) ^ key[i % L] for i in range(n)]
    for i in range(n):
        bvi = pt[i]
        if cons.printable_ascii:
            s.add(_z3.And(_z3.UGE(bvi, 0x20), _z3.ULE(bvi, 0x7E)))
        if cons.alphanumeric:
            s.add(_z3.Or(
                _z3.And(_z3.UGE(bvi, 0x30), _z3.ULE(bvi, 0x39)),
                _z3.And(_z3.UGE(bvi, 0x41), _z3.ULE(bvi, 0x5A)),
                _z3.And(_z3.UGE(bvi, 0x61), _z3.ULE(bvi, 0x7A)),
            ))
        if cons._char_mask is not None:
            allowed = [c for c in range(256) if cons._char_mask[c]]
            if allowed:
                s.add(_z3.Or([bvi == c for c in allowed]))
    for off, b in cons.crib_bytes(n).items():
        s.add(pt[off] == b)
    if s.check() != _z3.sat:
        return []
    model = s.model()
    keyvals = [model.eval(k, model_completion=True).as_long() for k in key]
    plain = bytes(ct[i] ^ keyvals[i % L] for i in range(n))
    fam = "fixed_single" if L == 1 else "fixed_multi"
    return [Solution(
        fam, plain, " ".join(f"0x{b:02x}" for b in keyvals),
        f"Z3 constraint solution, key length {L}", "z3",
    )]


# ============================================================================
# Orchestration
# ============================================================================


def _family_solvers(ct: bytes, cons: Constraints, *, key_length: int,
                    key_function: str, position_formula: str, table: bytes,
                    table_len: int, brute_cap: int) -> dict[str, list[Solution]]:
    """Run a family (or all families for auto) and return {family: [Solution]}."""
    return {
        "fixed_single": _solve_fixed_single(ct, cons, brute_cap),
        "fixed_multi": _solve_fixed_multi(
            ct, cons, key_length or len(cons.known_prefix) or 0, brute_cap),
        "self_referential": _solve_self_referential(ct, cons, key_function, brute_cap),
        "rolling": _solve_rolling(ct, cons, brute_cap),
        "position_dependent": _solve_position_dependent(
            ct, cons, position_formula, brute_cap),
        "two_layer": _solve_two_layer(ct, cons, brute_cap),
        "table_lookup": _solve_table_lookup(ct, cons, table, table_len, brute_cap),
        "cumulative": _solve_cumulative(ct, cons, brute_cap),
    }


def _rank(solutions: list[Solution], cons: Constraints) -> list[tuple[Solution, bool, float]]:
    """Evaluate and rank candidates: verified first, then by soft score."""
    scored = []
    for sol in solutions:
        verified, score = sol.evaluate(cons)
        scored.append((sol, verified, score))
    scored.sort(key=lambda t: (t[1], t[2]), reverse=True)
    return scored


def _confidence(verified: bool, score: float, method: str, has_constraints: bool,
                margin: float) -> str:
    """Map (verified, score, derivation, separation from runner-up) → label."""
    if not verified:
        return "low"
    algebraic = method in (
        "algebraic_simplification", "algebraic_crib", "known_table", "z3",
    )
    if has_constraints and (algebraic or margin > 0.3) and score >= 0.9:
        return "high"
    if score >= 0.95 and margin > 0.2:
        return "high"
    if score >= 0.6:
        return "medium"
    return "low"


def solve(ct: bytes, family: str, cons: Constraints, *, key_length: int = 0,
          key_function: str = "xor_reduce", position_formula: str = "key+i",
          table: bytes = b"", table_len: int = 0, solver: str = "auto",
          brute_cap: int = _BRUTE_CAP_DEFAULT,
          max_candidates: int = 5) -> dict:
    """Pure-Python entry point. Returns a structured result dict (no IDA).

    This is what the IDA tool wraps; it is also the unit-test surface.
    """
    if not ct:
        return {"ok": False, "error": "empty ciphertext"}

    # Strategy: Z3-only forces the constraint solver; otherwise gather family
    # candidates (algebraic+brute) and, when constraints are present and Z3 is
    # available, also try Z3 for the fixed families as a fallback/confirmation.
    pools: dict[str, list[Solution]] = {}
    if family == "auto":
        pools = _family_solvers(
            ct, cons, key_length=key_length, key_function=key_function,
            position_formula=position_formula, table=table, table_len=table_len,
            brute_cap=brute_cap)
    elif family in FAMILIES:
        single = _family_solvers(
            ct, cons, key_length=key_length, key_function=key_function,
            position_formula=position_formula, table=table, table_len=table_len,
            brute_cap=brute_cap)
        pools = {family: single.get(family, [])}
    else:
        return {"ok": False,
                "error": f"unknown family {family!r}; valid: auto, {', '.join(FAMILIES)}"}

    all_sols: list[Solution] = []
    for sols in pools.values():
        all_sols.extend(sols)

    # ── Algebraic inconsistency detection (Improvement 5) ─────────────────────
    # For self_referential: if the buffer length is odd and XOR(buffer) != 0,
    # there is NO self-consistent solution under the simple model
    # `key = reduce(plaintext)`. We still brute-force (the model may be
    # slightly wrong, e.g. wrong length or wrong reduction), but we *flag*
    # this so the agent knows the answer is heuristic.
    #
    # `diagnostic` is always a concrete string. Earlier it was `Optional[str]`
    # (default None), and the MCP server's strict JSON-schema validator
    # rejected the response whenever the detector did not fire (i.e. for
    # `family="auto"` with a consistent buffer, `family="fixed_single"`,
    # or any even-length self_referential case). Returning `""` keeps
    # the schema happy while preserving the field's null-equivalent
    # semantics for downstream code.
    diagnostic: str = ""
    if family in ("auto", "self_referential") and len(ct) > 0:
        bx = _xor_reduce(ct)
        if len(ct) % 2 == 1 and bx != 0:
            diagnostic = (
                f"Algebraic inconsistency: odd-length buffer ({len(ct)} bytes) with "
                f"XOR(buffer) = 0x{bx:02x} ≠ 0 has no self-consistent solution under "
                f"the simple `key = reduce(plaintext)` model. Returning the highest-"
                f"scoring brute-force candidate; this may indicate the buffer length "
                f"is wrong (try 24/26 for the selfkey crackme) or the cipher model is "
                f"not pure self-referential (e.g. it might be a rolling + accumulator "
                f"hybrid). See plans/XOR_SWISS_ARMY_KNIFE_PROPOSAL.md §'Updated "
                f"Algebraic Derivation for Self-Referential XOR'."
            )

    z3_used = False
    # Z3 only models the fixed / repeating-key families. For families it cannot
    # express (self_referential, rolling, …) the algebraic+brute path is already
    # complete, so we never attempt or force Z3 there — that avoids both wasted
    # work and (in forced mode) discarding the correct non-Z3 solution.
    z3_modelable = family in ("auto", "fixed_single", "fixed_multi", "table_lookup")
    if solver in ("auto", "z3") and Z3_AVAILABLE and cons.any_set() and z3_modelable:
        want_multi = family in ("fixed_multi", "table_lookup", "auto")
        kl = key_length or len(cons.known_prefix) or 1
        targets = {1}
        if want_multi and kl > 1:
            targets.add(kl)
        force = solver == "z3"
        if force or not any(v for s, v, _ in _rank(all_sols, cons)):
            for L in sorted(targets):
                z3_sols = _solve_z3_fixed(ct, cons, L)
                if z3_sols:
                    all_sols.extend(z3_sols)
                    z3_used = True
        # In forced-Z3 mode keep only Z3 solutions for transparency — but only
        # when Z3 actually produced some, otherwise fall back to the family pool.
        if force and z3_used:
            all_sols = [s for s in all_sols if s.method == "z3"]

    ranked = _rank(all_sols, cons)
    if not ranked:
        return {
            "ok": False,
            "error": "no candidate solutions produced for the chosen family/constraints",
            "family_requested": family,
            "z3_available": Z3_AVAILABLE,
            "diagnostic": diagnostic,
        }

    best, best_verified, best_score = ranked[0]
    margin = best_score - (ranked[1][2] if len(ranked) > 1 else 0.0)
    conf = _confidence(best_verified, best_score, best.method, cons.any_set(), margin)

    candidates = []
    for sol, verified, score in ranked[:max(1, max_candidates)]:
        candidates.append({
            "family": sol.family,
            "plaintext": _safe_text(sol.plaintext),
            "plaintext_hex": sol.plaintext.hex(" "),
            "key": sol.key_repr,
            "key_derivation": sol.key_derivation,
            "method": sol.method,
            "verified": verified,
            "score": round(score, 4),
        })

    return {
        "ok": True,
        "family_detected": best.family,
        "family_requested": family,
        "key": best.key_repr,
        "key_derivation": best.key_derivation,
        "plaintext": _safe_text(best.plaintext),
        "plaintext_hex": best.plaintext.hex(" "),
        "confidence": conf,
        "method": best.method,
        "verification": best_verified,
        "z3_used": z3_used,
        "z3_available": Z3_AVAILABLE,
        "candidates": candidates,
        "diagnostic": diagnostic,
    }


def _safe_text(b: bytes) -> str:
    """Decode for display: real text stays readable, binary becomes escaped."""
    try:
        s = b.decode("utf-8")
        if all(0x20 <= ord(c) < 0x7F or c in "\t\n\r" for c in s):
            return s
    except UnicodeDecodeError:
        pass
    return b.decode("latin-1").encode("unicode_escape").decode("ascii")


# ============================================================================
# Input parsing helpers shared by the tools
# ============================================================================


def _parse_bytes_arg(value: str) -> bytes:
    """Parse a 'hex:..' / '0x..' / bare-hex / plain-text argument into bytes."""
    if not value:
        return b""
    v = value.strip()
    if v.startswith("hex:"):
        return bytes.fromhex(v[4:].replace(" ", "").replace("0x", ""))
    if v.startswith("0x") and len(v) > 2:
        return bytes.fromhex(v[2:].replace(" ", ""))
    stripped = v.replace(" ", "")
    if len(stripped) >= 4 and len(stripped) % 2 == 0 and all(
        c in "0123456789abcdefABCDEF" for c in stripped
    ):
        return bytes.fromhex(stripped)
    return v.encode("utf-8")


def _parse_known_pairs(spec: str) -> list[tuple[int, int]]:
    """Parse 'off:val' pairs, e.g. '0:0x54,-1:0x7d' or '5:A'. val: hex or char."""
    pairs: list[tuple[int, int]] = []
    if not spec:
        return pairs
    for tok in spec.split(","):
        tok = tok.strip()
        if not tok or ":" not in tok:
            continue
        off_s, val_s = tok.split(":", 1)
        off = int(off_s.strip(), 0)
        val_s = val_s.strip()
        # Disambiguation, most-specific first: '0x..' is hex; a two-hex-digit
        # token is hex; a single character is its ASCII code; anything else is a
        # plain integer literal. This makes '0:A' mean the letter 'A' (0x41) and
        # '0:41' mean 0x41 too, while '0:0x41' is explicit.
        if val_s.startswith(("0x", "0X")):
            val = int(val_s, 16)
        elif len(val_s) == 2 and all(c in "0123456789abcdefABCDEF" for c in val_s):
            val = int(val_s, 16)
        elif len(val_s) == 1:
            val = ord(val_s)
        else:
            val = int(val_s, 0)
        pairs.append((off, val & 0xFF))
    return pairs


def _build_constraints(known_prefix: str, known_suffix: str, regex: str,
                       printable_ascii: bool, alphanumeric: bool, char_set: str,
                       min_length: int, max_length: int, known_plaintext_pairs: str,
                       self_consistency: bool) -> Constraints:
    return Constraints(
        known_prefix=_parse_bytes_arg(known_prefix),
        known_suffix=_parse_bytes_arg(known_suffix),
        known_pairs=_parse_known_pairs(known_plaintext_pairs),
        regex=regex,
        printable_ascii=printable_ascii,
        alphanumeric=alphanumeric,
        char_set=char_set,
        min_length=min_length,
        max_length=max_length,
        self_consistency=self_consistency,
    )


# ============================================================================
# IDA-facing tools
# ============================================================================


class XorStatusResult(TypedDict, total=False):
    ok: bool
    available: bool
    z3_available: bool
    z3_version: Optional[str]
    families: list[str]
    constraints: list[str]
    hint: Optional[str]


@tool
@idasync
def xor_status() -> XorStatusResult:
    """Report XOR-solver availability, supported families, and Z3 presence.

    The solver core is always available (pure Python, no hard dependency).
    ``z3_available`` indicates whether the optional Z3 constraint-solving path
    (for multi-byte keys under charset/regex constraints) is usable. Install it
    with ``pip install z3-solver`` (often already present via triton/angr).

    Profile: analysis
    """
    return {
        "ok": True,
        "available": True,
        "z3_available": Z3_AVAILABLE,
        "z3_version": Z3_VERSION,
        "families": list(FAMILIES),
        "constraints": [
            "known_prefix", "known_suffix", "known_plaintext_pairs", "regex",
            "printable_ascii", "alphanumeric", "char_set", "min_length",
            "max_length", "self_consistency",
        ],
        "hint": None if Z3_AVAILABLE else (
            "Z3 path disabled — install with: pip install z3-solver "
            "(algebraic + brute-force families still work)"
        ),
    }


class XorSolveCandidate(TypedDict, total=False):
    family: str
    plaintext: str
    plaintext_hex: str
    key: str
    key_derivation: str
    method: str
    verified: bool
    score: float


class XorSolveResult(TypedDict, total=False):
    ok: bool
    addr: str
    length: int
    family_detected: str
    family_requested: str
    key: str
    key_derivation: str
    plaintext: str
    plaintext_hex: str
    confidence: str
    method: str
    verification: bool
    z3_used: bool
    z3_available: bool
    candidates: list[XorSolveCandidate]
    hint: str
    diagnostic: str
    error: str
    error_type: str


@tool
@idasync
@tool_timeout(30.0)
def xor_solve_universal(
    addr: Annotated[
        str,
        "Ciphertext address (hex or symbol). Leave empty and pass ciphertext_hex "
        "to solve raw bytes without an IDB.",
    ] = "",
    length: Annotated[
        int, "Bytes to read from addr (0 = auto: stop at first NUL, max 256)."
    ] = 0,
    ciphertext_hex: Annotated[
        str, "Raw ciphertext as hex (alternative to addr), e.g. '54 65 73 74'."
    ] = "",
    family: Annotated[
        str,
        "Cipher family: 'auto' (try all, rank by constraints) | fixed_single | "
        "fixed_multi | self_referential | rolling | position_dependent | "
        "two_layer | table_lookup | cumulative.",
    ] = "auto",
    key_length: Annotated[
        int, "Key length for fixed_multi / table_lookup (0 = infer from known_prefix)."
    ] = 0,
    key_function: Annotated[
        str, "self_referential reduction: 'xor_reduce' (default) | 'sum'."
    ] = "xor_reduce",
    position_formula: Annotated[
        str, "position_dependent formula: 'key+i' (default) | 'key-i' | 'key^i' | 'i'."
    ] = "key+i",
    table_hex: Annotated[
        str, "Known XOR table as hex for table_lookup (empty = recover it)."
    ] = "",
    known_prefix: Annotated[
        str, "Expected plaintext start (text, or 'hex:..'), e.g. 'flag{' — also a crib."
    ] = "",
    known_suffix: Annotated[
        str, "Expected plaintext end (text or 'hex:..'), e.g. '}' — also a crib."
    ] = "",
    known_plaintext_pairs: Annotated[
        str,
        "Known bytes at offsets as 'off:val' list (val = hex or char; negative "
        "offsets count from the end), e.g. '0:0x54,-1:}'.",
    ] = "",
    regex: Annotated[
        str, "Plaintext must match this regex (searched, latin-1 decoded)."
    ] = "",
    printable_ascii: Annotated[
        bool, "Require/strongly prefer printable ASCII (0x20-0x7E)."
    ] = False,
    alphanumeric: Annotated[bool, "Require [A-Za-z0-9] plaintext."] = False,
    char_set: Annotated[
        str, "Allowed-character spec, e.g. 'a-z0-9_' (ranges with '-')."
    ] = "",
    min_length: Annotated[int, "Minimum plaintext length (0 = no bound)."] = 0,
    max_length: Annotated[int, "Maximum plaintext length (0 = no bound)."] = 0,
    self_consistency: Annotated[
        bool, "Hint that output must equal input (strcmp-style self-key checks)."
    ] = False,
    solver: Annotated[
        str, "Strategy: 'auto' | 'algebraic' | 'brute_force' | 'z3'."
    ] = "auto",
    max_brute_force_keys: Annotated[int, "Safety cap on brute-forced keys."] = _BRUTE_CAP_DEFAULT,
    max_candidates: Annotated[int, "How many ranked candidates to return."] = 5,
) -> XorSolveResult:
    """Universal XOR cipher solver — model-driven, algebraic-first, constraint-aware.

    Enumerates common XOR cipher families and returns the one(s) whose recovered
    plaintext satisfies your constraints. Unlike ``xor_invert`` (fixed key) and
    ``numpy_xor_key_recovery`` (statistical repeating key), this handles the
    *slightly non-standard* variants that those models silently fail on:

      • fixed_single / fixed_multi — classic single & repeating-key XOR
      • self_referential          — key derived from the plaintext (self-key);
                                    solves the 'strcmp(pw, buf ^ XOR(pw))' pattern
      • rolling                   — chained XOR (ciphertext- or plaintext-feedback)
      • position_dependent        — out[i] = ct[i] ^ (key + i), ^ i, etc.
      • cumulative                — prefix-scan XOR over the input
      • two_layer                 — (ct ^ K1) ^ K2  (shown to collapse to one key)
      • table_lookup              — out[i] = ct[i] ^ T[i % len(T)]

    Provide ciphertext via ``addr`` (read from the IDB) or ``ciphertext_hex``.
    Constraints (``known_prefix``/``known_suffix`` double as cribs,
    ``printable_ascii``, ``char_set``, ``regex``, length bounds, ``known_plaintext_pairs``)
    both *gate* (a candidate is ``verified`` only if every hard constraint holds)
    and *rank* the results. With ``family='auto'`` and only ``printable_ascii=true``
    the solver picks the right model itself.

    Strategy ladder: algebraic simplification (e.g. self-key reduces to one byte;
    two-layer collapses) → bounded brute force (≤256 per unknown byte) → Z3 for
    multi-byte keys under charset/regex (when z3-solver is installed; see
    ``xor_status``). The result reports ``family_detected``, ``method``, and a
    per-candidate ``verified`` flag so the derivation is transparent.

    Example — recover a self-key password constraint:
        xor_solve_universal(addr='0x2060', length=25, family='auto',
                            printable_ascii=true, known_prefix='a_')

    Profile: analysis
    """
    try:
        # ── Resolve ciphertext ────────────────────────────────────────────
        ct: bytes
        resolved_addr = ""
        if ciphertext_hex:
            # This parameter is hex by definition — parse strictly (no text
            # fallback), tolerating spaces, '0x' groups and a 'hex:' prefix.
            hx = ciphertext_hex.strip()
            if hx.startswith("hex:"):
                hx = hx[4:]
            hx = hx.replace("0x", "").replace(" ", "")
            try:
                ct = bytes.fromhex(hx)
            except ValueError:
                return {"ok": False,
                        "error": f"ciphertext_hex is not valid hex: {ciphertext_hex!r}"}
            if not ct:
                return {"ok": False, "error": "ciphertext_hex did not parse to any bytes"}
        elif addr:
            ea = parse_address(addr)
            resolved_addr = hex(ea)
            read_len = length if length > 0 else _DEFAULT_READ
            read_len = min(read_len, _MAX_LENGTH)
            raw = ida_bytes.get_bytes(ea, read_len)
            if not raw:
                return {"ok": False,
                        "error": f"could not read bytes at {addr} (unmapped?)"}
            if length <= 0:
                nul = raw.find(b"\x00")
                ct = raw[:nul] if nul > 0 else raw
            else:
                ct = raw
        else:
            return {"ok": False,
                    "error": "provide either addr or ciphertext_hex"}

        if len(ct) > _MAX_LENGTH:
            ct = ct[:_MAX_LENGTH]
        if not ct:
            return {"ok": False, "error": "no ciphertext bytes to solve"}

        cons = _build_constraints(
            known_prefix, known_suffix, regex, printable_ascii, alphanumeric,
            char_set, min_length, max_length, known_plaintext_pairs, self_consistency,
        )

        # Map the public strategy onto solve()'s solver token. The family
        # solvers always run (each chooses algebra vs brute internally); the
        # token only governs whether the optional Z3 pass fires. solve() gates
        # Z3 on solver in {auto, z3}, so 'off' (used for algebraic/brute_force)
        # cleanly disables it.
        solver_token = {
            "auto": "auto",
            "z3": "z3",
            "algebraic": "off",
            "brute_force": "off",
        }.get(solver, "auto")
        brute_cap = max(1, min(max_brute_force_keys, _BRUTE_CAP_DEFAULT))

        result = solve(
            ct, family, cons,
            key_length=key_length, key_function=key_function,
            position_formula=position_formula,
            table=_parse_bytes_arg(table_hex), table_len=key_length,
            solver=solver_token, brute_cap=brute_cap, max_candidates=max_candidates,
        )

        if not result.get("ok"):
            result.setdefault("hint", (
                "No family fit the constraints. Try family='auto', loosen "
                "constraints, or run xor_model_from_disassembly on the routine "
                "to identify the cipher, or numpy_xor_key_recovery for a long "
                "repeating-key blob."
            ))
            if resolved_addr:
                result["addr"] = resolved_addr
            result["length"] = len(ct)
            return result

        result["addr"] = resolved_addr
        result["length"] = len(ct)
        if result.get("verification"):
            result["hint"] = (
                f"Solved as {result['family_detected']} "
                f"({result['confidence']} confidence, method={result['method']}). "
                f"Key={result['key']}. Plaintext verified against all constraints."
            )
        else:
            result["hint"] = (
                "Best candidate did not satisfy every hard constraint — inspect "
                "the candidates list, add a known_prefix/known_plaintext_pairs "
                "crib, or try a different family."
            )
        # If the algebraic-inconsistency detector fired, append a one-liner
        # so the agent does not miss it when reading `hint`. The full
        # diagnostic is in the `diagnostic` field.
        if result.get("diagnostic"):
            result["hint"] = (result.get("hint") or "") + " [DIAGNOSTIC: " + result["diagnostic"] + "]"
        return result

    except ValueError as e:
        return {"ok": False, **tool_error(e, "xor_solve_universal")}
    except Exception as e:
        return {"ok": False, **tool_error(e, "xor_solve_universal")}


class XorModelResult(TypedDict, total=False):
    ok: bool
    addr: str
    function_name: str
    detected_family: str
    confidence: float
    key_derivation: str
    buffer_source: Optional[str]
    buffer_length: Optional[int]
    operation: str
    signals: list[str]
    notes: str
    suggested_call: dict
    error: str
    error_type: str


@tool
@idasync
@tool_timeout(30.0)
def xor_model_from_disassembly(
    addr: Annotated[str, "Function address or name to classify (hex or symbol)."],
    max_insns: Annotated[int, "Maximum instructions to scan (default 4000)."] = 4000,
) -> XorModelResult:
    """Classify which XOR cipher family a function implements, from its code.

    Bridges code analysis and cryptanalysis: scans the disassembly (and, when
    available, the Hex-Rays pseudocode) for the structural signatures of each
    XOR family, then recommends a ready-to-run ``xor_solve_universal`` call.

    Signatures detected:
      • xor reg, imm in a loop                      → fixed_single
      • xor reg, [table + i] / xor reg, mem[i % n]  → fixed_multi / table_lookup
      • xor accumulator folding the whole buffer,
        then xor buffer with that accumulator        → self_referential (self-key)
      • xor with the loop counter / index            → position_dependent
      • xor where the operand is the previous output  → rolling
      • running ^= byte; out = byte ^ running         → cumulative

    Pure pattern matching — no symbolic execution. Use this first when you find
    an obfuscation routine but don't yet know the cipher model, then feed the
    suggested call into xor_solve_universal.

    Profile: analysis
    """
    try:
        ea = parse_address(addr)
        func = idaapi.get_func(ea)
        if not func:
            return {"ok": False, "error": f"no function found at {addr}"}
        func_name = ida_funcs.get_func_name(func.start_ea) or hex(func.start_ea)

        # Collect (ea, mnem, ops[]) for the function body.
        insns: list[tuple[int, str, list[str]]] = []
        for item_ea in idautils.FuncItems(func.start_ea):
            mnem = (idc.print_insn_mnem(item_ea) or "").lower()
            ops: list[str] = []
            for n in range(4):
                if idc.get_operand_type(item_ea, n) == idaapi.o_void:
                    break
                ops.append((idc.print_operand(item_ea, n) or "").lower())
            insns.append((item_ea, mnem, ops))
            if len(insns) >= max_insns:
                break

        # Loop headers (a successor that targets an earlier address).
        loop_headers: set[int] = set()
        buffer_refs: list[int] = []
        try:
            fc = idaapi.FlowChart(func)
            for block in fc:
                for succ in block.succs():
                    if succ.start_ea <= block.start_ea:
                        loop_headers.add(succ.start_ea)
        except Exception:
            pass

        xor_imm = 0
        xor_index = 0          # xor with a register that also indexes (i)
        xor_mem_indexed = 0    # xor reg, [base + reg*scale] — table/multi
        xor_reg_reg = 0
        xor_total = 0
        accum_xor = 0          # xor acc, src where acc is reused (folding)
        signals: list[str] = []

        # Track data xrefs (likely the constant buffer / table source).
        for item_ea, mnem, ops in insns:
            for dref in idautils.DataRefsFrom(item_ea):
                buffer_refs.append(dref)

        index_tokens = ("[", "+rax", "+rcx", "+rdx", "+rbx", "+rsi", "+rdi",
                        "+eax", "+ecx", "+edx", "+ebx", "+esi", "+edi",
                        "i]", "*", "+r8", "+r9")

        for idx, (item_ea, mnem, ops) in enumerate(insns):
            if mnem != "xor":
                continue
            if len(ops) < 2:
                continue
            op0, op1 = ops[0], ops[1]
            if op0 == op1:
                continue  # xor reg, reg (zeroing) — ignore
            xor_total += 1
            # Immediate?
            is_imm = False
            try:
                int(op1, 0)
                is_imm = True
            except (ValueError, TypeError):
                is_imm = False
            mem_indexed = ("[" in op1 and any(t in op1 for t in index_tokens)) or \
                          ("[" in op0 and any(t in op0 for t in index_tokens))
            if mem_indexed:
                xor_mem_indexed += 1
            elif is_imm:
                xor_imm += 1
            else:
                xor_reg_reg += 1
            # Folding accumulator heuristic: same dest reg XORed repeatedly with
            # successive loads (acc ^= buf[k]).
            if not is_imm and not mem_indexed:
                accum_xor += 1

        in_loop = bool(loop_headers)

        # Pseudocode enrichment (optional — Hex-Rays may be unavailable).
        pseudo = ""
        try:
            import ida_hexrays

            if ida_hexrays.init_hexrays_plugin():
                cf = ida_hexrays.decompile(func.start_ea)
                if cf:
                    pseudo = str(cf)
        except Exception:
            pseudo = ""

        if pseudo:
            if re.search(r"\^=\s*\w+\s*;", pseudo) and re.search(r"for\s*\(|while\s*\(", pseudo):
                signals.append("pseudocode: accumulator ^= ... inside a loop")
            if re.search(r"\[\s*\w*\s*[-+]?\s*\w*\s*\]\s*\^", pseudo) or re.search(r"\^\s*\w+\[", pseudo):
                signals.append("pseudocode: indexed XOR (table/repeating)")
            if re.search(r"\^\s*\(?\s*\w+\s*\+\s*i\b", pseudo) or re.search(r"\^\s*i\b", pseudo):
                signals.append("pseudocode: XOR with loop index")

        # ── Decision ──────────────────────────────────────────────────────
        family = "fixed_single"
        confidence = 0.3
        key_derivation = "single constant key"
        operation = "out[i] = in[i] ^ K"

        # self_referential: a folding accumulator over the buffer AND input,
        # then the buffer XORed by that accumulator. Strong tell: many reg-reg
        # XORs accumulating, plus an indexed XOR write-back.
        self_ref_signal = any("accumulator" in s for s in signals)
        if self_ref_signal or (accum_xor >= 3 and xor_mem_indexed >= 1 and in_loop):
            family = "self_referential"
            confidence = 0.85 if self_ref_signal else 0.6
            key_derivation = "XOR-reduction of the plaintext (self-key)"
            operation = "out[i] = buf[i] ^ XOR(all input/buffer bytes)"
        elif any("loop index" in s for s in signals) or (xor_index and in_loop):
            family = "position_dependent"
            confidence = 0.7
            key_derivation = "key combined with the position counter"
            operation = "out[i] = in[i] ^ (key + i)"
        elif xor_mem_indexed >= 1 and in_loop:
            family = "fixed_multi"
            confidence = 0.65
            key_derivation = "repeating key / table indexed by position"
            operation = "out[i] = in[i] ^ table[i % len]"
        elif xor_imm >= 1 and in_loop:
            family = "fixed_single"
            confidence = 0.6
            key_derivation = "single constant key applied in a loop"
            operation = "out[i] = in[i] ^ K"
        elif xor_imm >= 1:
            family = "fixed_single"
            confidence = 0.45
        elif xor_total == 0:
            return {
                "ok": True,
                "addr": hex(func.start_ea),
                "function_name": func_name,
                "detected_family": "none",
                "confidence": 0.0,
                "key_derivation": "no XOR operations found",
                "operation": "",
                "signals": signals,
                "notes": (
                    "No data-XOR instructions detected. The routine may use a "
                    "non-XOR transform (ADD/SUB/NOT/ROL) — try find_alphabet_encoder "
                    "or check_constraint_type."
                ),
            }

        # Pick a likely constant-buffer source from data xrefs (lowest mapped).
        buffer_source = None
        buffer_length = None
        if buffer_refs:
            cand = min(set(buffer_refs))
            buffer_source = hex(cand)

        suggested = {
            "tool": "xor_solve_universal",
            "args": {
                "addr": buffer_source or hex(func.start_ea),
                "family": family,
                "printable_ascii": True,
            },
        }
        if family == "self_referential":
            suggested["args"]["key_function"] = "xor_reduce"
        if family in ("fixed_multi", "table_lookup"):
            suggested["args"]["key_length"] = 0
            suggested["notes"] = "set key_length once known (try numpy_xor_key_recovery to detect it)"

        notes = (
            f"{xor_total} data-XOR instructions "
            f"(imm={xor_imm}, indexed={xor_mem_indexed}, reg-reg={xor_reg_reg}); "
            f"{'in a loop' if in_loop else 'no loop detected'}. "
            "Confidence is heuristic — confirm by running the suggested solver."
        )

        return {
            "ok": True,
            "addr": hex(func.start_ea),
            "function_name": func_name,
            "detected_family": family,
            "confidence": round(confidence, 2),
            "key_derivation": key_derivation,
            "buffer_source": buffer_source,
            "buffer_length": buffer_length,
            "operation": operation,
            "signals": signals,
            "notes": notes,
            "suggested_call": suggested,
        }

    except ValueError as e:
        return {"ok": False, **tool_error(e, f"xor_model_from_disassembly at {addr}")}
    except Exception as e:
        return {"ok": False, **tool_error(e, f"xor_model_from_disassembly at {addr}")}
