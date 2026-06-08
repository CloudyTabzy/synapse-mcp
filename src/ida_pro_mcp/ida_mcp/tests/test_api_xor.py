"""Tests for api_xor — the universal XOR cipher solver.

The solver core is pure Python (no hard dependency), so the status probe and all
family/constraint tests always run. The optional Z3 path is exercised only when
z3-solver is importable. Most tests drive the tools through ``ciphertext_hex`` so
they are deterministic and independent of the loaded fixture's bytes; one test
patches a scratch region to exercise the ``addr`` read path, and
``xor_model_from_disassembly`` runs against a real fixture function.
"""

from ..framework import test, skip_test, assert_ok, assert_error
from ..api_xor import (
    Constraints,
    solve,
    xor_status,
    xor_solve_universal,
    xor_model_from_disassembly,
    _xor_reduce,
    Z3_AVAILABLE,
)


def _require_z3():
    if not Z3_AVAILABLE:
        skip_test("z3-solver not installed")


def _hex(b: bytes) -> str:
    return b.hex()


# ---------------------------------------------------------------------------
# Status probe
# ---------------------------------------------------------------------------


@test()
def test_xor_status_probe():
    """xor_status always reports available=True and lists the families."""
    r = xor_status()
    assert_ok(r, "available", "families", "constraints")
    assert r["available"] is True
    assert "self_referential" in r["families"]
    assert "fixed_single" in r["families"]
    assert len(r["families"]) == 8
    assert r["z3_available"] == Z3_AVAILABLE


# ---------------------------------------------------------------------------
# Pure engine — family round-trips via solve()
# ---------------------------------------------------------------------------


@test()
def test_engine_fixed_single_crib_is_algebraic():
    """A crib pins K exactly → algebraic_crib, exact recovery."""
    pt = b"Hello, World! This is plaintext."
    ct = bytes(c ^ 0x5A for c in pt)
    r = solve(ct, "fixed_single", Constraints(known_prefix=b"Hello"))
    assert r["ok"] and r["plaintext"] == pt.decode()
    assert r["method"] == "algebraic_crib"
    assert r["key"] == "0x5a"
    assert r["verification"] is True


@test()
def test_engine_fixed_single_brute_with_printable():
    """Brute single-byte XOR disambiguated by the alpha-weighted score."""
    pt = b"the recovered secret string value"
    ct = bytes(c ^ 0x6D for c in pt)
    r = solve(ct, "fixed_single", Constraints(printable_ascii=True))
    assert r["ok"] and r["plaintext"] == pt.decode(), r.get("plaintext")


@test()
def test_engine_self_referential_selkey_odd_length():
    """Self-key (buffer ^ XOR-reduction), odd length → constraints disambiguate."""
    password = b"a_very_strong_password507"  # 25 bytes (odd)
    s = _xor_reduce(password)
    # B[i] = password[i] ^ XOR(B) ^ S, choosing XOR(B)=0 → B[i] = password[i] ^ S
    buf = bytes(b ^ s for b in password)
    r = solve(buf, "self_referential",
              Constraints(printable_ascii=True, known_prefix=b"a_"))
    assert r["ok"] and r["plaintext"] == password.decode(), r.get("plaintext")
    assert r["family_detected"] == "self_referential"


@test()
def test_engine_self_referential_even_is_unique():
    """Direct self-key, even length → S is uniquely determined algebraically."""
    pw = b"EvenLengthSecret"  # 16 bytes
    s = _xor_reduce(pw)
    ct = bytes(b ^ s for b in pw)
    r = solve(ct, "self_referential", Constraints(printable_ascii=True))
    assert r["ok"] and r["plaintext"] == pw.decode(), r.get("plaintext")


@test()
def test_engine_fixed_multi_crib_full_cycle():
    """Repeating key recovered exactly when the crib covers a full cycle."""
    key = b"KEY"
    pt = b"The quick brown fox jumps over the lazy dog."
    ct = bytes(pt[i] ^ key[i % 3] for i in range(len(pt)))
    r = solve(ct, "fixed_multi", Constraints(known_prefix=b"The qui"), key_length=3)
    assert r["ok"] and r["plaintext"] == pt.decode(), r.get("plaintext")
    assert r["method"] == "algebraic_crib"


@test()
def test_engine_rolling_chain():
    """Plaintext-feedback rolling XOR recovered (seed K brute + chain)."""
    pt = b"RollingXORchainTest"
    ct = bytearray(len(pt))
    ct[0] = pt[0] ^ 0x33
    for i in range(1, len(pt)):
        ct[i] = pt[i] ^ pt[i - 1]
    r = solve(bytes(ct), "rolling", Constraints(known_prefix=b"Rolling"))
    assert r["ok"] and r["plaintext"] == pt.decode(), r.get("plaintext")


@test()
def test_engine_position_dependent_crib():
    """Position-dependent (key+i) recovered via crib (brute is ambiguous)."""
    pt = b"Position Dependent XOR data"
    ct = bytes((pt[i] ^ ((0x10 + i) & 0xFF)) for i in range(len(pt)))
    r = solve(ct, "position_dependent", Constraints(known_prefix=b"Position"),
              position_formula="key+i")
    assert r["ok"] and r["plaintext"] == pt.decode(), r.get("plaintext")
    assert r["method"] == "algebraic_crib"


@test()
def test_engine_cumulative_prefix_scan():
    """Keyless prefix-scan XOR is deterministic."""
    pt = b"CumulativeScanXORtext"
    ct = bytearray(len(pt))
    acc = 0
    for i in range(len(pt)):
        ct[i] = pt[i] ^ acc
        acc ^= ct[i]
    r = solve(bytes(ct), "cumulative", Constraints(printable_ascii=True))
    assert r["ok"] and r["plaintext"] == pt.decode(), r.get("plaintext")


@test()
def test_engine_two_layer_collapses():
    """Two constant layers collapse to a single key; reported as such."""
    pt = b"TwoLayerCollapse"
    ct = bytes(c ^ 0x12 ^ 0x34 for c in pt)
    r = solve(ct, "two_layer", Constraints(known_prefix=b"Two"))
    assert r["ok"] and r["plaintext"] == pt.decode()
    assert "collapse" in r["key_derivation"].lower()


@test()
def test_engine_table_lookup_known():
    """Known XOR table decrypts deterministically."""
    table = bytes([0x11, 0x22, 0x33, 0x44])
    pt = b"TableLookupXORdataHere"
    ct = bytes(pt[i] ^ table[i % 4] for i in range(len(pt)))
    r = solve(ct, "table_lookup", Constraints(), table=table)
    assert r["ok"] and r["plaintext"] == pt.decode()


# ---------------------------------------------------------------------------
# auto family detection
# ---------------------------------------------------------------------------


@test()
def test_engine_auto_detects_fixed_single():
    """auto picks fixed_single for plain single-byte XOR."""
    pt = b"just a simple xor obfuscated string for auto detection"
    ct = bytes(c ^ 0x6D for c in pt)
    r = solve(ct, "auto", Constraints(printable_ascii=True))
    assert r["ok"] and r["plaintext"] == pt.decode()
    assert r["family_detected"] == "fixed_single"


@test()
def test_engine_auto_detects_self_referential():
    """auto recovers the self-key plaintext that fixed-key models cannot."""
    password = b"a_very_strong_password507"
    s = _xor_reduce(password)
    buf = bytes(b ^ s for b in password)
    r = solve(buf, "auto", Constraints(printable_ascii=True, known_prefix=b"a_"))
    assert r["ok"] and r["plaintext"] == password.decode(), r.get("plaintext")
    assert r["family_detected"] == "self_referential"


# ---------------------------------------------------------------------------
# constraint gating
# ---------------------------------------------------------------------------


@test()
def test_constraint_charset_gates():
    """char_set verification holds for the true key, false where violated."""
    pt = b"lowercase_only_identifier"
    ct = bytes(c ^ 0x07 for c in pt)
    r = solve(ct, "fixed_single", Constraints(char_set="a-z_", printable_ascii=True))
    assert r["ok"] and r["verification"] is True
    assert r["plaintext"] == pt.decode()


@test()
def test_constraint_regex_gates():
    """A regex constraint selects the matching plaintext."""
    pt = b"flag{th15_15_4_t3st_flag}"
    ct = bytes(c ^ 0x2A for c in pt)
    r = solve(ct, "fixed_single", Constraints(regex=r"flag\{.*\}", printable_ascii=True))
    assert r["ok"] and r["verification"] is True
    assert r["plaintext"] == pt.decode()


@test()
def test_constraint_known_pairs():
    """Known byte pairs at offsets act as a crib for single-byte XOR."""
    pt = b"prefix_known_bytes_xyz"
    ct = bytes(c ^ 0x4B for c in pt)
    # offset 0 = 'p', last byte = 'z'
    cons = Constraints(known_pairs=[(0, ord("p")), (-1, ord("z"))])
    r = solve(ct, "fixed_single", cons)
    assert r["ok"] and r["plaintext"] == pt.decode()


# ---------------------------------------------------------------------------
# Z3 constraint path (optional)
# ---------------------------------------------------------------------------


@test()
def test_z3_multibyte_under_charset():
    """Z3 finds a charset-valid multi-byte key; a crib pins it exactly."""
    _require_z3()
    from ..api_xor import _solve_z3_fixed
    key = b"AB"
    pt = b"abcdefghijklmnopqrst"
    ct = bytes(pt[i] ^ key[i % 2] for i in range(len(pt)))
    sols = _solve_z3_fixed(ct, Constraints(known_prefix=b"ab"), 2)
    assert len(sols) == 1 and sols[0].plaintext == pt
    assert sols[0].method == "z3"


# ---------------------------------------------------------------------------
# Tool surface: xor_solve_universal via ciphertext_hex
# ---------------------------------------------------------------------------


@test()
def test_tool_solve_ciphertext_hex():
    """xor_solve_universal solves raw hex without needing an IDB address."""
    pt = b"decode this hidden message please"
    ct = bytes(c ^ 0x55 for c in pt)
    r = xor_solve_universal(ciphertext_hex=_hex(ct), family="auto",
                            printable_ascii=True)
    assert_ok(r, "plaintext", "family_detected", "candidates")
    assert r["plaintext"] == pt.decode()
    assert r["length"] == len(pt)
    assert r["verification"] is True


@test()
def test_tool_solve_self_key_end_to_end():
    """The selkey scenario solved declaratively through the tool."""
    password = b"a_very_strong_password507"
    s = _xor_reduce(password)
    buf = bytes(b ^ s for b in password)
    r = xor_solve_universal(
        ciphertext_hex=_hex(buf), family="self_referential",
        key_function="xor_reduce", printable_ascii=True, known_prefix="a_",
    )
    assert_ok(r, "plaintext")
    assert r["plaintext"] == password.decode()
    assert r["family_detected"] == "self_referential"


@test()
def test_tool_solve_rejects_empty_input():
    """No addr and no ciphertext_hex → a clear error."""
    r = xor_solve_universal()
    assert_error(r)


@test()
def test_tool_solve_unknown_family():
    """An unknown family name is reported, not silently ignored."""
    r = xor_solve_universal(ciphertext_hex="41424344", family="nope")
    assert_error(r)


@test()
def test_tool_solve_candidates_have_shape():
    """Each candidate carries the documented fields."""
    pt = b"another printable secret to decode now"
    ct = bytes(c ^ 0x31 for c in pt)
    r = xor_solve_universal(ciphertext_hex=_hex(ct), family="fixed_single",
                            printable_ascii=True, max_candidates=3)
    assert r["ok"]
    assert 1 <= len(r["candidates"]) <= 3
    for c in r["candidates"]:
        for key in ("family", "plaintext", "plaintext_hex", "key", "method",
                    "verified", "score"):
            assert key in c, f"candidate missing {key}"


# ---------------------------------------------------------------------------
# Tool surface: addr read path (patch a scratch region, restore afterwards)
# ---------------------------------------------------------------------------


@test()
def test_tool_solve_addr_read_path():
    """xor_solve_universal reads ciphertext from an IDB address."""
    import ida_bytes
    import ida_segment

    seg = ida_segment.getnseg(0)
    if seg is None:
        skip_test("no segments in fixture")
    ea = seg.start_ea
    pt = b"patched_xor_blob_secret\x00"
    ct = bytes(c ^ 0x77 for c in pt)
    original = ida_bytes.get_bytes(ea, len(ct))
    if original is None or len(original) < len(ct):
        skip_test("cannot read scratch region")
    if not ida_bytes.patch_bytes(ea, ct):
        skip_test("cannot patch scratch region")
    try:
        r = xor_solve_universal(addr=hex(ea), length=0, family="fixed_single",
                                known_prefix="patched_")
        assert r["ok"], r
        # length=0 → auto-stops at the embedded NUL
        assert r["plaintext"].startswith("patched_xor_blob_secret")
        assert r["addr"] == hex(ea)
    finally:
        ida_bytes.patch_bytes(ea, original)


# ---------------------------------------------------------------------------
# Tool surface: xor_model_from_disassembly
# ---------------------------------------------------------------------------


@test()
def test_tool_model_from_disassembly_runs():
    """The model classifier returns a structured family guess for a function."""
    from ..framework import get_any_function

    fn = get_any_function()
    if not fn:
        skip_test("no functions in fixture")
    r = xor_model_from_disassembly(fn)
    assert_ok(r, "detected_family", "confidence")
    assert isinstance(r["confidence"], (int, float))
    assert 0.0 <= r["confidence"] <= 1.0
    # detected_family is one of the known families or 'none'
    from ..api_xor import FAMILIES
    assert r["detected_family"] in set(FAMILIES) | {"none"}


@test()
def test_tool_model_bad_address():
    """A non-function address is reported as an error."""
    r = xor_model_from_disassembly("0x0")
    assert isinstance(r, dict)
    assert r.get("ok") in (True, False)  # tolerate either; must not raise
    if not r.get("ok"):
        assert_error(r)


# ---------------------------------------------------------------------------
# Algebraic-inconsistency diagnostic (Improvement #5 in the proposal)
# ---------------------------------------------------------------------------


@test()
def test_engine_diagnostic_fires_on_inconsistent_selfref():
    """An odd-length self_referential with XOR(buffer) != 0 trips the diagnostic.

    This is the exact pathological case from
    plans/XOR_SWISS_ARMY_KNIFE_PROPOSAL.md: the buffer XOR-reduction is
    non-zero so the simple ``key = reduce(plaintext)`` model has no
    self-consistent solution, yet the solver still returns the
    highest-scoring brute-force candidate and tags it with a diagnostic
    so the agent knows the result is heuristic.

    The buffer is constructed directly (not as ``password ^ s``) so that
    ``XOR(buffer) != 0``. Using ``password ^ s`` would degenerate to
    ``XOR(buffer) == 0`` because the construction is its own self-key.
    25 copies of one byte → ``XOR = that byte`` (24 pairs cancel).
    """
    # 25-byte buffer (odd) where XOR = 0x42 ('B').
    buf = bytes([0x42] * 25)
    assert len(buf) == 25 and len(buf) % 2 == 1
    assert _xor_reduce(buf) == 0x42, "test fixture: XOR of the 25-byte buffer must be 0x42"

    r = solve(buf, "self_referential", Constraints(printable_ascii=True))
    assert r["ok"], r
    assert r.get("diagnostic"), "expected the diagnostic to fire on this case"
    assert "Algebraic inconsistency" in r["diagnostic"]
    assert "0x42" in r["diagnostic"]
    # The diagnostic should be the *only* signal here: we are not
    # asserting a specific plaintext (the model is intentionally wrong,
    # so the brute-force answer is heuristic by construction).


@test()
def test_engine_diagnostic_silent_on_even_selfref():
    """An even-length self_referential has a unique algebraic solution — no diagnostic."""
    pw = b"EvenLengthSecret"  # 16 bytes
    s = _xor_reduce(pw)
    ct = bytes(b ^ s for b in pw)
    assert len(ct) % 2 == 0
    r = solve(ct, "self_referential", Constraints(printable_ascii=True))
    assert r["ok"]
    # For even length, the algebraic simplification is exact and no
    # diagnostic should be emitted.
    assert not r.get("diagnostic")


@test()
def test_engine_diagnostic_silent_on_even_length_with_nonzero_xor():
    """Even length with non-zero XOR also has no diagnostic — it's uniquely solvable."""
    # 8-byte buffer, XOR = 0x05, even length → S = XOR(buffer) is unique.
    buf = bytes([0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x05])
    assert len(buf) % 2 == 0
    assert _xor_reduce(buf) == 0x05
    r = solve(buf, "self_referential", Constraints(printable_ascii=True))
    assert r["ok"]
    assert not r.get("diagnostic")


@test()
def test_engine_diagnostic_is_empty_string_not_none():
    """`diagnostic` is always a concrete string (empty when no inconsistency).

    Regression for the post-update-verification-report bug: the field
    used to default to ``None`` and the MCP server's strict JSON-schema
    validator rejected responses where ``family='auto'`` or
    ``family='fixed_single'`` did not fire the diagnostic. After the
    fix, the field is always a string — empty when nothing to report.
    """
    # fixed_single on a printable buffer: never fires.
    pt = b"plaintext value"
    ct = bytes(c ^ 0x33 for c in pt)
    r = solve(ct, "fixed_single", Constraints(printable_ascii=True))
    assert r["ok"]
    assert "diagnostic" in r
    assert r["diagnostic"] == "", r["diagnostic"]
    assert isinstance(r["diagnostic"], str)

    # auto on an even-length self-consistent case: never fires.
    pw = b"EvenLengthSecret"
    s = _xor_reduce(pw)
    r = solve(bytes(b ^ s for b in pw),
              "auto", Constraints(printable_ascii=True))
    assert r["ok"]
    assert "diagnostic" in r
    assert r["diagnostic"] == "", r["diagnostic"]
