"""Tests for api_yara — YARA signature-based pattern scanning tools.

All tests except the status probe skip gracefully when yara-python is not installed.
File-based tests use the crackme03.elf fixture (ELF64 Linux binary).
"""

from ..framework import test, skip_test, assert_non_empty, assert_is_list

try:
    from ..api_yara import (
        yara_status,
        YARA_AVAILABLE,
    )
    if YARA_AVAILABLE:
        from ..api_yara import (
            yara_scan,
            yara_scan_builtin_crypto,
            yara_scan_builtin_threats,
            yara_rule_validate,
            yara_generate_rule,
            yara_idb_annotate,
            yara_function_classifier,
            hybrid_yara_lief_profile,
        )
except ImportError:
    YARA_AVAILABLE = False


def _require_yara():
    if not YARA_AVAILABLE:
        skip_test("yara-python not installed")


# ---------------------------------------------------------------------------
# Status probe — always runs, even without yara-python
# ---------------------------------------------------------------------------


@test()
def test_yara_status_probe():
    """yara_status must not crash regardless of whether yara-python is installed."""
    result = yara_status()
    assert isinstance(result, dict), "yara_status must return a dict"
    assert "available" in result, "yara_status must include 'available' key"
    assert "ok" in result, "yara_status must include 'ok' key"
    assert result.get("ok") is True


@test()
def test_yara_status_version():
    """version is a non-empty string when yara-python is available."""
    _require_yara()
    result = yara_status()
    assert result.get("available") is True
    version = result.get("version")
    assert isinstance(version, str) and len(version) > 0, "version must be non-empty"


@test()
def test_yara_status_builtin_rule_counts():
    """builtin_crypto_rules and builtin_threat_rules are positive integers when available."""
    _require_yara()
    result = yara_status()
    crypto_count = result.get("builtin_crypto_rules", 0)
    threat_count = result.get("builtin_threat_rules", 0)
    assert isinstance(crypto_count, int) and crypto_count >= 1, \
        "builtin_crypto_rules must be >= 1"
    assert isinstance(threat_count, int) and threat_count >= 1, \
        "builtin_threat_rules must be >= 1"


@test()
def test_yara_status_no_yara_hint():
    """hint field is present when yara-python is not installed."""
    if YARA_AVAILABLE:
        skip_test("yara is installed — no-yara path not reachable")
    result = yara_status()
    assert result.get("ok") is True
    assert "hint" in result, "hint must be present when yara-python is absent"


# ---------------------------------------------------------------------------
# yara_rule_validate
# ---------------------------------------------------------------------------


@test()
def test_yara_rule_validate_valid():
    """Valid YARA rule returns valid=True and rule_count=1."""
    _require_yara()
    rule = 'rule test_valid { strings: $s = "hello" condition: $s }'
    result = yara_rule_validate(rules=rule)
    assert result.get("ok") is True
    assert result.get("valid") is True
    assert result.get("rule_count") == 1
    assert result.get("error") is None


@test()
def test_yara_rule_validate_invalid():
    """Broken YARA syntax returns valid=False with error details."""
    _require_yara()
    bad_rule = "rule { this is garbage }"
    result = yara_rule_validate(rules=bad_rule)
    assert result.get("ok") is True
    assert result.get("valid") is False
    assert result.get("error") is not None
    assert result.get("rule_count") == 0


@test()
def test_yara_rule_validate_multi_rule():
    """Multiple rules in one block all count."""
    _require_yara()
    rules = (
        'rule r1 { strings: $a = "abc" condition: $a } '
        'rule r2 { strings: $b = "xyz" condition: $b }'
    )
    result = yara_rule_validate(rules=rules)
    assert result.get("valid") is True
    assert result.get("rule_count") == 2


@test()
def test_yara_rule_validate_empty_rules():
    """Empty string returns valid=False without crashing."""
    _require_yara()
    result = yara_rule_validate(rules="")
    assert result.get("ok") is True
    assert result.get("valid") is False
    assert result.get("rule_count") == 0
    assert result.get("error") is not None


# ---------------------------------------------------------------------------
# yara_scan
# ---------------------------------------------------------------------------


@test(binary="crackme03.elf")
def test_yara_scan_inline_rule_elf():
    """yara_scan with a condition:true rule always matches the whole IDB source file."""
    _require_yara()
    result = yara_scan(rules="rule always { condition: true }")
    assert result.get("ok") is True
    assert result.get("total_matches", 0) >= 1


@test(binary="crackme03.elf")
def test_yara_scan_result_shape():
    """yara_scan result has required top-level fields."""
    _require_yara()
    result = yara_scan(rules="rule always { condition: true }")
    assert result.get("ok") is True
    for key in ("source", "bytes_scanned", "rules_compiled", "total_matches", "matches"):
        assert key in result, f"Missing key: {key}"


@test(binary="crackme03.elf")
def test_yara_scan_bytes_scanned_positive():
    """bytes_scanned is a positive integer."""
    _require_yara()
    result = yara_scan(rules="rule always { condition: true }")
    assert isinstance(result.get("bytes_scanned"), int)
    assert result["bytes_scanned"] > 0


@test(binary="crackme03.elf")
def test_yara_scan_bad_rule_error():
    """Broken rule text returns ok=False with a descriptive error."""
    _require_yara()
    result = yara_scan(rules="rule broken { not valid syntax }")
    assert result.get("ok") is False
    assert "error" in result


@test(binary="crackme03.elf")
def test_yara_scan_empty_rules_error():
    """Empty rules string returns ok=False without crashing or poisoning the cache."""
    _require_yara()
    result = yara_scan(rules="")
    assert result.get("ok") is False
    assert "error" in result


@test(binary="crackme03.elf")
def test_yara_scan_matches_is_list():
    """matches field is always a list."""
    _require_yara()
    result = yara_scan(rules="rule always { condition: true }")
    assert isinstance(result.get("matches"), list)


# ---------------------------------------------------------------------------
# yara_scan_builtin_crypto
# ---------------------------------------------------------------------------


@test(binary="crackme03.elf")
def test_yara_scan_builtin_crypto_shape():
    """yara_scan_builtin_crypto returns required fields."""
    _require_yara()
    result = yara_scan_builtin_crypto()
    assert result.get("ok") is True
    for key in ("bytes_scanned", "total_matches", "algorithm_summary", "matches"):
        assert key in result, f"Missing key: {key}"


@test(binary="crackme03.elf")
def test_yara_scan_builtin_crypto_algorithm_summary_keys():
    """algorithm_summary contains all expected algorithm keys."""
    _require_yara()
    result = yara_scan_builtin_crypto()
    assert result.get("ok") is True
    summary = result.get("algorithm_summary", {})
    assert isinstance(summary, dict)
    expected = {"aes", "md5", "sha1", "sha256", "sha512", "crc32", "rc4"}
    for alg in expected:
        assert alg in summary, f"algorithm_summary missing '{alg}'"


@test(binary="crackme03.elf")
def test_yara_scan_builtin_crypto_filter_single_alg():
    """Filtering to a single algorithm only scans that algorithm."""
    _require_yara()
    result = yara_scan_builtin_crypto(algorithms="aes")
    assert result.get("ok") is True
    summary = result.get("algorithm_summary", {})
    assert "aes" in summary
    # Only the requested algo should appear
    assert len(summary) == 1 or all(k == "aes" for k in summary)


# ---------------------------------------------------------------------------
# yara_scan_builtin_threats
# ---------------------------------------------------------------------------


@test(binary="crackme03.elf")
def test_yara_scan_builtin_threats_shape():
    """yara_scan_builtin_threats returns required fields."""
    _require_yara()
    result = yara_scan_builtin_threats()
    assert result.get("ok") is True
    for key in ("bytes_scanned", "risk_score", "risk_level", "category_summary",
                "total_matches", "matches"):
        assert key in result, f"Missing key: {key}"


@test(binary="crackme03.elf")
def test_yara_scan_builtin_threats_risk_level_valid():
    """risk_level is one of the four valid strings (unified vocabulary)."""
    _require_yara()
    result = yara_scan_builtin_threats()
    assert result.get("risk_level") in ("CLEAN", "SUSPICIOUS", "LIKELY_MALICIOUS", "MALICIOUS")


@test(binary="crackme03.elf")
def test_yara_scan_builtin_threats_risk_score_range():
    """risk_score is an integer in [0, 100]."""
    _require_yara()
    result = yara_scan_builtin_threats()
    score = result.get("risk_score", -1)
    assert isinstance(score, int) and 0 <= score <= 100


@test(binary="crackme03.elf")
def test_yara_scan_builtin_threats_category_summary_keys():
    """category_summary contains all four threat categories."""
    _require_yara()
    result = yara_scan_builtin_threats()
    summary = result.get("category_summary", {})
    for cat in ("packers", "c2_frameworks", "hack_tools", "shellcode"):
        assert cat in summary, f"category_summary missing '{cat}'"


# ---------------------------------------------------------------------------
# yara_idb_annotate (killer feature)
# ---------------------------------------------------------------------------


@test(binary="crackme03.elf")
def test_yara_idb_annotate_dry_run_shape():
    """yara_idb_annotate in dry_run mode returns the required top-level fields."""
    _require_yara()
    result = yara_idb_annotate(
        rules="rule always { condition: true }",
        dry_run=True,
    )
    assert result.get("ok") is True
    for key in ("dry_run", "scope", "rules_compiled", "targets_scanned",
                "bytes_scanned", "total_matches", "functions_matched",
                "functions_annotated", "annotation_report"):
        assert key in result, f"Missing key: {key}"


@test(binary="crackme03.elf")
def test_yara_idb_annotate_dry_run_true():
    """dry_run=True is echoed back in the result."""
    _require_yara()
    result = yara_idb_annotate(
        rules="rule always { condition: true }",
        dry_run=True,
    )
    assert result.get("dry_run") is True


@test(binary="crackme03.elf")
def test_yara_idb_annotate_annotation_report_is_list():
    """annotation_report is a list of dicts."""
    _require_yara()
    result = yara_idb_annotate(
        rules="rule always { condition: true }",
        dry_run=True,
    )
    report = result.get("annotation_report", [])
    assert isinstance(report, list)
    for entry in report[:5]:
        assert isinstance(entry, dict)
        assert "function_ea" in entry
        assert "rules_matched" in entry


@test(binary="crackme03.elf")
def test_yara_idb_annotate_functions_matched_positive():
    """A condition:true rule must match at least one function in a non-trivial binary."""
    _require_yara()
    result = yara_idb_annotate(
        rules="rule always { condition: true }",
        dry_run=True,
        min_func_size=8,
    )
    assert result.get("ok") is True
    assert result.get("functions_matched", 0) >= 1


@test(binary="crackme03.elf")
def test_yara_idb_annotate_segments_scope():
    """scope='segments' produces a valid result."""
    _require_yara()
    result = yara_idb_annotate(
        rules="rule always { condition: true }",
        scope="segments",
        dry_run=True,
    )
    assert result.get("ok") is True
    assert result.get("scope") == "segments"
    assert isinstance(result.get("targets_scanned"), int)


# ---------------------------------------------------------------------------
# yara_function_classifier
# ---------------------------------------------------------------------------


@test(binary="crackme03.elf")
def test_yara_function_classifier_shape():
    """yara_function_classifier returns the required top-level fields."""
    _require_yara()
    result = yara_function_classifier()
    assert result.get("ok") is True
    for key in ("functions_scanned", "functions_classified",
                "functions_unclassified", "category_summary", "function_map"):
        assert key in result, f"Missing key: {key}"


@test(binary="crackme03.elf")
def test_yara_function_classifier_counts_consistent():
    """classified + unclassified == scanned."""
    _require_yara()
    result = yara_function_classifier()
    scanned = result.get("functions_scanned", 0)
    classified = result.get("functions_classified", 0)
    unclassified = result.get("functions_unclassified", 0)
    assert classified + unclassified == scanned, \
        f"classified ({classified}) + unclassified ({unclassified}) != scanned ({scanned})"


@test(binary="crackme03.elf")
def test_yara_function_classifier_function_map_entries():
    """Each function_map entry has address, name, size, categories, rules."""
    _require_yara()
    result = yara_function_classifier()
    for entry in result.get("function_map", [])[:10]:
        for field in ("address", "name", "size", "categories", "rules"):
            assert field in entry, f"function_map entry missing '{field}'"
        assert isinstance(entry["categories"], list)
        assert isinstance(entry["rules"], list)


# ---------------------------------------------------------------------------
# yara_generate_rule
# ---------------------------------------------------------------------------


@test(binary="crackme03.elf")
def test_yara_generate_rule_shape():
    """yara_generate_rule returns rule_text and valid=True for a sane address."""
    _require_yara()
    import idautils
    funcs = list(idautils.Functions())
    if not funcs:
        skip_test("No functions in binary")
    first_func = funcs[0]
    import idaapi
    func = idaapi.get_func(first_func)
    if not func:
        skip_test("Could not get first function")
    size = min(64, func.end_ea - func.start_ea)
    result = yara_generate_rule(address=hex(first_func), size=size, rule_name="test_gen")
    assert result.get("ok") is True
    assert isinstance(result.get("rule_text"), str)
    assert "rule" in result.get("rule_text", "")
    assert result.get("valid") is True


@test(binary="crackme03.elf")
def test_yara_generate_rule_coverage_range():
    """coverage is a float between 0 and 1."""
    _require_yara()
    import idautils, idaapi
    funcs = list(idautils.Functions())
    if not funcs:
        skip_test("No functions")
    first = funcs[0]
    func = idaapi.get_func(first)
    if not func:
        skip_test("No func object")
    size = min(64, func.end_ea - first)
    result = yara_generate_rule(address=hex(first), size=size)
    cov = result.get("coverage", -1)
    assert isinstance(cov, float) and 0.0 <= cov <= 1.0


# ---------------------------------------------------------------------------
# hybrid_yara_lief_profile
# ---------------------------------------------------------------------------


@test(binary="crackme03.elf")
def test_hybrid_yara_lief_profile_shape():
    """hybrid_yara_lief_profile returns ok=True and the required top-level fields."""
    _require_yara()
    result = hybrid_yara_lief_profile()
    assert result.get("ok") is True
    for key in ("threat_score", "threat_level", "crypto_hits", "section_hits"):
        assert key in result, f"Missing key: {key}"


@test(binary="crackme03.elf")
def test_hybrid_yara_lief_profile_threat_level_valid():
    """threat_level is one of the valid strings."""
    _require_yara()
    result = hybrid_yara_lief_profile()
    assert result.get("ok") is True
    assert result.get("threat_level") in ("CLEAN", "SUSPICIOUS", "LIKELY_MALICIOUS",
                                           "MALICIOUS"), \
        f"Unexpected threat_level: {result.get('threat_level')}"


@test(binary="crackme03.elf")
def test_hybrid_yara_lief_profile_threat_score_range():
    """threat_score is an integer in [0, 100]."""
    _require_yara()
    result = hybrid_yara_lief_profile()
    score = result.get("threat_score", -1)
    assert isinstance(score, int) and 0 <= score <= 100


@test(binary="crackme03.elf")
def test_threat_vocabulary_consistent():
    """yara_scan_builtin_threats and hybrid_yara_lief_profile use the same level vocabulary."""
    _require_yara()
    shared_levels = {"CLEAN", "SUSPICIOUS", "LIKELY_MALICIOUS", "MALICIOUS"}
    r1 = yara_scan_builtin_threats()
    assert r1.get("risk_level") in shared_levels, \
        f"yara_scan_builtin_threats risk_level '{r1.get('risk_level')}' not in shared vocabulary"
    r2 = hybrid_yara_lief_profile()
    if r2.get("ok"):
        assert r2.get("threat_level") in shared_levels, \
            f"hybrid_yara_lief_profile threat_level '{r2.get('threat_level')}' not in shared vocabulary"
