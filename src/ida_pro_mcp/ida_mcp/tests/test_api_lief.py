"""Tests for api_lief — LIEF binary format analysis tools.

All tests except the status probe skip gracefully when lief is not installed.
File-based tests use the crackme03.elf fixture (ELF64 Linux binary).
"""

from ..framework import test, skip_test, assert_non_empty, assert_is_list

try:
    from ..api_lief import (
        lief_status,
        LIEF_AVAILABLE,
        YARA_AVAILABLE,
    )
    if LIEF_AVAILABLE:
        from ..api_lief import (
            lief_info,
            lief_checksec,
            lief_sections,
            lief_imports,
            lief_exports,
            lief_strings,
            lief_tls_callbacks,
            lief_verify_signature,
            lief_rich_header,
            lief_pe_overlay,
            lief_guard_functions,
            lief_compare_to_idb,
            lief_imphash,
            lief_version_info,
            lief_resources,
            lief_debug_directory,
            lief_load_config,
            hybrid_lief_checksec_exploit_assess,
            hybrid_lief_yara_section_scan,
        )
except ImportError:
    LIEF_AVAILABLE = False
    YARA_AVAILABLE = False


def _require_lief():
    if not LIEF_AVAILABLE:
        skip_test("lief not installed")


# ---------------------------------------------------------------------------
# Status probe — always runs, even without lief
# ---------------------------------------------------------------------------


@test()
def test_lief_status_probe():
    """lief_status must not crash regardless of whether lief is installed."""
    result = lief_status()
    assert isinstance(result, dict), "lief_status must return a dict"
    assert "available" in result, "lief_status must include 'available' key"
    assert "ok" in result, "lief_status must include 'ok' key"


@test()
def test_lief_status_version():
    """version is a non-empty string when lief is available."""
    _require_lief()
    result = lief_status()
    assert result.get("available") is True
    assert isinstance(result.get("version"), str)
    assert len(result["version"]) > 0, "version must be non-empty"


@test()
def test_lief_status_supported_formats():
    """supported_formats list present and non-empty when lief is available."""
    _require_lief()
    result = lief_status()
    fmts = result.get("supported_formats", [])
    assert isinstance(fmts, list) and len(fmts) >= 1
    assert "PE" in fmts and "ELF" in fmts


# ---------------------------------------------------------------------------
# lief_info
# ---------------------------------------------------------------------------


@test(binary="crackme03.elf")
def test_lief_info_elf():
    """lief_info on ELF returns correct format and arch fields."""
    _require_lief()
    result = lief_info()
    assert result.get("ok") is True
    assert result.get("format") == "ELF"
    assert result.get("bits") in (32, 64)
    assert result.get("section_count", 0) >= 1


@test(binary="crackme03.elf")
def test_lief_info_has_required_keys():
    """lief_info result contains all required top-level keys."""
    _require_lief()
    result = lief_info()
    for key in ("ok", "format", "arch", "bits", "is_pie", "entrypoint",
                "section_count", "header"):
        assert key in result, f"Missing key: {key}"


@test(binary="crackme03.elf")
def test_lief_info_entrypoint_is_hex():
    """entrypoint is a hex string starting with 0x."""
    _require_lief()
    result = lief_info()
    ep = result.get("entrypoint", "")
    assert isinstance(ep, str) and ep.startswith("0x")


# ---------------------------------------------------------------------------
# lief_checksec
# ---------------------------------------------------------------------------


@test(binary="crackme03.elf")
def test_lief_checksec_elf_fields():
    """lief_checksec on ELF returns nx, pie, relro, canary, and score."""
    _require_lief()
    result = lief_checksec()
    assert result.get("ok") is True
    assert "nx" in result
    assert "pie" in result
    assert "relro" in result
    assert isinstance(result.get("score"), int) and result["score"] >= 0


@test(binary="crackme03.elf")
def test_lief_checksec_relro_valid():
    """relro value must be one of the three valid strings."""
    _require_lief()
    result = lief_checksec()
    assert result.get("relro") in ("none", "partial", "full")


@test(binary="crackme03.elf")
def test_lief_checksec_summary_is_list():
    """summary field is a list of strings."""
    _require_lief()
    result = lief_checksec()
    summary = result.get("summary", [])
    assert isinstance(summary, list)
    for item in summary:
        assert isinstance(item, str)


# ---------------------------------------------------------------------------
# lief_sections
# ---------------------------------------------------------------------------


@test(binary="crackme03.elf")
def test_lief_sections_nonempty():
    """lief_sections returns at least one section."""
    _require_lief()
    result = lief_sections()
    assert result.get("ok") is True
    assert len(result.get("sections", [])) >= 1


@test(binary="crackme03.elf")
def test_lief_sections_entropy_range():
    """All section entropies are in the valid range [0.0, 8.0]."""
    _require_lief()
    result = lief_sections()
    for sec in result.get("sections", []):
        ent = sec.get("entropy")
        if ent is not None:
            assert 0.0 <= ent <= 8.0, f"Entropy {ent} out of range for section {sec.get('name')}"


@test(binary="crackme03.elf")
def test_lief_sections_no_content_by_default():
    """content_hex is absent from sections when include_content=False."""
    _require_lief()
    result = lief_sections(include_content=False)
    for sec in result.get("sections", []):
        assert "content_hex" not in sec, "content_hex should not appear when include_content=False"


@test(binary="crackme03.elf")
def test_lief_sections_permission_fields():
    """Each section has is_executable, is_readable, is_writable booleans."""
    _require_lief()
    result = lief_sections()
    for sec in result.get("sections", []):
        for field in ("is_executable", "is_readable", "is_writable"):
            assert field in sec, f"Section '{sec.get('name')}' missing field '{field}'"


# ---------------------------------------------------------------------------
# lief_imports
# ---------------------------------------------------------------------------


@test(binary="crackme03.elf")
def test_lief_imports_returns_libraries():
    """lief_imports returns a list of library entries."""
    _require_lief()
    result = lief_imports()
    assert result.get("ok") is True
    assert isinstance(result.get("libraries"), list)


@test(binary="crackme03.elf")
def test_lief_imports_each_has_name():
    """Every library entry has a 'name' key."""
    _require_lief()
    result = lief_imports()
    for lib in result.get("libraries", []):
        assert "name" in lib, "Library entry missing 'name' key"
        assert "functions" in lib, "Library entry missing 'functions' key"


@test(binary="crackme03.elf")
def test_lief_imports_total_is_int():
    """total_imports is a non-negative integer."""
    _require_lief()
    result = lief_imports()
    assert isinstance(result.get("total_imports"), int)
    assert result["total_imports"] >= 0


# ---------------------------------------------------------------------------
# lief_exports
# ---------------------------------------------------------------------------


@test(binary="crackme03.elf")
def test_lief_exports_elf():
    """lief_exports on ELF returns ok=True and total_exports is int."""
    _require_lief()
    result = lief_exports()
    assert result.get("ok") is True
    assert isinstance(result.get("total_exports"), int)


# ---------------------------------------------------------------------------
# lief_strings
# ---------------------------------------------------------------------------


@test(binary="crackme03.elf")
def test_lief_strings_min_length_filter():
    """No string shorter than min_length is returned."""
    _require_lief()
    min_len = 6
    result = lief_strings(min_length=min_len)
    for s in result.get("strings", []):
        assert len(s.get("value", "")) >= min_len, \
            f"String '{s.get('value')}' is shorter than min_length={min_len}"


@test(binary="crackme03.elf")
def test_lief_strings_encoding_field():
    """encoding field in each string entry is 'ascii' or 'utf16'."""
    _require_lief()
    result = lief_strings(encoding="both")
    for s in result.get("strings", []):
        assert s.get("encoding") in ("ascii", "utf16"), \
            f"Unexpected encoding '{s.get('encoding')}'"


@test(binary="crackme03.elf")
def test_lief_strings_section_field():
    """Every string entry has a 'section' field."""
    _require_lief()
    result = lief_strings()
    for s in result.get("strings", []):
        assert "section" in s


# ---------------------------------------------------------------------------
# lief_tls_callbacks
# ---------------------------------------------------------------------------


@test(binary="crackme03.elf")
def test_lief_tls_callbacks_elf():
    """ELF binary has no TLS directory — has_tls must be False."""
    _require_lief()
    result = lief_tls_callbacks()
    assert result.get("ok") is True
    assert result.get("has_tls") is False


@test(binary="crackme03.elf")
def test_lief_tls_result_shape():
    """Result always has 'has_tls' and 'callbacks' keys."""
    _require_lief()
    result = lief_tls_callbacks()
    assert "has_tls" in result
    assert "callbacks" in result
    assert isinstance(result["callbacks"], list)


# ---------------------------------------------------------------------------
# lief_verify_signature
# ---------------------------------------------------------------------------


@test(binary="crackme03.elf")
def test_lief_verify_signature_unsigned_elf():
    """ELF binary has no Authenticode signature."""
    _require_lief()
    result = lief_verify_signature()
    assert result.get("ok") is True
    assert result.get("has_signature") is False


@test(binary="crackme03.elf")
def test_lief_verify_signature_shape():
    """Result always has has_signature and is_valid keys."""
    _require_lief()
    result = lief_verify_signature()
    assert "has_signature" in result
    assert "is_valid" in result


# ---------------------------------------------------------------------------
# lief_rich_header
# ---------------------------------------------------------------------------


@test(binary="crackme03.elf")
def test_lief_rich_header_elf():
    """ELF binary has no Rich Header — has_rich_header must be False."""
    _require_lief()
    result = lief_rich_header()
    assert result.get("ok") is True
    assert result.get("has_rich_header") is False


# ---------------------------------------------------------------------------
# lief_pe_overlay
# ---------------------------------------------------------------------------


@test(binary="crackme03.elf")
def test_lief_pe_overlay_non_pe():
    """Non-PE binary returns has_overlay=False."""
    _require_lief()
    result = lief_pe_overlay()
    assert result.get("ok") is True
    assert result.get("has_overlay") is False


# ---------------------------------------------------------------------------
# lief_guard_functions
# ---------------------------------------------------------------------------


@test(binary="crackme03.elf")
def test_lief_guard_functions_no_cfg_elf():
    """ELF binary has no CFG — cfg_enabled must be False."""
    _require_lief()
    result = lief_guard_functions()
    assert result.get("ok") is True
    assert result.get("cfg_enabled") is False
    assert isinstance(result.get("guard_cf_functions"), list)


# ---------------------------------------------------------------------------
# lief_compare_to_idb
# ---------------------------------------------------------------------------


@test(binary="crackme03.elf")
def test_lief_compare_to_idb_shape():
    """Result has entry_point, sections, imports, exports top-level keys."""
    _require_lief()
    result = lief_compare_to_idb()
    assert result.get("ok") is True
    for key in ("entry_point", "sections", "imports", "exports"):
        assert key in result, f"lief_compare_to_idb missing '{key}'"


@test(binary="crackme03.elf")
def test_lief_compare_ep_is_dict():
    """entry_point is a dict with lief, ida, match keys."""
    _require_lief()
    result = lief_compare_to_idb()
    ep = result.get("entry_point", {})
    assert isinstance(ep, dict)
    for key in ("lief", "ida", "match"):
        assert key in ep, f"entry_point missing '{key}'"


# ---------------------------------------------------------------------------
# hybrid_lief_checksec_exploit_assess
# ---------------------------------------------------------------------------


@test(binary="crackme03.elf")
def test_hybrid_exploit_assess_shape():
    """Exploit assess result has exploitability_rating and checksec_score."""
    _require_lief()
    result = hybrid_lief_checksec_exploit_assess()
    assert result.get("ok") is True
    assert "exploitability_rating" in result
    assert result["exploitability_rating"] in ("HIGH", "MEDIUM", "LOW")
    assert isinstance(result.get("checksec_score"), int)


@test(binary="crackme03.elf")
def test_hybrid_exploit_assess_attack_surface_is_list():
    """attack_surface is a list of strings."""
    _require_lief()
    result = hybrid_lief_checksec_exploit_assess()
    surface = result.get("attack_surface", [])
    assert isinstance(surface, list)


# ---------------------------------------------------------------------------
# hybrid_lief_yara_section_scan
# ---------------------------------------------------------------------------


def _require_yara():
    if not YARA_AVAILABLE:
        skip_test("yara-python not installed")


@test(binary="crackme03.elf")
def test_hybrid_yara_section_scan_no_yara_graceful():
    """Returns ok=False with a hint when yara-python is not installed."""
    _require_lief()
    if YARA_AVAILABLE:
        skip_test("yara is installed — no-yara path not reachable")
    result = hybrid_lief_yara_section_scan(yara_rules="rule x { condition: true }")
    assert result.get("ok") is False
    assert "hint" in result


@test(binary="crackme03.elf")
def test_hybrid_yara_section_scan_shape():
    """Scan result has sections_scanned, total_rule_hits, and matches list."""
    _require_lief()
    _require_yara()
    result = hybrid_lief_yara_section_scan(yara_rules="rule always_true { condition: true }")
    assert result.get("ok") is True
    assert isinstance(result.get("sections_scanned"), int)
    assert isinstance(result.get("total_rule_hits"), int)
    assert isinstance(result.get("matches"), list)


@test(binary="crackme03.elf")
def test_hybrid_yara_section_scan_match_structure():
    """Each match entry has section, entropy, and rules_matched fields."""
    _require_lief()
    _require_yara()
    result = hybrid_lief_yara_section_scan(yara_rules="rule always_true { condition: true }")
    assert result.get("ok") is True
    for entry in result.get("matches", []):
        assert "section" in entry
        assert "entropy" in entry
        assert isinstance(entry.get("rules_matched"), list)


# ---------------------------------------------------------------------------
# lief_imphash
# ---------------------------------------------------------------------------


@test(binary="crackme03.elf")
def test_lief_imphash_non_pe():
    """ELF binary returns ok=False with wrong_format error — imphash is PE-only."""
    _require_lief()
    result = lief_imphash()
    assert result.get("ok") is False
    assert result.get("error_type") == "wrong_format"
    assert result.get("format") == "ELF"


# ---------------------------------------------------------------------------
# lief_version_info
# ---------------------------------------------------------------------------


@test(binary="crackme03.elf")
def test_lief_version_info_non_pe():
    """ELF binary returns ok=False — version info is PE-only."""
    _require_lief()
    result = lief_version_info()
    assert result.get("ok") is False
    assert result.get("format") == "ELF"


@test(binary="crackme03.elf")
def test_lief_version_info_result_shape():
    """Even on failure, result dict has expected top-level keys."""
    _require_lief()
    result = lief_version_info()
    assert "ok" in result
    assert "format" in result


# ---------------------------------------------------------------------------
# lief_resources
# ---------------------------------------------------------------------------


@test(binary="crackme03.elf")
def test_lief_resources_non_pe():
    """ELF binary returns ok=False — resources are PE-only."""
    _require_lief()
    result = lief_resources()
    assert result.get("ok") is False
    assert result.get("format") == "ELF"


@test(binary="crackme03.elf")
def test_lief_resources_result_has_keys():
    """Even on failure, result dict has expected top-level keys."""
    _require_lief()
    result = lief_resources()
    assert "ok" in result
    assert "format" in result


# ---------------------------------------------------------------------------
# lief_debug_directory
# ---------------------------------------------------------------------------


@test(binary="crackme03.elf")
def test_lief_debug_directory_non_pe():
    """ELF binary returns ok=False — debug directory is PE-only."""
    _require_lief()
    result = lief_debug_directory()
    assert result.get("ok") is False
    assert result.get("format") == "ELF"


# ---------------------------------------------------------------------------
# lief_load_config
# ---------------------------------------------------------------------------


@test(binary="crackme03.elf")
def test_lief_load_config_non_pe():
    """ELF binary returns ok=False — load config is PE-only."""
    _require_lief()
    result = lief_load_config()
    assert result.get("ok") is False
    assert result.get("format") == "ELF"
