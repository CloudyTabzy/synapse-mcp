"""Tests for api_elf — pyelftools ELF/DWARF analysis tools.

All tests except the status probe skip gracefully when pyelftools is not
installed. File-based tests use the crackme03.elf fixture (ELF64 Linux binary).
"""
from ..framework import test, skip_test

try:
    from ..api_elf import (
        elf_status,
        ELFTOOLS_AVAILABLE,
        DWARF_AVAILABLE,
    )
    if ELFTOOLS_AVAILABLE:
        from ..api_elf import (
            elf_symbols,
            elf_dwarf_functions,
            elf_dwarf_line_info,
            elf_dwarf_types,
            hybrid_elf_sync_dwarf_to_idb,
        )
except ImportError:
    ELFTOOLS_AVAILABLE = False
    DWARF_AVAILABLE = False


def _require_elf():
    if not ELFTOOLS_AVAILABLE:
        skip_test("pyelftools not installed")


def _require_dwarf():
    _require_elf()
    if not DWARF_AVAILABLE:
        skip_test("DWARF subsystem not available in pyelftools")


# ---------------------------------------------------------------------------
# elf_status — always runs, even without pyelftools
# ---------------------------------------------------------------------------


@test()
def test_elf_status_probe():
    """elf_status must not crash regardless of whether pyelftools is installed."""
    result = elf_status()
    assert isinstance(result, dict), "elf_status must return a dict"
    assert "available" in result, "elf_status must include 'available' key"
    assert "ok" in result, "elf_status must include 'ok' key"
    assert result["ok"] is True


@test()
def test_elf_status_has_dwarf_flag():
    """dwarf_supported is a boolean."""
    _require_elf()
    result = elf_status()
    assert isinstance(result.get("dwarf_supported"), bool)


@test()
def test_elf_status_version_string():
    """version is a non-empty string when pyelftools is available."""
    _require_elf()
    result = elf_status()
    assert result.get("available") is True
    assert isinstance(result.get("version"), str)
    assert len(result["version"]) > 0


# ---------------------------------------------------------------------------
# elf_symbols
# ---------------------------------------------------------------------------


@test(binary="crackme03.elf")
def test_elf_symbols_has_required_keys():
    """elf_symbols returns ok, symtab_count, dynsym_count, total, symbols."""
    _require_elf()
    result = elf_symbols()
    assert result.get("ok") is True
    assert result.get("format") == "ELF"
    assert isinstance(result.get("symtab_count"), int)
    assert isinstance(result.get("dynsym_count"), int)
    assert isinstance(result.get("total"), int)
    assert isinstance(result.get("symbols"), list)


@test(binary="crackme03.elf")
def test_elf_symbols_symtab_only():
    """table='symtab' returns only .symtab entries."""
    _require_elf()
    result = elf_symbols(table="symtab")
    assert result.get("ok") is True
    assert result.get("symtab_count", 0) >= 0
    assert result.get("dynsym_count", 0) == 0


@test(binary="crackme03.elf")
def test_elf_symbols_each_has_fields():
    """Each symbol entry has name, value, size, type, bind, visibility."""
    _require_elf()
    result = elf_symbols(limit=10)
    for sym in result.get("symbols", []):
        for field in ("name", "value", "size", "ty", "bind", "visibility"):
            assert field in sym, f"Symbol missing field '{field}'"


# ---------------------------------------------------------------------------
# elf_dwarf_functions
# ---------------------------------------------------------------------------


@test(binary="crackme03.elf")
def test_elf_dwarf_functions_result_shape():
    """DWARF functions tool returns structured result with has_dwarf flag."""
    _require_elf()
    result = elf_dwarf_functions()
    assert result.get("ok") is True
    assert "has_dwarf" in result
    assert isinstance(result.get("functions"), list)


@test(binary="crackme03.elf")
def test_elf_dwarf_functions_filter():
    """filter substring works without crashing."""
    _require_elf()
    result = elf_dwarf_functions(filter="main", limit=5)
    assert result.get("ok") is True


@test(binary="crackme03.elf")
def test_elf_dwarf_functions_truncated_flag():
    """truncated flag is a boolean."""
    _require_elf()
    result = elf_dwarf_functions(limit=5)
    assert isinstance(result.get("truncated"), bool)


# ---------------------------------------------------------------------------
# elf_dwarf_line_info
# ---------------------------------------------------------------------------


@test(binary="crackme03.elf")
def test_elf_dwarf_line_info_shape():
    """Line info tool returns structured result with has_dwarf flag."""
    _require_elf()
    result = elf_dwarf_line_info()
    assert result.get("ok") is True
    assert "has_dwarf" in result
    assert isinstance(result.get("entries"), list)


@test(binary="crackme03.elf")
def test_elf_dwarf_line_info_addr_lookup():
    """Address lookup with invalid addr returns ok=False without crashing."""
    _require_elf()
    result = elf_dwarf_line_info(addr="0xDEADBEEF")
    assert "ok" in result


# ---------------------------------------------------------------------------
# elf_dwarf_types
# ---------------------------------------------------------------------------


@test(binary="crackme03.elf")
def test_elf_dwarf_types_shape():
    """Types tool returns structured result with has_dwarf flag."""
    _require_elf()
    result = elf_dwarf_types()
    assert result.get("ok") is True
    assert "has_dwarf" in result
    assert isinstance(result.get("types"), list)


@test(binary="crackme03.elf")
def test_elf_dwarf_types_kind_filter():
    """kind='struct' filter works without crashing."""
    _require_elf()
    result = elf_dwarf_types(kind="struct", limit=10)
    assert result.get("ok") is True


# ---------------------------------------------------------------------------
# hybrid_elf_sync_dwarf_to_idb
# ---------------------------------------------------------------------------


@test(binary="crackme03.elf")
def test_hybrid_elf_sync_dry_run():
    """dry_run=True returns proposed changes without modifying IDB."""
    _require_elf()
    result = hybrid_elf_sync_dwarf_to_idb(dry_run=True)
    assert result.get("ok") is True
    assert "has_dwarf" in result
    assert isinstance(result.get("proposed_count"), int)
    assert isinstance(result.get("changes"), list)
    assert result.get("dry_run") is True


@test(binary="crackme03.elf")
def test_hybrid_elf_sync_change_structure():
    """Each change entry has addr, old_name, new_name, kind."""
    _require_elf()
    result = hybrid_elf_sync_dwarf_to_idb(dry_run=True)
    for ch in result.get("changes", []):
        assert "addr" in ch
        assert "old_name" in ch
        assert "new_name" in ch
        assert "kind" in ch
