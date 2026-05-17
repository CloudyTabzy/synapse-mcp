"""Standalone pytest tests for api_filetype (no IDA required).

Tests filetype identification from bytes and the status probe.
"""

import os
import sys
import types

import pytest

# Pre-seed IDA modules
_ida_modules = [
    "ida_bytes", "ida_funcs", "ida_hexrays", "ida_kernwin", "ida_nalt",
    "ida_typeinf", "idaapi", "idautils", "idc", "ida_auto", "ida_lines",
    "ida_ida", "ida_struct", "ida_segment", "ida_search", "ida_ua",
    "ida_idd", "ida_dbg", "ida_pro", "ida_moves", "ida_frame",
    "ida_offset", "ida_xref", "ida_entry", "ida_name", "ida_netnode",
]
for _mod_name in _ida_modules:
    if _mod_name not in sys.modules:
        sys.modules[_mod_name] = types.ModuleType(_mod_name)

_src = os.path.join(os.path.dirname(__file__), "..", "src")
_src = os.path.abspath(_src)
if _src not in sys.path:
    sys.path.insert(0, _src)

if "ida_pro_mcp" not in sys.modules:
    _pkg = types.ModuleType("ida_pro_mcp")
    _pkg.__path__ = [os.path.join(_src, "ida_pro_mcp")]
    sys.modules["ida_pro_mcp"] = _pkg

if "ida_pro_mcp.ida_mcp" not in sys.modules:
    _subpkg = types.ModuleType("ida_pro_mcp.ida_mcp")
    _subpkg.__path__ = [os.path.join(_src, "ida_pro_mcp", "ida_mcp")]
    sys.modules["ida_pro_mcp.ida_mcp"] = _subpkg

# Mock sync
_sync_mod = types.ModuleType("ida_pro_mcp.ida_mcp.sync")
class _IDAError(Exception):
    @property
    def message(self):
        return self.args[0] if self.args else ""
_sync_mod.IDAError = _IDAError
_sync_mod.idasync = lambda f: f
_sync_mod.IDASyncError = Exception
_sync_mod.CancelledError = Exception
sys.modules["ida_pro_mcp.ida_mcp.sync"] = _sync_mod

# Mock rpc
_rpc_mod = types.ModuleType("ida_pro_mcp.ida_mcp.rpc")
_rpc_mod.tool = lambda f: f
_rpc_mod.unsafe = lambda f: f
_rpc_mod.McpToolError = Exception
_rpc_mod.MCP_UNSAFE = set()
sys.modules["ida_pro_mcp.ida_mcp.rpc"] = _rpc_mod

# Mock utils
_utils_mod = types.ModuleType("ida_pro_mcp.ida_mcp.utils")
def _parse_address(addr):
    if isinstance(addr, int):
        return addr
    return int(addr, 0)
def _read_bytes_bss_safe(ea, size):
    return b"\x00" * size
def _tool_error(exc, context="", hint=None):
    return {"ok": False, "error": str(exc), "error_type": "internal_error"}
_utils_mod.parse_address = _parse_address
_utils_mod.read_bytes_bss_safe = _read_bytes_bss_safe
_utils_mod.tool_error = _tool_error
_utils_mod.item_error = _tool_error
_utils_mod.normalize_list_input = lambda v: v if isinstance(v, list) else [x.strip() for x in str(v).split(",") if x.strip()]
sys.modules["ida_pro_mcp.ida_mcp.utils"] = _utils_mod

# Mock compat
_compat_mod = types.ModuleType("ida_pro_mcp.ida_mcp.compat")
_compat_mod.inf_is_64bit = lambda: True
_compat_mod.inf_is_32bit = lambda: False
_compat_mod.inf_get_procname = lambda: "metapc"
_compat_mod.inf_is_be = lambda: False
_compat_mod.inf_get_omin_ea = lambda: 0
_compat_mod.inf_get_omax_ea = lambda: 0x10000
sys.modules["ida_pro_mcp.ida_mcp.compat"] = _compat_mod

try:
    from ida_pro_mcp.ida_mcp.api_filetype import (
        FILETYPE_AVAILABLE,
        filetype_status,
        filetype_identify_buffer,
        filetype_list_supported,
        _infer_category,
    )
except ImportError as exc:
    FILETYPE_AVAILABLE = False
    _import_error = str(exc)
    print(f"Import error: {exc}")

pytestmark = pytest.mark.skipif(not FILETYPE_AVAILABLE, reason="filetype not installed")

for _mod_name in _ida_modules:
    if _mod_name in sys.modules and sys.modules[_mod_name].__spec__ is None:
        del sys.modules[_mod_name]


# ============================================================================
# Status probe
# ============================================================================


class TestFiletypeStatus:
    def test_status_returns_available(self):
        result = filetype_status()
        assert result["available"] is True
        assert result["version"] != ""
        assert result["supported_types_count"] > 0


# ============================================================================
# Buffer identification
# ============================================================================


class TestFiletypeIdentifyBuffer:
    def test_identify_png_from_hex(self):
        png_header = b"\x89PNG\r\n\x1a\n"
        result = filetype_identify_buffer(data_hex=png_header.hex())
        assert result["ok"] is True
        assert result["extension"] == "png"
        assert result["mime"] == "image/png"
        assert result["category"] == "image"

    def test_identify_elf_from_hex(self):
        # filetype needs a more complete ELF header for detection
        elf_header = bytes([
            0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x02, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00,
        ]) + b"\x00" * 40
        result = filetype_identify_buffer(data_hex=elf_header.hex())
        assert result["ok"] is True
        assert result["extension"] == "elf"
        assert result["mime"] == "application/x-executable"
        assert result["category"] == "executable"

    def test_identify_zip_from_hex(self):
        zip_header = b"PK\x03\x04"
        result = filetype_identify_buffer(data_hex=zip_header.hex())
        assert result["ok"] is True
        assert result["extension"] == "zip"
        assert result["category"] == "archive"

    def test_identify_unknown_bytes(self):
        result = filetype_identify_buffer(data_hex=b"\x00\x00\x00\x00".hex())
        assert result["ok"] is True
        assert result["extension"] == "unknown"
        assert result["confidence"] == "none"

    def test_no_input_returns_error(self):
        result = filetype_identify_buffer()
        assert result["ok"] is False
        assert "data_hex or address" in result["error"]

    def test_invalid_hex_returns_error(self):
        result = filetype_identify_buffer(data_hex="not-hex")
        assert result["ok"] is False


# ============================================================================
# Category inference
# ============================================================================


class TestInferCategory:
    def test_image_category(self):
        assert _infer_category("image/png") == "image"
        assert _infer_category("image/jpeg") == "image"

    def test_video_category(self):
        assert _infer_category("video/mp4") == "video"

    def test_archive_category(self):
        assert _infer_category("application/zip") == "archive"
        assert _infer_category("application/x-7z-compressed") == "archive"

    def test_executable_category(self):
        assert _infer_category("application/x-executable") == "executable"
        assert _infer_category("application/x-elf") == "executable"

    def test_document_category(self):
        assert _infer_category("application/pdf") == "document"

    def test_unknown_category(self):
        assert _infer_category("") == "unknown"
        assert _infer_category("application/octet-stream") == "application"


# ============================================================================
# List supported types
# ============================================================================


class TestFiletypeListSupported:
    def test_list_all_types(self):
        result = filetype_list_supported()
        assert result["ok"] is True
        assert result["total"] > 0
        assert all("extension" in t and "mime" in t and "category" in t for t in result["types"])

    def test_filter_by_category(self):
        result = filetype_list_supported(category="image")
        assert result["ok"] is True
        assert all(t["category"] == "image" for t in result["types"])
        assert result["total"] > 0

    def test_filter_by_empty_category(self):
        result = filetype_list_supported(category="nonexistent")
        assert result["ok"] is True
        assert result["total"] == 0
