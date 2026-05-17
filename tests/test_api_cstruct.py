"""Standalone pytest tests for api_cstruct (no IDA required).

Tests C struct parsing, serialization, registry, and pre-defined templates
using synthetic binary data.
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
    from ida_pro_mcp.ida_mcp.api_cstruct import (
        CSTRUCT_AVAILABLE,
        cstruct_status,
        cstruct_parse_c_definition,
        cstruct_define_struct,
        cstruct_list_defined_structs,
        cstruct_to_bytes,
        cstruct_parse_at_address,
        _cstruct_to_dict,
        _PREDEFINED_NAMES,
        _reset_registry,
    )
except ImportError as exc:
    CSTRUCT_AVAILABLE = False
    _import_error = str(exc)
    print(f"Import error: {exc}")

pytestmark = pytest.mark.skipif(not CSTRUCT_AVAILABLE, reason="dissect.cstruct not installed")

for _mod_name in _ida_modules:
    if _mod_name in sys.modules and sys.modules[_mod_name].__spec__ is None:
        del sys.modules[_mod_name]


# ============================================================================
# Status probe
# ============================================================================


class TestCstructStatus:
    def test_status_returns_available(self):
        result = cstruct_status()
        assert result["available"] is True
        assert result["version"] != ""
        assert len(result["predefined_templates"]) > 0


# ============================================================================
# Object serialization
# ============================================================================


class TestCstructToDict:
    def test_serialize_simple_struct(self):
        from dissect import cstruct
        cs = cstruct.cstruct(endian="<")
        cs.load("struct test { uint8 a; uint16 b; uint32 c; };")
        obj = cs.test(b"\x01\x02\x00\x03\x00\x00\x00")
        d = _cstruct_to_dict(obj)
        assert d == {"a": 1, "b": 2, "c": 3}

    def test_serialize_bytes_field(self):
        from dissect import cstruct
        cs = cstruct.cstruct(endian="<")
        cs.load("struct test { char name[4]; };")
        obj = cs.test(b"ABCD")
        d = _cstruct_to_dict(obj)
        assert d["name"]["_type"] == "bytes"
        assert d["name"]["hex"] == "41424344"
        assert d["name"]["ascii"] == "ABCD"

    def test_serialize_enum(self):
        from dissect import cstruct
        cs = cstruct.cstruct(endian="<")
        cs.load("enum Color : uint8 { RED = 1, GREEN = 2, BLUE = 3 }; struct test { Color col; };")
        obj = cs.test(b"\x02")
        d = _cstruct_to_dict(obj)
        assert d["col"]["_type"] == "enum"
        assert d["col"]["name"] == "GREEN"
        assert d["col"]["value"] == 2

    def test_serialize_nested_struct(self):
        from dissect import cstruct
        cs = cstruct.cstruct(endian="<")
        cs.load("struct inner { uint8 x; }; struct test { inner n; uint8 y; };")
        obj = cs.test(b"\x01\x02")
        d = _cstruct_to_dict(obj)
        assert d == {"n": {"x": 1}, "y": 2}

    def test_serialize_array(self):
        from dissect import cstruct
        cs = cstruct.cstruct(endian="<")
        cs.load("struct test { uint32 arr[3]; };")
        obj = cs.test(b"\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00")
        d = _cstruct_to_dict(obj)
        assert d["arr"] == [1, 2, 3]


# ============================================================================
# Parse with C definition
# ============================================================================


class TestCstructParseCDefinition:
    def test_parse_simple_struct(self, tmp_path):
        _reset_registry()
        data = b"\x01\x02\x00\x03\x00\x00\x00"
        f = tmp_path / "test.bin"
        f.write_bytes(data)
        result = cstruct_parse_c_definition(
            c_definition="struct foo { uint8 a; uint16 b; uint32 c; };",
            struct_name="foo",
            file_path=str(f),
            size_hint=len(data),
        )
        assert result["ok"] is True
        assert result["struct_size"] == 7
        assert result["parsed"]["a"] == 1
        assert result["parsed"]["b"] == 2
        assert result["parsed"]["c"] == 3

    def test_parse_multiple_instances(self, tmp_path):
        _reset_registry()
        data = b"\x01\x00\x00\x00\x02\x00\x00\x00"
        f = tmp_path / "test.bin"
        f.write_bytes(data)
        result = cstruct_parse_c_definition(
            c_definition="struct foo { uint32 x; };",
            struct_name="foo",
            file_path=str(f),
            size_hint=len(data),
            count=2,
        )
        assert result["ok"] is True
        assert result["count"] == 2
        assert result["parsed"][0]["x"] == 1
        assert result["parsed"][1]["x"] == 2

    def test_parse_enum(self, tmp_path):
        _reset_registry()
        data = b"\x02"
        f = tmp_path / "test.bin"
        f.write_bytes(data)
        result = cstruct_parse_c_definition(
            c_definition="enum Color : uint8 { RED=1, GREEN=2 }; struct foo { Color c; };",
            struct_name="foo",
            file_path=str(f),
            size_hint=len(data),
        )
        assert result["ok"] is True
        assert result["parsed"]["c"]["_type"] == "enum"
        assert result["parsed"]["c"]["name"] == "GREEN"

    def test_definition_too_large(self):
        _reset_registry()
        result = cstruct_parse_c_definition(
            c_definition="struct foo { uint8 a; };" + " " * 40000,
            struct_name="foo",
            data_hex="01",
        )
        assert result["ok"] is False
        assert "exceeds" in result["error"]

    def test_unknown_struct_name(self, tmp_path):
        _reset_registry()
        f = tmp_path / "test.bin"
        f.write_bytes(b"\x01")
        result = cstruct_parse_c_definition(
            c_definition="struct foo { uint8 a; };",
            struct_name="bar",
            file_path=str(f),
            size_hint=1,
        )
        assert result["ok"] is False
        assert "not found" in result["error"]

    def test_invalid_c_syntax(self, tmp_path):
        _reset_registry()
        f = tmp_path / "test.bin"
        f.write_bytes(b"\x01")
        result = cstruct_parse_c_definition(
            c_definition="this is not valid C",
            struct_name="foo",
            file_path=str(f),
            size_hint=1,
        )
        assert result["ok"] is False
        assert "Failed to parse" in result["error"]


# ============================================================================
# Define and list structs
# ============================================================================


class TestCstructDefineStruct:
    def test_define_and_list(self):
        _reset_registry()
        result = cstruct_define_struct(
            name="my_struct",
            c_definition="struct my_struct { uint8 a; uint16 b; };",
        )
        assert result["ok"] is True
        assert result["name"] == "my_struct"
        assert result["struct_size"] == 3
        assert "a" in result["fields"]
        assert "b" in result["fields"]

        list_result = cstruct_list_defined_structs()
        assert list_result["ok"] is True
        user_names = [s["name"] for s in list_result["structs"] if s["source"] == "user_defined"]
        assert "my_struct" in user_names

    def test_define_with_enum(self):
        _reset_registry()
        result = cstruct_define_struct(
            name="packet",
            c_definition="enum Proto : uint8 { TCP=6, UDP=17 }; struct packet { Proto p; uint16 port; };",
        )
        assert result["ok"] is True
        assert "packet" in result["defined_types"]


# ============================================================================
# Pre-defined templates
# ============================================================================


class TestPredefinedTemplates:
    def test_elf64_ehdr_parses(self):
        _reset_registry()
        # Minimal ELF64 header (64 bytes)
        elf64 = bytes([
            0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x02, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00,
        ]) + b"\x00" * 40

        import tempfile
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(elf64)
            path = f.name

        result = cstruct_parse_c_definition(
            c_definition="struct MyElf64 { char e_ident[16]; uint16 e_type; uint16 e_machine; uint32 e_version; };",
            struct_name="MyElf64",
            file_path=path,
            size_hint=len(elf64),
        )
        assert result["ok"] is True
        assert result["struct_size"] > 0

    def test_predefined_elf64_exists(self):
        _reset_registry()
        list_result = cstruct_list_defined_structs()
        names = [s["name"] for s in list_result["structs"]]
        assert "Elf64_Ehdr" in names

    def test_dos_header_exists(self):
        _reset_registry()
        list_result = cstruct_list_defined_structs()
        names = [s["name"] for s in list_result["structs"]]
        assert "IMAGE_DOS_HEADER" in names


# ============================================================================
# Build / serialize round-trip
# ============================================================================


class TestCstructToBytes:
    def test_round_trip_simple(self):
        _reset_registry()
        # Define struct
        cstruct_define_struct(
            name="rt",
            c_definition="struct rt { uint8 a; uint16 b; uint32 c; };",
        )
        # Build
        build_result = cstruct_to_bytes(
            struct_name="rt",
            data={"a": 1, "b": 2, "c": 3},
        )
        assert build_result["ok"] is True
        assert build_result["size"] == 7
        assert build_result["hex"] == "01020003000000"

    def test_round_trip_with_enum(self):
        _reset_registry()
        cstruct_define_struct(
            name="pkt",
            c_definition="enum P : uint8 { A=1, B=2 }; struct pkt { P proto; };",
        )
        build_result = cstruct_to_bytes(
            struct_name="pkt",
            data={"proto": {"_type": "enum", "value": 2}},
        )
        assert build_result["ok"] is True
        assert build_result["hex"] == "02"
