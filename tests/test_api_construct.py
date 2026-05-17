"""Standalone pytest tests for api_construct helpers (no IDA required).

These tests exercise the safe DSL evaluator, container conversion, and
pre-defined templates using real binary fixtures or synthetic data.
"""

import os
import struct
import sys
import tempfile
import types

import pytest

# Pre-seed every IDA module with a dummy so api_construct's imports succeed
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

# Ensure the src path is present so we can import the package
_src = os.path.join(os.path.dirname(__file__), "..", "src")
_src = os.path.abspath(_src)
if _src not in sys.path:
    sys.path.insert(0, _src)

# Create the package hierarchy with __path__ so relative imports work
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
    return {"error": str(exc), "error_type": "internal_error"}
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

# Now import api_construct through the package (relative imports will resolve)
try:
    from ida_pro_mcp.ida_mcp.api_construct import (
        CONSTRUCT_AVAILABLE,
        _compile_dsl,
        _container_to_dict,
        _count_ast_nodes,
        _validate_ast,
        DSLSecurityError,
        _PE_DOS_HEADER,
        _PE_FILE_HEADER,
        _PE_SECTION_HEADER,
        _ELF64_HEADER,
        _ELF32_HEADER,
        _ELF64_PHDR,
        _ELF64_SHDR,
        _IPV4_HEADER,
        _TCP_HEADER,
        _UDP_HEADER,
        _PROTOCOL_TEMPLATES,
    )
except ImportError as exc:
    CONSTRUCT_AVAILABLE = False
    _import_error = str(exc)
    print(f"Import error: {exc}")

pytestmark = pytest.mark.skipif(not CONSTRUCT_AVAILABLE, reason="construct not installed")

# Clean up mock IDA modules so we don't pollute sys.modules for other tests
for _mod_name in _ida_modules:
    if _mod_name in sys.modules and sys.modules[_mod_name].__spec__ is None:
        del sys.modules[_mod_name]


# ============================================================================
# DSL Security
# ============================================================================


class TestDSLSecurity:
    """Tests for the safe Construct DSL evaluator."""

    def test_compile_basic_struct(self):
        template = _compile_dsl('Struct("magic" / Const(b"MZ"), "count" / Int32ul)')
        result = template.parse(b"MZ\x05\x00\x00\x00")
        assert result.magic == b"MZ"
        assert result.count == 5

    def test_compile_with_this(self):
        template = _compile_dsl('Struct("len" / Int8ul, "data" / Bytes(this.len))')
        result = template.parse(b"\x05hello")
        assert result.len == 5
        assert result.data == b"hello"

    def test_compile_array(self):
        template = _compile_dsl('Struct("count" / Int8ul, "items" / Array(this.count, Int16ul))')
        result = template.parse(b"\x03\x01\x00\x02\x00\x03\x00")
        assert result.count == 3
        assert list(result["items"]) == [1, 2, 3]

    def test_compile_enum(self):
        template = _compile_dsl('Enum(Int8ul, A=1, B=2, C=3)')
        result = template.parse(b"\x02")
        assert str(result) == "B" or int(result) == 2

    def test_compile_flags_enum(self):
        template = _compile_dsl('FlagsEnum(Int8ul, x=1, y=2, z=4)')
        result = template.parse(b"\x03")
        assert result.x is True
        assert result.y is True
        assert result.z is False

    def test_rejects_import(self):
        with pytest.raises(DSLSecurityError):
            _compile_dsl("__import__('os').system('whoami')")

    def test_rejects_eval(self):
        with pytest.raises(DSLSecurityError):
            _compile_dsl("eval('1+1')")

    def test_rejects_open(self):
        with pytest.raises(DSLSecurityError):
            _compile_dsl("open('/etc/passwd')")

    def test_rejects_exec(self):
        with pytest.raises(DSLSecurityError):
            _compile_dsl("exec('print(1)')")

    def test_rejects_os_system(self):
        with pytest.raises(DSLSecurityError):
            _compile_dsl("import os; os.system('whoami')")

    def test_rejects_lambda(self):
        with pytest.raises(DSLSecurityError):
            _compile_dsl("(lambda: 1)()")

    def test_rejects_large_template(self):
        huge = "Struct(" + ",".join(f'"f{i}" / Int32ul' for i in range(300)) + ")"
        with pytest.raises(DSLSecurityError) as exc_info:
            _compile_dsl(huge)
        assert "too complex" in str(exc_info.value).lower()

    def test_empty_template_rejected(self):
        with pytest.raises(DSLSecurityError):
            _compile_dsl("")

    def test_invalid_syntax_rejected(self):
        with pytest.raises(DSLSecurityError):
            _compile_dsl("Struct(!!!)")

    def test_count_ast_nodes_basic(self):
        import ast
        tree = ast.parse("1 + 2", mode="eval")
        count = _count_ast_nodes(tree)
        assert count >= 3  # BinOp, Constant(1), Constant(2)


# ============================================================================
# Container to dict
# ============================================================================


class TestContainerToDict:
    def test_simple_container(self):
        from construct import Container
        c = Container(a=1, b="hello", c=b"world")
        d = _container_to_dict(c)
        assert d["a"] == 1
        assert d["b"] == "hello"
        assert isinstance(d["c"], dict)
        assert "_bytes" in d["c"]

    def test_nested_container(self):
        from construct import Container
        inner = Container(x=42)
        outer = Container(y=inner, z=[1, 2, 3])
        d = _container_to_dict(outer)
        assert d["y"]["x"] == 42
        assert d["z"] == [1, 2, 3]

    def test_bytes_conversion(self):
        from construct import Container
        c = Container(raw=b"\x00\x01\x02")
        d = _container_to_dict(c)
        assert d["raw"]["_bytes"] == "000102"


# ============================================================================
# Pre-defined templates
# ============================================================================


class TestPETemplates:
    """Tests for pre-defined PE header templates."""

    def test_pe_dos_header_parses(self):
        data = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x80)  # e_lfanew = 0x80
        result = _PE_DOS_HEADER.parse(data)
        assert result.e_magic == b"MZ"
        assert result.e_lfanew == 0x80

    def test_pe_file_header_parses(self):
        data = struct.pack("<HHIIIHH", 0x8664, 3, 0x5F3A1B2C, 0, 0, 0xF0, 0x2022)
        result = _PE_FILE_HEADER.parse(data)
        assert result.Machine == 0x8664
        assert result.NumberOfSections == 3
        assert result.TimeDateStamp == 0x5F3A1B2C

    def test_pe_section_header_parses(self):
        data = b".text\x00\x00\x00" + struct.pack(
            "<IIIIIIHHI", 0x1000, 0x1000, 0x400, 0x200, 0, 0, 0, 0, 0x60000020
        )
        result = _PE_SECTION_HEADER.parse(data)
        assert result.Name == b".text\x00\x00\x00"
        assert result.VirtualAddress == 0x1000
        assert result.Characteristics == 0x60000020


class TestELFTemplates:
    """Tests for pre-defined ELF header templates."""

    def test_elf32_header_parses(self):
        data = (
            b"\x7fELF"  # magic
            + b"\x01"   # 32-bit
            + b"\x01"   # little endian
            + b"\x01"   # version
            + b"\x00"   # OS/ABI
            + b"\x00"   # ABI version
            + b"\x00" * 7  # pad
            + struct.pack("<HHIIIIIHHHHHH", 2, 3, 1, 0x8048000, 0x34, 0, 0, 52, 32, 2, 40, 5, 3)
        )
        result = _ELF32_HEADER.parse(data)
        assert result.e_ident.EI_MAG == b"\x7fELF"
        assert result.e_type == 2
        assert result.e_entry == 0x8048000

    def test_elf64_header_parses(self):
        data = (
            b"\x7fELF"  # magic
            + b"\x02"   # 64-bit
            + b"\x01"   # little endian
            + b"\x01"   # version
            + b"\x00"   # OS/ABI
            + b"\x00"   # ABI version
            + b"\x00" * 7  # pad
            + struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0x400000, 0x40, 0, 0, 64, 56, 2, 64, 6, 3)
        )
        result = _ELF64_HEADER.parse(data)
        assert result.e_ident.EI_MAG == b"\x7fELF"
        assert result.e_type == 2
        assert result.e_entry == 0x400000

    def test_elf_magic_validation(self):
        with pytest.raises(Exception):
            _ELF64_HEADER.parse(b"NOTELF" + b"\x00" * 58)


class TestProtocolTemplates:
    """Tests for pre-defined protocol header templates."""

    def test_ipv4_parses(self):
        data = bytes([
            0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00,
            0x40, 0x06, 0x00, 0x00, 192, 168, 1, 1, 192, 168, 1, 2,
        ])
        result = _IPV4_HEADER.parse(data)
        assert result.version_ihl == 0x45
        assert result.ttl == 64
        assert result.protocol == 6
        assert result.src_ip == bytes([192, 168, 1, 1])
        assert result.dst_ip == bytes([192, 168, 1, 2])

    def test_tcp_parses(self):
        data = bytes([
            0x00, 0x50, 0x1f, 0x90,  # ports
            0x00, 0x00, 0x00, 0x01,  # seq
            0x00, 0x00, 0x00, 0x02,  # ack
            0x50, 0x02, 0x20, 0x00,  # offset/flags/window
            0x00, 0x00, 0x00, 0x00,  # checksum/urgent
        ])
        result = _TCP_HEADER.parse(data)
        assert result.src_port == 80
        assert result.dst_port == 8080

    def test_udp_parses(self):
        data = struct.pack(">HHHH", 53, 12345, 8, 0)
        result = _UDP_HEADER.parse(data)
        assert result.src_port == 53
        assert result.dst_port == 12345
        assert result.length == 8

    def test_protocol_registry(self):
        assert "ipv4" in _PROTOCOL_TEMPLATES
        assert "tcp" in _PROTOCOL_TEMPLATES
        assert "udp" in _PROTOCOL_TEMPLATES
        assert "icmp" in _PROTOCOL_TEMPLATES
        assert "ethernet" in _PROTOCOL_TEMPLATES
        assert "dns" in _PROTOCOL_TEMPLATES
        assert "tls_record" in _PROTOCOL_TEMPLATES


# ============================================================================
# Integration: parse real ELF fixture
# ============================================================================


class TestRealBinaryParsing:
    """Integration tests using the crackme03.elf fixture."""

    @pytest.fixture
    def elf_fixture(self):
        path = os.path.join(os.path.dirname(__file__), "crackme03.elf")
        if not os.path.exists(path):
            pytest.skip("crackme03.elf fixture not found")
        return path

    def test_parse_elf_fixture(self, elf_fixture):
        with open(elf_fixture, "rb") as f:
            data = f.read(64)
        result = _ELF64_HEADER.parse(data)
        assert result.e_ident.EI_MAG == b"\x7fELF"
        assert result.e_ident.EI_CLASS == 2  # ELFCLASS64
        assert result.e_type in (2, 3)  # ET_EXEC or ET_DYN

    def test_parse_elf_program_headers(self, elf_fixture):
        with open(elf_fixture, "rb") as f:
            data = f.read(64)
        hdr = _ELF64_HEADER.parse(data)
        if hdr.e_phnum == 0:
            pytest.skip("No program headers in fixture")
        with open(elf_fixture, "rb") as f:
            f.seek(hdr.e_phoff)
            for _ in range(min(hdr.e_phnum, 2)):
                phdr_data = f.read(56)
                phdr = _ELF64_PHDR.parse(phdr_data)
                assert phdr.p_type in (1, 2, 3, 4, 5, 6, 7)  # Valid PT_* types

    def test_parse_elf_section_headers(self, elf_fixture):
        with open(elf_fixture, "rb") as f:
            data = f.read(64)
        hdr = _ELF64_HEADER.parse(data)
        if hdr.e_shnum == 0:
            pytest.skip("No section headers in fixture")
        with open(elf_fixture, "rb") as f:
            f.seek(hdr.e_shoff)
            for _ in range(min(hdr.e_shnum, 2)):
                shdr_data = f.read(64)
                shdr = _ELF64_SHDR.parse(shdr_data)
                # sh_type should be a valid SHT_* value
                assert shdr.sh_type <= 19 or shdr.sh_type >= 0x60000000


# ============================================================================
# Build / round-trip
# ============================================================================


class TestBuildRoundTrip:
    def test_build_and_parse_round_trip(self):
        template = _compile_dsl('Struct("count" / Int32ul, "name" / CString("utf8"))')
        data = {"count": 42, "name": "hello"}
        built = template.build(data)
        parsed = template.parse(built)
        assert parsed.count == 42
        assert parsed.name == "hello"

    def test_build_array(self):
        template = _compile_dsl('Struct("count" / Int8ul, "items" / Array(this.count, Int16ul))')
        data = {"count": 3, "items": [10, 20, 30]}
        built = template.build(data)
        parsed = template.parse(built)
        assert list(parsed["items"]) == [10, 20, 30]
