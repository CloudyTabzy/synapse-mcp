"""Construct declarative binary format parsing for IDA Pro MCP.

Optional module: tools are only registered when construct is installed.
Install with: pip install construct

Provides pre-defined format parsers (PE, ELF, protocol headers), an IDA
struct-to-Construct bridge, a safe DSL evaluator for ad-hoc structures,
and heuristic structure guessing.
"""

from __future__ import annotations

import ast
import logging
import os
import struct
import threading
from typing import Annotated, Any, NotRequired, TypedDict

logger = logging.getLogger(__name__)

# ============================================================================
# Optional import guard
# ============================================================================

try:
    import construct as _construct_lib
    from construct import (
        # Core containers
        Struct, Array, Enum, FlagsEnum, If, Switch, Const, Padding,
        Tell, Seek, Pointer, Computed, Rebuild, Checksum, RawCopy,
        # Integers
        Byte, Int8ul, Int8ub, Int16ul, Int16ub, Int32ul, Int32ub,
        Int64ul, Int64ub, BytesInteger, BitsInteger,
        # Strings
        CString, PascalString, GreedyString, PaddedString,
        # Binary
        Bytes, GreedyBytes, BitStruct, Flag,
        # Context
        this, len_,
        # Containers / errors
        Container, StreamError, ConstError, FormatFieldError,
    )
    CONSTRUCT_AVAILABLE = True
except ImportError:
    CONSTRUCT_AVAILABLE = False
    _construct_lib = None
    logger.warning(
        "construct not installed — Construct tools unavailable. "
        "Run: ida-pro-mcp --install-deps construct"
    )

from .rpc import tool, unsafe
from .sync import idasync, IDAError
from .utils import parse_address, read_bytes_bss_safe, tool_error

# ============================================================================
# Safe DSL Evaluator
# ============================================================================

_ALLOWED_CONSTRUCT_NAMES = frozenset({
    "Struct", "Array", "Enum", "FlagsEnum", "If", "Switch", "Const", "Padding",
    "Tell", "Seek", "Pointer", "Computed", "Rebuild", "Checksum", "RawCopy",
    "Byte", "Int8ul", "Int8ub", "Int16ul", "Int16ub", "Int32ul", "Int32ub",
    "Int64ul", "Int64ub", "BytesInteger", "BitsInteger",
    "CString", "PascalString", "GreedyString", "PaddedString",
    "Bytes", "GreedyBytes", "BitStruct", "Flag",
    "this", "len_",
})

_MAX_DSL_NODES = 256


class DSLSecurityError(Exception):
    """Raised when a Construct DSL template contains disallowed constructs."""
    pass


def _count_ast_nodes(node: ast.AST) -> int:
    """Recursively count AST nodes."""
    return 1 + sum(_count_ast_nodes(child) for child in ast.iter_child_nodes(node))


def _validate_ast(node: ast.AST, source: str) -> None:
    """Walk an AST and verify every node is on the whitelist.

    Raises DSLSecurityError on any disallowed construct.
    """
    allowed_nodes = frozenset({
        ast.Module, ast.Expression, ast.Expr,
        ast.Call, ast.Name, ast.Attribute,
        ast.Constant, ast.Tuple, ast.List, ast.Dict, ast.Set,
        ast.BinOp, ast.UnaryOp, ast.BoolOp, ast.Compare,
        ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Mod, ast.Pow,
        ast.LShift, ast.RShift, ast.BitOr, ast.BitXor, ast.BitAnd,
        ast.FloorDiv, ast.Invert, ast.Not, ast.UAdd, ast.USub,
        ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE,
        ast.Is, ast.IsNot, ast.In, ast.NotIn,
        ast.Subscript, ast.Index,  # py3.8 compat
        ast.Slice, ast.Load, ast.Store, ast.Del,
        ast.keyword, ast.Starred, ast.JoinedStr, ast.FormattedValue,
    })

    if type(node) not in allowed_nodes:
        raise DSLSecurityError(
            f"Disallowed AST node {type(node).__name__!r} in Construct DSL. "
            f"Only Construct types and Python literals are permitted."
        )

    if isinstance(node, ast.Call):
        # Validate function name is allowed
        func_name = _get_call_name(node.func)
        if func_name and func_name not in _ALLOWED_CONSTRUCT_NAMES:
            raise DSLSecurityError(
                f"Disallowed function {func_name!r} in Construct DSL."
            )

    if isinstance(node, ast.Name):
        if node.id not in _ALLOWED_CONSTRUCT_NAMES and node.id not in {"True", "False", "None"}:
            raise DSLSecurityError(
                f"Disallowed name {node.id!r} in Construct DSL."
            )

    if isinstance(node, ast.Attribute):
        # Allow attribute access like this.count, len_(...)
        # but only on whitelisted base names
        base = _get_attribute_base_name(node)
        if base and base not in _ALLOWED_CONSTRUCT_NAMES:
            raise DSLSecurityError(
                f"Disallowed attribute base {base!r} in Construct DSL."
            )

    for child in ast.iter_child_nodes(node):
        _validate_ast(child, source)


def _get_call_name(node: ast.AST) -> str | None:
    """Extract the string name of a Call's function."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parts = []
        current: ast.AST = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))
    return None


def _get_attribute_base_name(node: ast.Attribute) -> str | None:
    """Get the root Name of an Attribute chain."""
    current: ast.AST = node
    while isinstance(current, ast.Attribute):
        current = current.value
    if isinstance(current, ast.Name):
        return current.id
    return None


def _compile_dsl(source: str) -> Any:
    """Safely compile a Construct DSL string into a Construct object.

    Returns the evaluated Construct object (e.g., a Struct).
    Raises DSLSecurityError if the template contains disallowed constructs.
    """
    source = source.strip()
    if not source:
        raise DSLSecurityError("Construct DSL template is empty.")

    try:
        tree = ast.parse(source, mode="eval")
    except SyntaxError as e:
        raise DSLSecurityError(f"Invalid Construct DSL syntax: {e}") from e

    node_count = _count_ast_nodes(tree)
    if node_count > _MAX_DSL_NODES:
        raise DSLSecurityError(
            f"Construct DSL too complex ({node_count} nodes > {_MAX_DSL_NODES} max)."
        )

    _validate_ast(tree, source)

    # Build restricted namespace with only Construct types
    namespace: dict[str, Any] = {}
    for name in _ALLOWED_CONSTRUCT_NAMES:
        try:
            namespace[name] = globals()[name]
        except KeyError:
            pass

    # Add safe builtins
    namespace["True"] = True
    namespace["False"] = False
    namespace["None"] = None

    compiled = compile(tree, filename="<construct_dsl>", mode="eval")
    return eval(compiled, {"__builtins__": {}}, namespace)


# ============================================================================
# Pre-defined Templates
# ============================================================================

# PE templates ----------------------------------------------------------------

_PE_DOS_HEADER = Struct(
    "e_magic" / Const(b"MZ"),
    "e_cblp" / Int16ul,
    "e_cp" / Int16ul,
    "e_crlc" / Int16ul,
    "e_cparhdr" / Int16ul,
    "e_minalloc" / Int16ul,
    "e_maxalloc" / Int16ul,
    "e_ss" / Int16ul,
    "e_sp" / Int16ul,
    "e_csum" / Int16ul,
    "e_ip" / Int16ul,
    "e_cs" / Int16ul,
    "e_lfarlc" / Int16ul,
    "e_ovno" / Int16ul,
    "e_res" / Bytes(8),
    "e_oemid" / Int16ul,
    "e_oeminfo" / Int16ul,
    "e_res2" / Bytes(20),
    "e_lfanew" / Int32ul,
)

_PE_FILE_HEADER = Struct(
    "Machine" / Int16ul,
    "NumberOfSections" / Int16ul,
    "TimeDateStamp" / Int32ul,
    "PointerToSymbolTable" / Int32ul,
    "NumberOfSymbols" / Int32ul,
    "SizeOfOptionalHeader" / Int16ul,
    "Characteristics" / Int16ul,
)

_PE_DATA_DIRECTORY = Struct(
    "VirtualAddress" / Int32ul,
    "Size" / Int32ul,
)

_PE_OPTIONAL_HEADER32 = Struct(
    "Magic" / Int16ul,
    "MajorLinkerVersion" / Byte,
    "MinorLinkerVersion" / Byte,
    "SizeOfCode" / Int32ul,
    "SizeOfInitializedData" / Int32ul,
    "SizeOfUninitializedData" / Int32ul,
    "AddressOfEntryPoint" / Int32ul,
    "BaseOfCode" / Int32ul,
    "BaseOfData" / Int32ul,
    "ImageBase" / Int32ul,
    "SectionAlignment" / Int32ul,
    "FileAlignment" / Int32ul,
    "MajorOperatingSystemVersion" / Int16ul,
    "MinorOperatingSystemVersion" / Int16ul,
    "MajorImageVersion" / Int16ul,
    "MinorImageVersion" / Int16ul,
    "MajorSubsystemVersion" / Int16ul,
    "MinorSubsystemVersion" / Int16ul,
    "Win32VersionValue" / Int32ul,
    "SizeOfImage" / Int32ul,
    "SizeOfHeaders" / Int32ul,
    "CheckSum" / Int32ul,
    "Subsystem" / Int16ul,
    "DllCharacteristics" / Int16ul,
    "SizeOfStackReserve" / Int32ul,
    "SizeOfStackCommit" / Int32ul,
    "SizeOfHeapReserve" / Int32ul,
    "SizeOfHeapCommit" / Int32ul,
    "LoaderFlags" / Int32ul,
    "NumberOfRvaAndSizes" / Int32ul,
    "DataDirectory" / Array(16, _PE_DATA_DIRECTORY),
)

_PE_OPTIONAL_HEADER64 = Struct(
    "Magic" / Int16ul,
    "MajorLinkerVersion" / Byte,
    "MinorLinkerVersion" / Byte,
    "SizeOfCode" / Int32ul,
    "SizeOfInitializedData" / Int32ul,
    "SizeOfUninitializedData" / Int32ul,
    "AddressOfEntryPoint" / Int32ul,
    "BaseOfCode" / Int32ul,
    "ImageBase" / Int64ul,
    "SectionAlignment" / Int32ul,
    "FileAlignment" / Int32ul,
    "MajorOperatingSystemVersion" / Int16ul,
    "MinorOperatingSystemVersion" / Int16ul,
    "MajorImageVersion" / Int16ul,
    "MinorImageVersion" / Int16ul,
    "MajorSubsystemVersion" / Int16ul,
    "MinorSubsystemVersion" / Int16ul,
    "Win32VersionValue" / Int32ul,
    "SizeOfImage" / Int32ul,
    "SizeOfHeaders" / Int32ul,
    "CheckSum" / Int32ul,
    "Subsystem" / Int16ul,
    "DllCharacteristics" / Int16ul,
    "SizeOfStackReserve" / Int64ul,
    "SizeOfStackCommit" / Int64ul,
    "SizeOfHeapReserve" / Int64ul,
    "SizeOfHeapCommit" / Int64ul,
    "LoaderFlags" / Int32ul,
    "NumberOfRvaAndSizes" / Int32ul,
    "DataDirectory" / Array(16, _PE_DATA_DIRECTORY),
)

_PE_SECTION_HEADER = Struct(
    "Name" / Bytes(8),
    "VirtualSize" / Int32ul,
    "VirtualAddress" / Int32ul,
    "SizeOfRawData" / Int32ul,
    "PointerToRawData" / Int32ul,
    "PointerToRelocations" / Int32ul,
    "PointerToLinenumbers" / Int32ul,
    "NumberOfRelocations" / Int16ul,
    "NumberOfLinenumbers" / Int16ul,
    "Characteristics" / Int32ul,
)


# ELF templates ---------------------------------------------------------------

_ELF_IDENT = Struct(
    "EI_MAG" / Const(b"\x7fELF"),
    "EI_CLASS" / Byte,
    "EI_DATA" / Byte,
    "EI_VERSION" / Byte,
    "EI_OSABI" / Byte,
    "EI_ABIVERSION" / Byte,
    "EI_PAD" / Bytes(7),
)

_ELF32_HEADER = Struct(
    "e_ident" / _ELF_IDENT,
    "e_type" / Int16ul,
    "e_machine" / Int16ul,
    "e_version" / Int32ul,
    "e_entry" / Int32ul,
    "e_phoff" / Int32ul,
    "e_shoff" / Int32ul,
    "e_flags" / Int32ul,
    "e_ehsize" / Int16ul,
    "e_phentsize" / Int16ul,
    "e_phnum" / Int16ul,
    "e_shentsize" / Int16ul,
    "e_shnum" / Int16ul,
    "e_shstrndx" / Int16ul,
)

_ELF64_HEADER = Struct(
    "e_ident" / _ELF_IDENT,
    "e_type" / Int16ul,
    "e_machine" / Int16ul,
    "e_version" / Int32ul,
    "e_entry" / Int64ul,
    "e_phoff" / Int64ul,
    "e_shoff" / Int64ul,
    "e_flags" / Int32ul,
    "e_ehsize" / Int16ul,
    "e_phentsize" / Int16ul,
    "e_phnum" / Int16ul,
    "e_shentsize" / Int16ul,
    "e_shnum" / Int16ul,
    "e_shstrndx" / Int16ul,
)

_ELF32_PHDR = Struct(
    "p_type" / Int32ul,
    "p_offset" / Int32ul,
    "p_vaddr" / Int32ul,
    "p_paddr" / Int32ul,
    "p_filesz" / Int32ul,
    "p_memsz" / Int32ul,
    "p_flags" / Int32ul,
    "p_align" / Int32ul,
)

_ELF64_PHDR = Struct(
    "p_type" / Int32ul,
    "p_flags" / Int32ul,
    "p_offset" / Int64ul,
    "p_vaddr" / Int64ul,
    "p_paddr" / Int64ul,
    "p_filesz" / Int64ul,
    "p_memsz" / Int64ul,
    "p_align" / Int64ul,
)

_ELF32_SHDR = Struct(
    "sh_name" / Int32ul,
    "sh_type" / Int32ul,
    "sh_flags" / Int32ul,
    "sh_addr" / Int32ul,
    "sh_offset" / Int32ul,
    "sh_size" / Int32ul,
    "sh_link" / Int32ul,
    "sh_info" / Int32ul,
    "sh_addralign" / Int32ul,
    "sh_entsize" / Int32ul,
)

_ELF64_SHDR = Struct(
    "sh_name" / Int32ul,
    "sh_type" / Int32ul,
    "sh_flags" / Int64ul,
    "sh_addr" / Int64ul,
    "sh_offset" / Int64ul,
    "sh_size" / Int64ul,
    "sh_link" / Int32ul,
    "sh_info" / Int32ul,
    "sh_addralign" / Int64ul,
    "sh_entsize" / Int64ul,
)


# Protocol templates ----------------------------------------------------------

_IPV4_HEADER = Struct(
    "version_ihl" / Byte,
    "tos" / Byte,
    "total_length" / Int16ub,
    "identification" / Int16ub,
    "flags_fragment" / Int16ub,
    "ttl" / Byte,
    "protocol" / Byte,
    "header_checksum" / Int16ub,
    "src_ip" / Bytes(4),
    "dst_ip" / Bytes(4),
)

_TCP_HEADER = Struct(
    "src_port" / Int16ub,
    "dst_port" / Int16ub,
    "seq_number" / Int32ub,
    "ack_number" / Int32ub,
    "data_offset_flags" / Int16ub,
    "window_size" / Int16ub,
    "checksum" / Int16ub,
    "urgent_pointer" / Int16ub,
)

_UDP_HEADER = Struct(
    "src_port" / Int16ub,
    "dst_port" / Int16ub,
    "length" / Int16ub,
    "checksum" / Int16ub,
)

_ICMP_HEADER = Struct(
    "type" / Byte,
    "code" / Byte,
    "checksum" / Int16ub,
    "rest" / Bytes(4),
)

_ETHERNET_HEADER = Struct(
    "dst_mac" / Bytes(6),
    "src_mac" / Bytes(6),
    "ethertype" / Int16ub,
)

_DNS_HEADER = Struct(
    "transaction_id" / Int16ub,
    "flags" / Int16ub,
    "questions" / Int16ub,
    "answer_rrs" / Int16ub,
    "authority_rrs" / Int16ub,
    "additional_rrs" / Int16ub,
)

_TLS_RECORD = Struct(
    "content_type" / Byte,
    "version" / Int16ub,
    "length" / Int16ub,
)


# Template registry -----------------------------------------------------------

_PROTOCOL_TEMPLATES: dict[str, Any] = {
    "ipv4": _IPV4_HEADER,
    "tcp": _TCP_HEADER,
    "udp": _UDP_HEADER,
    "icmp": _ICMP_HEADER,
    "ethernet": _ETHERNET_HEADER,
    "dns": _DNS_HEADER,
    "tls_record": _TLS_RECORD,
}


# Compile cache for DSL templates ---------------------------------------------

_dsl_compile_cache: dict[str, Any] = {}
_dsl_compile_lock = threading.Lock()


def _get_compiled_template(source: str) -> Any:
    """Return a compiled Construct template, using cache if available."""
    with _dsl_compile_lock:
        if source in _dsl_compile_cache:
            return _dsl_compile_cache[source]
    obj = _compile_dsl(source)
    with _dsl_compile_lock:
        _dsl_compile_cache[source] = obj
    return obj


# ============================================================================
# Helpers
# ============================================================================

def _container_to_dict(obj: Any) -> Any:
    """Recursively convert a Construct Container to a plain JSON-serializable dict."""
    if isinstance(obj, Container):
        result: dict[str, Any] = {}
        for key, value in obj.items():
            if key.startswith("_"):
                continue
            result[key] = _container_to_dict(value)
        return result
    if isinstance(obj, (list, tuple)):
        return [_container_to_dict(item) for item in obj]
    if isinstance(obj, bytes):
        return {"_bytes": obj.hex(), "_ascii": _bytes_to_ascii_preview(obj)}
    return obj


def _bytes_to_ascii_preview(data: bytes, max_len: int = 64) -> str:
    """Return an ASCII preview of bytes, replacing non-printable with '.'."""
    preview = data[:max_len]
    chars = []
    for b in preview:
        if 32 <= b < 127:
            chars.append(chr(b))
        else:
            chars.append(".")
    return "".join(chars)


def _get_input_file_path() -> str | None:
    """Return the path to the original input file for the current IDB."""
    try:
        import ida_nalt
        path = ida_nalt.get_input_file_path()
        if path and os.path.exists(path):
            return path
    except Exception:
        pass
    return None


def _read_file_bytes(path: str, offset: int, size: int) -> bytes:
    """Read bytes from a file at a given offset."""
    with open(path, "rb") as f:
        f.seek(offset)
        return f.read(size)


def _parse_from_source(
    template: Any,
    address: str = "",
    file_path: str = "",
    file_offset: int = 0,
    size_hint: int = 4096,
) -> tuple[dict, int]:
    """Parse bytes from either IDA memory or a file using a Construct template.

    Returns (parsed_dict, bytes_consumed).
    Raises ValueError if neither address nor file_path is provided.
    """
    if address:
        ea = parse_address(address)
        raw = read_bytes_bss_safe(ea, size_hint)
        result = template.parse(raw)
        return _container_to_dict(result), len(raw)
    elif file_path:
        raw = _read_file_bytes(file_path, file_offset, size_hint)
        result = template.parse(raw)
        return _container_to_dict(result), len(raw)
    else:
        raise ValueError("Either address or file_path must be provided.")


def _get_pe_optional_header_type(pe_file_path: str | None = None) -> Any:
    """Peek at a PE file to determine whether it uses 32- or 64-bit optional header."""
    try:
        path = pe_file_path or _get_input_file_path()
        if not path:
            return _PE_OPTIONAL_HEADER32
        with open(path, "rb") as f:
            f.seek(0x3C)  # e_lfanew offset in DOS header
            lfanew = struct.unpack("<I", f.read(4))[0]
            f.seek(lfanew + 24)  # Offset to OptionalHeader magic
            magic = struct.unpack("<H", f.read(2))[0]
            if magic == 0x20B:
                return _PE_OPTIONAL_HEADER64
    except Exception:
        pass
    return _PE_OPTIONAL_HEADER32


# ============================================================================
# TypedDict result types
# ============================================================================

class ConstructStatusResult(TypedDict):
    available: bool
    version: str
    templates_loaded: int
    install_hint: NotRequired[str]


class ConstructParseResult(TypedDict):
    ok: bool
    parsed: NotRequired[dict[str, Any]]
    bytes_consumed: NotRequired[int]
    template: NotRequired[str]
    error: NotRequired[str]


class ConstructBuildResult(TypedDict):
    ok: bool
    hex: NotRequired[str]
    size: NotRequired[int]
    patched_at: NotRequired[str]
    error: NotRequired[str]


class ConstructParseIdaStructResult(TypedDict):
    ok: bool
    struct_name: NotRequired[str]
    address: NotRequired[str]
    parsed: NotRequired[list[dict[str, Any]]]
    construct_template: NotRequired[str]
    error: NotRequired[str]


class ConstructGuessResult(TypedDict):
    ok: bool
    guessed_template: NotRequired[str]
    fields: NotRequired[list[dict[str, Any]]]
    note: NotRequired[str]
    error: NotRequired[str]


class ConstructBatchParseResult(TypedDict):
    ok: bool
    count: NotRequired[int]
    elements: NotRequired[list[dict[str, Any]]]
    total_bytes: NotRequired[int]
    error: NotRequired[str]


class ConstructProtocolResult(TypedDict):
    ok: bool
    protocol: NotRequired[str]
    parsed: NotRequired[dict[str, Any]]
    header_length: NotRequired[int]
    error: NotRequired[str]


class ConstructScanResult(TypedDict):
    ok: bool
    matches: NotRequired[list[dict[str, Any]]]
    scan_attempts: NotRequired[int]
    region_size: NotRequired[int]
    error: NotRequired[str]


# ============================================================================
# Tool 1 — construct_status (always available)
# ============================================================================

@tool
@idasync
def construct_status() -> ConstructStatusResult:
    """Report whether the construct library is installed and available.

    Always returns a result — safe to call before other construct tools
    to check availability. When available=false, install construct and restart IDA.
    """
    version = "unknown"
    templates_loaded = 0

    if CONSTRUCT_AVAILABLE:
        version = getattr(_construct_lib, "__version__", "installed")
        templates_loaded = len(_PROTOCOL_TEMPLATES)
        return {
            "available": True,
            "version": str(version),
            "templates_loaded": templates_loaded,
        }

    return {
        "available": False,
        "version": version,
        "templates_loaded": 0,
        "install_hint": "pip install construct  (then restart IDA)",
    }


# ============================================================================
# Tools 2-3 — PE / ELF header parsers
# ============================================================================

@tool
@idasync
def construct_parse_pe_headers(
    file_path: Annotated[str, "Path to PE file; omit to use the currently loaded binary"] = "",
    include_sections: Annotated[bool, "Include section table headers"] = True,
    include_data_dirs: Annotated[bool, "Include data directory entries"] = True,
) -> ConstructParseResult:
    """Parse a PE file's headers using Construct and return structured header data.

    Reads the DOS header, NT headers (signature + file header + optional header),
    and optionally the section table and data directories. The optional header
    type (32-bit or 64-bit) is auto-detected from the PE magic.
    """
    if not CONSTRUCT_AVAILABLE:
        return {"ok": False, "error": "construct not installed. Run: pip install construct"}

    try:
        path = file_path or _get_input_file_path()
        if not path:
            return {"ok": False, "error": "No file_path provided and no binary is currently loaded in IDA."}

        with open(path, "rb") as f:
            dos_raw = f.read(64)
            dos = _PE_DOS_HEADER.parse(dos_raw)

            f.seek(dos.e_lfanew)
            sig = f.read(4)
            if sig != b"PE\x00\x00":
                return {"ok": False, "error": f"Invalid PE signature at e_lfanew={dos.e_lfanew}: {sig!r}"}

            file_hdr_raw = f.read(20)
            file_hdr = _PE_FILE_HEADER.parse(file_hdr_raw)

            opt_header_type = _get_pe_optional_header_type(path)
            opt_hdr_size = file_hdr.SizeOfOptionalHeader
            opt_hdr_raw = f.read(opt_hdr_size)
            opt_hdr = opt_header_type.parse(opt_hdr_raw)

        result: dict[str, Any] = {
            "dos_header": _container_to_dict(dos),
            "file_header": _container_to_dict(file_hdr),
            "optional_header": _container_to_dict(opt_hdr),
        }

        if include_data_dirs:
            result["data_directories"] = result["optional_header"].pop("DataDirectory", [])

        if include_sections:
            with open(path, "rb") as f:
                f.seek(dos.e_lfanew + 24 + opt_hdr_size)  # After optional header
                sections = []
                for _ in range(file_hdr.NumberOfSections):
                    sec_raw = f.read(40)
                    sec = _PE_SECTION_HEADER.parse(sec_raw)
                    sec_dict = _container_to_dict(sec)
                    # Decode section name bytes
                    name_bytes = bytes.fromhex(sec_dict["Name"]["_bytes"]) if isinstance(sec_dict.get("Name"), dict) else sec_raw[:8]
                    sec_dict["Name_decoded"] = name_bytes.rstrip(b"\x00").decode("ascii", errors="replace")
                    sections.append(sec_dict)
                result["sections"] = sections

        return {
            "ok": True,
            "parsed": result,
            "bytes_consumed": dos.e_lfanew + 24 + opt_hdr_size + (file_hdr.NumberOfSections * 40),
            "template": "PE_HEADER",
        }

    except Exception as e:
        logger.exception("construct_parse_pe_headers failed")
        return {**tool_error(e), "ok": False}


@tool
@idasync
def construct_parse_elf_headers(
    file_path: Annotated[str, "Path to ELF file; omit to use the currently loaded binary"] = "",
    include_phdrs: Annotated[bool, "Include program headers"] = True,
    include_shdrs: Annotated[bool, "Include section headers"] = True,
) -> ConstructParseResult:
    """Parse an ELF file's headers using Construct.

    Auto-detects 32/64-bit and endianness from the ELF e_ident magic.
    Returns the ELF header and optionally the program header table
    and section header table.
    """
    if not CONSTRUCT_AVAILABLE:
        return {"ok": False, "error": "construct not installed. Run: pip install construct"}

    try:
        path = file_path or _get_input_file_path()
        if not path:
            return {"ok": False, "error": "No file_path provided and no binary is currently loaded in IDA."}

        with open(path, "rb") as f:
            ident_raw = f.read(16)
            if ident_raw[:4] != b"\x7fELF":
                return {"ok": False, "error": f"Invalid ELF magic: {ident_raw[:4]!r}"}

            ei_class = ident_raw[4]
            ei_data = ident_raw[5]

            is_64 = ei_class == 2
            is_be = ei_data == 2

            # We have pre-defined little-endian templates; for big-endian we fall back
            if is_be:
                return {"ok": False, "error": "Big-endian ELF not yet supported by pre-defined templates. Use construct_parse_custom_struct with a custom template."}

            f.seek(0)
            if is_64:
                elf_hdr = _ELF64_HEADER.parse(f.read(64))
                phdr_type = _ELF64_PHDR
                shdr_type = _ELF64_SHDR
                phdr_size = 56
                shdr_size = 64
            else:
                elf_hdr = _ELF32_HEADER.parse(f.read(52))
                phdr_type = _ELF32_PHDR
                shdr_type = _ELF32_SHDR
                phdr_size = 32
                shdr_size = 40

            result: dict[str, Any] = {
                "elf_header": _container_to_dict(elf_hdr),
                "is_64bit": is_64,
                "is_little_endian": not is_be,
            }

            if include_phdrs and elf_hdr.e_phnum > 0:
                f.seek(elf_hdr.e_phoff)
                phdrs = []
                for _ in range(elf_hdr.e_phnum):
                    phdr = phdr_type.parse(f.read(phdr_size))
                    phdrs.append(_container_to_dict(phdr))
                result["program_headers"] = phdrs

            if include_shdrs and elf_hdr.e_shnum > 0:
                f.seek(elf_hdr.e_shoff)
                shdrs = []
                for _ in range(elf_hdr.e_shnum):
                    shdr = shdr_type.parse(f.read(shdr_size))
                    shdrs.append(_container_to_dict(shdr))
                result["section_headers"] = shdrs

            total_size = max(
                (elf_hdr.e_phoff + elf_hdr.e_phnum * phdr_size) if include_phdrs else 0,
                (elf_hdr.e_shoff + elf_hdr.e_shnum * shdr_size) if include_shdrs else 0,
                64 if is_64 else 52,
            )

        return {
            "ok": True,
            "parsed": result,
            "bytes_consumed": total_size,
            "template": "ELF_HEADER",
        }

    except Exception as e:
        logger.exception("construct_parse_elf_headers failed")
        return {**tool_error(e), "ok": False}


# ============================================================================
# Tools 4-5 — Custom struct parse / build
# ============================================================================

@tool
@idasync
def construct_parse_custom_struct(
    construct_template: Annotated[
        str,
        'Construct DSL string. Example: \'Struct("magic" / Const(b"MZ"), "count" / Int32ul)\''
    ],
    address: Annotated[str, "IDA address (hex or symbol) to parse from"] = "",
    file_path: Annotated[str, "File path to parse from (mutually exclusive with address)"] = "",
    file_offset: Annotated[int, "Byte offset in file (required when file_path is used)"] = 0,
    size_hint: Annotated[int, "Max bytes to read (safety cap, default 4096)"] = 4096,
) -> ConstructParseResult:
    """Parse binary data at an IDA address or file offset using a user-provided Construct template.

    The template is evaluated in a restricted namespace containing only Construct types.
    Use this to parse arbitrary data structures without writing Python scripts.
    """
    if not CONSTRUCT_AVAILABLE:
        return {"ok": False, "error": "construct not installed. Run: pip install construct"}

    try:
        template = _get_compiled_template(construct_template)
        parsed, consumed = _parse_from_source(
            template, address=address, file_path=file_path,
            file_offset=file_offset, size_hint=size_hint,
        )
        return {
            "ok": True,
            "parsed": parsed,
            "bytes_consumed": consumed,
            "template": construct_template,
        }
    except DSLSecurityError as e:
        return {"ok": False, "error": f"DSL security error: {e}"}
    except (StreamError, ConstError, FormatFieldError) as e:
        return {"ok": False, "error": f"Parse error — template may not match data: {e}"}
    except Exception as e:
        logger.exception("construct_parse_custom_struct failed")
        return {**tool_error(e), "ok": False}


@tool
@idasync
def construct_build_struct(
    construct_template: Annotated[str, "Construct DSL string for building"],
    data: Annotated[dict, "Python dict matching the template structure"],
    output_address: Annotated[
        str,
        "IDA address to patch (requires --unsafe; mutually exclusive with return_only)"
    ] = "",
    return_only: Annotated[bool, "Return hex bytes without writing to IDA"] = True,
) -> ConstructBuildResult:
    """Build binary data from a dict using a Construct template.

    By default returns the hex-encoded bytes without modifying the database.
    Set return_only=false and provide output_address to patch the IDA database
    (requires the --unsafe flag).
    """
    if not CONSTRUCT_AVAILABLE:
        return {"ok": False, "error": "construct not installed. Run: pip install construct"}

    try:
        template = _get_compiled_template(construct_template)
        built: bytes = template.build(data)
        hex_str = built.hex()

        if not return_only and output_address:
            ea = parse_address(output_address)
            import ida_bytes
            ida_bytes.patch_bytes(ea, built)
            return {
                "ok": True,
                "patched_at": hex(ea),
                "size": len(built),
            }

        return {
            "ok": True,
            "hex": hex_str,
            "size": len(built),
        }

    except DSLSecurityError as e:
        return {"ok": False, "error": f"DSL security error: {e}"}
    except Exception as e:
        logger.exception("construct_build_struct failed")
        return {**tool_error(e), "ok": False}


# ============================================================================
# Tool 6 — IDA struct-to-Construct bridge
# ============================================================================

# Mapping from IDA base type codes to Construct integer types (little-endian default)
_BTF_TO_CONSTRUCT_LE: dict[int, Any] = {
    0x00: Int8ul,   # int8  (BTF_INT8)
    0x01: Int16ul,  # int16
    0x02: Int32ul,  # int32
    0x03: Int64ul,  # int64
    0x04: BytesInteger(16),  # int128
    0x10: Byte,     # uint8
    0x11: Int16ul,  # uint16
    0x12: Int32ul,  # uint32
    0x13: Int64ul,  # uint64
    0x14: BytesInteger(16),  # uint128
}


def _ida_type_to_construct(
    tif: Any,
    ptr_size: int,
    visited: set[int] | None = None,
) -> Any:
    """Recursively convert an IDA tinfo_t to a Construct type.

    Args:
        tif: ida_typeinf.tinfo_t instance
        ptr_size: Size of pointers in bytes (4 or 8)
        visited: Set of type ordinals already visited (prevents infinite recursion)

    Returns:
        A Construct type object, or None if unsupported.
    """
    if visited is None:
        visited = set()

    import ida_typeinf

    # Pointer
    if tif.is_ptr():
        return BytesInteger(ptr_size)

    # Array
    if tif.is_array():
        elem_tif = ida_typeinf.tinfo_t()
        if tif.get_array_element(elem_tif):
            nelems = tif.get_array_nelems()
            elem_ct = _ida_type_to_construct(elem_tif, ptr_size, visited)
            if elem_ct is not None and nelems > 0:
                return Array(nelems, elem_ct)
        return GreedyBytes

    # Struct / union
    if tif.is_struct() or tif.is_union():
        udt_data = ida_typeinf.udt_type_data_t()
        if not tif.get_udt_details(udt_data):
            return None

        fields = []
        for member in udt_data:
            member_name = member.name
            member_tif = ida_typeinf.tinfo_t()
            if not tif.get_udm_by_tid(member_tif, member.tid):
                member_tif = member.type
            member_ct = _ida_type_to_construct(member_tif, ptr_size, visited)
            if member_ct is None:
                # Fallback: emit raw bytes of the member's size
                member_size = member.size // 8  # bits to bytes
                member_ct = Bytes(max(member_size, 1))
            fields.append(member_name / member_ct)

        return Struct(*fields) if fields else Bytes(1)

    # Enum
    if tif.is_enum():
        enum_data = ida_typeinf.enum_type_data_t()
        if tif.get_enum_details(enum_data):
            enum_map: dict[str, int] = {}
            for member in enum_data:
                enum_map[member.name] = member.value
            return Enum(Int32ul, enum_map) if enum_map else Int32ul
        return Int32ul

    # Scalar / typedef
    base_type = tif.get_base_type()
    if base_type in _BTF_TO_CONSTRUCT_LE:
        return _BTF_TO_CONSTRUCT_LE[base_type]

    # Float
    if tif.is_float():
        size = tif.get_size()
        if size == 4:
            return Bytes(4)  # Construct has no native float parser
        elif size == 8:
            return Bytes(8)
        elif size == 10:
            return Bytes(10)

    # Final fallback: raw bytes of the type's size
    size = tif.get_size()
    if size > 0:
        return Bytes(size)
    return Bytes(1)


def _ida_struct_to_construct(struct_name: str, ptr_size: int) -> Any | None:
    """Look up a named struct in IDA's type library and convert it to Construct."""
    try:
        import ida_typeinf
        tif = ida_typeinf.tinfo_t()
        # Try struct first
        if tif.get_named_type(None, struct_name, ida_typeinf.BTF_STRUCT):
            return _ida_type_to_construct(tif, ptr_size)
        # Try typedef
        if tif.get_named_type(None, struct_name, ida_typeinf.BTF_TYPEDEF):
            # Unwrap typedef
            inner = ida_typeinf.tinfo_t()
            if tif.get_base_type() == ida_typeinf.BTF_TYPEDEF:
                tif.get_base(inner)
                return _ida_type_to_construct(inner, ptr_size)
            return _ida_type_to_construct(tif, ptr_size)
        # Try union
        if tif.get_named_type(None, struct_name, ida_typeinf.BTF_UNION):
            return _ida_type_to_construct(tif, ptr_size)
    except Exception:
        logger.exception("_ida_struct_to_construct failed for %r", struct_name)
    return None


@tool
@idasync
def construct_parse_ida_struct(
    struct_name: Annotated[
        str,
        "Name of an existing IDA struct/typedef (e.g. 'IMAGE_DOS_HEADER', 'sockaddr_in')"
    ],
    address: Annotated[str, "IDA address to parse at (hex or symbol)"],
    count: Annotated[int, "Number of consecutive struct instances to parse (default 1)"] = 1,
) -> ConstructParseIdaStructResult:
    """Parse data at an IDA address using an existing struct definition from the IDB's type library.

    Automatically converts the IDA struct to a Construct template and parses the bytes.
    No Construct DSL knowledge required — just the struct name from the Types window.
    """
    if not CONSTRUCT_AVAILABLE:
        return {"ok": False, "error": "construct not installed. Run: pip install construct"}

    try:
        from . import compat
        ptr_size = 8 if compat.inf_is_64bit() else 4

        template = _ida_struct_to_construct(struct_name, ptr_size)
        if template is None:
            return {
                "ok": False,
                "error": f"Struct {struct_name!r} not found in IDA's type library. "
                         "Check the Types window (Shift+F9) for the exact name.",
            }

        ea = parse_address(address)
        parsed_instances = []
        total_size = 0

        for i in range(max(count, 1)):
            offset = ea + total_size
            # Read a reasonable chunk; Construct will only consume what it needs
            raw = read_bytes_bss_safe(offset, 4096)
            try:
                result = template.parse(raw)
                parsed_instances.append({
                    "index": i,
                    "address": hex(offset),
                    "parsed": _container_to_dict(result),
                })
                total_size += template.sizeof(result)
            except Exception as e:
                parsed_instances.append({
                    "index": i,
                    "address": hex(offset),
                    "error": str(e),
                })
                break

        # Try to stringify the template for the response
        template_str = str(template)

        return {
            "ok": True,
            "struct_name": struct_name,
            "address": hex(ea),
            "parsed": parsed_instances,
            "construct_template": template_str,
        }

    except Exception as e:
        logger.exception("construct_parse_ida_struct failed")
        return {**tool_error(e), "ok": False}


# ============================================================================
# Tool 7 — Heuristic struct guesser
# ============================================================================

_PRINTABLE = set(range(32, 127))


def _is_printable_ascii(data: bytes) -> bool:
    return all(b in _PRINTABLE for b in data)


def _guess_field_at_offset(data: bytes, offset: int, ptr_size: int, image_base: int) -> dict[str, Any] | None:
    """Heuristically guess what field exists at a given offset within a byte buffer.

    Returns a dict with offset, type, confidence, value_preview, or None if unknown.
    """
    remaining = len(data) - offset
    if remaining <= 0:
        return None

    # Check for null-terminated string
    if data[offset] != 0:
        end = offset
        while end < len(data) and data[end] != 0:
            end += 1
        if end > offset and end < len(data) and (end - offset) >= 2:
            candidate = data[offset:end]
            if _is_printable_ascii(candidate) and (end - offset) <= 256:
                return {
                    "offset": offset,
                    "type": "CString",
                    "confidence": 0.85,
                    "value_preview": candidate.decode("ascii", errors="replace")[:32],
                    "size": end - offset + 1,
                }

    # Check for Pascal string (length-prefixed)
    if remaining > 1:
        plen = data[offset]
        if 1 <= plen <= 64 and offset + 1 + plen <= len(data):
            candidate = data[offset + 1:offset + 1 + plen]
            if _is_printable_ascii(candidate):
                return {
                    "offset": offset,
                    "type": "PascalString",
                    "confidence": 0.75,
                    "value_preview": candidate.decode("ascii", errors="replace")[:32],
                    "size": 1 + plen,
                }

    # Check for pointer candidate (aligned)
    if remaining >= ptr_size and offset % ptr_size == 0:
        if ptr_size == 4:
            val = struct.unpack("<I", data[offset:offset + 4])[0]
        else:
            val = struct.unpack("<Q", data[offset:offset + 8])[0]
        if val != 0:
            # Check if it looks like a valid pointer
            is_near_base = abs(val - image_base) < 0x10000000 if image_base else False
            is_aligned = val % ptr_size == 0
            is_reasonable = 0x10000 <= val <= 0x7FFFFFFFFFFF
            if is_near_base or (is_aligned and is_reasonable):
                return {
                    "offset": offset,
                    "type": f"Pointer{ptr_size * 8}",
                    "confidence": 0.8 if is_near_base else 0.6,
                    "value_preview": hex(val),
                    "size": ptr_size,
                }

    # Check for repeated zero padding
    if data[offset] == 0:
        end = offset
        while end < len(data) and data[end] == 0:
            end += 1
        pad_len = end - offset
        if pad_len >= 4:
            return {
                "offset": offset,
                "type": "Padding",
                "confidence": 0.9,
                "value_preview": f"{pad_len} zero bytes",
                "size": pad_len,
            }

    # Default: single byte / unknown
    return {
        "offset": offset,
        "type": "Byte",
        "confidence": 0.3,
        "value_preview": hex(data[offset]),
        "size": 1,
    }


@tool
@idasync
def construct_guess_struct(
    address: Annotated[str, "IDA address to analyze (hex or symbol)"],
    size: Annotated[int, "Number of bytes to analyze (default 256, max 4096)"] = 256,
    image_base: Annotated[str, "Optional image base for pointer validation (auto-detected if omitted)"] = "",
) -> ConstructGuessResult:
    """Heuristically guess the structure layout of bytes at an IDA address.

    Identifies strings, pointers, arrays, and repeated patterns. Returns a
    suggested Construct template plus confidence scores for each field guess.
    This is a heuristic — always validate guesses before relying on them.
    """
    if not CONSTRUCT_AVAILABLE:
        return {"ok": False, "error": "construct not installed. Run: pip install construct"}

    try:
        ea = parse_address(address)
        size = min(max(size, 1), 4096)
        data = read_bytes_bss_safe(ea, size)

        base = parse_address(image_base) if image_base else 0
        if base == 0:
            try:
                import idaapi
                base = idaapi.get_imagebase()
            except Exception:
                pass

        from . import compat
        ptr_size = 8 if compat.inf_is_64bit() else 4

        fields = []
        offset = 0
        while offset < len(data):
            field = _guess_field_at_offset(data, offset, ptr_size, base)
            if field is None:
                break
            fields.append(field)
            offset += field["size"]

        # Build a suggested template string
        template_parts = []
        for f in fields:
            typename = f["type"]
            if typename == "CString":
                template_parts.append(f'"field_{f["offset"]}" / CString("utf8")')
            elif typename == "PascalString":
                template_parts.append(f'"field_{f["offset"]}" / PascalString(Byte, "utf8")')
            elif typename.startswith("Pointer"):
                template_parts.append(f'"field_{f["offset"]}" / Int{ptr_size * 8}ul')
            elif typename == "Padding":
                template_parts.append(f'"pad_{f["offset"]}" / Padding({f["size"]})')
            else:
                template_parts.append(f'"field_{f["offset"]}" / Byte')

        guessed_template = "Struct(\n    " + ",\n    ".join(template_parts) + "\n)"

        return {
            "ok": True,
            "guessed_template": guessed_template,
            "fields": fields,
            "note": "Heuristic guesses — validate before use. Pointer detection uses image base alignment. String detection requires printable ASCII.",
        }

    except Exception as e:
        logger.exception("construct_guess_struct failed")
        return {**tool_error(e), "ok": False}


# ============================================================================
# Tool 8 — Batch parse array
# ============================================================================

@tool
@idasync
def construct_batch_parse_array(
    construct_template: Annotated[str, "Construct DSL for one array element"],
    address: Annotated[str, "IDA address of array start"],
    count: Annotated[int, "Number of elements (0 = auto-detect via null terminator or max_size)"] = 0,
    max_size: Annotated[int, "Max total bytes to consume (safety cap)"] = 65536,
    terminator_field: Annotated[
        str,
        "Field name to check for null terminator (e.g. 'e_magic'; empty = use count only)"
    ] = "",
) -> ConstructBatchParseResult:
    """Parse an array of identical structures at an IDA address.

    Useful for parsing tables like import descriptors, section headers,
    or protocol message arrays. Auto-terminates when a null/empty
    element is encountered if terminator_field is provided.
    """
    if not CONSTRUCT_AVAILABLE:
        return {"ok": False, "error": "construct not installed. Run: pip install construct"}

    try:
        template = _get_compiled_template(construct_template)
        ea = parse_address(address)
        max_size = min(max(max_size, 1), 65536)

        raw = read_bytes_bss_safe(ea, max_size)
        elements = []
        offset = 0
        idx = 0

        while offset < len(raw):
            if count > 0 and idx >= count:
                break

            try:
                result = template.parse(raw[offset:])
            except Exception:
                break

            parsed = _container_to_dict(result)

            # Check terminator
            if terminator_field:
                term_val = parsed.get(terminator_field)
                is_empty = term_val is None or term_val == 0 or term_val == ""
                # Handle bytes wrapper
                if isinstance(term_val, dict) and term_val.get("_bytes") in ("00", "0000", "00000000"):
                    is_empty = True
                if is_empty and idx > 0:
                    break

            try:
                elem_size = template.sizeof(result)
            except Exception:
                # Fallback: estimate size from parsed fields
                elem_size = 1

            elements.append({
                "index": idx,
                "address": hex(ea + offset),
                "parsed": parsed,
                "size": elem_size,
            })

            offset += elem_size
            idx += 1

            if elem_size <= 0:
                break

        return {
            "ok": True,
            "count": len(elements),
            "elements": elements,
            "total_bytes": offset,
        }

    except DSLSecurityError as e:
        return {"ok": False, "error": f"DSL security error: {e}"}
    except Exception as e:
        logger.exception("construct_batch_parse_array failed")
        return {**tool_error(e), "ok": False}


# ============================================================================
# Tool 9 — Protocol header extractor
# ============================================================================

@tool
@idasync
def construct_extract_protocol_header(
    protocol: Annotated[
        str,
        "Protocol name: ipv4, tcp, udp, icmp, ethernet, dns, tls_record"
    ],
    address: Annotated[str, "IDA address of the header"] = "",
    file_path: Annotated[str, "File path (mutually exclusive with address)"] = "",
    file_offset: Annotated[int, "Offset in file"] = 0,
) -> ConstructProtocolResult:
    """Parse a well-known protocol header using a pre-built Construct template.

    No Construct DSL required — just specify the protocol name.
    Supports common network headers and malware-relevant structures.
    """
    if not CONSTRUCT_AVAILABLE:
        return {"ok": False, "error": "construct not installed. Run: pip install construct"}

    protocol = protocol.lower().strip()
    template = _PROTOCOL_TEMPLATES.get(protocol)
    if template is None:
        valid = ", ".join(sorted(_PROTOCOL_TEMPLATES))
        return {"ok": False, "error": f"Unknown protocol {protocol!r}. Valid: {valid}"}

    try:
        parsed, consumed = _parse_from_source(
            template, address=address, file_path=file_path,
            file_offset=file_offset, size_hint=256,
        )

        # Add human-readable IP addresses for IPv4
        if protocol == "ipv4":
            src = parsed.get("src_ip", {})
            dst = parsed.get("dst_ip", {})
            if isinstance(src, dict) and "_bytes" in src:
                b = bytes.fromhex(src["_bytes"])
                parsed["src_ip_readable"] = ".".join(str(x) for x in b)
            if isinstance(dst, dict) and "_bytes" in dst:
                b = bytes.fromhex(dst["_bytes"])
                parsed["dst_ip_readable"] = ".".join(str(x) for x in b)
            # Extract version and IHL
            vihl = parsed.get("version_ihl", 0)
            if isinstance(vihl, int):
                parsed["version"] = (vihl >> 4) & 0xF
                parsed["ihl"] = vihl & 0xF

        # Add human-readable port numbers for TCP/UDP
        if protocol in ("tcp", "udp"):
            for field in ("src_port", "dst_port"):
                val = parsed.get(field)
                if isinstance(val, int):
                    parsed[f"{field}_readable"] = val

        return {
            "ok": True,
            "protocol": protocol,
            "parsed": parsed,
            "header_length": consumed,
        }

    except Exception as e:
        logger.exception("construct_extract_protocol_header failed")
        return {**tool_error(e), "ok": False}


# ============================================================================
# Tool 10 — Scan for struct patterns
# ============================================================================

@tool
@idasync
def construct_scan_for_structs(
    construct_template: Annotated[str, "Construct DSL for the structure to find"],
    start_address: Annotated[str, "Start address of scan region"],
    end_address: Annotated[str, "End address of scan region (exclusive)"],
    alignment: Annotated[int, "Byte alignment (default 1)"] = 1,
    max_results: Annotated[int, "Max matches to return (default 100)"] = 100,
    validate_field: Annotated[
        str,
        "Optional field name that must match a specific value (e.g. 'magic')"
    ] = "",
    validate_value_hex: Annotated[str, "Expected hex value for validate_field (e.g. '5045')"] = "",
) -> ConstructScanResult:
    """Scan a binary region for occurrences of a Construct-defined structure.

    Attempts to parse the template at each aligned offset. Returns all
    offsets where parsing succeeds and optional validation passes.
    Useful for finding all instances of a header, descriptor, or record.
    """
    if not CONSTRUCT_AVAILABLE:
        return {"ok": False, "error": "construct not installed. Run: pip install construct"}

    try:
        template = _get_compiled_template(construct_template)
        start_ea = parse_address(start_address)
        end_ea = parse_address(end_address)
        if end_ea <= start_ea:
            return {"ok": False, "error": "end_address must be greater than start_address"}

        region_size = end_ea - start_ea
        if region_size > 10 * 1024 * 1024:  # 10MB cap
            return {"ok": False, "error": "Scan region too large (> 10MB). Narrow the range."}

        raw = read_bytes_bss_safe(start_ea, region_size)
        alignment = max(alignment, 1)
        max_results = min(max(max_results, 1), 1000)

        expected_val = None
        if validate_field and validate_value_hex:
            try:
                expected_val = bytes.fromhex(validate_value_hex.replace(" ", ""))
            except ValueError:
                pass

        matches = []
        scan_attempts = 0

        for offset in range(0, len(raw), alignment):
            if len(matches) >= max_results:
                break
            if offset + 8 > len(raw):  # Need at least a few bytes
                break

            scan_attempts += 1
            try:
                result = template.parse(raw[offset:])
                parsed = _container_to_dict(result)

                # Validate field if requested
                if validate_field:
                    actual = parsed.get(validate_field)
                    if expected_val is not None:
                        actual_bytes = None
                        if isinstance(actual, dict) and "_bytes" in actual:
                            actual_bytes = bytes.fromhex(actual["_bytes"])
                        elif isinstance(actual, bytes):
                            actual_bytes = actual
                        elif isinstance(actual, int):
                            actual_bytes = actual.to_bytes(len(expected_val), "little")
                        if actual_bytes != expected_val:
                            continue
                    elif actual in (0, None, "", b""):
                        continue

                # Try to get consumed size
                try:
                    consumed = template.sizeof(result)
                except Exception:
                    consumed = 0

                matches.append({
                    "address": hex(start_ea + offset),
                    "parsed": parsed,
                    "bytes_consumed": consumed,
                })

            except (StreamError, ConstError, FormatFieldError):
                continue
            except Exception:
                continue

        return {
            "ok": True,
            "matches": matches,
            "scan_attempts": scan_attempts,
            "region_size": region_size,
        }

    except DSLSecurityError as e:
        return {"ok": False, "error": f"DSL security error: {e}"}
    except Exception as e:
        logger.exception("construct_scan_for_structs failed")
        return {**tool_error(e), "ok": False}
