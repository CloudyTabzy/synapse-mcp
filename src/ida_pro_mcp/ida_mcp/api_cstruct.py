"""dissect.cstruct — C-syntax binary structure parsing for IDA Pro MCP.

Optional module: tools are only registered when dissect.cstruct is installed.
Install with: pip install dissect.cstruct

Provides C-struct parsing using definitions copied from kernel headers, MSDN,
or firmware SDKs. Bidirectional (parse and serialize). Includes pre-defined
templates for PE/ELF headers and common network structures.

License note: dissect.cstruct is AGPL-3.0. It is an optional dependency that
is dynamically imported — not bundled or modified.
"""

from __future__ import annotations

import enum
import logging
import threading
from collections import OrderedDict
from typing import Annotated, Any, NotRequired, TypedDict

logger = logging.getLogger(__name__)

# ============================================================================
# Optional import guard
# ============================================================================

try:
    from dissect import cstruct as _cstruct_mod
    from dissect.cstruct import cstruct as _cstruct_cls
    from dissect.cstruct.types.enum import EnumMetaType

    CSTRUCT_AVAILABLE = True
except ImportError:
    CSTRUCT_AVAILABLE = False
    _cstruct_mod = None  # type: ignore[assignment]
    _cstruct_cls = None  # type: ignore[assignment,misc]
    EnumMetaType = None  # type: ignore[misc,assignment]
    logger.warning(
        "dissect.cstruct not installed — cstruct_* tools unavailable. "
        "Run: pip install dissect.cstruct"
    )

from .rpc import tool
from .sync import idasync
from .utils import parse_address, read_bytes_bss_safe, tool_error

# ============================================================================
# TypedDict result types
# ============================================================================


class CstructStatusResult(TypedDict, total=False):
    available: bool
    version: str
    registered_structs: int
    predefined_templates: list[str]


class CstructParseResult(TypedDict, total=False):
    ok: bool
    parsed: Any
    bytes_consumed: int
    struct_size: int
    count: int
    error: str


class CstructDefineResult(TypedDict, total=False):
    ok: bool
    name: str
    struct_size: int
    fields: list[str]
    defined_types: list[str]
    error: str


class CstructListResult(TypedDict, total=False):
    ok: bool
    structs: list[dict[str, Any]]
    predefined_count: int
    user_defined_count: int
    error: str


class CstructBuildResult(TypedDict, total=False):
    ok: bool
    hex: str
    size: int
    error: str


class CstructIdaBridgeResult(TypedDict, total=False):
    ok: bool
    c_definition: str
    parsed: Any
    field_count: int
    error: str


# ============================================================================
# Pre-defined C templates
# ============================================================================

_PE_TEMPLATES = r"""
struct IMAGE_DOS_HEADER {
    uint16 e_magic;
    uint16 e_cblp;
    uint16 e_cp;
    uint16 e_crlc;
    uint16 e_cparhdr;
    uint16 e_minalloc;
    uint16 e_maxalloc;
    uint16 e_ss;
    uint16 e_sp;
    uint16 e_csum;
    uint16 e_ip;
    uint16 e_cs;
    uint16 e_lfarlc;
    uint16 e_ovno;
    uint16 e_res[4];
    uint16 e_oemid;
    uint16 e_oeminfo;
    uint16 e_res2[10];
    uint32 e_lfanew;
};

struct IMAGE_FILE_HEADER {
    uint16 Machine;
    uint16 NumberOfSections;
    uint32 TimeDateStamp;
    uint32 PointerToSymbolTable;
    uint32 NumberOfSymbols;
    uint16 SizeOfOptionalHeader;
    uint16 Characteristics;
};

struct IMAGE_DATA_DIRECTORY {
    uint32 VirtualAddress;
    uint32 Size;
};

struct IMAGE_OPTIONAL_HEADER32 {
    uint16 Magic;
    uint8  MajorLinkerVersion;
    uint8  MinorLinkerVersion;
    uint32 SizeOfCode;
    uint32 SizeOfInitializedData;
    uint32 SizeOfUninitializedData;
    uint32 AddressOfEntryPoint;
    uint32 BaseOfCode;
    uint32 BaseOfData;
    uint32 ImageBase;
    uint32 SectionAlignment;
    uint32 FileAlignment;
    uint16 MajorOperatingSystemVersion;
    uint16 MinorOperatingSystemVersion;
    uint16 MajorImageVersion;
    uint16 MinorImageVersion;
    uint16 MajorSubsystemVersion;
    uint16 MinorSubsystemVersion;
    uint32 Win32VersionValue;
    uint32 SizeOfImage;
    uint32 SizeOfHeaders;
    uint32 CheckSum;
    uint16 Subsystem;
    uint16 DllCharacteristics;
    uint32 SizeOfStackReserve;
    uint32 SizeOfStackCommit;
    uint32 SizeOfHeapReserve;
    uint32 SizeOfHeapCommit;
    uint32 LoaderFlags;
    uint32 NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
};

struct IMAGE_OPTIONAL_HEADER64 {
    uint16 Magic;
    uint8  MajorLinkerVersion;
    uint8  MinorLinkerVersion;
    uint32 SizeOfCode;
    uint32 SizeOfInitializedData;
    uint32 SizeOfUninitializedData;
    uint32 AddressOfEntryPoint;
    uint32 BaseOfCode;
    uint64 ImageBase;
    uint32 SectionAlignment;
    uint32 FileAlignment;
    uint16 MajorOperatingSystemVersion;
    uint16 MinorOperatingSystemVersion;
    uint16 MajorImageVersion;
    uint16 MinorImageVersion;
    uint16 MajorSubsystemVersion;
    uint16 MinorSubsystemVersion;
    uint32 Win32VersionValue;
    uint32 SizeOfImage;
    uint32 SizeOfHeaders;
    uint32 CheckSum;
    uint16 Subsystem;
    uint16 DllCharacteristics;
    uint64 SizeOfStackReserve;
    uint64 SizeOfStackCommit;
    uint64 SizeOfHeapReserve;
    uint64 SizeOfHeapCommit;
    uint32 LoaderFlags;
    uint32 NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
};

struct IMAGE_NT_HEADERS32 {
    uint32 Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
};

struct IMAGE_NT_HEADERS64 {
    uint32 Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
};

struct IMAGE_SECTION_HEADER {
    char Name[8];
    uint32 VirtualSize;
    uint32 VirtualAddress;
    uint32 SizeOfRawData;
    uint32 PointerToRawData;
    uint32 PointerToRelocations;
    uint32 PointerToLinenumbers;
    uint16 NumberOfRelocations;
    uint16 NumberOfLinenumbers;
    uint32 Characteristics;
};

struct IMAGE_IMPORT_DESCRIPTOR {
    uint32 OriginalFirstThunk;
    uint32 TimeDateStamp;
    uint32 ForwarderChain;
    uint32 Name;
    uint32 FirstThunk;
};

struct IMAGE_EXPORT_DIRECTORY {
    uint32 Characteristics;
    uint32 TimeDateStamp;
    uint16 MajorVersion;
    uint16 MinorVersion;
    uint32 Name;
    uint32 Base;
    uint32 NumberOfFunctions;
    uint32 NumberOfNames;
    uint32 AddressOfFunctions;
    uint32 AddressOfNames;
    uint32 AddressOfNameOrdinals;
};
"""

_ELF_TEMPLATES = r"""
struct Elf32_Ehdr {
    char     e_ident[16];
    uint16   e_type;
    uint16   e_machine;
    uint32   e_version;
    uint32   e_entry;
    uint32   e_phoff;
    uint32   e_shoff;
    uint32   e_flags;
    uint16   e_ehsize;
    uint16   e_phentsize;
    uint16   e_phnum;
    uint16   e_shentsize;
    uint16   e_shnum;
    uint16   e_shstrndx;
};

struct Elf64_Ehdr {
    char     e_ident[16];
    uint16   e_type;
    uint16   e_machine;
    uint32   e_version;
    uint64   e_entry;
    uint64   e_phoff;
    uint64   e_shoff;
    uint32   e_flags;
    uint16   e_ehsize;
    uint16   e_phentsize;
    uint16   e_phnum;
    uint16   e_shentsize;
    uint16   e_shnum;
    uint16   e_shstrndx;
};

struct Elf32_Phdr {
    uint32   p_type;
    uint32   p_offset;
    uint32   p_vaddr;
    uint32   p_paddr;
    uint32   p_filesz;
    uint32   p_memsz;
    uint32   p_flags;
    uint32   p_align;
};

struct Elf64_Phdr {
    uint32   p_type;
    uint32   p_flags;
    uint64   p_offset;
    uint64   p_vaddr;
    uint64   p_paddr;
    uint64   p_filesz;
    uint64   p_memsz;
    uint64   p_align;
};

struct Elf32_Shdr {
    uint32   sh_name;
    uint32   sh_type;
    uint32   sh_flags;
    uint32   sh_addr;
    uint32   sh_offset;
    uint32   sh_size;
    uint32   sh_link;
    uint32   sh_info;
    uint32   sh_addralign;
    uint32   sh_entsize;
};

struct Elf64_Shdr {
    uint32   sh_name;
    uint32   sh_type;
    uint64   sh_flags;
    uint64   sh_addr;
    uint64   sh_offset;
    uint64   sh_size;
    uint32   sh_link;
    uint32   sh_info;
    uint64   sh_addralign;
    uint64   sh_entsize;
};
"""

_NETWORK_TEMPLATES = r"""
struct ip_header {
    uint8   ihl:4;
    uint8   version:4;
    uint8   tos;
    uint16  tot_len;
    uint16  id;
    uint16  frag_off;
    uint8   ttl;
    uint8   protocol;
    uint16  check;
    uint32  saddr;
    uint32  daddr;
};

struct tcp_header {
    uint16  source;
    uint16  dest;
    uint32  seq;
    uint32  ack_seq;
    uint8   res1:4;
    uint8   doff:4;
    uint8   fin:1;
    uint8   syn:1;
    uint8   rst:1;
    uint8   psh:1;
    uint8   ack:1;
    uint8   urg:1;
    uint8   res2:2;
    uint16  window;
    uint16  check;
    uint16  urg_ptr;
};

struct udp_header {
    uint16  source;
    uint16  dest;
    uint16  len;
    uint16  check;
};

struct icmp_header {
    uint8   type;
    uint8   code;
    uint16  checksum;
    uint32  rest_of_header;
};

struct ethernet_header {
    uint8   dst[6];
    uint8   src[6];
    uint16  type;
};
"""

_ALL_PREDEFINED = _PE_TEMPLATES + _ELF_TEMPLATES + _NETWORK_TEMPLATES

_BUILTIN_TYPE_NAMES = {
    "int8", "uint8", "int16", "uint16", "int32", "uint32", "int64", "uint64",
    "float16", "float", "double", "char", "wchar", "int24", "uint24",
    "int48", "uint48", "int128", "uint128", "uleb128", "ileb128", "void",
    "pointer",
}

_PREDEFINED_NAMES = [
    "IMAGE_DOS_HEADER",
    "IMAGE_FILE_HEADER",
    "IMAGE_DATA_DIRECTORY",
    "IMAGE_OPTIONAL_HEADER32",
    "IMAGE_OPTIONAL_HEADER64",
    "IMAGE_NT_HEADERS32",
    "IMAGE_NT_HEADERS64",
    "IMAGE_SECTION_HEADER",
    "IMAGE_IMPORT_DESCRIPTOR",
    "IMAGE_EXPORT_DIRECTORY",
    "Elf32_Ehdr",
    "Elf64_Ehdr",
    "Elf32_Phdr",
    "Elf64_Phdr",
    "Elf32_Shdr",
    "Elf64_Shdr",
    "ip_header",
    "tcp_header",
    "udp_header",
    "icmp_header",
    "ethernet_header",
]

_MAX_DEFINITION_SIZE = 32768  # 32 KiB cap on C definition strings
_MAX_REGISTRY_ENTRIES = 20

# ============================================================================
# Session registry
# ============================================================================

_registries: OrderedDict[str, "_cstruct_cls"] = OrderedDict()
_registry_lock = threading.Lock()


def _get_or_create_registry(endian: str = "<", session: str = "__default__") -> "_cstruct_cls":
    """Get or create a cstruct registry for the given session and endian.

    cs.endian is a live reference used by all loaded types — mutating it after
    loading changes how every type in the registry parses.  We avoid mutation
    entirely by keeping separate registries per endian.
    """
    key = f"{session}_{endian}"
    with _registry_lock:
        reg = _registries.get(key)
        if reg is None:
            reg = _cstruct_cls(endian=endian)
            reg.load(_ALL_PREDEFINED)
            _registries[key] = reg
        _registries.move_to_end(key)
        while len(_registries) > _MAX_REGISTRY_ENTRIES:
            _registries.popitem(last=False)
        return reg


def _resolve_endian(endianness: str) -> str:
    """Resolve 'little'/'big'/'auto' to '<' or '>'."""
    if endianness == "big":
        return ">"
    if endianness == "auto":
        try:
            from . import compat
            return ">" if compat.inf_is_be() else "<"
        except Exception:
            return "<"
    return "<"


def _reset_registry(endian: str = "<", session: str = "__default__") -> None:
    """Clear a registry so it will be recreated on next access."""
    with _registry_lock:
        _registries.pop(f"{session}_{endian}", None)


# ============================================================================
# Object serialization
# ============================================================================

def _safe_ascii(data: bytes) -> str | None:
    """Return ASCII representation of bytes if all printable, else None."""
    if all(32 <= b < 127 for b in data):
        return data.decode("ascii")
    return None


def _cstruct_to_dict(obj: Any, seen: set[int] | None = None) -> Any:
    """Recursively convert a cstruct parsed object to plain Python types."""
    if seen is None:
        seen = set()

    if obj is None:
        return None
    if isinstance(obj, enum.Enum):
        return {"_type": "enum", "name": obj.name, "value": int(obj.value) if hasattr(obj.value, "__int__") else obj.value}
    if isinstance(obj, bytes):
        result: dict[str, Any] = {"_type": "bytes", "hex": obj.hex()}
        ascii_repr = _safe_ascii(obj)
        if ascii_repr is not None:
            result["ascii"] = ascii_repr
        return result
    if isinstance(obj, (int, float, str, bool)):
        return obj
    if isinstance(obj, (list, tuple)):
        return [_cstruct_to_dict(v, seen) for v in obj]

    # Custom cstruct object (structure / union)
    oid = id(obj)
    if oid in seen:
        return {"_type": "circular_ref"}
    seen.add(oid)

    result_dict: dict[str, Any] = {}
    for k, v in obj.__dict__.items():
        if not k.startswith("_"):
            result_dict[k] = _cstruct_to_dict(v, seen)
    return result_dict


# ============================================================================
# Unified data source helper
# ============================================================================

def _read_bytes(
    data_hex: str = "",
    address: str = "",
    file_path: str = "",
    file_offset: int = 0,
    size_hint: int = 4096,
) -> bytes:
    """Read bytes from hex string, IDA memory, or a file on disk."""
    if data_hex:
        return bytes.fromhex(data_hex)
    if address:
        ea = parse_address(address)
        return read_bytes_bss_safe(ea, size_hint)
    if file_path:
        with open(file_path, "rb") as f:
            f.seek(file_offset)
            return f.read(size_hint)
    raise ValueError("Either data_hex, address, or file_path must be provided")


# ============================================================================
# Tools
# ============================================================================


@tool
@idasync
def cstruct_status() -> CstructStatusResult:
    """Report dissect.cstruct availability, version, and registered struct count."""
    if not CSTRUCT_AVAILABLE:
        return {
            "available": False,
            "version": "",
            "registered_structs": 0,
            "predefined_templates": [],
        }
    reg = _get_or_create_registry(endian="<")
    struct_count = len([
        n for n, obj in reg.typedefs.items()
        if not isinstance(obj, str) and n not in _BUILTIN_TYPE_NAMES
    ])
    return {
        "available": True,
        "version": getattr(_cstruct_mod, "__version__", "unknown"),
        "registered_structs": struct_count,
        "predefined_templates": list(_PREDEFINED_NAMES),
    }


@tool
@idasync
def cstruct_parse_c_definition(
    c_definition: Annotated[str, "C struct/enum/union definitions (e.g. struct foo { uint32 bar; });"],
    struct_name: Annotated[str, "Name of the top-level struct to instantiate"],
    data_hex: Annotated[str, "Hex-encoded bytes to parse (omit if using address or file_path)"] = "",
    address: Annotated[str, "IDA address to read from"] = "",
    file_path: Annotated[str, "File path to read from"] = "",
    file_offset: Annotated[int, "Offset in file"] = 0,
    size_hint: Annotated[int, "Max bytes to read"] = 4096,
    endianness: Annotated[str, "little | big | auto"] = "auto",
    count: Annotated[int, "Parse N consecutive instances"] = 1,
) -> CstructParseResult:
    """Parse binary data using a user-provided C struct definition.

    Accepts C-like syntax: struct, union, enum, #define, arrays, bitfields,
    and nested types. The definition is loaded into a session-scoped registry
    and can be reused via cstruct_parse_at_address.
    """
    if not CSTRUCT_AVAILABLE:
        return {"ok": False, "error": "dissect.cstruct not installed. Run: pip install dissect.cstruct", "parsed": None, "bytes_consumed": 0, "struct_size": 0, "count": 0}

    try:
        if len(c_definition) > _MAX_DEFINITION_SIZE:
            return {"ok": False, "error": f"C definition exceeds {_MAX_DEFINITION_SIZE} byte limit", "parsed": None, "bytes_consumed": 0, "struct_size": 0, "count": 0}

        target_endian = _resolve_endian(endianness)
        reg = _get_or_create_registry(endian=target_endian)

        try:
            reg.load(c_definition)
        except Exception as e:
            return {"ok": False, "error": f"Failed to parse C definition: {e}", "parsed": None, "bytes_consumed": 0, "struct_size": 0, "count": 0}

        # Resolve the struct type
        try:
            struct_type = getattr(reg, struct_name)
        except AttributeError:
            available = [n for n, obj in reg.typedefs.items() if not isinstance(obj, str) and n not in _BUILTIN_TYPE_NAMES]
            return {"ok": False, "error": f"Struct '{struct_name}' not found after loading definition. Available: {available[:20]}", "parsed": None, "bytes_consumed": 0, "struct_size": 0, "count": 0}

        struct_size = getattr(struct_type, "size", 0)
        if not struct_size:
            return {"ok": False, "error": f"Could not determine size of struct '{struct_name}'", "parsed": None, "bytes_consumed": 0, "struct_size": 0, "count": 0}

        data = _read_bytes(data_hex, address, file_path, file_offset, size_hint)
        if not data:
            return {"ok": False, "error": "No data available at the specified source", "parsed": None, "bytes_consumed": 0, "struct_size": 0, "count": 0}

        instances = []
        bytes_consumed = 0
        max_count = min(max(count, 1), len(data) // struct_size) if struct_size > 0 else 0

        for i in range(max_count):
            offset = i * struct_size
            chunk = data[offset:offset + struct_size]
            try:
                instance = struct_type(chunk)
                instances.append(_cstruct_to_dict(instance))
                bytes_consumed += struct_size
            except Exception as e:
                instances.append({"_error": str(e), "_index": i})
                break

        return {
            "ok": True,
            "parsed": instances if count != 1 else (instances[0] if instances else None),
            "bytes_consumed": bytes_consumed,
            "struct_size": struct_size,
            "count": len(instances),
        }

    except Exception as e:
        return {"ok": False, "error": str(e), "parsed": None, "bytes_consumed": 0, "struct_size": 0, "count": 0}


@tool
@idasync
def cstruct_parse_at_address(
    struct_name: Annotated[str, "Registered struct name"],
    address: Annotated[str, "IDA address (hex or symbol)"],
    count: Annotated[int, "Number of consecutive instances"] = 1,
    endian: Annotated[str, "little | big | auto (default auto detects from IDA binary)"] = "auto",
) -> CstructParseResult:
    """Parse at an IDA address using a previously registered struct definition.

    The struct must have been defined earlier in the session via
    cstruct_parse_c_definition or cstruct_define_struct, or be one of the
    pre-defined templates (e.g. IMAGE_DOS_HEADER, Elf64_Ehdr).

    Endian must match what was used when the struct was defined. Use 'auto'
    to match the endianness of the currently loaded IDA binary.
    """
    if not CSTRUCT_AVAILABLE:
        return {"ok": False, "error": "dissect.cstruct not installed", "parsed": None, "bytes_consumed": 0, "struct_size": 0, "count": 0}

    try:
        target_endian = _resolve_endian(endian)
        reg = _get_or_create_registry(endian=target_endian)
        try:
            struct_type = getattr(reg, struct_name)
        except AttributeError:
            available = [n for n, obj in reg.typedefs.items() if not isinstance(obj, str) and n not in _BUILTIN_TYPE_NAMES]
            return {"ok": False, "error": f"Struct '{struct_name}' not found. Available: {available[:20]}", "parsed": None, "bytes_consumed": 0, "struct_size": 0, "count": 0}

        struct_size = getattr(struct_type, "size", 0)
        if not struct_size:
            return {"ok": False, "error": f"Could not determine size of struct '{struct_name}'", "parsed": None, "bytes_consumed": 0, "struct_size": 0, "count": 0}

        ea = parse_address(address)
        total_size = struct_size * max(count, 1)
        data = read_bytes_bss_safe(ea, total_size)

        instances = []
        bytes_consumed = 0
        max_count = min(max(count, 1), len(data) // struct_size) if struct_size > 0 else 0

        for i in range(max_count):
            offset = i * struct_size
            chunk = data[offset:offset + struct_size]
            try:
                instance = struct_type(chunk)
                instances.append(_cstruct_to_dict(instance))
                bytes_consumed += struct_size
            except Exception as e:
                instances.append({"_error": str(e), "_index": i})
                break

        return {
            "ok": True,
            "parsed": instances if count != 1 else (instances[0] if instances else None),
            "bytes_consumed": bytes_consumed,
            "struct_size": struct_size,
            "count": len(instances),
        }

    except Exception as e:
        return {"ok": False, "error": str(e), "parsed": None, "bytes_consumed": 0, "struct_size": 0, "count": 0}


@tool
@idasync
def cstruct_define_struct(
    name: Annotated[str, "Unique identifier for this definition"],
    c_definition: Annotated[str, "Full C struct definition(s)"],
    endianness: Annotated[str, "little | big | auto"] = "auto",
) -> CstructDefineResult:
    """Register a C struct definition for reuse within the current MCP session.

    After defining, the struct can be used by name in cstruct_parse_at_address
    and cstruct_to_bytes.
    """
    if not CSTRUCT_AVAILABLE:
        return {"ok": False, "error": "dissect.cstruct not installed", "name": name, "struct_size": 0, "fields": [], "defined_types": []}

    try:
        if len(c_definition) > _MAX_DEFINITION_SIZE:
            return {"ok": False, "error": f"C definition exceeds {_MAX_DEFINITION_SIZE} byte limit", "name": name, "struct_size": 0, "fields": [], "defined_types": []}

        target_endian = _resolve_endian(endianness)
        reg = _get_or_create_registry(endian=target_endian)

        try:
            reg.load(c_definition)
        except Exception as e:
            return {"ok": False, "error": f"Failed to parse C definition: {e}", "name": name, "struct_size": 0, "fields": [], "defined_types": []}

        # Verify the named struct exists
        try:
            struct_type = getattr(reg, name)
        except AttributeError:
            available = [n for n, obj in reg.typedefs.items() if not isinstance(obj, str) and n not in _BUILTIN_TYPE_NAMES]
            return {"ok": False, "error": f"Struct '{name}' not found after loading definition. Available: {available[:20]}", "name": name, "struct_size": 0, "fields": [], "defined_types": []}

        struct_size = getattr(struct_type, "size", 0)
        fields = list(struct_type.fields.keys()) if hasattr(struct_type, "fields") else []

        # Collect all newly defined type names
        defined_types = [
            n for n, obj in reg.typedefs.items()
            if not isinstance(obj, str) and n not in _BUILTIN_TYPE_NAMES and n not in _PREDEFINED_NAMES
        ]

        return {
            "ok": True,
            "name": name,
            "struct_size": struct_size,
            "fields": fields,
            "defined_types": defined_types,
        }

    except Exception as e:
        return {"ok": False, "error": str(e), "name": name, "struct_size": 0, "fields": [], "defined_types": []}  # type: ignore[return-value]


@tool
@idasync
def cstruct_list_defined_structs(
    endian: Annotated[str, "little | big | auto — which endian registry to list (default auto)"] = "auto",
) -> CstructListResult:
    """List all registered struct definitions for the current session.

    Returns both pre-defined templates (PE, ELF, network headers) and any
    user-defined structs registered via cstruct_define_struct.
    """
    if not CSTRUCT_AVAILABLE:
        return {"ok": False, "structs": [], "predefined_count": 0, "user_defined_count": 0, "error": "dissect.cstruct not installed"}

    try:
        target_endian = _resolve_endian(endian)
        reg = _get_or_create_registry(endian=target_endian)
        structs = []
        predefined_count = 0
        user_defined_count = 0

        for n, obj in reg.typedefs.items():
            if isinstance(obj, str):
                continue  # type alias
            if n in _BUILTIN_TYPE_NAMES:
                continue
            size = getattr(obj, "size", 0)
            fields = list(obj.fields.keys()) if hasattr(obj, "fields") else []
            is_predefined = n in _PREDEFINED_NAMES
            if is_predefined:
                predefined_count += 1
            else:
                user_defined_count += 1

            structs.append({
                "name": n,
                "size": size,
                "field_count": len(fields),
                "source": "predefined" if is_predefined else "user_defined",
            })

        return {
            "ok": True,
            "structs": structs,
            "predefined_count": predefined_count,
            "user_defined_count": user_defined_count,
        }

    except Exception as e:
        return {"ok": False, "error": str(e), "structs": [], "predefined_count": 0, "user_defined_count": 0}  # type: ignore[return-value]


@tool
@idasync
def cstruct_to_bytes(
    struct_name: Annotated[str, "Registered struct name"],
    data: Annotated[dict, "Python dict matching struct fields"],
    endianness: Annotated[str, "little | big | auto"] = "auto",
) -> CstructBuildResult:
    """Serialize a Python dict back to binary bytes using a registered C struct.

    Useful for crafting fake headers, building packet structures, or preparing
    patch data before writing to the IDA database.
    """
    if not CSTRUCT_AVAILABLE:
        return {"ok": False, "hex": "", "size": 0, "error": "dissect.cstruct not installed"}

    try:
        target_endian = _resolve_endian(endianness)
        reg = _get_or_create_registry(endian=target_endian)
        try:
            struct_type = getattr(reg, struct_name)
        except AttributeError:
            return {"ok": False, "hex": "", "size": 0, "error": f"Struct '{struct_name}' not found"}

        # Build kwargs: recursively handle enum and bytes fields
        def _prepare_value(v: Any, field_name: str = "", elem_type: Any = None) -> Any:
            if isinstance(v, dict):
                if v.get("_type") == "bytes" and "hex" in v:
                    return bytes.fromhex(v["hex"])
                if v.get("_type") == "enum" and "value" in v:
                    # Convert raw int to cstruct enum instance if the field expects one
                    field_type = elem_type or (
                        getattr(struct_type.fields.get(field_name), "type", None)
                        if hasattr(struct_type, "fields") else None
                    )
                    if EnumMetaType is not None and field_type is not None and isinstance(field_type, EnumMetaType):
                        return field_type(v["value"])
                    return v["value"]
                # Nested struct as plain dict
                nested_type = elem_type or (
                    getattr(struct_type.fields.get(field_name), "type", None)
                    if hasattr(struct_type, "fields") else None
                )
                if nested_type is not None and hasattr(nested_type, "fields"):
                    return nested_type(**{k: _prepare_value(val, k) for k, val in v.items() if not k.startswith("_")})
                return v
            if isinstance(v, list):
                # Resolve array element type so enum/struct items in arrays are handled
                arr_field = struct_type.fields.get(field_name) if hasattr(struct_type, "fields") else None
                arr_elem_type = getattr(arr_field, "type", None) if arr_field is not None else None
                # cstruct array types expose their element type via .type
                inner_type = getattr(arr_elem_type, "type", None) if arr_elem_type is not None else None
                return [_prepare_value(item, elem_type=inner_type) for item in v]
            return v

        kwargs = {k: _prepare_value(v, k) for k, v in data.items() if not k.startswith("_")}
        instance = struct_type(**kwargs)
        raw = instance.dumps()
        return {
            "ok": True,
            "hex": raw.hex(),
            "size": len(raw),
        }

    except Exception as e:
        return {"ok": False, "error": str(e), "hex": "", "size": 0}  # type: ignore[return-value]


# ============================================================================
# IDA struct bridge
# ============================================================================

# Mapping from IDA base type codes to C type strings
# These are the BTF_INT* constants used by ida_typeinf
_BTF_TO_C_TYPE: dict[int, str] = {
    0x00: "int8",
    0x01: "int16",
    0x02: "int32",
    0x03: "int64",
    0x04: "uint8[16]",   # int128
    0x10: "uint8",
    0x11: "uint16",
    0x12: "uint32",
    0x13: "uint64",
    0x14: "uint8[16]",   # uint128
}

_BTF_TO_C_TYPE_FLOAT: dict[int, str] = {
    0x20: "float",       # float
    0x21: "double",      # double
    0x22: "long double", # long double
}


def _ida_type_to_c(
    tif: Any,
    ptr_size: int,
    visited: set[int] | None = None,
) -> str | None:
    """Recursively convert an IDA tinfo_t to a C type string.

    Returns None for unsupported types.
    """
    if visited is None:
        visited = set()

    import ida_typeinf

    # Pointer
    if tif.is_ptr():
        return f"uint{ptr_size * 8}"

    # Array
    if tif.is_array():
        elem_tif = ida_typeinf.tinfo_t()
        if tif.get_array_element(elem_tif):
            nelems = tif.get_array_nelems()
            elem_c = _ida_type_to_c(elem_tif, ptr_size, visited)
            if elem_c:
                return f"{elem_c}[{nelems}]"
        return "uint8[0]"

    # Struct / union
    if tif.is_struct() or tif.is_union():
        udt_data = ida_typeinf.udt_type_data_t()
        if not tif.get_udt_details(udt_data):
            return None

        kind = "union" if tif.is_union() else "struct"
        ordinal = tif.get_ordinal()
        name = tif.get_type_name() or f"anon_{ordinal}"
        if ordinal in visited:
            return name
        visited.add(ordinal)

        lines = [f"{kind} {name} {{"]
        for member in udt_data:
            member_name = member.name or "field"
            member_tif = ida_typeinf.tinfo_t()
            if not tif.get_udm_by_tid(member_tif, member.tid):
                member_tif = member.type
            member_c = _ida_type_to_c(member_tif, ptr_size, visited)
            if member_c is None:
                member_size = member.size // 8  # bits to bytes
                member_c = f"uint8[{max(member_size, 1)}]"
            lines.append(f"    {member_c} {member_name};")
        lines.append("};")
        return "\n".join(lines)

    # Enum
    if tif.is_enum():
        enum_data = ida_typeinf.enum_type_data_t()
        if tif.get_enum_details(enum_data):
            ordinal = tif.get_ordinal()
            name = tif.get_type_name() or f"enum_{ordinal}"
            if ordinal in visited:
                return name
            visited.add(ordinal)

            lines = [f"enum {name} : uint32 {{"]
            for member in enum_data:
                lines.append(f"    {member.name} = {member.value},")
            lines.append("};")
            return "\n".join(lines)
        return "uint32"

    # Float types
    base_type = tif.get_base_type()
    if base_type in _BTF_TO_C_TYPE_FLOAT:
        return _BTF_TO_C_TYPE_FLOAT[base_type]

    # Scalar / typedef
    if base_type in _BTF_TO_C_TYPE:
        return _BTF_TO_C_TYPE[base_type]

    # Typedef unwrap
    if base_type == ida_typeinf.BTF_TYPEDEF:
        inner = ida_typeinf.tinfo_t()
        if tif.get_base(inner):
            return _ida_type_to_c(inner, ptr_size, visited)

    return None


def _ida_struct_to_c_definition(struct_name: str, ptr_size: int) -> str | None:
    """Look up a named struct in IDA's type library and convert it to C syntax."""
    try:
        import ida_typeinf
        tif = ida_typeinf.tinfo_t()
        if tif.get_named_type(None, struct_name, ida_typeinf.BTF_STRUCT):
            return _ida_type_to_c(tif, ptr_size)
        if tif.get_named_type(None, struct_name, ida_typeinf.BTF_UNION):
            return _ida_type_to_c(tif, ptr_size)
        if tif.get_named_type(None, struct_name, ida_typeinf.BTF_TYPEDEF):
            inner = ida_typeinf.tinfo_t()
            if tif.get_base(inner):
                return _ida_type_to_c(inner, ptr_size)
            return _ida_type_to_c(tif, ptr_size)
        if tif.get_named_type(None, struct_name, ida_typeinf.BTF_ENUM):
            return _ida_type_to_c(tif, ptr_size)
    except Exception:
        logger.exception("_ida_struct_to_c_definition failed for %r", struct_name)
    return None


@tool
@idasync
def cstruct_parse_ida_struct(
    ida_struct_name: Annotated[str, "Name of struct in IDA type library"],
    address: Annotated[str, "Address to parse at (omit to just return C definition)"] = "",
) -> CstructIdaBridgeResult:
    """Convert an existing IDA struct definition to C syntax and optionally parse bytes.

    Uses IDA's type library (Shift+F9) to find the struct, maps each member
    type to a C equivalent, and returns the C definition. If an address is
    provided, also parses the bytes through the generated definition.
    """
    if not CSTRUCT_AVAILABLE:
        return {"ok": False, "c_definition": "", "parsed": None, "field_count": 0, "error": "dissect.cstruct not installed"}

    try:
        from . import compat
        ptr_size = 8 if compat.inf_is_64bit() else 4

        c_def = _ida_struct_to_c_definition(ida_struct_name, ptr_size)
        if c_def is None:
            return {
                "ok": False,
                "c_definition": "",
                "parsed": None,
                "field_count": 0,
                "error": f"Struct '{ida_struct_name}' not found in IDA's type library. Check the Types window (Shift+F9).",
            }

        # Parse to count fields
        field_count = c_def.count(";") - c_def.count("struct") - c_def.count("union") - c_def.count("enum")
        field_count = max(field_count, 0)

        parsed = None
        if address:
            target_endian = ">" if ptr_size == 8 and _resolve_endian("auto") == ">" else "<"
            reg = _get_or_create_registry(endian=target_endian)
            try:
                reg.load(c_def)
            except Exception as e:
                return {
                    "ok": False,
                    "c_definition": c_def,
                    "parsed": None,
                    "field_count": field_count,
                    "error": f"Generated C definition failed to parse: {e}",
                }

            # Try to find the struct name in the generated definition
            struct_type = None
            for line in c_def.splitlines():
                if "struct" in line or "union" in line or "enum" in line:
                    parts = line.replace("struct", "").replace("union", "").replace("enum", "").strip().split()
                    if parts:
                        candidate = parts[0].rstrip("{")
                        try:
                            struct_type = getattr(reg, candidate)
                            break
                        except AttributeError:
                            continue

            if struct_type is None:
                # Fallback: try the original name
                try:
                    struct_type = getattr(reg, ida_struct_name)
                except AttributeError:
                    return {
                        "ok": False,
                        "c_definition": c_def,
                        "parsed": None,
                        "field_count": field_count,
                        "error": f"Could not resolve generated struct type for '{ida_struct_name}'",
                    }

            ea = parse_address(address)
            struct_size = getattr(struct_type, "size", 0)
            data = read_bytes_bss_safe(ea, max(struct_size, 1))
            try:
                instance = struct_type(data)
                parsed = _cstruct_to_dict(instance)
            except Exception as e:
                return {
                    "ok": False,
                    "c_definition": c_def,
                    "parsed": None,
                    "field_count": field_count,
                    "error": f"Parse failed: {e}",
                }

        return {
            "ok": True,
            "c_definition": c_def,
            "parsed": parsed,
            "field_count": field_count,
        }

    except Exception as e:
        return {"ok": False, "error": str(e), "c_definition": "", "parsed": None, "field_count": 0}  # type: ignore[return-value]
