"""Memory reading and writing operations for IDA Pro MCP.

This module provides batch operations for reading and writing memory at various
granularities (bytes, integers, strings) and patching binary data.
"""

import re

from typing import Annotated, NotRequired, TypedDict
import ida_bytes
import idaapi

from .rpc import tool
from .sync import idasync
from .utils import (
    IntRead,
    IntWrite,
    MemoryPatch,
    MemoryRead,
    normalize_list_input,
    parse_address,
    read_bytes_bss_safe,
    read_int_bss_safe,
    item_error,
)


class BytesReadResult(TypedDict):
    addr: str | None
    data: str | None
    error: NotRequired[str]
    error_type: NotRequired[str]
    hint: NotRequired[str]


class IntReadResult(TypedDict):
    addr: str
    ty: str
    value: int | None
    error: NotRequired[str]
    error_type: NotRequired[str]
    hint: NotRequired[str]


class StringReadResult(TypedDict):
    addr: str
    value: str | None
    error: NotRequired[str]
    error_type: NotRequired[str]
    hint: NotRequired[str]


class GlobalValueResult(TypedDict):
    query: str
    value: str | None
    error: NotRequired[str]
    error_type: NotRequired[str]
    hint: NotRequired[str]


class PatchResult(TypedDict):
    addr: str | None
    size: int
    error: NotRequired[str]
    error_type: NotRequired[str]
    hint: NotRequired[str]


class IntWriteResult(TypedDict):
    addr: str
    ty: str
    value: str | None
    error: NotRequired[str]
    error_type: NotRequired[str]
    hint: NotRequired[str]


# ============================================================================
# Memory Reading Operations
# ============================================================================


@tool
@idasync
def get_bytes(regions: list[MemoryRead] | MemoryRead) -> list[BytesReadResult]:
    """Read bytes from memory addresses"""
    if isinstance(regions, dict):
        regions = [regions]

    results = []
    for item in regions:
        addr = item.get("addr", "")
        size = item.get("size", 0)

        try:
            ea = parse_address(addr)
            raw = read_bytes_bss_safe(ea, size)
            data = " ".join(f"{x:#02x}" for x in raw)
            results.append({"addr": addr, "data": data})
        except Exception as e:
            results.append({"addr": addr, "data": None, **item_error(e, f"read {size} bytes at {addr}")})

    return results


class ReadLocalFileResult(TypedDict):
    ok: bool
    path: str
    offset: int
    total_bytes: int
    has_more: bool
    data: str
    encoding: str
    error: NotRequired[str]


@tool
@idasync
def read_local_file(
    path: Annotated[str, "Absolute path to the file on the IDA host machine."],
    offset: Annotated[int, "Byte offset to start reading from."] = 0,
    max_bytes: Annotated[
        int, "Maximum bytes to read (default 32768, cap 50000)."
    ] = 32768,
    encoding: Annotated[
        str,
        "Text encoding to use for decoding (default 'utf-8'). Use 'base64' to "
        "return raw bytes as a base64 string without any text decoding.",
    ] = "utf-8",
) -> ReadLocalFileResult:
    """Read a file from the IDA host's local filesystem.

    This tool is useful when another MCP tool writes output to a temporary
    file (e.g. graph exports, reports) and you need to retrieve the contents.
    Use offset/max_bytes to page through large files.

    Security: the path is validated to prevent directory traversal. Only
    absolute paths are accepted.
    """
    import os
    import base64

    # Security: reject relative paths and directory traversal
    cleaned = os.path.normpath(os.path.abspath(path))
    if ".." in cleaned.split(os.sep):
        return {
            "ok": False,
            "path": path,
            "offset": 0,
            "total_bytes": 0,
            "has_more": False,
            "data": "",
            "encoding": encoding,
            "error": "Invalid path: directory traversal not allowed.",
        }

    if not os.path.isfile(cleaned):
        return {
            "ok": False,
            "path": path,
            "offset": 0,
            "total_bytes": 0,
            "has_more": False,
            "data": "",
            "encoding": encoding,
            "error": f"File not found: {cleaned}",
        }

    try:
        total = os.path.getsize(cleaned)
    except OSError as e:
        return {
            "ok": False,
            "path": path,
            "offset": 0,
            "total_bytes": 0,
            "has_more": False,
            "data": "",
            "encoding": encoding,
            "error": f"Cannot stat file: {e}",
        }

    max_bytes = min(max_bytes, 50000)
    if offset < 0:
        offset = 0
    if offset > total:
        offset = total

    try:
        with open(cleaned, "rb") as f:
            f.seek(offset)
            raw = f.read(max_bytes)
    except OSError as e:
        return {
            "ok": False,
            "path": path,
            "offset": offset,
            "total_bytes": total,
            "has_more": False,
            "data": "",
            "encoding": encoding,
            "error": f"Read failed: {e}",
        }

    if encoding.lower() == "base64":
        data = base64.b64encode(raw).decode("ascii")
    else:
        try:
            data = raw.decode(encoding, errors="replace")
        except LookupError:
            data = raw.decode("utf-8", errors="replace")

    has_more = offset + len(raw) < total

    return {
        "ok": True,
        "path": cleaned,
        "offset": offset,
        "total_bytes": total,
        "has_more": has_more,
        "data": data,
        "encoding": encoding,
    }


_INT_CLASS_RE = re.compile(r"^(?P<sign>[iu])(?P<bits>8|16|32|64)(?P<endian>le|be)?$")


def _parse_int_class(text: str) -> tuple[int, bool, str, str]:
    if not text:
        raise ValueError("Missing integer class")

    cleaned = text.strip().lower()
    match = _INT_CLASS_RE.match(cleaned)
    if not match:
        raise ValueError(f"Invalid integer class: {text}")

    bits = int(match.group("bits"))
    signed = match.group("sign") == "i"
    endian = match.group("endian") or "le"
    byte_order = "little" if endian == "le" else "big"
    normalized = f"{'i' if signed else 'u'}{bits}{endian}"
    return bits, signed, byte_order, normalized


def _parse_int_value(text: str, signed: bool, bits: int) -> int:
    if text is None:
        raise ValueError("Missing integer value")

    value_text = str(text).strip()
    try:
        value = int(value_text, 0)
    except ValueError:
        raise ValueError(f"Invalid integer value: {text}")

    if not signed and value < 0:
        raise ValueError(f"Negative value not allowed for u{bits}")

    return value


@tool
@idasync
def get_int(
    queries: Annotated[
        list[IntRead] | IntRead,
        "Integer read requests with {addr, ty}. "
        "ty format: <sign><bits>[<endian>] — "
        "sign: 'i' (signed) or 'u' (unsigned); "
        "bits: 8, 16, 32, 64; "
        "endian: 'le' (little, default) or 'be' (big). "
        "Examples: i8, u8, i16, u16, i32, u32, i64, u64, "
        "i16le, u16be, i32le, u32be, i64le, u64be.",
    ],
) -> list[IntReadResult]:
    """Read integer values from memory addresses.

    ty examples: ``i8`` ``u8`` ``i16`` ``u16le`` ``u32be`` ``i64`` ``u64le``
    """
    if isinstance(queries, dict):
        queries = [queries]

    results = []
    for item in queries:
        addr = item.get("addr", "")
        ty = item.get("ty", "")

        try:
            bits, signed, byte_order, normalized = _parse_int_class(ty)
            ea = parse_address(addr)
            size = bits // 8
            data = read_bytes_bss_safe(ea, size)
            if len(data) != size:
                raise ValueError(f"Failed to read {size} bytes at {addr}")

            value = int.from_bytes(data, byte_order, signed=signed)
            results.append(
                {"addr": addr, "ty": normalized, "value": value}
            )
        except Exception as e:
            results.append({"addr": addr, "ty": ty, "value": None, **item_error(e, f"read {ty} at {addr}")})

    return results


@tool
@idasync
def get_string(
    addrs: Annotated[list[str] | str, "Addresses to read strings from"],
    max_length: Annotated[
        int,
        "Maximum string length in bytes (0 = IDA auto-detect, default). "
        "Useful for truncating very long strings or reading fixed-length buffers.",
    ] = 0,
) -> list[StringReadResult]:
    """Read null-terminated strings from memory addresses.

    Uses IDA's string literal detection by default (``max_length=0``).
    Supply ``max_length`` to cap the result or to read from addresses where
    IDA has not yet defined a string item.
    """
    addrs = normalize_list_input(addrs)
    ida_len = max_length if max_length > 0 else -1
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            raw = idaapi.get_strlit_contents(ea, ida_len, 0)
            if not raw:
                results.append(
                    {"addr": addr, "value": None, "error": "No string at address"}
                )
                continue
            value = raw.decode("utf-8", errors="replace")
            results.append({"addr": addr, "value": value})
        except Exception as e:
            results.append({"addr": addr, "value": None, **item_error(e, f"read string at {addr}")})

    return results


def get_global_variable_value_internal(ea: int) -> str:
    import ida_typeinf
    import ida_nalt
    import ida_bytes
    from .sync import IDAError

    tif = ida_typeinf.tinfo_t()
    if not ida_nalt.get_tinfo(tif, ea):
        if not ida_bytes.has_any_name(ea):
            raise IDAError(f"Failed to get type information for variable at {ea:#x}")

        size = ida_bytes.get_item_size(ea)
        if size == 0:
            raise IDAError(f"Failed to get type information for variable at {ea:#x}")
    else:
        size = tif.get_size()

    if size == 0 and tif.is_array() and tif.get_array_element().is_decl_char():
        raw = idaapi.get_strlit_contents(ea, -1, 0)
        if not raw:
            return '""'
        return_string = raw.decode("utf-8", errors="replace").strip()
        return f'"{return_string}"'

    if size in (1, 2, 4, 8):
        return hex(read_int_bss_safe(ea, size))
    return " ".join(hex(b) for b in read_bytes_bss_safe(ea, size))


@tool
@idasync
def get_global_value(
    queries: Annotated[
        list[str] | str, "Global variable addresses or names to read values from"
    ],
) -> list[GlobalValueResult]:
    """Read global variable values by address or symbol name."""
    from .utils import looks_like_address

    queries = normalize_list_input(queries)
    results = []

    for query in queries:
        try:
            ea = idaapi.BADADDR

            # Try as address first if it looks like one
            if looks_like_address(query):
                try:
                    ea = parse_address(query)
                except Exception:
                    ea = idaapi.BADADDR

            # Fall back to name lookup
            if ea == idaapi.BADADDR:
                ea = idaapi.get_name_ea(idaapi.BADADDR, query)

            if ea == idaapi.BADADDR:
                results.append({"query": query, "value": None, "error": "Not found"})
                continue

            value = get_global_variable_value_internal(ea)
            results.append({"query": query, "value": value})
        except Exception as e:
            results.append({"query": query, "value": None, **item_error(e, f"read global {query!r}")})

    return results


# ============================================================================
# Batch Data Operations
# ============================================================================


@tool
@idasync
def patch(patches: list[MemoryPatch] | MemoryPatch) -> list[PatchResult]:
    """Patch bytes at memory addresses with hex data"""
    if isinstance(patches, dict):
        patches = [patches]

    results = []

    for patch in patches:
        try:
            ea = parse_address(patch["addr"])
            data = bytes.fromhex(patch["data"])

            if not ida_bytes.is_mapped(ea):
                raise ValueError(f"Address not mapped: {patch['addr']}")

            ida_bytes.patch_bytes(ea, data)
            results.append(
                {"addr": patch["addr"], "size": len(data)}
            )

        except Exception as e:
            results.append({"addr": patch.get("addr"), "size": 0, **item_error(e, f"patch bytes at {patch.get('addr', '?')}")})

    return results


@tool
@idasync
def put_int(
    items: Annotated[
        list[IntWrite] | IntWrite,
        "Integer write requests (ty, addr, value). value is a string; supports 0x.. and negatives",
    ],
) -> list[IntWriteResult]:
    """Write integer values to memory addresses"""
    if isinstance(items, dict):
        items = [items]

    results = []
    for item in items:
        addr = item.get("addr", "")
        ty = item.get("ty", "")
        value_text = item.get("value")

        try:
            bits, signed, byte_order, normalized = _parse_int_class(ty)
            value = _parse_int_value(value_text, signed, bits)
            size = bits // 8
            try:
                data = value.to_bytes(size, byte_order, signed=signed)
            except OverflowError:
                raise ValueError(f"Value {value_text} does not fit in {normalized}")

            ea = parse_address(addr)
            if not ida_bytes.is_mapped(ea):
                raise ValueError(f"Address not mapped: {addr}")
            ida_bytes.patch_bytes(ea, data)
            results.append(
                {
                    "addr": addr,
                    "ty": normalized,
                    "value": str(value_text),
                }
            )
        except Exception as e:
            results.append(
                {
                    "addr": addr,
                    "ty": ty,
                    "value": str(value_text) if value_text is not None else None,
                    **item_error(e, f"write {ty} at {addr}"),
                }
            )

    return results
