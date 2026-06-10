"""filetype — lightweight magic-byte file type identification for IDA Pro MCP.

Optional module: tools are only registered when filetype is installed.
Install with: pip install filetype

Pure Python, zero dependencies, 79+ detectable file formats. Only the first
261 bytes of a buffer are needed for identification.
"""

from __future__ import annotations

import logging
from typing import Annotated, Any, NotRequired, TypedDict

logger = logging.getLogger(__name__)

# ============================================================================
# Optional import guard
# ============================================================================

try:
    import filetype as _filetype_lib

    FILETYPE_AVAILABLE = True
except ImportError:
    FILETYPE_AVAILABLE = False
    _filetype_lib = None  # type: ignore[assignment]
    logger.warning(
        "filetype not installed — filetype_* tools unavailable. "
        "Run: pip install filetype"
    )

from .rpc import tool
from .sync import idasync
from .utils import parse_address, read_bytes_bss_safe, tool_error

# ============================================================================
# TypedDict result types
# ============================================================================


class FiletypeStatusResult(TypedDict, total=False):
    available: bool
    version: str
    supported_types_count: int


class FiletypeIdentifyResult(TypedDict, total=False):
    ok: bool
    extension: str
    mime: str
    category: str
    confidence: str
    error: str


class FiletypeListResult(TypedDict, total=False):
    ok: bool
    types: list[dict[str, str]]
    total: int
    error: str


# ============================================================================
# Helpers
# ============================================================================

def _infer_category(mime: str) -> str:
    """Infer a broad category from a MIME type string."""
    if not mime:
        return "unknown"
    major = mime.split("/")[0]
    category_map = {
        "image": "image",
        "video": "video",
        "audio": "audio",
        "font": "font",
    }
    if major in category_map:
        return category_map[major]
    # Application types need finer-grained inspection
    if major == "application":
        app_categories = {
            "zip": "archive",
            "x-rar": "archive",
            "x-7z": "archive",
            "x-tar": "archive",
            "x-gzip": "archive",
            "x-bzip2": "archive",
            "x-xz": "archive",
            "pdf": "document",
            "msword": "document",
            "vnd.openxmlformats": "document",
            "vnd.ms-excel": "document",
            "vnd.ms-powerpoint": "document",
            "x-executable": "executable",
            "x-elf": "executable",
            "x-dosexec": "executable",
            "x-mach-binary": "executable",
        }
        for key, cat in app_categories.items():
            if key in mime:
                return cat
        return "application"
    return "unknown"


def _filetype_kind_to_dict(kind: Any) -> dict[str, str]:
    """Convert a filetype.Kind object to a plain dict."""
    mime = kind.mime if kind else ""
    return {
        "extension": kind.extension if kind else "unknown",
        "mime": mime,
        "category": _infer_category(mime),
    }


# ============================================================================
# Tools
# ============================================================================


@tool
@idasync
def filetype_status() -> FiletypeStatusResult:
    """Report whether the filetype library is installed and available.

    Returns version and the number of supported file type signatures.
    """
    if not FILETYPE_AVAILABLE:
        return {
            "available": False,
            "version": "",
            "supported_types_count": 0,
        }
    return {
        "available": True,
        "version": getattr(_filetype_lib, "__version__", "unknown"),
        "supported_types_count": len(_filetype_lib.types),
    }


@tool
@idasync
def filetype_identify_buffer(
    data_hex: Annotated[str, "Hex-encoded bytes to identify (omit if using address)"] = "",
    address: Annotated[str, "IDA address to read from (omit if using data_hex)"] = "",
    size: Annotated[int, "Number of bytes to read from IDA address"] = 4096,
) -> FiletypeIdentifyResult:
    """Identify the file type of a raw byte buffer by magic number signature.

    Uses only the first 261 bytes of the input, so large buffers are truncated
    automatically. Returns extension, MIME type, and inferred category.
    """
    if not FILETYPE_AVAILABLE:
        return {
            "ok": False,
            "extension": "",
            "mime": "",
            "category": "",
            "confidence": "",
            "error": "filetype not installed",
        }

    try:
        data: bytes
        if data_hex:
            data = bytes.fromhex(data_hex)
        elif address:
            ea = parse_address(address)
            data = read_bytes_bss_safe(ea, size)
        else:
            return {
                "ok": False,
                "extension": "",
                "mime": "",
                "category": "",
                "confidence": "",
                "error": "Either data_hex or address must be provided",
            }

        kind = _filetype_lib.guess(data)
        result = _filetype_kind_to_dict(kind)
        result["ok"] = True
        result["confidence"] = "signature" if kind else "none"
        return result  # type: ignore[return-value]
    except Exception as e:
        return {"ok": False, "error": str(e), "extension": "", "mime": "", "category": "", "confidence": ""}  # type: ignore[return-value]


@tool
@idasync
def filetype_identify_ida_segment(
    segment_name: Annotated[str, "Segment name (omit to use first loaded segment)"] = "",
) -> FiletypeIdentifyResult:
    """Identify the file type of the currently loaded binary or a specific segment.

    Reads the first 4096 bytes of the target segment and runs magic-byte
    identification. Useful for quick triage of unknown blobs.
    """
    if not FILETYPE_AVAILABLE:
        return {
            "ok": False,
            "extension": "",
            "mime": "",
            "category": "",
            "confidence": "",
            "error": "filetype not installed",
        }

    try:
        import ida_segment
        import idautils

        if segment_name:
            seg = ida_segment.get_segm_by_name(segment_name)
            if seg is None:
                return {
                    "ok": False,
                    "extension": "",
                    "mime": "",
                    "category": "",
                    "confidence": "",
                    "error": f"Segment not found: {segment_name}",
                }
            start_ea = seg.start_ea
        else:
            # Use the first segment that contains data
            segs = list(idautils.Segments())
            if not segs:
                return {
                    "ok": False,
                    "extension": "",
                    "mime": "",
                    "category": "",
                    "confidence": "",
                    "error": "No segments in current IDB",
                }
            start_ea = segs[0]

        data = read_bytes_bss_safe(start_ea, 4096)
        kind = _filetype_lib.guess(data)
        result = _filetype_kind_to_dict(kind)
        result["ok"] = True
        result["confidence"] = "signature" if kind else "none"
        return result  # type: ignore[return-value]
    except Exception as e:
        return {"ok": False, "error": str(e), "extension": "", "mime": "", "category": "", "confidence": ""}  # type: ignore[return-value]


@tool
@idasync
def filetype_list_supported(
    category: Annotated[
        str,
        "Filter by category: image, video, audio, archive, executable, document, font, application, or empty for all",
    ] = "",
) -> FiletypeListResult:
    """List all file types detectable by the filetype library.

    Optionally filter by category. Each entry includes extension, MIME type,
    and inferred category.
    """
    if not FILETYPE_AVAILABLE:
        return {
            "ok": False,
            "types": [],
            "total": 0,
            "error": "filetype not installed",
        }

    try:
        types: list[dict[str, str]] = []
        cat_filter = category.lower().strip()
        for t in _filetype_lib.types:
            item = {
                "extension": t.extension,
                "mime": t.mime,
                "category": _infer_category(t.mime),
            }
            if not cat_filter or item["category"] == cat_filter:
                types.append(item)

        return {
            "ok": True,
            "types": types,
            "total": len(types),
        }
    except Exception as e:
        return {"ok": False, "error": str(e), "types": [], "total": 0}  # type: ignore[return-value]
