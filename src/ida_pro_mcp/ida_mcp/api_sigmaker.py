"""Signature creation and scanning tools for IDA Pro MCP.

This module integrates sigmaker.py functionality to provide:
- Unique signature generation for addresses/functions
- Range-based signature generation (selection)
- XREF-based signature discovery
- Multiple output formats: IDA, x64dbg, mask, bitmask
"""

from typing import Annotated, NotRequired, TypedDict

import idaapi
import ida_funcs

from .rpc import tool
from .sync import idasync
from .utils import parse_address, normalize_list_input, tool_error, item_error

from . import _sigmaker as _sm


# ---------------------------------------------------------------------------
# Output format helpers
# ---------------------------------------------------------------------------

_FORMAT_ALIASES = {
    "ida": "ida",
    "x64dbg": "x64dbg",
    "mask": "mask",
    "bitmask": "bitmask",
}


def _resolve_format(fmt: str) -> "str":
    key = fmt.lower().strip()
    if key not in _FORMAT_ALIASES:
        raise ValueError(
            f"Unknown signature format '{fmt}'. "
            f"Valid formats: ida, x64dbg, mask, bitmask"
        )
    return _FORMAT_ALIASES[key]


def _make_config(
    fmt: str,
    wildcard_operands: bool = True,
    continue_outside_function: bool = True,
    max_length: int = 1000,
) -> "object":
    return _sm.SigMakerConfig(
        output_format=_sm.SignatureType(fmt),
        wildcard_operands=wildcard_operands,
        continue_outside_of_function=continue_outside_function,
        wildcard_optimized=False,
        ask_longer_signature=False,
        max_single_signature_length=max_length,
        max_xref_signature_length=max_length,
    )


def _resolve_addr(addr_str: str) -> int:
    """Resolve an address string or name to an ea."""
    try:
        return parse_address(addr_str)
    except Exception:
        ea = idaapi.get_name_ea(idaapi.BADADDR, addr_str)
        if ea == idaapi.BADADDR:
            raise ValueError(f"Cannot resolve address or name: {addr_str}")
        return ea


def _format_sig(sig, fmt: str) -> str:
    return format(sig, fmt)


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


class MakeSigResult(TypedDict):
    query: str
    addr: str | None
    signature: str | None
    format: str
    unique: NotRequired[bool]
    error: NotRequired[str]
    error_type: NotRequired[str]
    hint: NotRequired[str]


class MakeSigForFunctionResult(TypedDict):
    query: str
    addr: str | None
    name: str | None
    signature: str | None
    format: str
    error: NotRequired[str]
    error_type: NotRequired[str]
    hint: NotRequired[str]


class XrefSigResult(TypedDict):
    query: str
    addr: str | None
    signatures: list[dict] | None
    total_xrefs: NotRequired[int]
    error: NotRequired[str]
    error_type: NotRequired[str]
    hint: NotRequired[str]


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


@tool
@idasync
def make_signature(
    addrs: Annotated[
        list[str] | str,
        "Address(es) or name(s) to create unique signatures for "
        "(e.g. '0x401000', 'main', or ['0x401000', 'sub_402000'])",
    ],
    format: Annotated[
        str,
        "Output format: 'ida' (default), 'x64dbg', 'mask', or 'bitmask'",
    ] = "ida",
    wildcard_operands: Annotated[
        bool,
        "Wildcard instruction operands for relocatable signatures (default: true)",
    ] = True,
    max_length: Annotated[
        int,
        "Maximum signature length in bytes before giving up (default: 1000)",
    ] = 1000,
) -> list[MakeSigResult]:
    """Create unique byte signatures for addresses. Generates the shortest
    unique signature starting at each address by walking instructions and
    wildcarding operands. Useful for finding stable patterns that survive
    recompilation."""
    sm = _sm
    fmt = _resolve_format(format)
    cfg = _make_config(fmt, wildcard_operands=wildcard_operands, max_length=max_length)
    maker = sm.SignatureMaker()
    addrs_list = normalize_list_input(addrs)

    results: list[MakeSigResult] = []
    for addr_str in addrs_list:
        try:
            ea = _resolve_addr(addr_str)
            result = maker.make_signature(ea, cfg)
            sig_str = _format_sig(result.signature, fmt)
            # Verify uniqueness
            is_unique = sm.SignatureSearcher.is_unique(f"{result.signature:ida}")
            results.append({
                "query": addr_str,
                "addr": hex(ea),
                "signature": sig_str,
                "format": format,
                "unique": is_unique,
            })
        except Exception as e:
            results.append({
                "query": addr_str,
                "addr": hex(ea) if 'ea' in locals() else None,
                "signature": None,
                "format": format,
                **item_error(e),
            })
    return results


@tool
@idasync
def make_signature_for_function(
    addrs: Annotated[
        list[str] | str,
        "Function address(es) or name(s) to create signatures for "
        "(e.g. 'main', '0x401000', or ['main', 'sub_402000'])",
    ],
    format: Annotated[
        str,
        "Output format: 'ida' (default), 'x64dbg', 'mask', or 'bitmask'",
    ] = "ida",
    wildcard_operands: Annotated[
        bool,
        "Wildcard instruction operands for relocatable signatures (default: true)",
    ] = True,
    max_length: Annotated[
        int,
        "Maximum signature length in bytes before giving up (default: 1000)",
    ] = 1000,
) -> list[MakeSigForFunctionResult]:
    """Create unique byte signatures for function entry points. Resolves each
    name/address to a function, then generates the shortest unique signature
    starting at the function start."""
    sm = _sm
    fmt = _resolve_format(format)
    cfg = _make_config(fmt, wildcard_operands=wildcard_operands, max_length=max_length)
    maker = sm.SignatureMaker()
    addrs_list = normalize_list_input(addrs)

    results: list[MakeSigForFunctionResult] = []
    for addr_str in addrs_list:
        ea = None
        try:
            ea = _resolve_addr(addr_str)
            func = ida_funcs.get_func(ea)
            if not func:
                results.append({
                    "query": addr_str,
                    "addr": hex(ea),
                    "name": None,
                    "signature": None,
                    "format": format,
                    "error": f"No function at {hex(ea)}",
                })
                continue

            func_ea = func.start_ea
            func_name = idaapi.get_func_name(func_ea) or None
            result = maker.make_signature(func_ea, cfg)
            sig_str = _format_sig(result.signature, fmt)
            results.append({
                "query": addr_str,
                "addr": hex(func_ea),
                "name": func_name,
                "signature": sig_str,
                "format": format,
            })
        except Exception as e:
            results.append({
                "query": addr_str,
                "addr": hex(ea) if ea is not None else None,
                "name": None,
                "signature": None,
                "format": format,
                **item_error(e),
            })
    return results


@tool
@idasync
def make_signature_for_range(
    start: Annotated[str, "Start address or name (e.g. '0x401000')"],
    end: Annotated[str, "End address or name (exclusive, e.g. '0x401020')"],
    format: Annotated[
        str,
        "Output format: 'ida' (default), 'x64dbg', 'mask', or 'bitmask'",
    ] = "ida",
    wildcard_operands: Annotated[
        bool,
        "Wildcard instruction operands for relocatable signatures (default: true)",
    ] = True,
) -> MakeSigResult:
    """Create a byte signature for a specific address range (e.g. a selected
    region). Unlike make_signature, this does NOT guarantee uniqueness — it
    simply encodes the bytes in the range with optional operand wildcarding."""
    sm = _sm
    fmt = _resolve_format(format)
    cfg = _make_config(fmt, wildcard_operands=wildcard_operands)
    maker = sm.SignatureMaker()

    try:
        start_ea = _resolve_addr(start)
        end_ea = _resolve_addr(end)
        result = maker.make_signature(start_ea, cfg, end=end_ea)
        sig_str = _format_sig(result.signature, fmt)
        is_unique = sm.SignatureSearcher.is_unique(f"{result.signature:ida}")
        return {
            "query": f"{start}-{end}",
            "addr": hex(start_ea),
            "signature": sig_str,
            "format": format,
            "unique": is_unique,
        }
    except Exception as e:
        return {
            "query": f"{start}-{end}",
            "addr": None,
            "signature": None,
            "format": format,
            **item_error(e),
        }


@tool
@idasync
def find_xref_signatures(
    addrs: Annotated[
        list[str] | str,
        "Address(es) or name(s) to find XREF signatures for "
        "(e.g. a data address referenced by code)",
    ],
    format: Annotated[
        str,
        "Output format: 'ida' (default), 'x64dbg', 'mask', or 'bitmask'",
    ] = "ida",
    top: Annotated[
        int,
        "Number of shortest signatures to return per address (default: 5)",
    ] = 5,
    max_length: Annotated[
        int,
        "Maximum signature length in bytes (default: 250)",
    ] = 250,
) -> list[XrefSigResult]:
    """Find signatures for code locations that reference an address. For each
    input address, finds all code cross-references TO it, generates a unique
    signature at each xref site, and returns the shortest ones. Ideal for
    creating signatures for data addresses, vtable entries, or string
    references that can't be signatured directly."""
    sm = _sm
    fmt = _resolve_format(format)
    cfg = _make_config(fmt, max_length=max_length)
    import dataclasses
    cfg = dataclasses.replace(cfg, print_top_x=top)
    finder = sm.XrefFinder()
    addrs_list = normalize_list_input(addrs)

    results: list[XrefSigResult] = []
    for addr_str in addrs_list:
        ea = None
        try:
            ea = _resolve_addr(addr_str)
            xref_result = finder.find_xrefs(ea, cfg)

            sigs = []
            for gs in xref_result.signatures[:top]:
                sig_str = _format_sig(gs.signature, fmt)
                sigs.append({
                    "xref_addr": hex(int(gs.address)) if gs.address else None,
                    "signature": sig_str,
                    "length": len(gs.signature),
                })

            results.append({
                "query": addr_str,
                "addr": hex(ea),
                "signatures": sigs,
                "total_xrefs": len(xref_result.signatures),
            })
        except Exception as e:
            results.append({
                "query": addr_str,
                "addr": hex(ea) if ea is not None else None,
                "signatures": None,
                **item_error(e),
            })
    return results


# ---------------------------------------------------------------------------
# Signature scanning
# ---------------------------------------------------------------------------


class ScanMatch(TypedDict):
    addr: str


class ScanSignatureResult(TypedDict, total=False):
    ok: bool
    pattern: str
    match_count: int
    truncated: bool
    matches: list[ScanMatch]
    error: str
    error_type: str
    hint: str


@tool
@idasync
def scan_signature(
    pattern: Annotated[
        str,
        "Byte pattern to search for. Accepts IDA format ('E8 ? ? ? ? 90'), "
        "x64dbg format, or hex string. Use ? or ?? as wildcards.",
    ],
    max_results: Annotated[int, "Maximum number of match addresses to return (default 200)"] = 200,
) -> ScanSignatureResult:
    """Scan the loaded binary for all occurrences of a byte pattern.

    Returns each matching address. Wildcards (? or ??) skip individual bytes.

    Examples:
      'E8 ? ? ? ? 90'   — call followed by NOP
      'FF 25 ?? ?? ?? ??' — indirect jump (x64 style)
    """
    try:
        if not pattern.strip():
            return {"ok": False, "error": "Pattern must not be empty"}

        searcher = _sm.SignatureSearcher.from_signature(pattern.strip())
        results = searcher.search()

        all_matches = results.matches
        truncated = len(all_matches) > max_results
        matches = [{"addr": hex(m.address)} for m in all_matches[:max_results]]

        return {
            "ok": True,
            "pattern": pattern.strip(),
            "match_count": len(all_matches),
            "truncated": truncated,
            "matches": matches,
        }
    except Exception as e:
        return tool_error(e)
