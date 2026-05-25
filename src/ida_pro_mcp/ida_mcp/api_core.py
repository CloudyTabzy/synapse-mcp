"""Core API Functions - IDB metadata and basic queries"""

import ast
import logging
import re
import time
from typing import Annotated, Any, NotRequired, TypedDict

import ida_auto
import ida_bytes
import idaapi
import ida_funcs
import ida_hexrays
import ida_lines
import ida_search
import ida_segment
import idautils
import ida_loader
import ida_nalt
import ida_typeinf
import ida_name
import idc

import json

from .rpc import tool, get_cached_output, MCP_PROFILES
from .sync import idasync, IDAError
from .utils import (
    tool_error,
    item_error,
    ConvertedNumber,
    EntityQuery,
    Function,
    FunctionQuery,
    Global,
    Import,
    ListQuery,
    NumberConversion,
    Page,
    ImportQuery,
    get_function,
    get_prototype,
    normalize_dict_list,
    normalize_list_input,
    parse_address,
    paginate,
    pattern_filter,
)


logger = logging.getLogger(__name__)


class ServerHealthResult(TypedDict):
    status: str
    uptime_sec: float
    idb_path: str | None
    module: str
    input_path: str
    imagebase: str
    auto_analysis_ready: bool | None
    hexrays_ready: bool
    strings_cache_ready: bool
    strings_cache_size: int
    profiles: NotRequired[dict[str, int]]


class ServerWarmupStep(TypedDict, total=False):
    step: str
    ok: bool
    ms: float
    error: str


class ServerWarmupResult(TypedDict):
    ok: bool
    steps: list[ServerWarmupStep]
    health: ServerHealthResult


class LookupFuncResult(TypedDict):
    query: str
    fn: Function | None
    error: str | None
    error_type: NotRequired[str]
    hint: NotRequired[str]


class IntConvertResult(TypedDict):
    input: str
    result: ConvertedNumber | None
    error: str | None


class FunctionQueryRow(Function, total=False):
    has_type: bool
    size_int: int


class FunctionQueryPage(TypedDict, total=False):
    data: list[FunctionQueryRow]
    next_offset: int | None
    total: int
    error: str | None


class EntityQueryPage(TypedDict, total=False):
    kind: str
    data: list[dict[str, Any]]
    next_offset: int | None
    total: int
    error: str | None


class ImportsQueryPage(TypedDict):
    data: list[Import]
    next_offset: int | None
    total: int


class IdbSaveResult(TypedDict):
    ok: bool
    path: str | None
    error: NotRequired[str]
    error_type: NotRequired[str]
    hint: NotRequired[str]


class DemangleEntry(TypedDict, total=False):
    raw: str
    demangled: str | None
    demangled_short: str | None
    mangling_type: str   # "msvc" | "itanium" | "plain"
    success: bool


class DemangleResult(TypedDict, total=False):
    ok: bool
    results: list[DemangleEntry]
    success_count: int
    fail_count: int
    error: str
    error_type: str


class FindRegexResult(TypedDict, total=False):
    n: int
    total: int            # total candidates before pagination
    matches: list[dict[str, Any]]
    cursor: dict[str, Any]
    error: str | None
    error_type: str
    hint: str


class SearchTextLine(TypedDict, total=False):
    kind: str  # "disasm" | "comment"
    text: str


class SearchTextHit(TypedDict, total=False):
    addr: str
    function: str
    segment: str
    matches: list[SearchTextLine]


class SearchTextResult(TypedDict, total=False):
    n: int
    hits: list[SearchTextHit]
    cursor: dict[str, Any]
    error: str
    error_type: str
    hint: str


# Cached strings list: [(ea, text), ...]
_strings_cache: list[tuple[int, str]] | None = None
_server_started_at = time.time()


def _get_strings_cache() -> list[tuple[int, str]]:
    """Get cached strings, building cache on first access."""
    global _strings_cache
    if _strings_cache is None:
        _strings_cache = [(s.ea, str(s)) for s in idautils.Strings() if s is not None]
    return _strings_cache


def invalidate_strings_cache():
    """Clear the strings cache (call after IDB changes)."""
    global _strings_cache
    _strings_cache = None


def init_caches():
    """Build caches on plugin startup (called from Ctrl+M)."""
    t0 = time.perf_counter()
    strings = _get_strings_cache()
    t1 = time.perf_counter()
    logger.info("[MCP] Cached %d strings in %.0fms", len(strings), (t1 - t0) * 1000)


# ============================================================================
# Core API Functions
# ============================================================================


def _parse_func_query(query: str) -> int:
    """Fast path for common function query patterns. Returns ea or BADADDR."""
    q = query.strip()

    # 0x<hex> - direct address
    if q.startswith("0x") or q.startswith("0X"):
        try:
            return int(q, 16)
        except ValueError:
            pass

    # sub_<hex> - IDA auto-named function
    if q.startswith("sub_"):
        try:
            return int(q[4:], 16)
        except ValueError:
            pass

    return idaapi.BADADDR


def _coerce_sort_number(value, default: int = 0) -> int:
    """Parse decimal or prefixed string numbers used by generic entity rows."""
    if value in (None, ""):
        return default
    if isinstance(value, int):
        return value
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return default


def _collect_imports() -> list[Import]:
    """Collect all imports in the current database."""
    all_imports: list[Import] = []
    nimps = ida_nalt.get_import_module_qty()

    for i in range(nimps):
        module_name = ida_nalt.get_import_module_name(i)
        if not module_name:
            module_name = "<unnamed>"

        def imp_cb(ea, symbol_name, ordinal, acc):
            if not symbol_name:
                symbol_name = f"#{ordinal}"
            acc += [Import(addr=hex(ea), imported_name=symbol_name, module=module_name)]
            return True

        def imp_cb_w_context(ea, symbol_name, ordinal):
            return imp_cb(ea, symbol_name, ordinal, all_imports)

        ida_nalt.enum_import_names(i, imp_cb_w_context)

    return all_imports


def _segment_name_for_ea(ea: int) -> str | None:
    seg = idaapi.getseg(ea)
    if not seg:
        return None
    try:
        return idaapi.get_segm_name(seg)
    except Exception:
        return None


def _primary_text_key(kind: str) -> str:
    if kind == "strings":
        return "text"
    return "name"


def _collect_entities(kind: str) -> list[dict]:
    if kind == "functions":
        rows: list[dict] = []
        for ea in idautils.Functions():
            fn = idaapi.get_func(ea)
            if not fn:
                continue
            size_int = fn.end_ea - fn.start_ea
            rows.append(
                {
                    "kind": "function",
                    "addr": hex(fn.start_ea),
                    "name": ida_funcs.get_func_name(fn.start_ea) or "<unnamed>",
                    "size": hex(size_int),
                    "size_int": size_int,
                    "segment": _segment_name_for_ea(fn.start_ea),
                    "has_type": bool(ida_nalt.get_tinfo(ida_typeinf.tinfo_t(), fn.start_ea)),
                }
            )
        return rows

    if kind == "globals":
        rows = []
        for ea, name in idautils.Names():
            if idaapi.get_func(ea) or name is None:
                continue
            rows.append(
                {
                    "kind": "global",
                    "addr": hex(ea),
                    "name": name,
                    "size": idc.get_item_size(ea),
                    "segment": _segment_name_for_ea(ea),
                }
            )
        return rows

    if kind == "imports":
        rows = []
        for imp in _collect_imports():
            rows.append(
                {
                    "kind": "import",
                    "addr": imp["addr"],
                    "name": imp["imported_name"],
                    "module": imp["module"],
                }
            )
        return rows

    if kind == "strings":
        rows = []
        for ea, text in _get_strings_cache():
            rows.append(
                {
                    "kind": "string",
                    "addr": hex(ea),
                    "text": text,
                    "length": len(text),
                    "segment": _segment_name_for_ea(ea),
                }
            )
        return rows

    if kind == "names":
        rows = []
        imports_by_ea = {int(imp["addr"], 16): imp for imp in _collect_imports()}
        for ea, name in idautils.Names():
            is_function = bool(idaapi.get_func(ea))
            is_import = ea in imports_by_ea
            rows.append(
                {
                    "kind": "name",
                    "addr": hex(ea),
                    "name": name,
                    "segment": _segment_name_for_ea(ea),
                    "is_function": is_function,
                    "is_import": is_import,
                }
            )
        return rows

    return []


def _apply_projection(items: list[dict], fields: list[str] | None) -> list[dict]:
    if not fields:
        return items
    normalized = [str(f).strip() for f in fields if str(f).strip()]
    if not normalized:
        return items
    keep = set(normalized)
    keep.add("kind")
    projected = []
    for item in items:
        projected.append({k: v for k, v in item.items() if k in keep})
    return projected


def _build_health_payload() -> dict:
    auto_is_ok = getattr(ida_auto, "auto_is_ok", None)
    auto_analysis_ready = bool(auto_is_ok()) if callable(auto_is_ok) else None

    hexrays_ready = False
    try:
        hexrays_ready = bool(ida_hexrays.init_hexrays_plugin())
    except Exception:
        hexrays_ready = False

    idb_path = None
    try:
        idb_path = idc.get_idb_path()
    except Exception:
        idb_path = None

    result: dict = {
        "status": "ok",
        "uptime_sec": round(time.time() - _server_started_at, 3),
        "idb_path": idb_path,
        "module": ida_nalt.get_root_filename(),
        "input_path": ida_nalt.get_input_file_path(),
        "imagebase": hex(idaapi.get_imagebase()),
        "auto_analysis_ready": auto_analysis_ready,
        "hexrays_ready": hexrays_ready,
        "strings_cache_ready": _strings_cache is not None,
        "strings_cache_size": len(_strings_cache) if _strings_cache is not None else 0,
    }
    if MCP_PROFILES:
        result["profiles"] = {
            name: len(tools) for name, tools in sorted(MCP_PROFILES.items())
        }
    return result


@tool
@idasync
def server_health() -> ServerHealthResult:
    """Health/ready probe for MCP server and current IDB state.

    Profile: core
    """
    return _build_health_payload()


@tool
@idasync
def server_warmup(
    wait_auto_analysis: Annotated[bool, "Wait for auto analysis queue"] = True,
    build_caches: Annotated[bool, "Build core caches (currently strings)"] = True,
    init_hexrays: Annotated[bool, "Initialize Hex-Rays decompiler plugin"] = True,
) -> ServerWarmupResult:
    """Warm up IDA subsystems to reduce first-call latency and transient failures."""
    steps = []

    if wait_auto_analysis:
        t0 = time.perf_counter()
        ida_auto.auto_wait()
        steps.append(
            {
                "step": "auto_wait",
                "ok": True,
                "ms": round((time.perf_counter() - t0) * 1000, 2),
            }
        )

    if build_caches:
        t0 = time.perf_counter()
        init_caches()
        steps.append(
            {
                "step": "init_caches",
                "ok": True,
                "ms": round((time.perf_counter() - t0) * 1000, 2),
            }
        )

    if init_hexrays:
        t0 = time.perf_counter()
        ok = bool(ida_hexrays.init_hexrays_plugin())
        step = {
            "step": "init_hexrays",
            "ok": ok,
            "ms": round((time.perf_counter() - t0) * 1000, 2),
        }
        if not ok:
            step["error"] = "Hex-Rays unavailable"
        steps.append(step)

    return {
        "ok": all(bool(step.get("ok")) for step in steps),
        "steps": steps,
        "health": _build_health_payload(),
    }


@tool
@idasync
def lookup_funcs(
    queries: Annotated[list[str] | str, "Address(es) or name(s)"],
) -> list[LookupFuncResult]:
    """Get functions by address or name (auto-detects)"""
    queries = normalize_list_input(queries)

    # Treat empty/"*" as "all functions" - but add limit
    if not queries or (len(queries) == 1 and queries[0] in ("*", "")):
        all_funcs = []
        for addr in idautils.Functions():
            all_funcs.append(get_function(addr))
            if len(all_funcs) >= 1000:
                break
        return [{"query": "*", "fn": fn, "error": None} for fn in all_funcs]

    results = []
    for query in queries:
        try:
            # Fast path: 0x<ea> or sub_<ea>
            ea = _parse_func_query(query)

            # Slow path: name lookup
            if ea == idaapi.BADADDR:
                ea = idaapi.get_name_ea(idaapi.BADADDR, query)

            if ea != idaapi.BADADDR:
                func = get_function(ea, raise_error=False)
                if func:
                    results.append({"query": query, "fn": func, "error": None})
                else:
                    results.append(
                        {"query": query, "fn": None, "error": "Not a function"}
                    )
            else:
                results.append({"query": query, "fn": None, "error": "Not found"})
        except Exception as e:
            results.append({"query": query, "fn": None, **item_error(e, f"lookup {query!r}")})

    return results


def _eval_int_expression(text: str) -> int:
    """Safely evaluate a numeric expression containing bitwise operators.

    Falls back to plain int() for simple literals. For expressions like
    '0x3e ^ 0x5d' or '(0x10 << 2) | 3', parses via ast and evaluates with
    a restricted namespace (no builtins, no calls, no attribute access).
    """
    # 1) Plain literal (hex, dec, oct, bin)
    try:
        return int(text, 0)
    except ValueError:
        pass

    # 2) Expression — validate AST, then eval safely
    try:
        tree = ast.parse(text.strip(), mode="eval")
    except SyntaxError as exc:
        raise ValueError(f"Invalid expression: {text}") from exc

    _ALLOWED = (
        ast.Expression,
        ast.BinOp,
        ast.UnaryOp,
        ast.Constant,
        ast.Add,
        ast.Sub,
        ast.Mult,
        ast.FloorDiv,
        ast.Mod,
        ast.Pow,
        ast.LShift,
        ast.RShift,
        ast.BitOr,
        ast.BitXor,
        ast.BitAnd,
        ast.Invert,
        ast.USub,
        ast.UAdd,
    )
    for node in ast.walk(tree):
        if not isinstance(node, _ALLOWED):
            raise ValueError(
                f"Unsupported element in expression: {type(node).__name__}"
            )

    result = eval(compile(tree, "<string>", "eval"), {"__builtins__": {}}, {})
    return int(result)


@tool
def int_convert(
    inputs: Annotated[
        list[NumberConversion] | NumberConversion,
        "Convert numbers to various formats (hex, decimal, binary, ascii). "
        "Supports basic arithmetic and bitwise expressions: + - * // % ** "
        "<< >> & | ^ ~.",
    ],
) -> list[IntConvertResult]:
    """Convert numbers to different formats. Supports expressions like 0x3e ^ 0x5d."""
    inputs = normalize_dict_list(inputs, lambda s: {"text": s, "size": 64})

    results = []
    for item in inputs:
        text = item.get("text", "")
        size = item.get("size")

        try:
            value = _eval_int_expression(text)
        except Exception as exc:
            results.append(
                {"input": text, "result": None, "error": f"Invalid number: {exc}"}
            )
            continue

        if not size:
            size = 0
            n = abs(value)
            while n:
                size += 1
                n >>= 1
            size += 7
            size //= 8

        try:
            bytes_data = value.to_bytes(size, "little", signed=True)
        except OverflowError:
            results.append(
                {
                    "input": text,
                    "result": None,
                    "error": f"Number {text} is too big for {size} bytes",
                }
            )
            continue

        ascii_str = ""
        for byte in bytes_data.rstrip(b"\x00"):
            if byte >= 32 and byte <= 126:
                ascii_str += chr(byte)
            else:
                ascii_str = None
                break

        results.append(
            {
                "input": text,
                "result": ConvertedNumber(
                    decimal=str(value),
                    hexadecimal=hex(value),
                    bytes=bytes_data.hex(" "),
                    ascii=ascii_str,
                    binary=bin(value),
                ),
                "error": None,
            }
        )

    return results


@tool
@idasync
def demangle_names(
    names: Annotated[
        list[str] | str,
        "One or more mangled C++ symbol names to demangle. "
        "Accepts MSVC ?-mangled names (e.g. '??0FString@@QAE@XZ') and "
        "Itanium/GCC _Z-mangled names (e.g. '_ZN3FooC1Ev'). "
        "Plain names are passed through as-is with success=false.",
    ],
) -> DemangleResult:
    """Batch-demangle C++ symbol names using IDA Pro's built-in demangler.

    Returns both a long form (full type signature with return type and calling
    convention) and a short form (ClassName::method only) for each name.
    IDA's demangler handles MSVC ?-mangled names (Engine.dll, Core.dll, etc.)
    and Itanium _Z-mangled names (Linux shared libraries).

    Use this tool when you have a list of mangled names from any source
    (vtable dumps, export tables, YARA matches, memory scans) and need
    human-readable class::method names for analysis or documentation.

    Profile: analysis
    """
    try:
        name_list = normalize_list_input(names)
        entries: list[DemangleEntry] = []
        success_count = 0
        fail_count = 0

        for raw in name_list:
            if not raw or not isinstance(raw, str):
                entries.append({"raw": str(raw), "demangled": None, "demangled_short": None,
                                 "mangling_type": "plain", "success": False})
                fail_count += 1
                continue

            # Detect mangling convention from name prefix
            if raw.startswith("?"):
                mangling_type = "msvc"
            elif raw.startswith("_Z") or raw.startswith("__Z"):
                mangling_type = "itanium"
            else:
                mangling_type = "plain"

            # Long form: full signature with return type and calling convention
            long_form: str | None = None
            try:
                r = ida_name.demangle_name(raw, ida_name.MNG_LONG_FORM)
                if r and r != raw:
                    long_form = r
            except Exception:
                pass

            # Short form: class::method without return type or calling convention.
            # MNG_NODEFINIT (0x8) + MNG_NORETTYPE (0x80) suppress those parts.
            # MNG_NORETTYPE may not be present on all IDA versions; fall back to 0x80.
            _MNG_NORETTYPE = getattr(ida_name, "MNG_NORETTYPE", 0x80)
            short_form: str | None = None
            try:
                r = ida_name.demangle_name(raw, ida_name.MNG_NODEFINIT | _MNG_NORETTYPE)
                if r and r != raw:
                    short_form = r
            except Exception:
                pass

            # If IDA couldn't produce a distinct short form, derive it from the
            # long form by stripping access specifier + return type prefix
            # (everything before the last token that contains "::").
            if long_form and not short_form:
                # e.g. "public: void __thiscall Foo::Bar(int)" → "Foo::Bar(int)"
                paren = long_form.find("(")
                prefix = long_form[:paren] if paren != -1 else long_form
                tokens = prefix.split()
                for i, tok in enumerate(tokens):
                    if "::" in tok:
                        short_form = " ".join(tokens[i:])
                        if paren != -1:
                            short_form += long_form[paren:]
                        break

            success = long_form is not None or short_form is not None
            if success:
                success_count += 1
            else:
                fail_count += 1

            entries.append({
                "raw": raw,
                "demangled": long_form,
                "demangled_short": short_form,
                "mangling_type": mangling_type,
                "success": success,
            })

        return {
            "ok": True,
            "results": entries,
            "success_count": success_count,
            "fail_count": fail_count,
        }
    except Exception as e:
        return {**tool_error(e), "ok": False}


@tool
@idasync
def list_funcs(
    queries: Annotated[
        list[ListQuery] | ListQuery,
        "List functions with optional filtering and pagination",
    ],
) -> list[Page[Function]]:
    """List functions with optional filtering and offset/count pagination."""
    queries = normalize_dict_list(queries)
    all_functions = [get_function(addr) for addr in idautils.Functions()]

    results = []
    for query in queries:
        offset = query.get("offset", 0)
        count = query.get("count", 100)
        filter_pattern = query.get("filter", "")

        # Treat empty/"*" filter as "all"
        if filter_pattern in ("", "*"):
            filter_pattern = ""

        filtered = pattern_filter(all_functions, filter_pattern, "name")
        results.append(paginate(filtered, offset, count))

    return results


@tool
@idasync
def list_functions_enhanced(
    filter: Annotated[str, "Glob filter on function name (empty = all)"] = "",
    offset: Annotated[int, "Start index for pagination (default: 0)"] = 0,
    count: Annotated[int, "Max functions to return (default: 100, 0 = all)"] = 100,
    include_prototype: Annotated[
        bool,
        "Include type/prototype string per function. Slower — skips IDB-untyped functions.",
    ] = False,
) -> dict:
    """List functions with extended classification flags.

    Returns ``is_thunk``, ``is_library``, ``is_noret``, ``has_prototype``, and
    ``is_external`` per function — flags that ``list_funcs`` omits.  Aggregate
    counts in the top-level result let you gauge annotation coverage at a glance.

    Profile: core
    """
    try:
        all_items: list[dict] = []
        for start_ea in idautils.Functions():
            fn = idaapi.get_func(start_ea)
            if not fn:
                continue
            flags = fn.flags
            name = ida_funcs.get_func_name(start_ea) or f"sub_{start_ea:X}"
            has_type = bool(ida_nalt.get_tinfo(ida_typeinf.tinfo_t(), start_ea))
            item: dict = {
                "addr": hex(start_ea),
                "name": name,
                "size": hex(fn.end_ea - start_ea),
                "is_thunk": bool(flags & ida_funcs.FUNC_THUNK),
                "is_library": bool(flags & ida_funcs.FUNC_LIB),
                "is_noret": bool(flags & ida_funcs.FUNC_NORET),
                "has_prototype": has_type,
                "is_external": False,
            }
            try:
                seg = idaapi.getseg(start_ea)
                if seg and (
                    seg.type == idaapi.SEG_XTRN
                    or any(
                        n in (idc.get_segm_name(start_ea) or "").lower()
                        for n in (".plt", ".idata", "__stubs", "extern")
                    )
                ):
                    item["is_external"] = True
            except Exception:
                pass
            if include_prototype:
                item["prototype"] = get_prototype(fn) if has_type else None
            all_items.append(item)

        filtered = pattern_filter(all_items, filter, "name") if filter and filter not in ("*", "") else all_items
        page = paginate(filtered, offset, count if count > 0 else len(filtered))
        return {
            "ok": True,
            **page,
            "total_functions": len(filtered),
            "thunk_count": sum(1 for r in all_items if r.get("is_thunk")),
            "library_count": sum(1 for r in all_items if r.get("is_library")),
            "noret_count": sum(1 for r in all_items if r.get("is_noret")),
            "typed_count": sum(1 for r in all_items if r.get("has_prototype")),
            "external_count": sum(1 for r in all_items if r.get("is_external")),
        }
    except Exception as e:
        return tool_error(e, context="list_functions_enhanced")


@tool
@idasync
def list_classes(
    filter: Annotated[str, "Glob filter on class/namespace name (empty = all)"] = "",
    offset: Annotated[int, "Start index (default: 0)"] = 0,
    count: Annotated[int, "Max classes to return (default: 100, 0 = all)"] = 100,
    min_methods: Annotated[int, "Minimum method count to include a class (default: 1)"] = 1,
    include_methods: Annotated[
        bool, "Include per-class method list (default: True)"
    ] = True,
) -> dict:
    """Extract class and namespace names from IDB symbols.

    Scans all named addresses for C++ mangling patterns (``::`` separator,
    ``_ZN``/``??`` prefixes) and groups methods by their class prefix.  Works
    on any binary where RTTI, PDB symbols, or user renaming has introduced
    ``ClassName::method`` style names.

    Profile: core
    """
    try:
        class_map: dict[str, list[dict]] = {}
        for ea, raw_name in idautils.Names():
            if not raw_name:
                continue
            demangled = (
                ida_name.demangle_name(raw_name, ida_name.MNG_LONG_FORM) or raw_name
            )
            if "::" not in demangled:
                continue
            # Strip argument list to get the "ReturnType Class::method" prefix
            name_part = demangled.split("(")[0].rstrip()
            last_sep = name_part.rfind("::")
            if last_sep < 0:
                continue
            raw_class = name_part[:last_sep].strip()
            method_short = name_part[last_sep + 2:].strip()
            # Strip leading return-type words (e.g. "int" in "int ClassName")
            ws = raw_class.rfind(" ")
            class_name = raw_class[ws + 1:] if ws >= 0 else raw_class
            if not class_name or not method_short:
                continue
            entry = {
                "addr": hex(ea),
                "name": demangled,
                "short_name": method_short,
            }
            class_map.setdefault(class_name, []).append(entry)

        classes: list[dict] = []
        for cls_name, methods in sorted(class_map.items(), key=lambda x: x[0].lower()):
            if len(methods) < min_methods:
                continue
            rec: dict = {
                "class_name": cls_name,
                "method_count": len(methods),
            }
            if include_methods:
                rec["methods"] = sorted(methods, key=lambda m: m["short_name"])
            classes.append(rec)

        filtered_cls = (
            pattern_filter(classes, filter, "class_name")
            if filter and filter not in ("*", "")
            else classes
        )
        total = len(filtered_cls)
        page = paginate(filtered_cls, offset, count if count > 0 else total)
        return {
            "ok": True,
            **page,
            "total_classes": total,
        }
    except Exception as e:
        return tool_error(e, context="list_classes")


@tool
@idasync
def func_query(
    queries: Annotated[
        list[FunctionQuery] | FunctionQuery,
        "Richer function query (size/type/name filters + pagination)",
    ],
) -> list[FunctionQueryPage]:
    """Query functions with richer filtering than list_funcs."""
    queries = normalize_dict_list(queries)

    all_functions: list[dict] = []
    for addr in idautils.Functions():
        fn = idaapi.get_func(addr)
        if not fn:
            continue
        size_int = fn.end_ea - fn.start_ea
        fn_name = ida_funcs.get_func_name(fn.start_ea) or "<unnamed>"
        has_type = ida_nalt.get_tinfo(ida_typeinf.tinfo_t(), fn.start_ea)
        all_functions.append(
            {
                "addr": hex(fn.start_ea),
                "name": fn_name,
                "size": hex(size_int),
                "size_int": size_int,
                "has_type": has_type,
            }
        )

    def apply_name_regex(items: list[dict], expr: str) -> list[dict]:
        if not expr:
            return items
        try:
            compiled = re.compile(expr)
        except re.error:
            return []
        return [item for item in items if compiled.search(item["name"])]

    results = []
    for query in queries:
        offset = query.get("offset", 0)
        count = query.get("count", 50)
        sort_by = query.get("sort_by", "addr")
        descending = bool(query.get("descending", False))
        if sort_by not in ("addr", "name", "size"):
            sort_by = "addr"

        filtered = all_functions
        name_filter = query.get("filter", "")
        if name_filter:
            filtered = pattern_filter(filtered, name_filter, "name")

        name_regex = query.get("name_regex", "")
        if name_regex:
            filtered = apply_name_regex(filtered, name_regex)

        min_size = query.get("min_size")
        if min_size is not None:
            filtered = [f for f in filtered if f["size_int"] >= int(min_size)]

        max_size = query.get("max_size")
        if max_size is not None:
            filtered = [f for f in filtered if f["size_int"] <= int(max_size)]

        if "has_type" in query:
            require_type = bool(query.get("has_type"))
            filtered = [f for f in filtered if bool(f["has_type"]) is require_type]

        if sort_by == "name":
            filtered.sort(key=lambda f: f["name"].lower(), reverse=descending)
        elif sort_by == "size":
            filtered.sort(key=lambda f: f["size_int"], reverse=descending)
        else:
            filtered.sort(key=lambda f: int(f["addr"], 16), reverse=descending)

        page = paginate(filtered, offset, count)
        page["data"] = [{k: v for k, v in item.items() if k != "size_int"} for item in page["data"]]
        results.append(page)

    return results


@tool
@idasync
def list_globals(
    queries: Annotated[
        list[ListQuery] | ListQuery,
        "List global variables with optional filtering and pagination",
    ],
) -> list[Page[Global]]:
    """List globals with optional filtering and offset/count pagination."""
    queries = normalize_dict_list(queries)
    all_globals: list[Global] = []
    for addr, name in idautils.Names():
        if not idaapi.get_func(addr) and name is not None:
            all_globals.append(Global(addr=hex(addr), name=name))

    results = []
    for query in queries:
        offset = query.get("offset", 0)
        count = query.get("count", 100)
        filter_pattern = query.get("filter", "")

        # Treat empty/"*" filter as "all"
        if filter_pattern in ("", "*"):
            filter_pattern = ""

        filtered = pattern_filter(all_globals, filter_pattern, "name")
        results.append(paginate(filtered, offset, count))

    return results


@tool
@idasync
def entity_query(
    queries: Annotated[
        list[EntityQuery] | EntityQuery,
        "Generic entity query with filtering, projection, and pagination",
    ],
) -> list[EntityQueryPage]:
    """Query IDB entities with typed filters, projection, and pagination."""
    queries = normalize_dict_list(queries)
    results: list[dict] = []

    for query in queries:
        kind = str(query.get("kind", "functions") or "functions").lower()
        if kind not in {"functions", "globals", "imports", "strings", "names"}:
            results.append(
                {
                    "kind": kind,
                    "data": [],
                    "next_offset": None,
                    "total": 0,
                    "error": f"Unsupported kind: {kind}",
                }
            )
            continue

        rows = _collect_entities(kind)
        primary_key = _primary_text_key(kind)
        filter_pattern = str(query.get("filter", "") or "")
        if filter_pattern:
            rows = pattern_filter(rows, filter_pattern, primary_key)

        regex = str(query.get("regex", "") or "")
        if regex:
            try:
                compiled = re.compile(regex)
                rows = [row for row in rows if compiled.search(str(row.get(primary_key, "")))]
            except re.error:
                rows = []

        segment_filter = str(query.get("segment", "") or "")
        if segment_filter and kind in {"functions", "globals", "strings", "names"}:
            rows = pattern_filter(rows, segment_filter, "segment")

        module_filter = str(query.get("module", "") or "")
        if module_filter and kind == "imports":
            rows = pattern_filter(rows, module_filter, "module")

        min_addr = query.get("min_addr")
        if min_addr not in (None, ""):
            try:
                min_ea = parse_address(min_addr)
                rows = [row for row in rows if int(str(row["addr"]), 16) >= min_ea]
            except Exception:
                rows = []

        max_addr = query.get("max_addr")
        if max_addr not in (None, ""):
            try:
                max_ea = parse_address(max_addr)
                rows = [row for row in rows if int(str(row["addr"]), 16) <= max_ea]
            except Exception:
                rows = []

        sort_by = str(query.get("sort_by", "addr") or "addr")
        descending = bool(query.get("descending", False))
        if sort_by == "addr":
            rows.sort(key=lambda row: int(str(row.get("addr", "0x0")), 16), reverse=descending)
        elif sort_by in {"size", "length"}:
            rows.sort(
                key=lambda row: row.get("size_int", _coerce_sort_number(row.get(sort_by, 0))),
                reverse=descending,
            )
        else:
            rows.sort(key=lambda row: str(row.get(sort_by, "")).lower(), reverse=descending)

        offset = int(query.get("offset", 0) or 0)
        count = int(query.get("count", 100) or 100)
        page = paginate(rows, offset, count)
        data = [{k: v for k, v in item.items() if k != "size_int"} for item in page["data"]]

        fields_raw = query.get("fields")
        fields = None
        if fields_raw is not None:
            if isinstance(fields_raw, str):
                fields = normalize_list_input(fields_raw)
            elif isinstance(fields_raw, list):
                fields = [str(f) for f in fields_raw]
            else:
                fields = [str(fields_raw)]
        data = _apply_projection(data, fields)

        results.append(
            {
                "kind": kind,
                "data": data,
                "next_offset": page["next_offset"],
                "total": len(rows),
                "error": None,
            }
        )

    return results


@tool
@idasync
def imports(
    offset: Annotated[int, "Starting pagination index (default: 0)"],
    count: Annotated[int, "Maximum rows (0 returns all imports)"],
) -> Page[Import]:
    """List imports with module names using offset/count pagination."""
    return paginate(_collect_imports(), offset, count)


@tool
@idasync
def imports_query(
    queries: Annotated[
        list[ImportQuery] | ImportQuery,
        "Import query with import/module filters and pagination",
    ],
) -> list[ImportsQueryPage]:
    """Query imports with richer filtering than imports(offset,count)."""
    queries = normalize_dict_list(queries)
    all_imports = _collect_imports()
    results = []

    for query in queries:
        filtered = all_imports
        name_filter = query.get("filter", "")
        module_filter = query.get("module", "")

        if name_filter:
            filtered = pattern_filter(filtered, name_filter, "imported_name")
        if module_filter:
            filtered = pattern_filter(filtered, module_filter, "module")

        results.append(
            paginate(filtered, query.get("offset", 0), query.get("count", 100))
        )

    return results


@tool
@idasync
def idb_save(
    path: Annotated[str, "Optional destination path (default: current IDB path)"] = "",
) -> IdbSaveResult:
    """Save active IDB to disk, optionally to a provided path."""
    try:
        save_path = path.strip() if path else ""
        if not save_path:
            save_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
        if not save_path:
            return {"ok": False, "path": None, "error": "Could not resolve IDB path"}

        ok = bool(ida_loader.save_database(save_path, 0))
        result: dict = {"ok": ok, "path": save_path}
        if not ok:
            result["error"] = "save_database returned false"
        return result
    except Exception as e:
        return {**tool_error(e), "path": path or None}


@tool
@idasync
def find_regex(
    pattern: Annotated[str, "Regex pattern to search for in strings"],
    limit: Annotated[int, "Max matches (default: 50, max: 500)"] = 50,
    offset: Annotated[int, "Skip first N matches (default: 0)"] = 0,
    search_strings: Annotated[bool, "Search string literals (default: true)"] = True,
    search_names: Annotated[bool, "Search function and symbol names (default: true)"] = True,
    scan_raw: Annotated[
        bool,
        "Also scan raw bytes of data segments for matches not in IDA's string table. "
        "Useful for encrypted/packed regions or unpacked shellcode where IDA has not "
        "yet defined string items. Slower; use only when normal string search is empty.",
    ] = False,
) -> FindRegexResult:
    """Search by case-insensitive regex across string literals and symbol names.

    By default searches both the string table (literal char* data) and all named
    symbols (functions, globals, labels). Use ``search_strings``/``search_names`` to
    narrow the scope.

    For searching the **disassembly listing or comments**, use ``search_text`` instead.
    For searching **raw bytes in data segments** (e.g. decrypted regions where IDA has
    not created string items), set ``scan_raw=true``.
    """
    if limit <= 0:
        limit = 50
    if limit > 500:
        limit = 500

    try:
        regex = re.compile(pattern, re.IGNORECASE)
    except re.error as e:
        return {"n": 0, "matches": [], "cursor": {"done": True}, "error": f"Invalid regex: {e}"}

    # Collect all candidates in a single ordered pass, then paginate.
    # Each entry: {"addr": hex, "text": str, "kind": "string"|"name"|"raw"}
    candidates: list[dict] = []
    seen_addrs: set[str] = set()

    if search_strings:
        for ea, text in _get_strings_cache():
            if regex.search(text):
                addr_hex = hex(ea)
                candidates.append({"addr": addr_hex, "text": text, "kind": "string"})
                seen_addrs.add(addr_hex)

    if search_names:
        for name_ea, name in idautils.Names():
            if name and regex.search(name):
                addr_hex = hex(name_ea)
                if addr_hex not in seen_addrs:
                    candidates.append({"addr": addr_hex, "text": name, "kind": "name"})
                    seen_addrs.add(addr_hex)

    if scan_raw:
        # Scan data segments for raw byte matches not in the string table
        _RAW_SCAN_CAP_PER_SEG = 16 * 1024 * 1024  # 16 MiB per segment
        for seg_ea in idautils.Segments():
            seg = idaapi.getseg(seg_ea)
            if not seg or seg.size() < 4:
                continue
            try:
                seg_size = min(int(seg.size()), _RAW_SCAN_CAP_PER_SEG)
                data = idaapi.get_bytes(seg.start_ea, seg_size)
                if not data:
                    continue
                for m in regex.finditer(data):
                    match_addr = seg.start_ea + m.start()
                    addr_hex = hex(match_addr)
                    if addr_hex in seen_addrs:
                        continue
                    match_bytes = data[m.start() : m.end()]
                    # Best-effort display: try UTF-8, fall back to hex
                    try:
                        text = match_bytes.decode("utf-8", errors="replace")
                    except Exception:
                        text = match_bytes.hex()
                    candidates.append({"addr": addr_hex, "text": text, "kind": "raw"})
                    seen_addrs.add(addr_hex)
            except Exception:
                continue

    # Stable sort: strings first, then names, then raw, preserving address order
    candidates.sort(
        key=lambda c: (
            {"string": 0, "name": 1, "raw": 2}.get(c["kind"], 3),
            int(c["addr"], 16),
        )
    )

    total = len(candidates)
    page = candidates[offset: offset + limit]
    more = (offset + limit) < total

    matches = [{"addr": c["addr"], "string": c["text"], "kind": c["kind"]} for c in page]

    return {
        "n": len(matches),
        "matches": matches,
        "total": total,
        "cursor": {"next": offset + limit} if more else {"done": True},
    }


_COMMENT_SCOLORS = tuple(
    c
    for c in (
        getattr(ida_lines, "SCOLOR_REGCMT", None),
        getattr(ida_lines, "SCOLOR_RPTCMT", None),
        getattr(ida_lines, "SCOLOR_AUTOCMT", None),
        getattr(ida_lines, "SCOLOR_COLLAPSED", None),
    )
    if c is not None
)


def _line_is_comment(tagged: str) -> bool:
    """A rendered listing line is a comment if it carries any comment SCOLOR tag."""
    if not tagged:
        return False
    for sc in _COMMENT_SCOLORS:
        if ida_lines.COLOR_ON + sc in tagged:
            return True
    return False


def _classify_hit_lines(
    ea: int,
    matcher,
    want_disasm: bool,
    want_comments: bool,
    max_lines: int = 32,
) -> list[SearchTextLine]:
    """Render the listing for `ea` once, classify each line, return matching lines."""
    out: list[SearchTextLine] = []
    try:
        result = ida_lines.generate_disassembly(ea, max_lines, False, False)
    except Exception:
        return out
    # Bindings vary: (n, lineno, lines) or (lines, lineno).
    lines = None
    if isinstance(result, tuple):
        for item in result:
            if isinstance(item, (list, tuple)) and item and isinstance(item[0], str):
                lines = list(item)
                break
    if lines is None:
        return out

    for tagged in lines:
        text = ida_lines.tag_remove(tagged) or ""
        if not text or not matcher(text):
            continue
        is_cmt = _line_is_comment(tagged)
        kind = "comment" if is_cmt else "disasm"
        if kind == "disasm" and not want_disasm:
            continue
        if kind == "comment" and not want_comments:
            continue
        out.append({"kind": kind, "text": text})
    return out


def _exec_segments() -> list[tuple[int, int]]:
    """Return [(start, end)] for executable segments in address order."""
    ranges: list[tuple[int, int]] = []
    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if not seg:
            continue
        if not (seg.perm & idaapi.SEGPERM_EXEC):
            continue
        ranges.append((seg.start_ea, seg.end_ea))
    return ranges


def _all_segments() -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if seg:
            ranges.append((seg.start_ea, seg.end_ea))
    return ranges


@tool
@idasync
def search_text(
    pattern: Annotated[str, "Text to search for in the rendered listing (literal substring by default)"],
    limit: Annotated[int, "Max hits per page (default: 30, max: 500)"] = 30,
    start: Annotated[str, "Cursor: address to resume from (hex or symbol). Empty = first segment."] = "",
    regex: Annotated[bool, "Treat pattern as a regex (uses IDA's SEARCH_REGEX)"] = False,
    case_sensitive: Annotated[bool, "Case-sensitive match (default: false)"] = False,
    include: Annotated[str, "'disasm' | 'comments' | 'all' (default: all)"] = "all",
    code_only: Annotated[bool, "Restrict search to executable segments (default: true)"] = True,
) -> SearchTextResult:
    """Search the rendered listing using IDA's native text search (fast C++ scan).

    Discovers candidate EAs with `ida_search.find_text()`, then renders each hit
    once via `ida_lines.generate_disassembly()` to extract matching lines and
    classify them as disasm or comment. Returns one hit per EA.
    """
    if limit <= 0:
        limit = 30
    if limit > 500:
        limit = 500

    include = (include or "all").lower()
    if include not in ("disasm", "comments", "all"):
        return {"n": 0, "hits": [], "cursor": {"done": True}, "error": f"invalid include: {include!r}"}

    want_disasm = include in ("disasm", "all")
    want_comments = include in ("comments", "all")

    # Build a Python-side matcher for per-line filtering after the C++ find.
    if regex:
        try:
            flags = 0 if case_sensitive else re.IGNORECASE
            rx = re.compile(pattern, flags)
        except re.error as e:
            return {"n": 0, "hits": [], "cursor": {"done": True}, "error": f"invalid regex: {e}"}
        matcher = lambda s: bool(rx.search(s))
    else:
        if case_sensitive:
            needle = pattern
            matcher = lambda s: needle in s
        else:
            needle = pattern.lower()
            matcher = lambda s: needle in s.lower()

    # Build IDA search flags.
    sflag = ida_search.SEARCH_DOWN | ida_search.SEARCH_NOSHOW
    if case_sensitive:
        sflag |= ida_search.SEARCH_CASE
    if regex:
        sflag |= ida_search.SEARCH_REGEX

    # Resolve cursor.
    segments = _exec_segments() if code_only else _all_segments()
    if not segments:
        return {"n": 0, "hits": [], "cursor": {"done": True}}

    if start:
        try:
            cursor_ea = parse_address(start)
        except Exception as e:
            return {"n": 0, "hits": [], "cursor": {"done": True}, "error": f"invalid start: {e}"}
    else:
        cursor_ea = segments[0][0]

    hits: list[SearchTextHit] = []
    next_cursor: int | None = None
    seg_idx = 0
    # Skip ahead to the segment that contains/follows cursor_ea.
    while seg_idx < len(segments) and segments[seg_idx][1] <= cursor_ea:
        seg_idx += 1
    if seg_idx < len(segments) and cursor_ea < segments[seg_idx][0]:
        cursor_ea = segments[seg_idx][0]

    while seg_idx < len(segments) and len(hits) < limit:
        seg_start, seg_end = segments[seg_idx]
        ea = ida_search.find_text(cursor_ea, 0, 0, pattern, sflag)
        if ea == idaapi.BADADDR or ea >= seg_end:
            seg_idx += 1
            if seg_idx < len(segments):
                cursor_ea = segments[seg_idx][0]
            continue
        if ea < seg_start:
            # Match landed in a segment we already passed; skip.
            cursor_ea = ea + 1
            continue

        lines = _classify_hit_lines(ea, matcher, want_disasm, want_comments)
        if lines:
            entry: SearchTextHit = {"addr": hex(ea), "matches": lines}
            func = idaapi.get_func(ea)
            if func is not None:
                fname = ida_funcs.get_func_name(func.start_ea)
                if fname:
                    entry["function"] = fname
            seg = idaapi.getseg(ea)
            if seg is not None:
                sname = ida_segment.get_segm_name(seg)
                if sname:
                    entry["segment"] = sname
            hits.append(entry)
            if len(hits) >= limit:
                # Compute resume cursor: just past this hit.
                size = max(1, idaapi.get_item_size(ea))
                next_cursor = ea + size
                break

        # Advance past this match. Use item size if known to avoid re-hitting
        # the same head's listing on the next iteration.
        size = idaapi.get_item_size(ea)
        cursor_ea = ea + (size if size > 0 else 1)

    cursor: dict[str, Any]
    if next_cursor is not None:
        cursor = {"next": hex(next_cursor)}
    else:
        cursor = {"done": True}

    return {"n": len(hits), "hits": hits, "cursor": cursor}


class ReadMcpOutputResult(TypedDict):
    ok: bool
    output_id: str
    offset: int
    total_chars: int
    has_more: bool
    chunk: str
    error: NotRequired[str]


@tool
@idasync
def read_mcp_output(
    output_id: Annotated[str, "Output ID from a truncated MCP tool response."],
    offset: Annotated[int, "Character offset to start reading from."] = 0,
    max_chars: Annotated[
        int, "Maximum characters to return per chunk (default 40000, cap 50000)."
    ] = 40000,
) -> ReadMcpOutputResult:
    """Read a previously cached MCP tool output by its output_id.

    When a tool response exceeds the 50KB size limit, the full output is cached
    in memory and an output_id is provided in the truncation hint. Use this tool
    to retrieve the full data in chunks. Each chunk includes offset, total size,
    and a has_more flag so you can page through large outputs.

    Typical workflow:
      1. Call any tool that may return large output (e.g. get_cfg_dot).
      2. If the response mentions truncation and gives an output_id,
         call read_mcp_output(output_id=..., offset=0).
      3. If has_more is true, call again with offset = previous_offset + len(chunk).
    """
    data = get_cached_output(output_id)
    if data is None:
        return {
            "ok": False,
            "output_id": output_id,
            "offset": offset,
            "total_chars": 0,
            "has_more": False,
            "chunk": "",
            "error": f"Output '{output_id}' not found or expired (cache holds max 100 entries).",
        }

    serialized = json.dumps(data)
    total = len(serialized)
    max_chars = min(max_chars, 50000)

    if offset < 0:
        offset = 0
    if offset > total:
        offset = total

    chunk = serialized[offset:offset + max_chars]
    has_more = offset + max_chars < total

    return {
        "ok": True,
        "output_id": output_id,
        "offset": offset,
        "total_chars": total,
        "has_more": has_more,
        "chunk": chunk,
    }
