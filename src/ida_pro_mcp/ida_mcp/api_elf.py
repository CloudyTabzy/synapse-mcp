"""pyelftools DWARF debug information tools.

Parses ELF symbols, DWARF debug info (functions, line info, types), and
syncs recovered names/types into the IDA database.

Requires: pip install pyelftools>=0.31
DWARF 2–5 supported. Pure-Python, zero native dependencies.
"""
from __future__ import annotations

import collections
import os
from typing import Annotated, NotRequired, TypedDict

import idaapi
import idc
import ida_name
import ida_typeinf

from .rpc import tool
from .sync import idasync
from .utils import tool_error

# ---------------------------------------------------------------------------
# Optional imports
# ---------------------------------------------------------------------------

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
    ELFTOOLS_AVAILABLE = True
except ImportError:
    ELFFile = None  # type: ignore[assignment]
    SymbolTableSection = None  # type: ignore[assignment]
    ELFTOOLS_AVAILABLE = False

DWARF_AVAILABLE = False
if ELFTOOLS_AVAILABLE:
    try:
        from elftools.dwarf.descriptions import describe_form_class
        DWARF_AVAILABLE = True
    except ImportError:
        describe_form_class = None  # type: ignore[assignment]

_ELFTOOLS_VERSION = ""
if ELFTOOLS_AVAILABLE:
    try:
        import importlib.metadata
        _ELFTOOLS_VERSION = importlib.metadata.version("pyelftools")
    except Exception:
        _ELFTOOLS_VERSION = "unknown"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_IDA_DB_EXTENSIONS = frozenset({".i64", ".idb", ".id0", ".id1", ".nam", ".til"})


def _resolve_elf_path(file_path: str) -> str:
    path = file_path if file_path else (idaapi.get_input_file_path() or "")
    if not path:
        return path
    _, ext = os.path.splitext(path.lower())
    if ext in _IDA_DB_EXTENSIONS:
        try:
            src = idaapi.get_input_file_path() or ""
        except Exception:
            src = ""
        raise ValueError(
            f"Path is an IDA database ({ext}), not a parseable ELF. "
            f"Pass the source ELF path instead." + (f" IDA source: {src}" if src else "")
        )
    return path


def _is_elf(path: str) -> bool:
    if not path:
        return False
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except Exception:
        return False


# ---------------------------------------------------------------------------
# TypedDicts
# ---------------------------------------------------------------------------


class ElfStatusResult(TypedDict, total=False):
    ok: bool
    available: bool
    version: str
    dwarf_supported: bool
    hint: str


class ElfSymbolEntry(TypedDict, total=False):
    name: str
    value: str
    size: int
    ty: str
    bind: str
    visibility: str
    section: str
    version: str


class ElfSymbolsResult(TypedDict, total=False):
    ok: bool
    format: str
    symtab_count: int
    dynsym_count: int
    total: int
    symbols: list[ElfSymbolEntry]
    truncated: bool
    note: str
    error: str
    error_type: str


class ElfDwarfParam(TypedDict, total=False):
    name: str
    ty: str


class ElfDwarfFunction(TypedDict, total=False):
    name: str
    low_pc: str
    high_pc: str
    return_type: str
    params: list[ElfDwarfParam]
    decl_file: str
    decl_line: int


class ElfDwarfFunctionsResult(TypedDict, total=False):
    ok: bool
    format: str
    has_dwarf: bool
    functions: list[ElfDwarfFunction]
    total: int
    truncated: bool
    note: str
    error: str
    error_type: str


class ElfDwarfLineEntry(TypedDict, total=False):
    addr: str
    file: str
    line: int
    column: int


class ElfDwarfLineResult(TypedDict, total=False):
    ok: bool
    format: str
    has_dwarf: bool
    entries: list[ElfDwarfLineEntry]
    total: int
    truncated: bool
    error: str
    error_type: str


class ElfDwarfMember(TypedDict, total=False):
    name: str
    offset: int
    ty: str
    byte_size: int


class ElfDwarfTypeEntry(TypedDict, total=False):
    name: str
    kind: str
    byte_size: int
    members: list[ElfDwarfMember]
    decl_file: str
    decl_line: int


class ElfDwarfTypesResult(TypedDict, total=False):
    ok: bool
    format: str
    has_dwarf: bool
    types: list[ElfDwarfTypeEntry]
    total: int
    truncated: bool
    note: str
    error: str
    error_type: str


class ElfSyncChange(TypedDict):
    addr: str
    old_name: str
    new_name: str
    kind: str


class ElfSyncDwarfResult(TypedDict, total=False):
    ok: bool
    format: str
    has_dwarf: bool
    proposed_count: int
    applied_count: int
    skipped_count: int
    not_found_count: int
    changes: list[ElfSyncChange]
    dry_run: bool
    error: str
    error_type: str


# ---------------------------------------------------------------------------
# elf_status — always registered even when pyelftools is absent
# ---------------------------------------------------------------------------


@tool
@idasync
def elf_status() -> ElfStatusResult:
    """Report pyelftools availability and DWARF support status.

    Always returns a result — safe to call before any other elf_* tool.
    When available=false, install with: pip install pyelftools>=0.31"""
    if not ELFTOOLS_AVAILABLE:
        return {
            "ok": True,
            "available": False,
            "version": "",
            "dwarf_supported": False,
            "hint": "Install pyelftools: pip install pyelftools>=0.31",
        }
    return {
        "ok": True,
        "available": True,
        "version": _ELFTOOLS_VERSION,
        "dwarf_supported": DWARF_AVAILABLE,
    }


# ---------------------------------------------------------------------------
# All remaining tools — only registered when pyelftools is installed
# ---------------------------------------------------------------------------

if ELFTOOLS_AVAILABLE:

    # -------------------------------------------------------------------
    # E.1 — elf_symbols
    # -------------------------------------------------------------------

    @tool
    @idasync
    def elf_symbols(
        file_path: Annotated[str, "Path to ELF file; empty string uses the IDB source file"] = "",
        table: Annotated[str, "Symbol table: 'symtab', 'dynsym', or 'both'"] = "both",
        defined_only: Annotated[bool, "Exclude undefined (imported) symbols"] = False,
        limit: Annotated[int, "Maximum symbols to return (0 = all, capped at 5000)"] = 2000,
    ) -> ElfSymbolsResult:
        """Read .symtab and .dynsym from an ELF file.

        Richer than LIEF's symbol view: includes symbol type, binding,
        visibility, section name, and GNU symbol versioning when present.

        Reads from the source ELF file, not the IDB."""
        try:
            path = _resolve_elf_path(file_path)
            if not _is_elf(path):
                return {
                    "ok": False,
                    "format": "",
                    "error": f"Not a valid ELF file: {path}",
                    "error_type": "wrong_format",
                }

            with open(path, "rb") as f:
                elffile = ELFFile(f)
                max_syms = min(limit if limit > 0 else 5000, 5000)

                rows: list[ElfSymbolEntry] = []
                symtab_count = 0
                dynsym_count = 0

                for section in elffile.iter_sections():
                    if not isinstance(section, SymbolTableSection):
                        continue
                    sec_name = section.name
                    is_dynsym = sec_name == ".dynsym"
                    is_symtab = sec_name == ".symtab"

                    if table == "symtab" and is_dynsym:
                        continue
                    if table == "dynsym" and not is_dynsym:
                        continue

                    for sym in section.iter_symbols():
                        if len(rows) >= max_syms:
                            break

                        shndx = sym.get("st_shndx", "SHN_UNDEF")
                        if defined_only and (shndx == "SHN_UNDEF" or shndx == 0):
                            continue

                        info = sym.get("st_info", {})
                        other = sym.get("st_other", {})
                        sym_type = info.get("type", "STT_NOTYPE") if isinstance(info, dict) else "STT_NOTYPE"
                        sym_bind = info.get("bind", "STB_LOCAL") if isinstance(info, dict) else "STB_LOCAL"
                        sym_vis = other.get("visibility", "STV_DEFAULT") if isinstance(other, dict) else "STV_DEFAULT"

                        version = ""
                        try:
                            vs = getattr(sym, "versions", None)
                            if vs and isinstance(vs, list):
                                version = ",".join(str(v) for v in vs if v)
                        except Exception:
                            pass

                        rows.append({
                            "name": sym.name or "",
                            "value": hex(sym.get("st_value", 0)),
                            "size": sym.get("st_size", 0),
                            "ty": sym_type,
                            "bind": sym_bind,
                            "visibility": sym_vis,
                            "section": str(shndx) if shndx else "",
                            "version": version,
                        })

                        if is_symtab:
                            symtab_count += 1
                        elif is_dynsym:
                            dynsym_count += 1

                return {
                    "ok": True,
                    "format": "ELF",
                    "symtab_count": symtab_count,
                    "dynsym_count": dynsym_count,
                    "total": len(rows),
                    "symbols": rows,
                    "truncated": len(rows) >= max_syms,
                }
        except Exception as e:
            return {**tool_error(e), "ok": False}

    # -------------------------------------------------------------------
    # E.2 — elf_dwarf_functions
    # -------------------------------------------------------------------

    def _resolve_dwarf_type_name(die, dwarf) -> str:
        """Follow a DW_AT_type reference to a readable type name."""
        try:
            attr = die.attributes.get("DW_AT_type")
            if attr is None:
                return "void"
            type_offset = attr.value + attr.cu.cu_offset if hasattr(attr, "cu") else attr.value
            target = dwarf.get_DIE_from_attribute(attr, die.cu)
            if target is None:
                return "void"
            tag = target.tag
            if "DW_AT_name" in target.attributes:
                nm = target.attributes["DW_AT_name"].value
                name_str = nm.decode("utf-8", errors="replace") if isinstance(nm, bytes) else str(nm)
                return name_str if name_str else str(tag or "void")
            return str(tag).split("_")[-1].lower() if tag else "void"
        except Exception:
            return "void"


    @tool
    @idasync
    def elf_dwarf_functions(
        file_path: Annotated[str, "Path to ELF file; empty string uses the IDB source file"] = "",
        filter: Annotated[str, "Case-insensitive substring filter on function name"] = "",
        limit: Annotated[int, "Maximum functions to return (0 = all, capped at 2000)"] = 1000,
    ) -> ElfDwarfFunctionsResult:
        """Recover function inventory from DWARF .debug_info.

        Iterates all compilation units, collects DW_TAG_subprogram DIEs with
        DW_AT_low_pc: name, low/high PC, return type, parameter names/types,
        and declaration file:line.

        Reads from the source ELF file, not the IDB."""
        try:
            path = _resolve_elf_path(file_path)
            if not _is_elf(path):
                return {
                    "ok": False,
                    "format": "",
                    "error": f"Not a valid ELF file: {path}",
                    "error_type": "wrong_format",
                }
            if not DWARF_AVAILABLE:
                return {
                    "ok": False,
                    "format": "ELF",
                    "error": "DWARF subsystem not available in pyelftools",
                    "error_type": "unavailable",
                }

            with open(path, "rb") as f:
                elffile = ELFFile(f)
                if not elffile.has_dwarf_info():
                    return {"ok": True, "format": "ELF", "has_dwarf": False, "functions": [], "total": 0, "truncated": False}

                dwarf = elffile.get_dwarf_info()
                max_funcs = min(limit if limit > 0 else 2000, 2000)
                filt = filter.strip().lower() if filter else ""
                funcs: list[ElfDwarfFunction] = []

                for cu in dwarf.iter_CUs():
                    for die in cu.iter_DIEs():
                        if die.tag != "DW_TAG_subprogram":
                            continue
                        if "DW_AT_low_pc" not in die.attributes:
                            continue
                        if "DW_AT_name" not in die.attributes:
                            continue

                        fname_val = die.attributes["DW_AT_name"].value
                        fname = fname_val.decode("utf-8", errors="replace") if isinstance(fname_val, bytes) else str(fname_val)

                        if filt and filt not in fname.lower():
                            continue
                        if len(funcs) >= max_funcs:
                            break

                        low = die.attributes["DW_AT_low_pc"].value
                        high = 0
                        if "DW_AT_high_pc" in die.attributes:
                            hp_attr = die.attributes["DW_AT_high_pc"]
                            fc = describe_form_class(hp_attr.form)
                            if fc == "constant":
                                high = low + hp_attr.value
                            else:
                                high = hp_attr.value

                        ret_type = _resolve_dwarf_type_name(die, dwarf)

                        params: list[ElfDwarfParam] = []
                        for child in die.iter_children():
                            if child.tag == "DW_TAG_formal_parameter":
                                pname = ""
                                if "DW_AT_name" in child.attributes:
                                    pv = child.attributes["DW_AT_name"].value
                                    pname = pv.decode("utf-8", errors="replace") if isinstance(pv, bytes) else str(pv)
                                ptype = _resolve_dwarf_type_name(child, dwarf)
                                params.append({"name": pname, "ty": ptype})
                            if child.tag == "DW_TAG_unspecified_parameters":
                                params.append({"name": "...", "ty": ""})

                        decl_file = ""
                        decl_line = 0
                        try:
                            df_attr = die.attributes.get("DW_AT_decl_file")
                            dl_attr = die.attributes.get("DW_AT_decl_line")
                            if df_attr is not None and dl_attr is not None:
                                lp = dwarf.line_program_for_CU(cu)
                                if lp and lp.header:
                                    version = lp.header.get("version", 2)
                                    fe = lp.header.get("file_entry")
                                    if fe is not None:
                                        idx = df_attr.value
                                        if version < 5:
                                            idx -= 1
                                        if 0 <= idx < len(fe):
                                            fi = fe[idx]
                                            name_raw = fi.get("name", b"")
                                            decl_file = name_raw.decode("utf-8", errors="replace") if isinstance(name_raw, bytes) else str(name_raw)
                                decl_line = dl_attr.value
                        except Exception:
                            pass

                        funcs.append({
                            "name": fname,
                            "low_pc": hex(low),
                            "high_pc": hex(high),
                            "return_type": ret_type,
                            "params": params,
                            "decl_file": decl_file,
                            "decl_line": decl_line,
                        })

                return {
                    "ok": True,
                    "format": "ELF",
                    "has_dwarf": True,
                    "functions": funcs,
                    "total": len(funcs),
                    "truncated": len(funcs) >= max_funcs,
                }
        except Exception as e:
            return {**tool_error(e), "ok": False}

    # -------------------------------------------------------------------
    # E.3 — elf_dwarf_line_info
    # -------------------------------------------------------------------

    @tool
    @idasync
    def elf_dwarf_line_info(
        file_path: Annotated[str, "Path to ELF file; empty string uses the IDB source file"] = "",
        addr: Annotated[str, "Address to look up (hex). Omit to return all entries for named function."] = "",
        function: Annotated[str, "Function name to filter by (returns all line entries in that function). Ignored when addr is provided."] = "",
        limit: Annotated[int, "Maximum entries to return (0 = all, capped at 5000)"] = 2000,
    ) -> ElfDwarfLineResult:
        """Address → source file:line mapping from DWARF .debug_line.

        Pass ``addr`` to look up a single address. Pass ``function`` to get
        all line entries within a named function's span.

        Reads from the source ELF file, not the IDB."""
        try:
            path = _resolve_elf_path(file_path)
            if not _is_elf(path):
                return {
                    "ok": False, "format": "",
                    "error": f"Not a valid ELF file: {path}", "error_type": "wrong_format",
                }
            if not DWARF_AVAILABLE:
                return {
                    "ok": False, "format": "ELF",
                    "error": "DWARF subsystem not available", "error_type": "unavailable",
                }

            with open(path, "rb") as f:
                elffile = ELFFile(f)
                if not elffile.has_dwarf_info():
                    return {"ok": True, "format": "ELF", "has_dwarf": False, "entries": [], "total": 0, "truncated": False}

                dwarf = elffile.get_dwarf_info()
                max_entries = min(limit if limit > 0 else 5000, 5000)
                entries: list[ElfDwarfLineEntry] = []

                if addr:
                    try:
                        lookup = int(addr, 16) if not isinstance(addr, int) else addr
                    except (TypeError, ValueError):
                        return {
                            "ok": False, "format": "ELF",
                            "error": f"Invalid address: {addr}", "error_type": "value_error",
                        }

                    for cu in dwarf.iter_CUs():
                        try:
                            lp = dwarf.line_program_for_CU(cu)
                            if lp is None:
                                continue
                            version = lp.header.get("version", 2)
                            fe = lp.header.get("file_entry")
                            entries_list = lp.get_entries()
                            if entries_list is None:
                                continue
                            for entry in entries_list:
                                if entry.state is None:
                                    continue
                                if entry.state.address != lookup:
                                    continue
                                fname = ""
                                if fe is not None:
                                    idx = entry.state.file
                                    if version < 5:
                                        idx -= 1
                                    if 0 <= idx < len(fe):
                                        fr = fe[idx]
                                        name_raw = fr.get("name", b"")
                                        fname = name_raw.decode("utf-8", errors="replace") if isinstance(name_raw, bytes) else str(name_raw)
                                entries.append({
                                    "addr": hex(entry.state.address),
                                    "file": fname,
                                    "line": entry.state.line,
                                    "column": entry.state.column,
                                })
                        except Exception:
                            continue
                elif function:
                    func_low = None
                    func_high = None
                    for cu in dwarf.iter_CUs():
                        for die in cu.iter_DIEs():
                            if die.tag != "DW_TAG_subprogram":
                                continue
                            if "DW_AT_name" not in die.attributes:
                                continue
                            nm_val = die.attributes["DW_AT_name"].value
                            fn = nm_val.decode("utf-8", errors="replace") if isinstance(nm_val, bytes) else str(nm_val)
                            if fn == function and "DW_AT_low_pc" in die.attributes:
                                func_low = die.attributes["DW_AT_low_pc"].value
                                if "DW_AT_high_pc" in die.attributes:
                                    hp = die.attributes["DW_AT_high_pc"]
                                    fc = describe_form_class(hp.form)
                                    if fc == "constant":
                                        func_high = func_low + hp.value
                                    else:
                                        func_high = hp.value
                                break
                        if func_low is not None:
                            break

                    if func_low is None:
                        return {"ok": True, "format": "ELF", "has_dwarf": True, "entries": [], "total": 0, "truncated": False}

                    for cu in dwarf.iter_CUs():
                        try:
                            lp = dwarf.line_program_for_CU(cu)
                            if lp is None:
                                continue
                            version = lp.header.get("version", 2)
                            fe = lp.header.get("file_entry")
                            for entry in lp.get_entries():
                                if entry.state is None:
                                    continue
                                if len(entries) >= max_entries:
                                    break
                                ea = entry.state.address
                                if ea < func_low:
                                    continue
                                if func_high and ea >= func_high:
                                    continue
                                fname = ""
                                if fe is not None:
                                    idx = entry.state.file
                                    if version < 5:
                                        idx -= 1
                                    if 0 <= idx < len(fe):
                                        fr = fe[idx]
                                        name_raw = fr.get("name", b"")
                                        fname = name_raw.decode("utf-8", errors="replace") if isinstance(name_raw, bytes) else str(name_raw)
                                entries.append({
                                    "addr": hex(ea),
                                    "file": fname,
                                    "line": entry.state.line,
                                    "column": entry.state.column,
                                })
                        except Exception:
                            continue
                else:
                    for cu in dwarf.iter_CUs():
                        try:
                            lp = dwarf.line_program_for_CU(cu)
                            if lp is None:
                                continue
                            version = lp.header.get("version", 2)
                            fe = lp.header.get("file_entry")
                            for entry in lp.get_entries():
                                if entry.state is None:
                                    continue
                                if len(entries) >= max_entries:
                                    break
                                fname = ""
                                if fe is not None:
                                    idx = entry.state.file
                                    if version < 5:
                                        idx -= 1
                                    if 0 <= idx < len(fe):
                                        fr = fe[idx]
                                        name_raw = fr.get("name", b"")
                                        fname = name_raw.decode("utf-8", errors="replace") if isinstance(name_raw, bytes) else str(name_raw)
                                entries.append({
                                    "addr": hex(entry.state.address),
                                    "file": fname,
                                    "line": entry.state.line,
                                    "column": entry.state.column,
                                })
                            if len(entries) >= max_entries:
                                break
                        except Exception:
                            continue

                return {
                    "ok": True, "format": "ELF", "has_dwarf": True,
                    "entries": entries, "total": len(entries),
                    "truncated": len(entries) >= max_entries,
                }
        except Exception as e:
            return {**tool_error(e), "ok": False}

    # -------------------------------------------------------------------
    # E.4 — elf_dwarf_types
    # -------------------------------------------------------------------

    @tool
    @idasync
    def elf_dwarf_types(
        file_path: Annotated[str, "Path to ELF file; empty string uses the IDB source file"] = "",
        name: Annotated[str, "Type name substring filter (case-insensitive). Empty = all."] = "",
        kind: Annotated[str, "Type kind: 'all', 'struct', 'union', 'enum', 'typedef'"] = "all",
        limit: Annotated[int, "Maximum types to return (0 = all, capped at 1000)"] = 500,
    ) -> ElfDwarfTypesResult:
        """Recover struct/union/enum/typedef layouts from DWARF .debug_info.

        Each type includes member names, byte offsets, member type names,
        and declaration file:line.

        Reads from the source ELF file, not the IDB."""
        try:
            path = _resolve_elf_path(file_path)
            if not _is_elf(path):
                return {
                    "ok": False, "format": "",
                    "error": f"Not a valid ELF file: {path}", "error_type": "wrong_format",
                }
            if not DWARF_AVAILABLE:
                return {
                    "ok": False, "format": "ELF",
                    "error": "DWARF subsystem not available", "error_type": "unavailable",
                }

            with open(path, "rb") as f:
                elffile = ELFFile(f)
                if not elffile.has_dwarf_info():
                    return {"ok": True, "format": "ELF", "has_dwarf": False, "types": [], "total": 0, "truncated": False}

                dwarf = elffile.get_dwarf_info()
                max_types = min(limit if limit > 0 else 1000, 1000)
                filt = name.strip().lower() if name else ""
                kind_filter = kind.lower() if kind else "all"

                wanted_tags: set[str] = {
                    "DW_TAG_structure_type", "DW_TAG_union_type",
                    "DW_TAG_enumeration_type", "DW_TAG_typedef",
                }
                if kind_filter == "struct":
                    wanted_tags = {"DW_TAG_structure_type"}
                elif kind_filter == "union":
                    wanted_tags = {"DW_TAG_union_type"}
                elif kind_filter == "enum":
                    wanted_tags = {"DW_TAG_enumeration_type"}
                elif kind_filter == "typedef":
                    wanted_tags = {"DW_TAG_typedef"}

                results: list[ElfDwarfTypeEntry] = []
                for cu in dwarf.iter_CUs():
                    for die in cu.iter_DIEs():
                        if die.tag not in wanted_tags:
                            continue
                        if len(results) >= max_types:
                            break

                        if "DW_AT_name" not in die.attributes:
                            continue
                        tname_val = die.attributes["DW_AT_name"].value
                        tname = tname_val.decode("utf-8", errors="replace") if isinstance(tname_val, bytes) else str(tname_val)
                        if filt and filt not in tname.lower():
                            continue

                        byte_size = 0
                        if "DW_AT_byte_size" in die.attributes:
                            try:
                                byte_size = int(die.attributes["DW_AT_byte_size"].value)
                            except (TypeError, ValueError):
                                pass

                        kind_label = str(die.tag).split("_")[2]

                        members: list[ElfDwarfMember] = []
                        for child in die.iter_children():
                            if child.tag == "DW_TAG_member":
                                mname = ""
                                if "DW_AT_name" in child.attributes:
                                    mv = child.attributes["DW_AT_name"].value
                                    mname = mv.decode("utf-8", errors="replace") if isinstance(mv, bytes) else str(mv)
                                offset = 0
                                if "DW_AT_data_member_location" in child.attributes:
                                    try:
                                        loc = child.attributes["DW_AT_data_member_location"].value
                                        offset = int(loc) if not isinstance(loc, (list, tuple)) else int(loc[0])
                                    except (TypeError, ValueError):
                                        pass
                                member_type = _resolve_dwarf_type_name(child, dwarf)
                                member_bs = 0
                                if "DW_AT_byte_size" in child.attributes:
                                    try:
                                        member_bs = int(child.attributes["DW_AT_byte_size"].value)
                                    except (TypeError, ValueError):
                                        pass
                                members.append({
                                    "name": mname,
                                    "offset": offset,
                                    "ty": member_type,
                                    "byte_size": member_bs,
                                })

                        decl_file = ""
                        decl_line = 0
                        try:
                            df_attr = die.attributes.get("DW_AT_decl_file")
                            dl_attr = die.attributes.get("DW_AT_decl_line")
                            if df_attr is not None and dl_attr is not None:
                                lp = dwarf.line_program_for_CU(cu)
                                if lp and lp.header:
                                    version = lp.header.get("version", 2)
                                    fe = lp.header.get("file_entry")
                                    if fe is not None:
                                        idx = df_attr.value
                                        if version < 5:
                                            idx -= 1
                                        if 0 <= idx < len(fe):
                                            fi = fe[idx]
                                            name_raw = fi.get("name", b"")
                                            decl_file = name_raw.decode("utf-8", errors="replace") if isinstance(name_raw, bytes) else str(name_raw)
                                decl_line = dl_attr.value
                        except Exception:
                            pass

                        results.append({
                            "name": tname,
                            "kind": kind_label,
                            "byte_size": byte_size,
                            "members": members,
                            "decl_file": decl_file,
                            "decl_line": decl_line,
                        })

                return {
                    "ok": True,
                    "format": "ELF",
                    "has_dwarf": True,
                    "types": results,
                    "total": len(results),
                    "truncated": len(results) >= max_types,
                }
        except Exception as e:
            return {**tool_error(e), "ok": False}

    # -------------------------------------------------------------------
    # E.5 — hybrid_elf_sync_dwarf_to_idb
    # -------------------------------------------------------------------

    @tool
    @idasync
    def hybrid_elf_sync_dwarf_to_idb(
        file_path: Annotated[str, "Path to ELF file; empty string uses the IDB source file"] = "",
        apply: Annotated[str, "What to apply: 'names', 'types', or 'both'"] = "names",
        dry_run: Annotated[bool, "Preview changes without writing to the IDB (default: True)"] = True,
        prefix: Annotated[str, "Optional prefix to prepend to every applied name"] = "",
    ) -> ElfSyncDwarfResult:
        """Apply DWARF-recovered function names and/or types into the IDA database.

        The ELF analogue of ``hybrid_lief_sync_symbols``. Recovers function
        names from DWARF DW_TAG_subprogram entries and applies them to the
        IDB, renaming auto-generated names (sub_*, loc_*, etc.).

        ``dry_run=True`` (default) previews changes without modifying the IDB.

        Reads from the source ELF file, maps DWARF low_pc to IDA addresses."""
        try:
            path = _resolve_elf_path(file_path)
            if not _is_elf(path):
                return {
                    "ok": False, "format": "",
                    "error": f"Not a valid ELF file: {path}", "error_type": "wrong_format",
                }
            if not DWARF_AVAILABLE:
                return {
                    "ok": False, "format": "ELF",
                    "error": "DWARF subsystem not available", "error_type": "unavailable",
                }

            with open(path, "rb") as f:
                elffile = ELFFile(f)
                if not elffile.has_dwarf_info():
                    return {
                        "ok": True, "format": "ELF", "has_dwarf": False,
                        "proposed_count": 0, "applied_count": 0,
                        "skipped_count": 0, "not_found_count": 0,
                        "changes": [], "dry_run": dry_run,
                    }

                dwarf = elffile.get_dwarf_info()
                changes: list[ElfSyncChange] = []
                proposed = 0
                applied = 0
                skipped = 0
                not_found = 0

                for cu in dwarf.iter_CUs():
                    for die in cu.iter_DIEs():
                        if die.tag != "DW_TAG_subprogram":
                            continue
                        if "DW_AT_name" not in die.attributes:
                            continue
                        if "DW_AT_low_pc" not in die.attributes:
                            continue

                        fname_val = die.attributes["DW_AT_name"].value
                        fname = fname_val.decode("utf-8", errors="replace") if isinstance(fname_val, bytes) else str(fname_val)
                        dw_low = die.attributes["DW_AT_low_pc"].value

                        proposed += 1
                        ida_ea = dw_low

                        func = idaapi.get_func(ida_ea)
                        if func is None:
                            not_found += 1
                            continue

                        fa = func.start_ea
                        cur_name = ida_name.get_ea_name(fa)

                        is_auto = (
                            not cur_name
                            or cur_name.startswith("sub_")
                            or cur_name.startswith("loc_")
                            or cur_name.startswith("j_")
                            or cur_name.startswith("nullsub_")
                            or cur_name.startswith("unknown_")
                        )

                        new_name = prefix + fname

                        changes.append({
                            "addr": hex(fa),
                            "old_name": cur_name,
                            "new_name": new_name,
                            "kind": "function",
                        })

                        if is_auto and not dry_run:
                            try:
                                if apply in ("names", "both"):
                                    idc.set_name(fa, new_name, idc.SN_NOWARN)
                                applied += 1
                            except Exception:
                                skipped += 1
                        elif is_auto and dry_run:
                            applied += 1
                        else:
                            skipped += 1

                return {
                    "ok": True,
                    "format": "ELF",
                    "has_dwarf": True,
                    "proposed_count": proposed,
                    "applied_count": applied,
                    "skipped_count": skipped,
                    "not_found_count": not_found,
                    "changes": changes[:200],
                    "dry_run": dry_run,
                }
        except Exception as e:
            return {**tool_error(e), "ok": False}
