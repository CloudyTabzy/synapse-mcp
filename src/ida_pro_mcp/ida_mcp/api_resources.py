"""MCP Resources - browsable IDB state

Resources represent browsable state (read-only data) following MCP's philosophy.
Use tools for actions that modify state or perform expensive computations.
"""

from typing import Annotated

import ida_nalt
import ida_segment
import ida_typeinf
import idaapi
import idautils
import idc

from .rpc import resource
from .sync import idasync
from .utils import (
    Metadata,
    Segment,
    StructureDefinition,
    StructureMember,
    get_image_size,
    parse_address,
)
from . import compat


# ============================================================================
# Core IDB State
# ============================================================================


@resource("ida://idb/metadata")
@idasync
def idb_metadata_resource() -> Metadata:
    """Get IDB file metadata (path, arch, base address, size, hashes)"""
    import hashlib

    path = idc.get_idb_path()
    module = ida_nalt.get_root_filename()
    base = hex(idaapi.get_imagebase())
    size = hex(get_image_size())

    input_path = ida_nalt.get_input_file_path()
    try:
        with open(input_path, "rb") as f:
            data = f.read()
        md5 = hashlib.md5(data).hexdigest()
        sha256 = hashlib.sha256(data).hexdigest()
        import zlib

        crc32 = hex(zlib.crc32(data) & 0xFFFFFFFF)
        filesize = hex(len(data))
    except Exception:
        md5 = sha256 = crc32 = filesize = "unavailable"

    return Metadata(
        path=path,
        module=module,
        base=base,
        size=size,
        md5=md5,
        sha256=sha256,
        crc32=crc32,
        filesize=filesize,
    )


@resource("ida://idb/segments")
@idasync
def idb_segments_resource() -> list[Segment]:
    """Get all memory segments with permissions"""
    segments = []
    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if seg:
            perms = []
            if seg.perm & idaapi.SEGPERM_READ:
                perms.append("r")
            if seg.perm & idaapi.SEGPERM_WRITE:
                perms.append("w")
            if seg.perm & idaapi.SEGPERM_EXEC:
                perms.append("x")

            segments.append(
                Segment(
                    name=ida_segment.get_segm_name(seg),
                    start=hex(seg.start_ea),
                    end=hex(seg.end_ea),
                    size=hex(seg.size()),
                    permissions="".join(perms) if perms else "---",
                )
            )
    return segments


@resource("ida://idb/entrypoints")
@idasync
def idb_entrypoints_resource() -> list[dict]:
    """Get entry points (main, TLS callbacks, etc.)"""
    entrypoints = []
    entry_count = compat.get_entry_qty()
    for i in range(entry_count):
        ordinal = compat.get_entry_ordinal(i)
        ea = compat.get_entry(ordinal)
        name = compat.get_entry_name(ordinal)
        entrypoints.append({"addr": hex(ea), "name": name, "ordinal": ordinal})
    return entrypoints


# ============================================================================
# UI State
# ============================================================================


@resource("ida://cursor")
@idasync
def cursor_resource() -> dict:
    """Get current cursor position and function"""
    import ida_kernwin

    ea = ida_kernwin.get_screen_ea()
    func = idaapi.get_func(ea)

    result = {"addr": hex(ea)}
    if func:
        func_name = compat.get_func_name(func)

        result["function"] = {
            "addr": hex(func.start_ea),
            "name": func_name,
        }

    return result


@resource("ida://selection")
@idasync
def selection_resource() -> dict:
    """Get current selection range (if any)"""
    import ida_kernwin

    start = ida_kernwin.read_range_selection(None)
    if start:
        return {"start": hex(start[0]), "end": hex(start[1]) if start[1] else None}
    return {"selection": None}


# ============================================================================
# Type Information
# ============================================================================


@resource("ida://types")
@idasync
def types_resource() -> list[dict]:
    """Get all local types"""
    types = []
    for ordinal in range(1, compat.get_ordinal_limit(None)):
        tif = ida_typeinf.tinfo_t()
        if tif.get_numbered_type(None, ordinal):
            name = tif.get_type_name()
            types.append({"ordinal": ordinal, "name": name, "type": str(tif)})
    return types


@resource("ida://structs")
@idasync
def structs_resource() -> list[dict]:
    """Get all structures/unions"""
    structs = []
    limit = compat.get_ordinal_limit()
    for ordinal in range(1, limit):
        tif = ida_typeinf.tinfo_t()
        if tif.get_numbered_type(None, ordinal) and tif.is_udt():
            udt_data = ida_typeinf.udt_type_data_t()
            is_union = False
            if tif.get_udt_details(udt_data):
                is_union = udt_data.is_union
            structs.append(
                {
                    "name": tif.get_type_name(),
                    "size": hex(tif.get_size()),
                    "is_union": is_union,
                }
            )
    return structs


@resource("ida://struct/{name}")
@idasync
def struct_name_resource(name: Annotated[str, "Structure name"]) -> dict:
    """Get structure definition with fields"""
    tif = ida_typeinf.tinfo_t()
    if not tif.get_named_type(None, name):
        return {"error": f"Structure not found: {name}"}

    if not tif.is_udt():
        return {"error": f"'{name}' is not a structure/union"}

    udt_data = ida_typeinf.udt_type_data_t()
    if not tif.get_udt_details(udt_data):
        return {"error": f"Failed to get struct details for '{name}'"}

    members = []
    for member in udt_data:
        members.append(
            StructureMember(
                name=member.name,
                offset=hex(member.offset // 8),
                size=hex(member.size // 8),
                type=str(member.type),
            )
        )

    return StructureDefinition(name=name, size=hex(tif.get_size()), members=members)


# ============================================================================
# Import/Export Lookup by Name
# ============================================================================


@resource("ida://import/{name}")
@idasync
def import_name_resource(name: Annotated[str, "Import name"]) -> dict:
    """Get specific import details by name"""
    nimps = ida_nalt.get_import_module_qty()
    for i in range(nimps):
        module = ida_nalt.get_import_module_name(i)
        result = {}

        def callback(ea, imp_name, ordinal):
            if imp_name == name or f"ord_{ordinal}" == name:
                result.update(
                    {
                        "addr": hex(ea),
                        "name": imp_name or f"ord_{ordinal}",
                        "module": module,
                        "ordinal": ordinal,
                    }
                )
                return False  # Stop enumeration
            return True

        ida_nalt.enum_import_names(i, callback)
        if result:
            return result

    return {"error": f"Import not found: {name}"}


@resource("ida://export/{name}")
@idasync
def export_name_resource(name: Annotated[str, "Export name"]) -> dict:
    """Get specific export details by name"""
    entry_count = compat.get_entry_qty()
    for i in range(entry_count):
        ordinal = compat.get_entry_ordinal(i)
        ea = compat.get_entry(ordinal)
        entry_name = compat.get_entry_name(ordinal)

        if entry_name == name:
            return {
                "addr": hex(ea),
                "name": entry_name,
                "ordinal": ordinal,
            }

    return {"error": f"Export not found: {name}"}


# ============================================================================
# Cross-references
# ============================================================================


@resource("ida://xrefs/from/{addr}")
@idasync
def xrefs_from_resource(addr: Annotated[str, "Source address"]) -> list[dict]:
    """Get cross-references from address"""
    ea = parse_address(addr)
    xrefs = []
    for xref in idautils.XrefsFrom(ea, 0):
        xrefs.append(
            {
                "addr": hex(xref.to),
                "type": "code" if xref.iscode else "data",
            }
        )
    return xrefs


# ============================================================================
# Triton MCP Resources
# ============================================================================


@resource("triton://session/context")
@idasync
def triton_session_context_resource() -> dict:
    """Dump the current Triton session context as JSON.

    Includes architecture, modes, symbolic variable count, path constraint
    count, taint state, and snapshot count.
    """
    try:
        from .api_triton import TRITON_AVAILABLE, _get_ctx, _arch_to_str
        if not TRITON_AVAILABLE:
            return {"error": "Triton not available"}
        ctx = _get_ctx()
        sym_vars = ctx.getSymbolicVariables()
        pcs = ctx.getPathConstraints()
        tainted_regs = ctx.getTaintedRegisters()
        tainted_mem = ctx.getTaintedMemory()

        modes_enabled = []
        try:
            from triton import MODE
            for mode in (
                MODE.ALIGNED_MEMORY,
                MODE.AST_OPTIMIZATIONS,
                MODE.CONSTANT_FOLDING,
                MODE.ONLY_ON_SYMBOLIZED,
                MODE.ONLY_ON_TAINTED,
                MODE.PC_TRACKING_SYMBOLIC,
                MODE.TAINT_THROUGH_POINTERS,
            ):
                if ctx.isModeEnabled(mode):
                    modes_enabled.append(str(mode))
        except Exception:
            pass

        return {
            "architecture": _arch_to_str(ctx.getArchitecture()),
            "gpr_bitsize": ctx.getGprBitSize(),
            "modes_enabled": modes_enabled,
            "symbolic_var_count": len(sym_vars),
            "path_constraint_count": len(pcs),
            "tainted_register_count": len(tainted_regs),
            "tainted_memory_cell_count": len(tainted_mem),
        }
    except Exception as exc:
        return {"error": str(exc)}


@resource("triton://session/constraints")
@idasync
def triton_session_constraints_resource() -> dict:
    """Return the accumulated path predicate in SMT-LIB 2 format.

    The output can be pasted into Z3 or any SMT-LIB 2 compliant solver
    for external verification or constraint manipulation.
    """
    try:
        from .api_triton import TRITON_AVAILABLE, _get_ctx
        if not TRITON_AVAILABLE:
            return {"error": "Triton not available"}
        ctx = _get_ctx()
        predicate = ctx.getPathPredicate()
        smt = ctx.liftToSMT(predicate, assert_=True, icomment=True)
        return {"smt_lib2": smt}
    except Exception as exc:
        return {"error": str(exc)}


@resource("triton://session/symbolic-vars")
@idasync
def triton_session_symbolic_vars_resource() -> dict:
    """List all symbolic variables in the current Triton session."""
    try:
        from .api_triton import TRITON_AVAILABLE, _get_ctx
        if not TRITON_AVAILABLE:
            return {"error": "Triton not available"}
        ctx = _get_ctx()
        from triton import SYMBOLIC
        variables = []
        for vid, sv in ctx.getSymbolicVariables().items():
            stype = sv.getType()
            if stype == SYMBOLIC.REGISTER_VARIABLE:
                kind = "register"
                try:
                    origin = ctx.getRegister(sv.getOrigin()).getName()
                except Exception:
                    origin = str(sv.getOrigin())
            elif stype == SYMBOLIC.MEMORY_VARIABLE:
                kind = "memory"
                origin = hex(sv.getOrigin())
            else:
                kind = "undefined"
                origin = str(sv.getOrigin())
            variables.append({
                "id": vid,
                "name": sv.getName(),
                "alias": sv.getAlias(),
                "bitsize": sv.getBitSize(),
                "kind": kind,
                "origin": origin,
            })
        return {"variables": variables}
    except Exception as exc:
        return {"error": str(exc)}


# ============================================================================
# Miasm MCP Resources
# ============================================================================


@resource("miasm://function/{address}/ir")
@idasync
def miasm_function_ir_resource(address: Annotated[str, "Function address (hex or symbol name)"]) -> dict:
    """Return the Miasm IR lifting (IRCFG) for a function as JSON."""
    try:
        from .api_miasm import MIASM_AVAILABLE, _manager, _iter_ircfg_blocks, _ircfg_edges, _ir_blocks_to_dict
        if not MIASM_AVAILABLE:
            return {"error": "Miasm not available"}
        import idaapi
        ea = parse_address(address)
        func = idaapi.get_func(ea)
        if not func:
            return {"error": f"No function at {hex(ea)}"}
        data = _manager.get_bytes(func.start_ea, func.end_ea)
        mdis, loc_db = _manager.get_mdis(data, func.start_ea)
        asmcfg = mdis.dis_multiblock(func.start_ea)
        lifter = _manager.machine.lifter_model_call(loc_db)
        ircfg = lifter.new_ircfg_from_asmcfg(asmcfg)
        edges = [{"src": str(s), "dst": str(d)} for s, d in _ircfg_edges(ircfg)]
        return {
            "function_ea": hex(func.start_ea),
            "blocks": _ir_blocks_to_dict(ircfg),
            "edges": edges,
        }
    except Exception as exc:
        return {"error": str(exc)}


@resource("miasm://function/{address}/ssa")
@idasync
def miasm_function_ssa_resource(address: Annotated[str, "Function address (hex or symbol name)"]) -> dict:
    """Return the SSA-transformed IRCFG for a function as JSON."""
    try:
        from .api_miasm import MIASM_AVAILABLE, _manager, _iter_ircfg_blocks, _ircfg_edges, _ir_blocks_to_dict
        if not MIASM_AVAILABLE:
            return {"error": "Miasm not available"}
        import idaapi
        from miasm.analysis.ssa import SSADiGraph
        ea = parse_address(address)
        func = idaapi.get_func(ea)
        if not func:
            return {"error": f"No function at {hex(ea)}"}
        data = _manager.get_bytes(func.start_ea, func.end_ea)
        mdis, loc_db = _manager.get_mdis(data, func.start_ea)
        asmcfg = mdis.dis_multiblock(func.start_ea)
        lifter = _manager.machine.lifter_model_call(loc_db)
        ircfg = lifter.new_ircfg_from_asmcfg(asmcfg)
        heads = list(ircfg.heads())
        if heads:
            ssa = SSADiGraph(ircfg)
            ssa.transform(heads[0])
        edges = [{"src": str(s), "dst": str(d)} for s, d in _ircfg_edges(ircfg)]
        return {
            "function_ea": hex(func.start_ea),
            "form": "ssa",
            "blocks": _ir_blocks_to_dict(ircfg),
            "edges": edges,
        }
    except Exception as exc:
        return {"error": str(exc)}


@resource("miasm://function/{address}/cfg-dot")
@idasync
def miasm_function_cfg_dot_resource(address: Annotated[str, "Function address (hex or symbol name)"]) -> dict:
    """Return a Graphviz DOT string for the function's assembly CFG."""
    try:
        from .api_miasm import MIASM_AVAILABLE, _manager
        if not MIASM_AVAILABLE:
            return {"error": "Miasm not available"}
        import idaapi
        ea = parse_address(address)
        func = idaapi.get_func(ea)
        if not func:
            return {"error": f"No function at {hex(ea)}"}
        data = _manager.get_bytes(func.start_ea, func.end_ea)
        mdis, _ = _manager.get_mdis(data, func.start_ea)
        asmcfg = mdis.dis_multiblock(func.start_ea)
        return {"dot": asmcfg.dot()}
    except Exception as exc:
        return {"error": str(exc)}
