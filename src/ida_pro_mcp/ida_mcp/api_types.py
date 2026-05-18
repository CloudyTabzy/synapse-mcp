from typing import Annotated, Any, TypedDict

import logging

import idc
import ida_typeinf
import ida_hexrays
import ida_nalt
import ida_bytes
import ida_frame
import idaapi
import ida_funcs
import idautils
import ida_name

from .rpc import tool
from .sync import idasync, tool_timeout
from .utils import (
    tool_error,
    item_error,
    normalize_list_input,
    normalize_dict_list,
    paginate,
    pattern_filter,
    parse_address,
    get_type_by_name,
    parse_decls_ctypes,
    my_modifier_t,
    read_bytes_bss_safe,
    read_int_bss_safe,
    StructRead,
    TypeEdit,
    TypeInspectQuery,
    TypeQuery,
    TypeApplyBatch,
    EnumUpsert,
)
from . import compat
from .compat import tinfo_get_udm

logger = logging.getLogger(__name__)


class DeclareTypeResult(TypedDict, total=False):
    decl: str
    error: str
    error_type: str
    hint: str


class EnumMemberUpsertResult(TypedDict, total=False):
    name: str
    value: int
    created: bool
    skipped: bool
    error: str
    error_type: str
    hint: str


class EnumUpsertSummaryResult(TypedDict):
    created: int
    skipped: int
    conflicts: int


class EnumUpsertResult(TypedDict, total=False):
    name: str
    enum_id: str
    created: bool
    bitfield: bool
    members: list[EnumMemberUpsertResult]
    summary: EnumUpsertSummaryResult
    error: str
    error_type: str
    hint: str


class StructMemberValueResult(TypedDict):
    offset: str
    type: str
    name: str
    size: int
    value: str


class ReadStructResult(TypedDict, total=False):
    addr: str | None
    struct: str | None
    members: list[StructMemberValueResult] | None
    error: str
    error_type: str
    hint: str


class SearchStructResult(TypedDict):
    name: str
    size: int
    cardinality: int
    is_union: bool
    ordinal: int


class TypeCatalogMemberResult(TypedDict):
    name: str
    offset: str
    size: int
    type: str


class TypeCatalogRow(TypedDict, total=False):
    ordinal: int
    name: str
    size: int
    kind: str
    declaration: str
    member_count: int
    members: list[TypeCatalogMemberResult]
    members_truncated: bool
    related_count: int
    related_types: list[str]
    related_truncated: bool


class TypeQueryResult(TypedDict):
    kind: str
    data: list[TypeCatalogRow]
    next_offset: int | None
    total: int


class TypeInspectResult(TypedDict, total=False):
    name: str
    exists: bool
    declaration: str
    size: int | None      # None when type is forward-declared without definition
    size_note: str        # present only when size is None
    is_func: bool
    is_ptr: bool
    is_enum: bool
    is_udt: bool
    members: list[TypeCatalogMemberResult] | None
    member_count: int
    error: str
    error_type: str
    hint: str


class SetTypeResult(TypedDict, total=False):
    edit: dict[str, Any]
    kind: str
    ok: bool
    error: str
    error_type: str
    hint: str


class TypeApplyBatchResult(TypedDict):
    ok: bool
    applied: int
    failed: int
    stopped: bool
    results: list[SetTypeResult]


class InferTypeResult(TypedDict, total=False):
    addr: str
    inferred_type: str | None
    method: str | None
    confidence: str
    error: str
    error_type: str
    hint: str



def _find_lvar_by_name(cfunc: ida_hexrays.cfunc_t, name: str):
    """Find a local variable by name (case-insensitive).

    Returns ``(lvar, idx)`` so callers can use the canonical index
    (``expr.v.idx``) without relying on the undocumented ``lvar.idx``.
    """
    for idx, lvar in enumerate(cfunc.get_lvars()):
        if lvar.name and lvar.name.lower() == name.lower():
            return lvar, idx
    return None, None


def _expr_is_target(expr, target_lvar_idx: int | None = None, target_ea: int | None = None) -> bool:
    """Check if a ctree expression is the target variable/global."""
    if expr is None:
        return False
    if target_lvar_idx is not None and expr.op == ida_hexrays.cot_var:
        return expr.v.idx == target_lvar_idx
    if target_ea is not None and expr.op == ida_hexrays.cot_obj:
        return expr.obj_ea == target_ea
    return False

class _UsageCollector(ida_hexrays.ctree_visitor_t):
    """Collect field accesses, call usages, and malloc origins for a target variable."""

    def __init__(self, cfunc: ida_hexrays.cfunc_t, target_lvar_idx: int | None = None, target_ea: int | None = None):
        super().__init__(ida_hexrays.CV_FAST)
        self.cfunc = cfunc
        self.target_lvar_idx = target_lvar_idx
        self.target_ea = target_ea
        self.field_accesses: list[dict] = []
        self.call_usages: list[dict] = []
        self.stored_in: list[dict] = []         # NEW: target stored INTO another struct's field
        self.malloc_origin: dict | None = None
        self.assignments: list[dict] = []
        self._found_vars: set[int] = set()
        self._seen_field_writes: set[tuple[str, int]] = set()  # (ea_hex, offset)
        self._seen_stored_in: set[tuple[str, int]] = set()
        if target_lvar_idx is not None:
            self._found_vars.add(target_lvar_idx)
        # Diagnostic counters — surfaced in `functions_analyzed[*].diag` so
        # callers can tell *why* no field accesses were found (visitor never
        # saw a memptr at all? saw one but rejected the base? rejected because
        # of a cast we don't unwrap?). These are essential for debugging
        # zero-field-access mysteries on real binaries.
        self._diag: dict[str, int] = {
            "asg_memptr_seen": 0,            # cot_asg with cot_memptr LHS encountered
            "asg_memptr_base_mismatch": 0,   # ...but the base wasn't the target
            "read_memptr_seen": 0,           # standalone cot_memptr / cot_memref reads
            "read_memptr_base_mismatch": 0,
            "read_ptr_seen": 0,              # cot_ptr / cot_idx reads
            "read_ptr_base_mismatch": 0,
            "read_ptr_decompose_failed": 0,  # cot_ptr that didn't decompose to (target, offset, size)
            "stored_in_count": 0,            # target appeared as RHS of `other_struct.field = target`
        }
        # Up to 3 sample base expressions we rejected — helps identify
        # unexpected wrapping (e.g. `cot_ref(cot_obj(...))`).
        self._base_mismatch_samples: list[str] = []

    def _is_target_expr(self, expr) -> bool:
        return _expr_is_target(expr, self.target_lvar_idx, self.target_ea)

    def _track_var_assignment(self, lhs, rhs):
        """Track assignments: if rhs resolves to the target (or to another
        tracked alias), the lhs local is added to ``_found_vars`` so later
        accesses through it are attributed correctly. Casts are stripped on
        both sides because Hex-Rays inserts ``(T*)`` wrappers liberally."""
        if lhs is None or rhs is None:
            return
        if lhs.op != ida_hexrays.cot_var:
            return
        rhs_unwrapped = _unwrap_casts(rhs)
        if rhs_unwrapped is None:
            return
        # Direct target → alias
        if self._is_target_expr(rhs_unwrapped):
            self._found_vars.add(lhs.v.idx)
            return
        # Alias chain: v_new = v_known
        if rhs_unwrapped.op == ida_hexrays.cot_var and rhs_unwrapped.v.idx in self._found_vars:
            self._found_vars.add(lhs.v.idx)

    def _record_field_access(self, expr, is_write: bool):
        """Record a memptr/memref access on the target."""
        try:
            offset_bytes = expr.m // 8
            access_size = getattr(expr, "ptrsize", 8)
            if access_size == 0:
                access_size = 8
            ea_hex = hex(expr.ea)
            # Deduplicate writes to avoid double-counting (cot_asg + cot_memptr)
            if is_write:
                self._seen_field_writes.add((ea_hex, offset_bytes))
            else:
                if (ea_hex, offset_bytes) in self._seen_field_writes:
                    return  # skip read that was already recorded as write
            func_ea = self.cfunc.entry_ea
            func_name = ida_funcs.get_func_name(func_ea) or hex(func_ea)
            self.field_accesses.append({
                "offset": offset_bytes,
                "access_size": access_size,
                "is_write": is_write,
                "ea": ea_hex,
                "func_ea": hex(func_ea),
                "func_name": func_name,
                "disasm": _get_expr_text(expr, self.cfunc),
            })
        except Exception as e:
            logger.debug("_record_field_access failed: %s", e)

    def _record_raw_field_access(self, expr, offset_bytes: int, access_size: int, is_write: bool):
        """Record a field access detected via raw pointer arithmetic.

        Distinct from ``_record_field_access`` (which handles ``cot_memptr``/
        ``cot_memref`` nodes from already-typed struct pointers) — this handles
        the ``*(T*)(ptr+N)`` shape Hex-Rays emits for *untyped* struct pointers,
        which is exactly what ``type_propagate`` is trying to identify.
        """
        try:
            if offset_bytes < 0:
                # Sign-extended negative offset — skip; struct fields don't
                # live at negative offsets, and this is usually base-pointer
                # arithmetic the caller doesn't want surfaced as a field.
                return
            ea_hex = hex(expr.ea)
            if is_write:
                self._seen_field_writes.add((ea_hex, offset_bytes))
            else:
                if (ea_hex, offset_bytes) in self._seen_field_writes:
                    return
            func_ea = self.cfunc.entry_ea
            func_name = ida_funcs.get_func_name(func_ea) or hex(func_ea)
            self.field_accesses.append({
                "offset": offset_bytes,
                "access_size": access_size,
                "is_write": is_write,
                "ea": ea_hex,
                "func_ea": hex(func_ea),
                "func_name": func_name,
                "disasm": f"*(uint{access_size*8}_t*)(target+0x{offset_bytes:X})",
            })
        except Exception as e:
            logger.debug("_record_raw_field_access failed: %s", e)

    def _record_stored_in(self, lhs_memptr):
        """Record that target appeared as the RHS of an assignment whose LHS
        is a struct-field access. Distinguishes "target is stored at offset N
        of another struct" from "target is a struct with a field at offset N".

        This is the inverse direction of ``_record_field_access`` and is
        critical for analyzing value-type globals (``char*``, ``int``, etc.)
        that are *held by* other structs rather than being struct bases
        themselves.
        """
        try:
            offset_bytes = lhs_memptr.m // 8
            access_size = getattr(lhs_memptr, "ptrsize", 8) or 8
            ea_hex = hex(lhs_memptr.ea)
            key = (ea_hex, offset_bytes)
            if key in self._seen_stored_in:
                return
            self._seen_stored_in.add(key)
            container_expr = _get_expr_text(lhs_memptr.x, self.cfunc)
            func_ea = self.cfunc.entry_ea
            func_name = ida_funcs.get_func_name(func_ea) or hex(func_ea)
            self.stored_in.append({
                "offset": offset_bytes,
                "access_size": access_size,
                "ea": ea_hex,
                "func_ea": hex(func_ea),
                "func_name": func_name,
                "container_expr": container_expr,
            })
            self._diag["stored_in_count"] += 1
        except Exception as e:
            logger.debug("_record_stored_in failed: %s", e)

    def _is_tracked_base(self, base) -> bool:
        """Whether ``base`` resolves to the propagation target.

        A base is "tracked" if it is the target global/lvar directly, or if it
        is a local variable that has been assigned from the target (a derived
        alias collected in ``_found_vars``). Casts are stripped before checks.
        """
        base = _unwrap_casts(base)
        if base is None:
            return False
        if self._is_target_expr(base):
            return True
        if base.op == ida_hexrays.cot_var and base.v.idx in self._found_vars:
            return True
        return False

    def _record_base_mismatch_sample(self, base) -> None:
        """Save up to 3 string samples of bases we rejected for diagnostics.

        Helps distinguish "ctree shape we don't recognize" (unexpected node
        op like ``cot_ref``) from "wrong target_ea" (cot_obj with non-matching
        obj_ea) from "untracked local" (cot_var not in _found_vars).
        """
        if len(self._base_mismatch_samples) >= 3:
            return
        try:
            unwrapped = _unwrap_casts(base)
            if unwrapped is None:
                self._base_mismatch_samples.append("None")
                return
            op_name = f"op={unwrapped.op}"
            if unwrapped.op == ida_hexrays.cot_var:
                detail = f"var.idx={unwrapped.v.idx}"
            elif unwrapped.op == ida_hexrays.cot_obj:
                detail = f"obj_ea={hex(unwrapped.obj_ea)}"
            else:
                detail = _get_expr_text(unwrapped, self.cfunc)
            self._base_mismatch_samples.append(f"{op_name} {detail}")
        except Exception:
            self._base_mismatch_samples.append("<exception extracting sample>")

    def _record_call_usage(self, call_expr, arg_index: int):
        """Record that target is passed as argument to a call."""
        try:
            callee = call_expr.x
            if callee is None:
                return
            callee_ea = callee.obj_ea if callee.op == ida_hexrays.cot_obj else idaapi.BADADDR
            callee_name = ida_name.get_func_name(callee_ea) or ida_name.get_name(callee_ea) or ""
            func_ea = self.cfunc.entry_ea
            func_name = ida_funcs.get_func_name(func_ea) or hex(func_ea)
            self.call_usages.append({
                "func_ea": hex(func_ea),
                "func_name": func_name,
                "call_ea": hex(call_expr.ea),
                "arg_index": arg_index,
                "callee_name": callee_name,
            })
        except Exception as e:
            logger.debug("_record_call_usage failed: %s", e)

    def _check_malloc_origin(self, rhs):
        """Check if rhs is a malloc-like call."""
        if rhs.op != ida_hexrays.cot_call:
            return False
        callee = rhs.x
        if callee.op != ida_hexrays.cot_obj:
            return False
        callee_name = ida_name.get_func_name(callee.obj_ea) or ""
        if any(m in callee_name for m in _MALLOC_LIKE):
            self.malloc_origin = {
                "ea": hex(rhs.ea),
                "func_ea": hex(self.cfunc.entry_ea),
                "func_name": ida_funcs.get_func_name(self.cfunc.entry_ea) or "",
                "allocator": callee_name,
            }
            return True
        return False

    def visit_expr(self, expr):
        try:
            # --- Assignment tracking ---
            if expr.op == ida_hexrays.cot_asg:
                lhs, rhs = expr.x, expr.y
                self._track_var_assignment(lhs, rhs)
                # Field write: target->field = value
                #
                # Modern Hex-Rays normalizes ``*(T*)(ptr + N) = value`` into
                # ``cot_asg(cot_memptr(ptr, m=N*8), value)`` regardless of
                # whether ``ptr`` has an applied struct type — the
                # memory-dereference *is* the LHS, never a ``cot_ptr``. So we
                # don't need a separate ``cot_ptr``/``cot_idx`` write branch
                # here; the read-side handler below catches those shapes when
                # they appear in rvalue contexts.
                if lhs.op in (ida_hexrays.cot_memptr, ida_hexrays.cot_memref):
                    self._diag["asg_memptr_seen"] += 1
                    if self._is_tracked_base(lhs.x):
                        self._record_field_access(lhs, is_write=True)
                    else:
                        self._diag["asg_memptr_base_mismatch"] += 1
                        self._record_base_mismatch_sample(lhs.x)
                        # Stored-in: if the RHS is the target, the LHS struct
                        # has the target as a field VALUE — record where.
                        # Only meaningful when the LHS base wasn't the target
                        # itself, otherwise it's just a self-field write.
                        rhs_uw = _unwrap_casts(rhs)
                        if rhs_uw is not None and self._is_target_expr(rhs_uw):
                            self._record_stored_in(lhs)
                # Malloc origin: var = malloc(...)
                if self._is_target_expr(lhs) or (lhs.op == ida_hexrays.cot_var and lhs.v.idx in self._found_vars):
                    self._check_malloc_origin(rhs)

            # --- Field reads (already-typed struct ptr) ---
            if expr.op in (ida_hexrays.cot_memptr, ida_hexrays.cot_memref):
                self._diag["read_memptr_seen"] += 1
                if self._is_tracked_base(expr.x):
                    self._record_field_access(expr, is_write=False)
                else:
                    self._diag["read_memptr_base_mismatch"] += 1
                    self._record_base_mismatch_sample(expr.x)

            # --- Field reads (raw pointer arithmetic on untyped ptr) ---
            # When Hex-Rays does *not* fold the access into a ``cot_memptr``
            # (typically because the cast type is one-off or the base is a
            # local), the rvalue appears as ``cot_ptr(cot_cast(cot_add(...)))``.
            elif expr.op in (ida_hexrays.cot_ptr, ida_hexrays.cot_idx):
                self._diag["read_ptr_seen"] += 1
                decomp = _decompose_ptr_access(expr)
                if decomp is None:
                    self._diag["read_ptr_decompose_failed"] += 1
                else:
                    target_expr, offset, access_size = decomp
                    if self._is_tracked_base(target_expr):
                        self._record_raw_field_access(expr, offset, access_size, is_write=False)
                    else:
                        self._diag["read_ptr_base_mismatch"] += 1
                        self._record_base_mismatch_sample(target_expr)

            # --- Call arguments ---
            if expr.op == ida_hexrays.cot_call:
                args = expr.a
                if args:
                    for idx, arg in enumerate(args):
                        arg_unwrapped = _unwrap_casts(arg)
                        if arg_unwrapped is not None and (
                            self._is_target_expr(arg_unwrapped)
                            or (arg_unwrapped.op == ida_hexrays.cot_var
                                and arg_unwrapped.v.idx in self._found_vars)
                        ):
                            self._record_call_usage(expr, idx)

        except Exception as e:
            logger.debug("_UsageCollector.visit_expr failed: %s", e)
        return 0





class FieldAccess(TypedDict, total=False):
    offset: int
    access_size: int
    is_write: bool
    ea: str
    func_ea: str
    func_name: str
    disasm: str


class CallUsage(TypedDict, total=False):
    func_ea: str
    func_name: str
    call_ea: str
    arg_index: int
    callee_name: str


class StoredIn(TypedDict, total=False):
    """Records target being *stored into* another struct's field.

    Distinct from ``FieldAccess`` (which records target's *own* fields being
    accessed). This is the "the target is a value held by something else" case
    — e.g. ``some_struct->member = target`` makes target the rvalue, not the
    base. Crucial for analyzing char*/value-type globals like ``String1``.
    """
    offset: int                # offset within the containing struct
    access_size: int           # size of the slot the target occupies
    ea: str
    func_ea: str
    func_name: str
    container_expr: str        # text of the base expression (e.g. "v8")


class PropagationStep(TypedDict, total=False):
    ea: str
    func_ea: str
    func_name: str
    kind: str
    detail: str


class FieldProfileEntry(TypedDict, total=False):
    reads: int
    writes: int
    max_size: int
    min_size: int
    function_count: int        # how many distinct functions accessed this offset


class ConfidenceFactor(TypedDict, total=False):
    kind: str                  # "api_match" | "field_accesses" | "malloc_origin" | "no_evidence"
    detail: str
    contribution: float


class TypePropagateResult(TypedDict, total=False):
    ok: bool
    address: str
    inferred_type: str
    confidence: float
    field_accesses: list[FieldAccess]
    field_profile: dict[str, FieldProfileEntry]    # offset (hex) -> stats
    call_usages: list[CallUsage]
    stored_in: list[StoredIn]
    propagation_path: list[PropagationStep]
    functions_analyzed: list[dict]
    suggested_struct_name: str | None
    suggested_struct_definition: str | None
    applied: bool
    confidence_breakdown: list[ConfidenceFactor]
    error: str
    error_type: str
    hint: str


# Known API signatures for type inference from call arguments
_KNOWN_API_TYPES: dict[str, str] = {
    "strlen": "char*",
    "strcmp": "char*",
    "strncmp": "char*",
    "strcpy": "char*",
    "strncpy": "char*",
    "strdup": "char*",
    "memcpy": "void*",
    "memmove": "void*",
    "memset": "void*",
    "memcmp": "void*",
    "malloc": "void*",
    "calloc": "void*",
    "realloc": "void*",
    "free": "void*",
    "fopen": "FILE*",
    "fclose": "FILE*",
    "fread": "FILE*",
    "fwrite": "FILE*",
    "fprintf": "FILE*",
    "sprintf": "char*",
    "snprintf": "char*",
    "printf": "const char*",
    "puts": "const char*",
    "atoi": "const char*",
    "atol": "const char*",
    "atof": "const char*",
    "strtol": "char*",
    "strtoul": "char*",
    "strtod": "char*",
    "sscanf": "const char*",
    "qsort": "void*",
    "bsearch": "void*",
}

# ============================================================================
# Type Declaration
# ============================================================================


@tool
@idasync
def declare_type(
    decls: Annotated[list[str] | str, "C type declarations"],
) -> list[DeclareTypeResult]:
    """Declare C type definitions in local type library."""
    decls = normalize_list_input(decls)
    results = []

    for decl in decls:
        try:
            flags = ida_typeinf.PT_SIL | ida_typeinf.PT_EMPTY | ida_typeinf.PT_TYP
            errors, messages = parse_decls_ctypes(decl, flags)

            pretty_messages = "\n".join(messages)
            if errors > 0:
                results.append(
                    {"decl": decl, "error": f"Failed to parse:\n{pretty_messages}"}
                )
            else:
                results.append({"decl": decl})
        except Exception as e:
            results.append({"decl": decl, **item_error(e)})

    return results


@tool
@idasync
def enum_upsert(
    queries: Annotated[
        list[EnumUpsert] | EnumUpsert,
        "Create enums if missing and upsert enum members without destructive replacement",
    ],
) -> list[EnumUpsertResult]:
    """Create or extend local enums in an idempotent way."""
    queries = normalize_dict_list(queries)
    results = []

    for query in queries:
        enum_name = str(query.get("name", "") or "").strip()
        members = normalize_dict_list(query.get("members"))
        bitfield = bool(query.get("bitfield", False))

        if not enum_name:
            results.append({"name": enum_name, "error": "Enum name is required"})
            continue
        if not members or members == [{}]:
            results.append({"name": enum_name, "error": "At least one enum member is required"})
            continue

        try:
            enum_id = idc.get_enum(enum_name)
            created = enum_id == idc.BADADDR
            if created:
                enum_id = idc.add_enum(idc.BADADDR, enum_name, 0)
                if enum_id == idc.BADADDR:
                    results.append({"name": enum_name, "error": f"Failed to create enum: {enum_name}"})
                    continue

            if bool(idc.is_bf(enum_id)) != bitfield and not created:
                results.append(
                    {
                        "name": enum_name,
                        "enum_id": hex(enum_id),
                        "error": f"Enum bitfield mismatch for {enum_name}",
                    }
                )
                continue
            idc.set_enum_bf(enum_id, bitfield)

            member_results = []
            created_count = 0
            skipped_count = 0
            conflict_count = 0
            for member in members:
                member_name = str(member.get("name", "") or "").strip()
                raw_value = member.get("value")
                if not member_name:
                    member_results.append({"name": member_name, "error": "Member name is required"})
                    conflict_count += 1
                    continue
                try:
                    value = _parse_enum_value(raw_value)
                except Exception as exc:
                    member_results.append({"name": member_name, "error": str(exc)})
                    conflict_count += 1
                    continue

                existing_member_id = idc.get_enum_member_by_name(member_name)
                if existing_member_id != idc.BADADDR:
                    existing_enum = idc.get_enum_member_enum(existing_member_id)
                    existing_value = idc.get_enum_member_value(existing_member_id)
                    if existing_enum == enum_id and existing_value == value:
                        member_results.append(
                            {"name": member_name, "value": value, "skipped": True}
                        )
                        skipped_count += 1
                        continue
                    member_results.append(
                        {
                            "name": member_name,
                            "value": value,
                            "error": (
                                f"Member name conflict: {member_name} already exists with value "
                                f"{existing_value} in enum {idc.get_enum_name(existing_enum) or hex(existing_enum)}"
                            ),
                        }
                    )
                    conflict_count += 1
                    continue

                existing_const = idc.get_enum_member(enum_id, value, 0, -1)
                if existing_const != -1:
                    existing_name = idc.get_enum_member_name(existing_const) or ""
                    if existing_name == member_name:
                        member_results.append(
                            {"name": member_name, "value": value, "skipped": True}
                        )
                        skipped_count += 1
                        continue
                    member_results.append(
                        {
                            "name": member_name,
                            "value": value,
                            "error": f"Enum value conflict: {value} already belongs to {existing_name}",
                        }
                    )
                    conflict_count += 1
                    continue

                rc = idc.add_enum_member(enum_id, member_name, value, -1)
                if rc != 0:
                    member_results.append(
                        {"name": member_name, "value": value, "error": f"Failed to add enum member: rc={rc}"}
                    )
                    conflict_count += 1
                    continue
                member_results.append({"name": member_name, "value": value, "created": True})
                created_count += 1

            result_dict: dict = {
                "name": enum_name,
                "enum_id": hex(enum_id),
                "created": created,
                "bitfield": bitfield,
                "members": member_results,
                "summary": {
                    "created": created_count,
                    "skipped": skipped_count,
                    "conflicts": conflict_count,
                },
            }
            if conflict_count > 0:
                result_dict["error"] = f"{conflict_count} member conflict(s)"
            results.append(result_dict)
        except Exception as exc:
            results.append({"name": enum_name, **item_error(exc, f"enum_upsert {enum_name!r}")})

    return results


def _parse_enum_value(value: int | str | None) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            raise ValueError("Enum member value is required")
        return int(text, 0)
    raise ValueError(f"Invalid enum member value: {value!r}")


# ============================================================================
# Structure Operations
# ============================================================================


@tool
@idasync
def read_struct(
    queries: list[StructRead] | StructRead,
) -> list[ReadStructResult]:
    """Read struct fields from memory at address; auto-detect type when possible."""

    queries = normalize_dict_list(queries)

    results = []
    for query in queries:
        addr_str = query.get("addr", "")
        struct_name = query.get("struct", "")

        try:
            # Parse address - this is required
            if not addr_str:
                results.append(
                    {
                        "addr": None,
                        "struct": struct_name,
                        "members": None,
                        "error": "Address is required for reading struct fields",
                    }
                )
                continue

            # Try to parse as address, then try name resolution
            try:
                addr = parse_address(addr_str)
            except Exception:
                addr = idaapi.get_name_ea(idaapi.BADADDR, addr_str)
                if addr == idaapi.BADADDR:
                    results.append(
                        {
                            "addr": addr_str,
                            "struct": struct_name,
                            "members": None,
                            "error": f"Failed to resolve address: {addr_str}",
                        }
                    )
                    continue

            # Auto-detect struct type from address if not provided
            if not struct_name:
                tif_auto = ida_typeinf.tinfo_t()
                if ida_nalt.get_tinfo(tif_auto, addr) and tif_auto.is_udt():
                    struct_name = tif_auto.get_type_name()

            if not struct_name:
                results.append(
                    {
                        "addr": addr_str,
                        "struct": None,
                        "members": None,
                        "error": "No struct specified and could not auto-detect from address",
                    }
                )
                continue

            tif = ida_typeinf.tinfo_t()
            if not tif.get_named_type(None, struct_name):
                results.append(
                    {
                        "addr": addr_str,
                        "struct": struct_name,
                        "members": None,
                        "error": f"Struct '{struct_name}' not found",
                    }
                )
                continue

            udt_data = ida_typeinf.udt_type_data_t()
            if not tif.get_udt_details(udt_data):
                results.append(
                    {
                        "addr": addr_str,
                        "struct": struct_name,
                        "members": None,
                        "error": "Failed to get struct details",
                    }
                )
                continue

            members = []
            for member in udt_data:
                offset = member.begin() // 8
                member_type = member.type._print()
                member_name = member.name
                member_size = member.type.get_size()

                # Read memory value at member address (BSS-aware: unloaded
                # bytes resolve to zero, matching runtime zero-init).
                member_addr = addr + offset
                try:
                    if member.type.is_ptr():
                        ptr_size = 8 if compat.inf_is_64bit() else 4
                        value = read_int_bss_safe(member_addr, ptr_size)
                        value_str = f"0x{value:0{ptr_size * 2}X}"
                    elif member_size in (1, 2, 4, 8):
                        value = read_int_bss_safe(member_addr, member_size)
                        value_str = f"0x{value:0{member_size * 2}X} ({value})"
                    else:
                        capped = min(member_size, 16)
                        raw = read_bytes_bss_safe(member_addr, capped)
                        bytes_data = [f"{b:02X}" for b in raw]
                        value_str = f"[{' '.join(bytes_data)}{'...' if member_size > 16 else ''}]"
                except Exception:
                    value_str = "<failed to read>"

                member_info = {
                    "offset": f"0x{offset:08X}",
                    "type": member_type,
                    "name": member_name,
                    "size": member_size,
                    "value": value_str,
                }

                members.append(member_info)

            results.append(
                {"addr": addr_str, "struct": struct_name, "members": members}
            )
        except Exception as e:
            results.append(
                {
                    "addr": addr_str,
                    "struct": struct_name,
                    "members": None,
                    **item_error(e),
                }
            )

    return results


@tool
@idasync
def search_structs(
    filter: Annotated[
        str, "Case-insensitive substring to search for in structure names"
    ],
) -> list[SearchStructResult]:
    """Search local structs/unions by name pattern."""
    results = []
    limit = compat.get_ordinal_limit()

    for ordinal in range(1, limit):
        tif = ida_typeinf.tinfo_t()
        if tif.get_numbered_type(None, ordinal):
            type_name: str = tif.get_type_name()
            if type_name and filter.lower() in type_name.lower():
                if tif.is_udt():
                    udt_data = ida_typeinf.udt_type_data_t()
                    cardinality = 0
                    if tif.get_udt_details(udt_data):
                        cardinality = udt_data.size()

                    results.append(
                        {
                            "name": type_name,
                            "size": tif.get_size(),
                            "cardinality": cardinality,
                            "is_union": (
                                udt_data.is_union
                                if tif.get_udt_details(udt_data)
                                else False
                            ),
                            "ordinal": ordinal,
                        }
                    )

    return results


def _type_kind(tif: ida_typeinf.tinfo_t) -> str:
    try:
        if tif.is_enum():
            return "enum"
    except Exception:
        pass
    try:
        if tif.is_typedef():
            return "typedef"
    except Exception:
        pass
    try:
        if tif.is_func():
            return "func"
    except Exception:
        pass
    try:
        if tif.is_ptr():
            return "ptr"
    except Exception:
        pass

    try:
        if tif.is_udt():
            udt = ida_typeinf.udt_type_data_t()
            if tif.get_udt_details(udt) and udt.is_union:
                return "union"
            return "struct"
    except Exception:
        pass

    return "other"


def _type_matches_kind(kind: str, tif: ida_typeinf.tinfo_t) -> bool:
    if kind == "any":
        return True
    if kind == "udt":
        try:
            return bool(tif.is_udt())
        except Exception:
            return False
    return _type_kind(tif) == kind


# ============================================================================
# Type Inference & Application
# ============================================================================


@tool
@idasync
def type_query(
    queries: Annotated[
        list[TypeQuery] | TypeQuery,
        "Type catalog query with filtering, pagination, and optional relationships",
    ],
) -> list[TypeQueryResult]:
    """Query local types with structured filters/projection-friendly output."""
    queries = normalize_dict_list(queries)

    # Build one local catalog and page/filter it per query.
    catalog: list[dict] = []
    limit = ida_typeinf.get_ordinal_limit()
    for ordinal in range(1, limit):
        tif = ida_typeinf.tinfo_t()
        if not tif.get_numbered_type(None, ordinal):
            continue
        name = tif.get_type_name()
        if not name:
            continue
        catalog.append(
            {
                "ordinal": ordinal,
                "name": name,
                "size": tif.get_size(),
                "kind": _type_kind(tif),
                "_tif": tif,
            }
        )

    results: list[dict] = []
    for query in queries:
        filter_pattern = str(query.get("filter", "") or "")
        kind = str(query.get("kind", "any") or "any").lower()
        if kind not in {"any", "struct", "union", "enum", "typedef", "func", "ptr", "udt"}:
            kind = "any"

        offset = int(query.get("offset", 0) or 0)
        count = int(query.get("count", 100) or 100)
        sort_by = str(query.get("sort_by", "name") or "name")
        descending = bool(query.get("descending", False))
        include_decl = bool(query.get("include_decl", True))
        include_members = bool(query.get("include_members", False))
        max_members = int(query.get("max_members", 64) or 64)
        include_relationships = bool(query.get("include_relationships", False))

        if max_members < 0:
            max_members = 0
        if max_members > 4096:
            max_members = 4096

        filtered: list[dict] = []
        for row in catalog:
            tif = row.get("_tif")
            if not isinstance(tif, ida_typeinf.tinfo_t):
                continue
            if not _type_matches_kind(kind, tif):
                continue
            filtered.append(row)

        if filter_pattern:
            filtered = pattern_filter(filtered, filter_pattern, "name")

        if sort_by == "size":
            filtered.sort(key=lambda r: int(r.get("size", 0) or 0), reverse=descending)
        elif sort_by == "ordinal":
            filtered.sort(key=lambda r: int(r.get("ordinal", 0) or 0), reverse=descending)
        else:
            filtered.sort(key=lambda r: str(r.get("name", "")).lower(), reverse=descending)

        output_rows: list[dict] = []
        for row in filtered:
            tif = row["_tif"]
            out = {
                "ordinal": row["ordinal"],
                "name": row["name"],
                "size": row["size"],
                "kind": row["kind"],
            }

            if include_decl:
                out["declaration"] = str(tif)

            if include_members:
                members = []
                member_count = 0
                members_truncated = False
                if tif.is_udt():
                    udt = ida_typeinf.udt_type_data_t()
                    if tif.get_udt_details(udt):
                        member_count = len(udt)
                        for idx, member in enumerate(udt):
                            if idx >= max_members:
                                members_truncated = True
                                break
                            members.append(
                                {
                                    "name": member.name,
                                    "offset": hex(member.begin() // 8),
                                    "size": member.type.get_size(),
                                    "type": member.type._print(),
                                }
                            )
                out["member_count"] = member_count
                out["members"] = members
                out["members_truncated"] = members_truncated

            if include_relationships:
                related: set[str] = set()
                if tif.is_udt():
                    udt = ida_typeinf.udt_type_data_t()
                    if tif.get_udt_details(udt):
                        for member in udt:
                            rel_name = member.type.get_type_name() or str(member.type)
                            if rel_name:
                                related.add(rel_name)
                if tif.is_ptr():
                    pointed = ida_typeinf.tinfo_t()
                    try:
                        if tif.get_pointed_object(pointed):
                            rel_name = pointed.get_type_name() or str(pointed)
                            if rel_name:
                                related.add(rel_name)
                    except Exception:
                        pass

                related_list = sorted(related)
                out["related_count"] = len(related_list)
                out["related_types"] = related_list[:256]
                out["related_truncated"] = len(related_list) > 256

            output_rows.append(out)

        page = paginate(output_rows, offset, count)
        results.append(
            {
                "kind": kind,
                "data": page["data"],
                "next_offset": page["next_offset"],
                "total": len(output_rows),
            }
        )

    return results


@tool
@idasync
def type_inspect(
    queries: Annotated[
        list[TypeInspectQuery] | TypeInspectQuery,
        "Inspect named types and optionally include member layout",
    ],
) -> list[TypeInspectResult]:
    """Inspect named types (size/kind/declaration/members)."""
    queries = normalize_dict_list(queries)
    results = []

    for query in queries:
        name = (query.get("name") or "").strip()
        include_members = bool(query.get("include_members", False))
        max_members = int(query.get("max_members", 128) or 128)
        if max_members < 0:
            max_members = 0
        if max_members > 4096:
            max_members = 4096

        if not name:
            results.append(
                {
                    "name": name,
                    "exists": False,
                    "error": "Type name is required",
                }
            )
            continue

        try:
            tif = ida_typeinf.tinfo_t()
            if not tif.get_named_type(None, name):
                results.append(
                    {"name": name, "exists": False, "error": f"Type not found: {name}"}
                )
                continue

            raw_size = tif.get_size()
            # get_size() returns BADSIZE (0xFFFFFFFFFFFFFFFF) when the type's
            # layout hasn't been resolved yet.  Expose None so callers can
            # distinguish "size unknown" from "size zero".
            resolved_size: int | None = None if raw_size == 0xFFFFFFFFFFFFFFFF else raw_size

            info = {
                "name": name,
                "exists": True,
                "declaration": str(tif),
                "size": resolved_size,
                "is_func": tif.is_func(),
                "is_ptr": tif.is_ptr(),
                "is_enum": tif.is_enum(),
                "is_udt": tif.is_udt(),
                "members": None,
                "member_count": 0,
            }
            if resolved_size is None:
                info["size_note"] = "size unknown — type declared but not fully defined in this IDB"

            if include_members and tif.is_udt():
                udt = ida_typeinf.udt_type_data_t()
                if tif.get_udt_details(udt):
                    info["member_count"] = len(udt)
                    members = []
                    for idx, member in enumerate(udt):
                        if idx >= max_members:
                            break
                        raw_member_size = member.type.get_size()
                        members.append(
                            {
                                "name": member.name,
                                "offset": hex(member.begin() // 8),
                                "size": None if raw_member_size == 0xFFFFFFFFFFFFFFFF else raw_member_size,
                                "type": member.type._print(),
                            }
                        )
                    info["members"] = members

            results.append(info)
        except Exception as e:
            results.append(
                {
                    "name": name,
                    "exists": False,
                    **item_error(e),
                }
            )

    return results


def _parse_addr_type_shorthand(s: str) -> dict:
    # Support "addr:typename" shorthand.
    if ":" in s:
        addr, ty = s.split(":", 1)
        return {"addr": addr.strip(), "ty": ty.strip()}
    return {"ty": s.strip()}


def _resolve_type_text(edit: dict) -> str:
    return str(
        edit.get("ty")
        or edit.get("type")
        or edit.get("decl")
        or edit.get("declaration")
        or ""
    ).strip()


def _parse_type_tinfo(type_text: str) -> ida_typeinf.tinfo_t:
    text = type_text.strip()
    if not text:
        raise ValueError("Type text is required")

    # Fast path for common type aliases and named types.
    try:
        return get_type_by_name(text)
    except Exception:
        pass

    flags = ida_typeinf.PT_SIL | ida_typeinf.PT_TYP
    parse_decl = getattr(ida_typeinf, "parse_decl", None)
    if callable(parse_decl):
        candidates = [text]
        if not text.endswith(";"):
            candidates.append(text + ";")
        for candidate in candidates:
            tif = ida_typeinf.tinfo_t()
            try:
                # parse_decl returns '' on success in IDA 9.0, check is not None
                if parse_decl(tif, None, candidate, flags) is not None and not tif.empty():
                    return tif
            except Exception:
                continue

    # Legacy constructor fallback.
    try:
        tif = ida_typeinf.tinfo_t(text, None, ida_typeinf.PT_SIL)
        empty = getattr(tif, "empty", None)
        if callable(empty):
            if not empty():
                return tif
        else:
            return tif
    except Exception:
        pass

    raise ValueError(f"Unable to parse type: {text}")


def _parse_function_tinfo(signature_text: str) -> ida_typeinf.tinfo_t:
    text = signature_text.strip()
    if not text:
        raise ValueError("Function signature is required")

    flags = ida_typeinf.PT_SIL | ida_typeinf.PT_TYP
    parse_decl = getattr(ida_typeinf, "parse_decl", None)
    if callable(parse_decl):
        candidates = [text]
        if not text.endswith(";"):
            candidates.append(text + ";")
        for candidate in candidates:
            tif = ida_typeinf.tinfo_t()
            try:
                # parse_decl returns '' on success in IDA 9.0, check is not None
                if parse_decl(tif, None, candidate, flags) is not None and tif.is_func():
                    return tif
            except Exception:
                continue

    try:
        tif = ida_typeinf.tinfo_t(text, None, ida_typeinf.PT_SIL)
        if tif.is_func():
            return tif
    except Exception:
        pass

    raise ValueError(f"Not a function type: {text}")


def _infer_type_edit_kind(edit: dict) -> str:
    kind = str(edit.get("kind") or "").strip().lower()
    if kind:
        return kind
    if edit.get("signature"):
        return "function"
    if edit.get("variable"):
        return "local"

    if "addr" in edit and "name" in edit and _resolve_type_text(edit):
        # Heuristic: addr + frame name usually indicates stack variable updates.
        try:
            fn = idaapi.get_func(parse_address(edit["addr"]))
            if fn:
                frame_tif = ida_typeinf.tinfo_t()
                if ida_frame.get_func_frame(frame_tif, fn):
                    _, udm = tinfo_get_udm(frame_tif, str(edit["name"]))
                    if udm:
                        return "stack"
        except Exception:
            pass

    return "global"


def _apply_type_edit(edit: dict[str, Any]) -> SetTypeResult:
    try:
        kind = _infer_type_edit_kind(edit)
        type_text = _resolve_type_text(edit)

        if kind == "function":
            addr_text = str(edit.get("addr", "")).strip()
            if not addr_text:
                return {"edit": edit, "kind": kind, "error": "Function address is required"}
            func = idaapi.get_func(parse_address(addr_text))
            if not func:
                return {"edit": edit, "kind": kind, "error": "Function not found"}

            signature = str(edit.get("signature") or type_text).strip()
            tif = _parse_function_tinfo(signature)
            ok = ida_typeinf.apply_tinfo(func.start_ea, tif, ida_typeinf.PT_SIL)
            result = {"edit": edit, "kind": kind, "ok": ok}
            if not ok:
                result["error"] = "Failed to apply function type"
            return result

        if kind == "global":
            ea = idaapi.BADADDR
            name = str(edit.get("name", "")).strip()
            if name:
                ea = idaapi.get_name_ea(idaapi.BADADDR, name)
            if ea == idaapi.BADADDR:
                addr_text = str(edit.get("addr", "")).strip()
                if not addr_text:
                    return {
                        "edit": edit,
                        "kind": kind,
                        "error": "Global requires name or address",
                    }
                ea = parse_address(addr_text)

            tif = _parse_type_tinfo(type_text)
            ok = ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.PT_SIL)
            result = {"edit": edit, "kind": kind, "ok": ok}
            if not ok:
                result["error"] = "Failed to apply global type"
            return result

        if kind == "local":
            addr_text = str(edit.get("addr", "")).strip()
            var_name = str(edit.get("variable", "")).strip()
            if not addr_text:
                return {"edit": edit, "kind": kind, "error": "Function address is required"}
            if not var_name:
                return {"edit": edit, "kind": kind, "error": "Local variable name is required"}

            func = idaapi.get_func(parse_address(addr_text))
            if not func:
                return {"edit": edit, "kind": kind, "error": "Function not found"}

            new_tif = _parse_type_tinfo(type_text)
            modifier = my_modifier_t(var_name, new_tif)
            ok = ida_hexrays.modify_user_lvars(func.start_ea, modifier)
            result = {"edit": edit, "kind": kind, "ok": ok}
            if not ok:
                result["error"] = "Failed to apply local variable type"
            return result

        if kind == "stack":
            addr_text = str(edit.get("addr", "")).strip()
            stack_name = str(edit.get("name", "")).strip()
            if not addr_text:
                return {"edit": edit, "kind": kind, "error": "Function address is required"}
            if not stack_name:
                return {"edit": edit, "kind": kind, "error": "Stack variable name is required"}

            func = idaapi.get_func(parse_address(addr_text))
            if not func:
                return {"edit": edit, "kind": kind, "error": "No function found"}

            frame_tif = ida_typeinf.tinfo_t()
            if not ida_frame.get_func_frame(frame_tif, func):
                return {"edit": edit, "kind": kind, "error": "No frame available"}

            idx, udm = tinfo_get_udm(frame_tif, stack_name)
            if not udm:
                return {
                    "edit": edit,
                    "kind": kind,
                    "error": f"Stack variable not found: {stack_name}",
                }

            tid = frame_tif.get_udm_tid(idx)
            udm = ida_typeinf.udm_t()
            frame_tif.get_udm_by_tid(udm, tid)
            offset = udm.offset // 8

            tif = _parse_type_tinfo(type_text)
            ok = ida_frame.set_frame_member_type(func, offset, tif)
            result = {"edit": edit, "kind": kind, "ok": ok}
            if not ok:
                result["error"] = "Failed to set stack member type"
            return result

        return {"edit": edit, "kind": kind, "error": f"Unknown kind: {kind}"}
    except Exception as e:
        return {"edit": edit, **item_error(e, "apply type edit")}


@tool
@idasync
def set_type(edits: list[TypeEdit] | TypeEdit) -> list[SetTypeResult]:
    """Apply types (function/global/local/stack)"""
    normalized_edits = normalize_dict_list(edits, _parse_addr_type_shorthand)
    return [_apply_type_edit(edit) for edit in normalized_edits]


@tool
@idasync
def type_apply_batch(
    batch: Annotated[
        TypeApplyBatch,
        "Batch type edits with optional stop_on_error behavior",
    ],
) -> TypeApplyBatchResult:
    """Apply multiple type edits and return aggregate status."""
    normalized_edits = normalize_dict_list(
        batch.get("edits", []), _parse_addr_type_shorthand
    )
    stop_on_error = bool(batch.get("stop_on_error", False))

    results: list[dict] = []
    for edit in normalized_edits:
        result = _apply_type_edit(edit)
        results.append(result)
        if stop_on_error and result.get("error"):
            break

    failed = sum(1 for r in results if r.get("error"))
    applied = sum(1 for r in results if r.get("ok"))
    return {
        "ok": failed == 0,
        "applied": applied,
        "failed": failed,
        "stopped": stop_on_error and failed > 0,
        "results": results,
    }


@tool
@idasync
def infer_types(
    addrs: Annotated[list[str] | str, "Addresses to infer types for"],
) -> list[InferTypeResult]:
    """Infer and apply likely types at target addresses."""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            tif = ida_typeinf.tinfo_t()

            # Try Hex-Rays inference
            if compat.guess_tinfo(tif, ea):
                results.append(
                    {
                        "addr": addr,
                        "inferred_type": str(tif),
                        "method": "hexrays",
                        "confidence": "high",
                    }
                )
                continue

            # Try getting existing type info
            if ida_nalt.get_tinfo(tif, ea):
                results.append(
                    {
                        "addr": addr,
                        "inferred_type": str(tif),
                        "method": "existing",
                        "confidence": "high",
                    }
                )
                continue

            # Try to guess from size
            size = ida_bytes.get_item_size(ea)
            if size > 0:
                type_guess = {
                    1: "uint8_t",
                    2: "uint16_t",
                    4: "uint32_t",
                    8: "uint64_t",
                }.get(size, f"uint8_t[{size}]")

                results.append(
                    {
                        "addr": addr,
                        "inferred_type": type_guess,
                        "method": "size_based",
                        "confidence": "low",
                    }
                )
                continue

            results.append(
                {
                    "addr": addr,
                    "inferred_type": None,
                    "method": None,
                    "confidence": "none",
                }
            )

        except Exception as e:
            results.append(
                {
                    "addr": addr,
                    "inferred_type": None,
                    "method": None,
                    "confidence": "none",
                    **item_error(e),
                }
            )

    return results


def _decompile_func(func_ea: int) -> ida_hexrays.cfunc_t | None:
    """Decompile a function; return None on failure."""
    try:
        hf = ida_hexrays.hexrays_failure_t()
        cfunc = ida_hexrays.decompile(func_ea, hf)
        if cfunc:
            return cfunc
        logger.debug("decompile 0x%x failed: %s", func_ea, hf.str)
    except Exception as e:
        logger.debug("decompile 0x%x exception: %s", func_ea, e)
    return None


def _get_expr_text(expr, cfunc) -> str:
    """Best-effort text representation of a ctree expression."""
    try:
        if expr.op == ida_hexrays.cot_var:
            lvars = cfunc.get_lvars()
            if 0 <= expr.v.idx < len(lvars):
                return lvars[expr.v.idx].name
            return f"v{expr.v.idx}"
        if expr.op == ida_hexrays.cot_obj:
            name = ida_name.get_func_name(expr.obj_ea) or ida_name.get_name(expr.obj_ea)
            return name or hex(expr.obj_ea)
        if expr.op == ida_hexrays.cot_num:
            return str(expr.n._value)
    except Exception:
        pass
    return f"expr_{expr.op}"


def _unwrap_casts(expr):
    """Strip ``cot_cast`` (and harmless ``cot_ref``) wrappers from an expression.

    Used because Hex-Rays often emits ``(T*)expr`` or ``&expr`` wrappers around
    the real address operand in untyped pointer-arithmetic patterns. Walks until
    a non-cast, non-ref node is found or until ``None``.
    """
    while expr is not None:
        if expr.op == ida_hexrays.cot_cast:
            expr = expr.x
        elif expr.op == ida_hexrays.cot_ref:
            expr = expr.x
        else:
            break
    return expr


def _const_value(expr) -> int | None:
    """Return the integer value of a ``cot_num`` expression, sign-extended.

    ``cnumber_t._value`` is an unsigned 64-bit raw value; negative offsets are
    stored as their two's-complement, so we sign-extend at 64 bits. Returns
    ``None`` for non-numeric expressions.
    """
    if expr is None or expr.op != ida_hexrays.cot_num:
        return None
    try:
        v = int(expr.n._value)
        if v >= (1 << 63):
            v -= (1 << 64)
        return v
    except Exception:
        return None


def _decompose_ptr_access(expr) -> tuple | None:
    """Decompose a raw-pointer-arithmetic dereference into ``(target_expr, offset_bytes, access_size)``.

    Handles these untyped-pointer field-access patterns Hex-Rays emits when a
    pointer has no struct type applied yet — patterns the constructor visitor
    recognises in order to record field writes:

    - ``*(T*)(ptr + N)`` → ``cot_ptr(cot_cast(cot_add(ptr, N)))``  (most common)
    - ``*(T*)ptr``       → ``cot_ptr(cot_cast(ptr))``               (offset = 0)
    - ``*ptr``           → ``cot_ptr(ptr)``                          (already typed)
    - ``ptr[N]``         → ``cot_idx(ptr, N)``                      (constant index)

    Returns ``None`` if the expression isn't one of these forms or if the
    offset is not a compile-time constant. Caller must check whether
    ``target_expr`` matches the propagation target.
    """
    if expr is None:
        return None

    # ptr[N] — array indexing with constant index
    if expr.op == ida_hexrays.cot_idx:
        base = _unwrap_casts(expr.x)
        index_val = _const_value(expr.y)
        if base is None or index_val is None:
            return None
        access_size = getattr(expr, "ptrsize", 0) or 8
        return (base, index_val * access_size, access_size)

    # *(T*)(...) — pointer dereference
    if expr.op != ida_hexrays.cot_ptr:
        return None

    access_size = getattr(expr, "ptrsize", 0) or 8
    inner = _unwrap_casts(expr.x)
    if inner is None:
        return None

    # *(T*)(ptr + N) — additive offset
    if inner.op == ida_hexrays.cot_add:
        lhs = _unwrap_casts(inner.x)
        rhs = _unwrap_casts(inner.y)
        rhs_v = _const_value(rhs)
        lhs_v = _const_value(lhs)
        if rhs_v is not None:
            return (lhs, rhs_v, access_size)
        if lhs_v is not None:
            return (rhs, lhs_v, access_size)
        return None

    # *(T*)ptr — plain dereference (offset = 0)
    return (inner, 0, access_size)


def _guess_field_type(access_size: int) -> str:
    return {1: "char", 2: "short", 4: "int", 8: "__int64"}.get(access_size, "void*")


def _build_struct_type(fields: list[tuple[int, int]], base_name: str) -> tuple[str, str] | None:
    """Create a struct tinfo_t from (offset, access_size) pairs. Returns (name, c_def) or None."""
    if not fields:
        return None
    try:
        # Deduplicate offsets, keep max access size
        offset_map: dict[int, int] = {}
        for off, sz in fields:
            offset_map[off] = max(offset_map.get(off, 0), sz)

        sorted_offsets = sorted(offset_map.items())

        tif = ida_typeinf.tinfo_t()
        tif.create_udt(ida_typeinf.BTF_STRUCT)

        # Add fields at observed offsets
        for off, sz in sorted_offsets:
            fname = f"field_{off:X}"
            ftype_str = _guess_field_type(sz)
            tif.add_udm(fname, ftype_str, offset=off * 8)

        # Set alignment; IDA auto-computes struct size from UDT layout
        tif.set_udt_align(8)

        til = ida_typeinf.get_idati()
        # Ensure unique name
        struct_name = base_name
        counter = 0
        while True:
            existing = ida_typeinf.tinfo_t()
            if not existing.get_named_type(til, struct_name, ida_typeinf.BTF_STRUCT):
                break
            counter += 1
            struct_name = f"{base_name}_{counter}"

        res = tif.set_named_type(til, struct_name, ida_typeinf.NTF_TYPE)
        if res != ida_typeinf.TERR_OK:
            logger.debug("set_named_type failed for %s: %d", struct_name, res)
            return None

        # Build C-like definition string
        lines = [f"struct {struct_name} {{"]
        for off, sz in sorted_offsets:
            lines.append(f"    {_guess_field_type(sz)} field_{off:X}; // +0x{off:X}")
        lines.append("};")
        c_def = "\n".join(lines)

        return struct_name, c_def
    except Exception as e:
        logger.debug("_build_struct_type failed: %s", e)
        return None




# ============================================================================
# Constructor Analysis — Phase 4.4
# ============================================================================

def _resolve_target(address: str) -> tuple[int | None, str | None, str | None]:
    """Parse address string. Returns (func_ea, var_name, error)."""
    if "::" in address:
        parts = address.rsplit("::", 1)
        func_spec = parts[0].strip()
        var_name = parts[1].strip()
        if not var_name:
            return None, None, "Variable name must not be empty after '::'"
        try:
            func_ea = parse_address(func_spec)
        except Exception:
            func_ea = ida_name.get_name_ea(idaapi.BADADDR, func_spec)
            if func_ea == idaapi.BADADDR:
                return None, None, f"Function '{func_spec}' not found"
        return func_ea, var_name, None
    return None, None, None


def _infer_type_and_confidence(evidence: dict) -> tuple[str, float]:
    """Infer type string and confidence from collected evidence."""
    field_accesses = evidence.get("field_accesses", [])
    call_usages = evidence.get("call_usages", [])
    malloc_origin = evidence.get("malloc_origin")

    # Check known API calls first
    for cu in call_usages:
        callee = cu.get("callee_name", "")
        for api_name, api_type in _KNOWN_API_TYPES.items():
            if api_name in callee.lower():
                return api_type, 0.90

    # Struct inference from field accesses
    if field_accesses:
        offsets = {fa["offset"] for fa in field_accesses}
        num_offsets = len(offsets)
        max_offset = max(offsets)
        # Confidence based on field count and offset coverage
        coverage = max_offset / (max_offset + 8) if max_offset > 0 else 1.0
        base_conf = min(0.50 + num_offsets * 0.12, 0.95)
        confidence = base_conf * (0.5 + 0.5 * coverage)
        if malloc_origin:
            confidence = min(confidence + 0.10, 0.95)
            return "struct_inferred*", confidence
        return "struct_inferred*", confidence

    if malloc_origin:
        return "void*", 0.50

    return "void*", 0.20


def _build_field_profile(field_accesses: list[dict]) -> dict[str, dict]:
    """Aggregate field accesses into a per-offset profile.

    Output: ``{ "0x18": { reads, writes, max_size, min_size, function_count } }``

    The ``function_count`` field is the killer signal for RE work: an offset
    accessed from 5 different functions is much stronger evidence than 50
    accesses all in one function. Sorted by offset for stable iteration.
    """
    by_offset: dict[int, dict] = {}
    for fa in field_accesses:
        off = fa.get("offset", 0)
        if off not in by_offset:
            by_offset[off] = {
                "reads": 0,
                "writes": 0,
                "max_size": 0,
                "min_size": None,
                "_funcs": set(),
            }
        slot = by_offset[off]
        if fa.get("is_write"):
            slot["writes"] += 1
        else:
            slot["reads"] += 1
        sz = fa.get("access_size", 0) or 0
        slot["max_size"] = max(slot["max_size"], sz)
        slot["min_size"] = sz if slot["min_size"] is None else min(slot["min_size"], sz)
        fea = fa.get("func_ea")
        if fea:
            slot["_funcs"].add(fea)

    out: dict[str, dict] = {}
    for off in sorted(by_offset.keys()):
        s = by_offset[off]
        out[f"0x{off:X}"] = {
            "reads": s["reads"],
            "writes": s["writes"],
            "max_size": s["max_size"],
            "min_size": s["min_size"] or 0,
            "function_count": len(s["_funcs"]),
        }
    return out


def _build_confidence_breakdown(evidence: dict, inferred_type: str, confidence: float) -> list[dict]:
    """Decompose the final confidence score into named factors.

    Each entry: ``{kind, detail, contribution}``. The sum of contributions
    won't equal ``confidence`` exactly because ``_infer_type_and_confidence``
    multiplies and caps — this list exposes the *inputs* to that scoring,
    letting analysts see *why* a number was chosen.
    """
    field_accesses = evidence.get("field_accesses", [])
    call_usages = evidence.get("call_usages", [])
    malloc_origin = evidence.get("malloc_origin")
    stored_in = evidence.get("stored_in", [])

    factors: list[dict] = []

    # API matches — highest-priority signal in _infer_type_and_confidence
    matched_apis: list[str] = []
    for cu in call_usages:
        callee = (cu.get("callee_name") or "").lower()
        for api_name in _KNOWN_API_TYPES:
            if api_name in callee:
                matched_apis.append(api_name)
                break
    if matched_apis:
        factors.append({
            "kind": "api_match",
            "detail": f"argument to {', '.join(sorted(set(matched_apis)))}",
            "contribution": 0.90,
        })

    # Field-access count + coverage
    if field_accesses:
        offsets = {fa.get("offset", 0) for fa in field_accesses}
        funcs = {fa.get("func_ea") for fa in field_accesses if fa.get("func_ea")}
        factors.append({
            "kind": "field_accesses",
            "detail": f"{len(offsets)} distinct offsets across {len(funcs)} functions",
            "contribution": min(0.50 + len(offsets) * 0.12, 0.95),
        })

    # Malloc origin boost
    if malloc_origin:
        factors.append({
            "kind": "malloc_origin",
            "detail": f"allocated via {malloc_origin.get('allocator', '?')}",
            "contribution": 0.10,
        })

    # Stored-in evidence (informational; doesn't bump confidence yet)
    if stored_in:
        containers = {s.get("container_expr", "?") for s in stored_in}
        factors.append({
            "kind": "stored_in",
            "detail": (
                f"appears as rvalue stored into {len(stored_in)} field(s) of "
                f"{len(containers)} container(s) — target is value-held, not a struct base"
            ),
            "contribution": 0.0,
        })

    if not factors:
        factors.append({
            "kind": "no_evidence",
            "detail": "no field accesses, call usages, or malloc origin observed",
            "contribution": 0.20,
        })

    return factors


def _build_zero_fields_hint(diag: dict, samples: list[str], stored_in_count: int) -> str:
    """Generate a diagnostic-aware hint when zero field accesses found.

    Distinguishes four failure modes:
    1. Visitor never saw any pointer dereference → likely scalar / unused.
    2. Target was stored INTO other structs → it's a value, not a base.
    3. Visitor saw many memptrs but rejected the bases → alias-tracking gap.
    4. Mixed signals → generic fallback.

    Without this kind of hint, a zero result is indistinguishable from a tool
    failure — the analyst can't tell whether to give up, change input, or
    file a bug.
    """
    asg_seen = diag.get("asg_memptr_seen", 0)
    read_seen = diag.get("read_memptr_seen", 0) + diag.get("read_ptr_seen", 0)
    seen_total = asg_seen + read_seen
    rejected_total = (
        diag.get("asg_memptr_base_mismatch", 0)
        + diag.get("read_memptr_base_mismatch", 0)
        + diag.get("read_ptr_base_mismatch", 0)
    )

    if stored_in_count > 0:
        return (
            f"Target was *stored into* {stored_in_count} struct field(s) but "
            f"is never used as a struct base itself. It's a value held by "
            f"another struct (likely a pointer/scalar field). See `stored_in` "
            f"for the containers; consider targeting THOSE for struct inference."
        )

    if seen_total == 0:
        return (
            "Visitor saw no pointer dereferences involving this target. "
            "Likely a scalar (int/char), an unused variable, or a value that "
            "only flows through registers. Try a wider `max_depth` or verify "
            "the target is referenced by the analyzed functions."
        )

    if rejected_total > 0 and rejected_total == seen_total:
        sample_hint = f" Sample bases: {samples[:3]}." if samples else ""
        return (
            f"Visitor saw {seen_total} dereferences but rejected every base. "
            f"The target is referenced but never used as the *base* of a field "
            f"access — most likely accesses go through a local copy obtained "
            f"via a function call or a struct-of-target relationship.{sample_hint}"
        )

    if rejected_total > 0:
        return (
            f"Saw {seen_total} dereferences ({seen_total - rejected_total} matched, "
            f"{rejected_total} rejected) but no offsets accumulated. Decode may "
            f"have skipped offset extraction — check `diag.read_ptr_decompose_failed`."
        )

    return "No field-access evidence collected. The target may not be a struct base."


def _collect_xref_functions(target_ea: int, direction: str, max_depth: int, max_funcs: int) -> set[int]:
    """Collect function EAs that xref target_ea, up to max_depth hops."""
    result: set[int] = set()
    if target_ea == idaapi.BADADDR:
        return result

    # BFS over xref graph
    visited: set[int] = set()
    queue: list[tuple[int, int]] = [(target_ea, 0)]

    while queue and len(result) < max_funcs:
        ea, depth = queue.pop(0)
        if ea in visited or depth > max_depth:
            continue
        visited.add(ea)

        if direction in ("backward", "both"):
            try:
                for xref in idautils.XrefsTo(ea, 0):
                    func = ida_funcs.get_func(xref.frm)
                    if func:
                        result.add(func.start_ea)
                    if depth < max_depth:
                        queue.append((xref.frm, depth + 1))
            except Exception:
                pass

        if direction in ("forward", "both"):
            try:
                for xref in idautils.XrefsFrom(ea, 0):
                    func = ida_funcs.get_func(xref.to)
                    if func:
                        result.add(func.start_ea)
                    if depth < max_depth:
                        queue.append((xref.to, depth + 1))
            except Exception:
                pass

    return result


@tool
@idasync




class ConstructorFieldEntry(TypedDict, total=False):
    offset: int           # byte offset from this pointer
    access_size: int      # bytes written
    inferred_type: str    # "bool", "int", "void*", "float", "__int64", etc.
    zero_init: bool       # True when this field is always zeroed in the ctor
    assigned_value: str   # human-readable repr of the constant assigned (if any)
    ea: str               # instruction address
    disasm: str           # decompiled expression text


class AnalyzeConstructorResult(TypedDict, total=False):
    ok: bool
    func_ea: str
    func_name: str
    this_param: str           # name of the identified this-pointer local
    this_param_idx: int       # lvar index of the this-pointer
    field_assignments: list[ConstructorFieldEntry]
    estimated_size: int | None  # max(offset + size) across all observed fields
    unique_offsets: int
    suggested_struct_name: str | None
    suggested_struct_definition: str | None
    applied: bool
    error: str
    error_type: str
    hint: str


# Whitelist of 32-bit float bit patterns that are unambiguously floats in
# constructor context — values like 1.0f, Pi, 180.0f.  Anything not in this
# set is emitted as "int" so we never misclassify an integer constant.
_KNOWN_FLOAT_BITS: frozenset[int] = frozenset({
    0x3F800000,  # 1.0f
    0xBF800000,  # -1.0f
    0x3F000000,  # 0.5f
    0xBF000000,  # -0.5f
    0x40000000,  # 2.0f
    0xC0000000,  # -2.0f
    0x40800000,  # 4.0f
    0xC0800000,  # -4.0f
    0x3E800000,  # 0.25f
    0x3F333333,  # 0.7f (approx)
    0x3F4CCCCD,  # 0.8f
    0x40490FDB,  # Pi
    0x402DF854,  # e
    0x43B40000,  # 360.0f
    0x43340000,  # 180.0f
    0x42B40000,  # 90.0f
    0x41200000,  # 10.0f
    0x42C80000,  # 100.0f
})


def _infer_ctor_field_type(access_size: int, rhs_val: int | None) -> tuple[str, bool, str]:
    """Infer a C type for a constructor field write from size + constant value.

    Returns ``(type_str, zero_init, value_repr)``.
    """
    zero_init = rhs_val == 0
    if rhs_val is not None:
        if access_size == 1:
            if rhs_val in (0, 1):
                return ("bool", zero_init, "true" if rhs_val else "false")
            return ("uint8_t", zero_init, hex(rhs_val & 0xFF))
        if access_size == 2:
            return ("uint16_t", zero_init, hex(rhs_val & 0xFFFF))
        if access_size == 4:
            bits = rhs_val & 0xFFFFFFFF
            if bits in _KNOWN_FLOAT_BITS:
                import struct
                try:
                    as_float = struct.unpack("f", bits.to_bytes(4, "little"))[0]
                    return ("float", False, f"{as_float}f")
                except Exception:
                    pass
            return ("int", zero_init, hex(bits))
        if access_size == 8:
            if rhs_val == 0:
                return ("void*", True, "nullptr")
            # Large address → likely pointer
            if rhs_val > 0x10000:
                return ("void*", False, hex(rhs_val))
            return ("__int64", zero_init, hex(rhs_val))
    # No constant: infer from size only
    return (_guess_field_type(access_size), False, "?")


class _ConstructorVisitor(ida_hexrays.ctree_visitor_t):
    """Walk a constructor's ctree and collect (this + N) field writes.

    Identifies the this-pointer as:
    1. A lvar named "this", "v0", or "a1" (first arg convention)
    2. Falling back to the first pointer-typed lvar if none of the above match
    """

    def __init__(self, cfunc: ida_hexrays.cfunc_t):
        ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
        self.cfunc = cfunc
        self.this_idx: int | None = None
        self.this_name: str = ""
        # alias set: lvar indices that hold a copy of this
        self._this_vars: set[int] = set()
        self.writes: list[dict] = []
        self._seen: set[tuple[str, int]] = set()
        self._identify_this()

    def _identify_this(self):
        lvars = self.cfunc.get_lvars()
        CANDIDATE_NAMES = {"this", "v0", "a1", "ecx", "rcx"}
        for idx, lv in enumerate(lvars):
            nm = (lv.name or "").lower()
            try:
                is_ptr = lv.tif.is_ptr()
            except Exception:
                is_ptr = False
            if nm in CANDIDATE_NAMES or (idx == 0 and is_ptr):
                self.this_idx = idx
                self.this_name = lv.name or f"arg{idx}"
                self._this_vars.add(idx)
                return
        # Last resort: first lvar that has pointer type
        for idx, lv in enumerate(lvars):
            try:
                if lv.tif.is_ptr():
                    self.this_idx = idx
                    self.this_name = lv.name or f"arg{idx}"
                    self._this_vars.add(idx)
                    return
            except Exception:
                continue

    def _is_this(self, expr) -> bool:
        expr = _unwrap_casts(expr)
        if expr is None:
            return False
        if expr.op == ida_hexrays.cot_var:
            return expr.v.idx in self._this_vars
        return False

    def _track_alias(self, lhs, rhs):
        """Track lhs = this → lhs is also a this alias."""
        rhs_uw = _unwrap_casts(rhs)
        if rhs_uw is None:
            return
        if rhs_uw.op == ida_hexrays.cot_var and rhs_uw.v.idx in self._this_vars:
            if lhs.op == ida_hexrays.cot_var:
                self._this_vars.add(lhs.v.idx)

    def _rhs_constant(self, rhs) -> int | None:
        """Extract a constant from the RHS of an assignment (strips casts)."""
        rhs = _unwrap_casts(rhs)
        return _const_value(rhs)

    def _rhs_repr(self, rhs) -> str:
        """Human-readable RHS."""
        try:
            return _get_expr_text(rhs, self.cfunc)
        except Exception:
            return "?"

    def visit_expr(self, expr):
        try:
            if expr.op == ida_hexrays.cot_asg:
                lhs, rhs = expr.x, expr.y
                self._track_alias(lhs, rhs)

                # cot_memptr(this, m) = rhs
                if lhs.op in (ida_hexrays.cot_memptr, ida_hexrays.cot_memref):
                    if self._is_this(lhs.x):
                        self._record_memptr_write(lhs, rhs)

                # *(T*)(this + N) = rhs
                elif lhs.op in (ida_hexrays.cot_ptr, ida_hexrays.cot_idx):
                    decomp = _decompose_ptr_access(lhs)
                    if decomp:
                        base, offset, size = decomp
                        if self._is_this(base):
                            self._record_ptr_write(lhs, offset, size, rhs)

        except Exception as e:
            logger.debug("_ConstructorVisitor.visit_expr failed: %s", e)
        return 0

    def _record_memptr_write(self, lhs, rhs):
        try:
            offset = lhs.m // 8
            size = getattr(lhs, "ptrsize", 8) or 8
            ea_hex = hex(lhs.ea)
            key = (ea_hex, offset)
            if key in self._seen:
                return
            self._seen.add(key)
            rhs_val = self._rhs_constant(rhs)
            inferred, zero_init, val_repr = _infer_ctor_field_type(size, rhs_val)
            self.writes.append({
                "offset": offset,
                "access_size": size,
                "inferred_type": inferred,
                "zero_init": zero_init,
                "assigned_value": self._rhs_repr(rhs) if rhs_val is None else val_repr,
                "ea": ea_hex,
                "disasm": _get_expr_text(lhs, self.cfunc),
            })
        except Exception as e:
            logger.debug("_record_memptr_write failed: %s", e)

    def _record_ptr_write(self, lhs, offset: int, size: int, rhs):
        try:
            if offset < 0:
                return
            ea_hex = hex(lhs.ea)
            key = (ea_hex, offset)
            if key in self._seen:
                return
            self._seen.add(key)
            rhs_val = self._rhs_constant(rhs)
            inferred, zero_init, val_repr = _infer_ctor_field_type(size, rhs_val)
            self.writes.append({
                "offset": offset,
                "access_size": size,
                "inferred_type": inferred,
                "zero_init": zero_init,
                "assigned_value": self._rhs_repr(rhs) if rhs_val is None else val_repr,
                "ea": ea_hex,
                "disasm": f"*(this+0x{offset:X})",
            })
        except Exception as e:
            logger.debug("_record_ptr_write failed: %s", e)


@tool
@idasync
@tool_timeout(60.0)
def analyze_constructor(
    address: Annotated[str, "Constructor function address or name"],
    infer_struct: Annotated[bool, "Create struct from observed field layout (default: True)"] = True,
    apply_type: Annotated[bool, "Apply inferred struct* type to the this parameter (default: False)"] = False,
) -> AnalyzeConstructorResult:
    """Infer struct layout by analyzing all field assignments in a constructor.

    Decompiles the constructor at ``address`` and walks its ctree to collect every
    ``*(this + N) = value`` write, including typed memptr accesses on already-typed
    structs. For each field, the tool records:

    - Byte offset from the this pointer
    - Write size (1/2/4/8 bytes)
    - Inferred C type (bool, int, float, void*, __int64, …) from size + constant pattern
    - Whether the field is zero-initialized
    - The constant or expression assigned

    From those writes it builds an estimated struct layout and optionally creates a
    named struct in the IDA type library. This is the fastest way to go from a raw
    constructor to a draft struct definition without manually tracing every assignment.

    Limitations:
    - Only direct writes to *this* (or aliases assigned in the same function) are seen.
      Delegating constructors that chain to another ctor will be missed unless you also
      analyze the callee.
    - Variable-stride array writes (``*(this + i*4) = …``) are skipped.
    - Value-type inference is heuristic; always review the generated struct.
    """
    try:
        if not ida_hexrays.init_hexrays_plugin():
            return {
                "ok": False,
                "error": "Hex-Rays decompiler is not available",
                "hint": "Ensure Hex-Rays is installed and licensed.",
            }

        func_ea = parse_address(address)
        func_name = ida_funcs.get_func_name(func_ea) or hex(func_ea)

        cfunc = _decompile_func(func_ea)
        if cfunc is None:
            return {
                "ok": False,
                "func_ea": hex(func_ea),
                "func_name": func_name,
                "error": "Decompilation failed",
            }

        visitor = _ConstructorVisitor(cfunc)
        if visitor.this_idx is None:
            return {
                "ok": False,
                "func_ea": hex(func_ea),
                "func_name": func_name,
                "error": "Could not identify this-pointer parameter",
                "hint": (
                    "Ensure the target is a __thiscall or __fastcall constructor. "
                    "If IDA hasn't typed the first argument as a pointer, try applying "
                    "a function signature first with set_type."
                ),
            }

        visitor.apply_to(cfunc.body, None)

        # Sort by offset for stable output
        writes = sorted(visitor.writes, key=lambda w: w["offset"])

        # Estimated struct size
        estimated_size: int | None = None
        if writes:
            last = max(writes, key=lambda w: w["offset"] + w["access_size"])
            estimated_size = last["offset"] + last["access_size"]

        # Build struct
        suggested_struct_name = None
        suggested_struct_definition = None
        applied = False

        if infer_struct and writes:
            fields = [(w["offset"], w["access_size"]) for w in writes]
            base_name = f"ctor_struct_{func_ea:X}"
            struct_result = _build_struct_type(fields, base_name)
            if struct_result:
                suggested_struct_name, suggested_struct_definition = struct_result
                # Apply struct* type to the this parameter if requested
                if apply_type and suggested_struct_name:
                    try:
                        tif = _parse_type_tinfo(f"{suggested_struct_name}*")
                        if tif and visitor.this_name:
                            modifier = my_modifier_t(visitor.this_name, tif)
                            applied = bool(ida_hexrays.modify_user_lvars(func_ea, modifier))
                    except Exception as ex:
                        logger.debug("apply_type failed in analyze_constructor: %s", ex)

        unique_offsets = len({w["offset"] for w in writes})

        result: dict = {
            "ok": True,
            "func_ea": hex(func_ea),
            "func_name": func_name,
            "this_param": visitor.this_name,
            "this_param_idx": visitor.this_idx,
            "field_assignments": writes,
            "estimated_size": estimated_size,
            "unique_offsets": unique_offsets,
            "suggested_struct_name": suggested_struct_name,
            "suggested_struct_definition": suggested_struct_definition,
            "applied": applied,
        }
        if not writes:
            result["hint"] = (
                "No this-pointer field writes detected. This may be a delegating "
                "constructor that calls another ctor, or the function may not be "
                "a constructor. Try analyze_constructor on any chained callees."
            )
        return result

    except Exception as e:
        logger.exception("analyze_constructor failed")
        return tool_error(e)

@tool
@idasync
@tool_timeout(120.0)
def type_propagate(
    address: Annotated[
        str,
        "Starting point: global address (hex or symbol), or 'function::variable' syntax "
        "(e.g. 'main::ptr' or '0x401000::ptr') to target a local variable.",
    ],
    direction: Annotated[
        str,
        "Propagation direction: 'forward' (where value flows), 'backward' (where it comes from), "
        "or 'both' (default).",
    ] = "both",
    max_depth: Annotated[int, "Max xref hop depth for cross-function propagation (default 3)"] = 3,
    max_functions: Annotated[int, "Cap on functions to decompile (default 10)"] = 10,
    infer_struct: Annotated[bool, "Auto-create struct in TIL from observed field accesses (default True)"] = True,
    apply_type: Annotated[bool, "Apply inferred type to target address/variable (default False)"] = False,
) -> TypePropagateResult:
    """Propagate and infer types across data-flow chains using decompiler analysis.

    Analyzes how a variable or global address is used across decompiled functions to infer
    its most likely type. The primary use case is struct layout inference from field access
    patterns — when you see ptr->field_0x18 = value across multiple functions, this tool
    collects all observed offsets, deduces field types from access sizes, and optionally
    creates a struct type in the IDA type library.

    Two input modes:
    - Global/stack address: pass a hex address or symbol name (e.g. "0x401000")
    - Function variable: use "func_name::var_name" syntax (e.g. "main::ptr")

    Direction:
    - "backward": trace where the value originates (assignments TO target)
    - "forward": trace where the value flows (assignments FROM target, call arguments)
    - "both": collect evidence from both directions

    Evidence collected:
    - Field accesses (cot_memptr / cot_memref / cot_ptr / cot_idx): offset, access size, read/write
    - Call arguments: which known API functions receive the target
    - Malloc origins: whether target is assigned from malloc/calloc/realloc

    Confidence is derived from the diversity and strength of evidence.

    Limitations:
    - The target must be the *base* of the field access, not a *stored value*.
      ``*(T*)(other_ptr + N) = target`` records a write to ``other_ptr``'s
      struct, not to ``target`` — so a ``char*`` global stored inside a struct
      field will report zero field accesses for itself.
    - Aliases through call returns are not tracked. ``v8 = sub_X(...); v8->f = ...``
      only finds the write if you target the struct pointer, not if you target
      something the struct happens to *contain*.
    - Only compile-time-constant offsets are captured. Variable-stride array
      indexing (``ptr[i]`` with non-constant ``i``) is skipped.

    When zero field accesses are returned, each ``functions_analyzed`` entry
    includes a ``diag`` dict and (when applicable) ``rejected_base_samples``
    to show *why* — useful for distinguishing "never saw a memptr" (target
    isn't a struct base) from "saw memptrs but the base wasn't recognized"
    (alias-tracking gap or unexpected ctree wrapping).
    """
    try:
        if not ida_hexrays.init_hexrays_plugin():
            return {
                "ok": False,
                "error": "Hex-Rays decompiler is not available",
                "hint": "Ensure Hex-Rays is installed and licensed. Use infer_types for address-local type guessing without decompiler.",
            }

        direction = direction.lower().strip()
        if direction not in ("forward", "backward", "both"):
            return {
                "ok": False,
                "error": f"Invalid direction '{direction}'. Use 'forward', 'backward', or 'both'.",
            }

        # Parse input address
        func_ea, var_name, parse_err = _resolve_target(address)
        target_global_ea: int | None = None
        containing_func_ea: int | None = None

        if parse_err:
            return {"ok": False, "error": parse_err, "address": address}

        if func_ea is not None and var_name is not None:
            # Function::variable mode
            containing_func_ea = func_ea
            target_global_ea = None
        else:
            # Raw address mode
            try:
                target_global_ea = parse_address(address)
            except Exception:
                target_global_ea = ida_name.get_name_ea(idaapi.BADADDR, address)
                if target_global_ea == idaapi.BADADDR:
                    return {"ok": False, "error": f"Address '{address}' not found", "address": address}

            # Find containing function
            func = ida_funcs.get_func(target_global_ea)
            if func:
                containing_func_ea = func.start_ea
            else:
                # Try to find a function that references this global
                for xref in idautils.XrefsTo(target_global_ea, 0):
                    func = ida_funcs.get_func(xref.frm)
                    if func:
                        containing_func_ea = func.start_ea
                        break

        # Build list of functions to analyze
        func_eas: set[int] = set()
        if containing_func_ea is not None:
            func_eas.add(containing_func_ea)

        if target_global_ea is not None and max_depth > 0:
            xref_funcs = _collect_xref_functions(target_global_ea, direction, max_depth, max_functions)
            func_eas.update(xref_funcs)

        # Cap — sort for determinism, then limit
        func_eas = set(sorted(func_eas)[:max_functions])

        if not func_eas:
            logger.info("type_propagate: no functions to analyze for %s", address)
            return {
                "ok": True,
                "address": address,
                "inferred_type": "unknown",
                "confidence": 0.0,
                "confidence_breakdown": [],
                "field_accesses": [],
                "field_profile": {},
                "call_usages": [],
                "stored_in": [],
                "propagation_path": [],
                "functions_analyzed": [],
                "suggested_struct_name": None,
                "suggested_struct_definition": None,
                "applied": False,
                "hint": "No functions found referencing this address. Try a different direction or verify the address is a data variable (not a code pointer).",
            }

        all_evidence = {
            "field_accesses": [],
            "call_usages": [],
            "stored_in": [],
            "malloc_origin": None,
            "assignments": [],
        }
        functions_analyzed: list[dict] = []
        propagation_path: list[PropagationStep] = []
        # Aggregate the visitor's diag counters across functions so we can
        # produce a coherent zero-fields explanation at the end.
        aggregated_diag: dict[str, int] = {}
        aggregated_samples: list[str] = []

        for fea in func_eas:
            func_name = ida_funcs.get_func_name(fea) or hex(fea)
            cfunc = _decompile_func(fea)
            if not cfunc:
                logger.info("type_propagate: decompilation failed for %s", func_name)
                functions_analyzed.append({
                    "func_ea": hex(fea),
                    "func_name": func_name,
                    "decompiled": False,
                })
                continue

            # Resolve target in this function
            target_lvar_idx: int | None = None
            if var_name is not None and containing_func_ea == fea:
                lvar, lvar_idx = _find_lvar_by_name(cfunc, var_name)
                if lvar is not None:
                    target_lvar_idx = lvar_idx
                else:
                    functions_analyzed.append({
                        "func_ea": hex(fea),
                        "func_name": func_name,
                        "decompiled": True,
                        "note": f"Variable '{var_name}' not found in decompiled locals",
                    })
                    continue

            collector = _UsageCollector(cfunc, target_lvar_idx=target_lvar_idx, target_ea=target_global_ea)
            collector.apply_to(cfunc.body, None)

            all_evidence["field_accesses"].extend(collector.field_accesses)
            all_evidence["call_usages"].extend(collector.call_usages)
            all_evidence["stored_in"].extend(collector.stored_in)
            if collector.malloc_origin and all_evidence["malloc_origin"] is None:
                all_evidence["malloc_origin"] = collector.malloc_origin
            all_evidence["assignments"].extend(collector.assignments)

            # Roll up diagnostic counters and sample bases for the final hint.
            for k, v in collector._diag.items():
                aggregated_diag[k] = aggregated_diag.get(k, 0) + v
            for sample in collector._base_mismatch_samples:
                if sample not in aggregated_samples and len(aggregated_samples) < 5:
                    aggregated_samples.append(sample)

            # Build propagation path entries
            for fa in collector.field_accesses:
                propagation_path.append({
                    "ea": fa["ea"],
                    "func_ea": fa["func_ea"],
                    "func_name": fa["func_name"],
                    "kind": "field_write" if fa["is_write"] else "field_read",
                    "detail": f"offset=0x{fa['offset']:X}, size={fa['access_size']}",
                })
            for cu in collector.call_usages:
                propagation_path.append({
                    "ea": cu["call_ea"],
                    "func_ea": cu["func_ea"],
                    "func_name": cu["func_name"],
                    "kind": "call_arg",
                    "detail": f"arg[{cu['arg_index']}] -> {cu['callee_name']}",
                })
            if collector.malloc_origin:
                propagation_path.append({
                    "ea": collector.malloc_origin["ea"],
                    "func_ea": collector.malloc_origin["func_ea"],
                    "func_name": collector.malloc_origin["func_name"],
                    "kind": "malloc",
                    "detail": f"assigned from {collector.malloc_origin['allocator']}",
                })
            for si in collector.stored_in:
                propagation_path.append({
                    "ea": si["ea"],
                    "func_ea": si["func_ea"],
                    "func_name": si["func_name"],
                    "kind": "stored_in",
                    "detail": f"stored at offset=0x{si['offset']:X} of {si['container_expr']} (size={si['access_size']})",
                })

            # Build per-function entry. When zero field accesses were
            # collected, also include diagnostic counters + rejected-base
            # samples — these are the only signal a caller has for whether
            # the visitor never saw a memptr ("target isn't really a struct
            # base") versus saw plenty of them but rejected the base ("alias
            # tracking gap").
            entry: dict = {
                "func_ea": hex(fea),
                "func_name": func_name,
                "decompiled": True,
                "field_access_count": len(collector.field_accesses),
                "call_usage_count": len(collector.call_usages),
            }
            if len(collector.field_accesses) == 0:
                entry["diag"] = dict(collector._diag)
                if collector._base_mismatch_samples:
                    entry["rejected_base_samples"] = list(collector._base_mismatch_samples)
            functions_analyzed.append(entry)

        # Deduplicate propagation path by (ea, kind, detail)
        seen_path = set()
        deduped_path = []
        for step in propagation_path:
            key = (step["ea"], step["kind"], step["detail"])
            if key not in seen_path:
                seen_path.add(key)
                deduped_path.append(step)
        propagation_path = deduped_path

        # Infer type
        inferred_type, confidence = _infer_type_and_confidence(all_evidence)

        # Diagnostic-aware hinting: when zero field accesses are found,
        # explain WHY using the aggregated visitor counters.
        hint_msg: str | None = None
        if not all_evidence["field_accesses"]:
            if target_global_ea is not None and ida_funcs.get_func(target_global_ea):
                inferred_type = "void*"
                confidence = 0.30
                hint_msg = (
                    "Target address is a function entry point, not a data variable. "
                    "Use 'forward' direction to trace where this function pointer flows, "
                    "or target a global data variable instead."
                )
            else:
                hint_msg = _build_zero_fields_hint(
                    aggregated_diag,
                    aggregated_samples,
                    len(all_evidence["stored_in"]),
                )

        # Build struct if requested
        suggested_struct_name = None
        suggested_struct_definition = None
        applied = False

        if infer_struct and all_evidence["field_accesses"]:
            # Dedupe field accesses by (offset, access_size) keeping max size per offset
            field_map: dict[int, int] = {}
            for fa in all_evidence["field_accesses"]:
                off = fa["offset"]
                field_map[off] = max(field_map.get(off, 0), fa["access_size"])
            fields = list(field_map.items())
            base_name = f"inferred_struct_{target_global_ea:X}" if target_global_ea else f"inferred_struct_{containing_func_ea:X}"
            struct_result = _build_struct_type(fields, base_name)
            if struct_result:
                suggested_struct_name, suggested_struct_definition = struct_result
                logger.info("type_propagate: created struct %s with %d fields", suggested_struct_name, len(fields))
                # If the inferred type was generic "struct_inferred*", make it specific
                if inferred_type == "struct_inferred*":
                    inferred_type = f"{suggested_struct_name}*"
            else:
                logger.warning("type_propagate: struct creation failed for %s", base_name)

        # Apply type if requested
        if apply_type and target_global_ea is not None and inferred_type not in ("unknown", "void*"):
            try:
                tif = _parse_type_tinfo(inferred_type)
                if tif:
                    ida_typeinf.apply_tinfo(target_global_ea, tif, ida_typeinf.TINFO_DEFINITE)
                    applied = True
                    logger.info("type_propagate: applied type %s to 0x%x", inferred_type, target_global_ea)
            except Exception as e:
                logger.warning("type_propagate: apply_type failed for %s: %s", inferred_type, e)

        # Build aggregated outputs that make raw evidence usable.
        field_profile = _build_field_profile(all_evidence["field_accesses"])
        confidence_breakdown = _build_confidence_breakdown(
            all_evidence, inferred_type, confidence
        )

        result: dict = {
            "ok": True,
            "address": address,
            "inferred_type": inferred_type,
            "confidence": round(confidence, 3),
            "confidence_breakdown": confidence_breakdown,
            "field_accesses": all_evidence["field_accesses"],
            "field_profile": field_profile,
            "call_usages": all_evidence["call_usages"],
            "stored_in": all_evidence["stored_in"],
            "propagation_path": propagation_path,
            "functions_analyzed": functions_analyzed,
            "suggested_struct_name": suggested_struct_name,
            "suggested_struct_definition": suggested_struct_definition,
            "applied": applied,
        }
        if hint_msg:
            result["hint"] = hint_msg
        return result

    except Exception as e:
        logger.exception("type_propagate failed")
        return tool_error(e)
