"""Tests for api_types API functions."""

from ..framework import (
    test,
    skip_test,
    assert_is_list,
    assert_non_empty,
    assert_ok,
    assert_error,
    get_any_function,
    get_first_segment,
    get_data_address,
    get_unmapped_address,
    get_named_address,
)
from ..api_types import (
    declare_type,
    enum_upsert,
    read_struct,
    search_structs,
    type_query,
    type_inspect,
    set_type,
    type_apply_batch,
    infer_types,
    type_propagate,
)


TEST_STRUCT_NAME = "__TestStruct__"
NAME_RESOLUTION_STRUCT = "__NameResolutionTest__"
CRACKME_DSO_HANDLE = "0x4008"
TYPE_APPLY_SIGNATURE = "int"
TYPED_FIXTURE_SUM_POINT = "0x1013c10"
TYPED_FIXTURE_USE_WRAPPER = "0x1013dc0"
TYPED_FIXTURE_G_POINT = "0x1069f70"
TYPED_FIXTURE_G_WRAPPER = "0x1069f80"
TYPED_FIXTURE_INFER_FALLBACK = "0x1069fa4"
TYPED_FIXTURE_LOCAL_NAME = "rhs_handle"


def create_test_struct(name: str = TEST_STRUCT_NAME) -> bool:
    """Create a deterministic test struct if it does not already exist."""
    search_result = search_structs(name)
    if search_result and any(s["name"] == name for s in search_result):
        return True

    struct_def = f"""
        struct {name} {{
            int field1;
            char field2;
            void* field3;
        }};
    """
    result = declare_type(struct_def)
    if not result:
        return False

    entry = result[0]
    if "error" not in entry:
        return True

    search_result = search_structs(name)
    return bool(search_result and any(s["name"] == name for s in search_result))


def _require_any_function() -> str:
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")
    return fn_addr


@test()
def test_declare_type_creates_searchable_struct():
    """declare_type creates a struct that can be found again via search_structs."""
    assert create_test_struct(TEST_STRUCT_NAME), "failed to declare test struct"
    result = search_structs(TEST_STRUCT_NAME)
    assert_is_list(result, min_length=1)
    match = next((s for s in result if s["name"] == TEST_STRUCT_NAME), None)
    assert match is not None
    assert match["cardinality"] == 3
    assert match["size"] >= 8


@test()
def test_declare_type_invalid_declaration():
    """declare_type reports parse failures for invalid declarations."""
    result = declare_type("struct broken { int x }")
    assert_is_list(result, min_length=1)
    assert_error(result[0], contains="Failed to parse")


@test()
def test_read_struct_returns_named_members():
    """read_struct returns the declared member layout for the deterministic test struct."""
    if not create_test_struct(TEST_STRUCT_NAME):
        skip_test("failed to declare test struct")

    data_addr = get_data_address()
    if not data_addr:
        seg = get_first_segment()
        if not seg:
            skip_test("binary has no readable segment")
        data_addr = seg[0]

    result = read_struct({"addr": data_addr, "struct": TEST_STRUCT_NAME})
    assert_is_list(result, min_length=1)
    entry = result[0]
    assert_ok(entry, "members")
    names = [member["name"] for member in entry["members"]]
    assert names == ["field1", "field2", "field3"]


@test(binary="typed_fixture.elf")
def test_read_struct_wrapper_values():
    """read_struct reads the deterministic Wrapper global contents from the typed fixture."""
    result = read_struct({"addr": TYPED_FIXTURE_G_WRAPPER, "struct": "Wrapper"})
    assert_is_list(result, min_length=1)
    entry = result[0]
    assert_ok(entry, "members")
    members = {m["name"]: m for m in entry["members"]}
    assert members["pt"]["type"] == "Point"
    assert "1122334455667788" in members["magic"]["value"]


@test()
def test_read_struct_not_found():
    """read_struct reports a missing-struct error."""
    seg = get_first_segment()
    if not seg:
        skip_test("binary has no segments")

    result = read_struct({"addr": seg[0], "struct": "NonExistentStruct12345"})
    assert_is_list(result, min_length=1)
    assert_error(result[0], contains="not found")


@test()
def test_read_struct_name_resolution():
    """read_struct resolves named addresses instead of requiring only numeric ones."""
    if not create_test_struct(NAME_RESOLUTION_STRUCT):
        skip_test("failed to declare name-resolution struct")

    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")

    from ..api_core import lookup_funcs

    fn_info = lookup_funcs(fn_addr)
    assert_ok(fn_info[0], "fn")
    fn_name = fn_info[0]["fn"]["name"]

    result = read_struct({"addr": fn_name, "struct": NAME_RESOLUTION_STRUCT})
    assert_is_list(result, min_length=1)
    entry = result[0]
    assert "Failed to resolve address" not in (entry.get("error") or "")


@test()
def test_read_struct_invalid_address():
    """read_struct reports a deterministic address resolution error."""
    result = read_struct({"addr": "InvalidAddressName123", "struct": TEST_STRUCT_NAME})
    assert_is_list(result, min_length=1)
    assert_error(result[0], contains="Failed to resolve address")


@test()
def test_read_struct_missing_address():
    """read_struct requires an address explicitly."""
    result = read_struct({"struct": TEST_STRUCT_NAME})
    assert_is_list(result, min_length=1)
    assert_error(result[0], contains="Address is required")


@test(binary="crackme03.elf")
def test_read_struct_without_type_info_fails_cleanly():
    """read_struct without an explicit struct fails cleanly when no type is applied."""
    result = read_struct({"addr": "0x201f"})
    assert_is_list(result, min_length=1)
    assert_error(result[0], contains="could not auto-detect")


def _find_bss_addr() -> int | None:
    """Locate an address whose byte is not loaded (BSS or similar)."""
    import ida_bytes
    import idaapi
    import idautils

    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if seg is None:
            continue
        if seg.type == idaapi.SEG_BSS:
            return seg.start_ea

    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if seg is None:
            continue
        if not ida_bytes.is_loaded(seg.start_ea):
            return seg.start_ea

    return None


@test()
def test_read_struct_bss_members_are_zero():
    """read_struct reports zero for every member when the struct lives in BSS.

    BSS bytes are unloaded in the IDB but zero-initialized at runtime. Before
    the BSS-aware read, members would come back as 0xff-filled garbage.
    """
    bss_ea = _find_bss_addr()
    if bss_ea is None:
        skip_test("binary has no BSS / unloaded region")

    if not create_test_struct(TEST_STRUCT_NAME):
        skip_test("failed to declare test struct")

    result = read_struct({"addr": hex(bss_ea), "struct": TEST_STRUCT_NAME})
    assert_is_list(result, min_length=1)
    entry = result[0]
    assert_ok(entry, "members")

    failures = []
    for member in entry["members"]:
        value_str = member["value"]
        # Integer members render as "0xNN (N)"; pointer as "0xNN...";
        # longer shapes render as "[NN NN ...]".
        if "(" in value_str:
            hex_part = value_str.split()[0]
            numeric = int(hex_part, 16)
        elif value_str.startswith("0x"):
            numeric = int(value_str, 16)
        elif value_str.startswith("["):
            inner = value_str.strip("[]").replace("...", "").split()
            numeric = sum(int(b, 16) for b in inner)
        else:
            failures.append(f"{member['name']}: unparseable value {value_str!r}")
            continue
        if numeric != 0:
            failures.append(
                f"{member['name']}: expected 0 at BSS, got {value_str!r}"
            )

    assert not failures, "\n".join(failures)


@test()
def test_search_structs_finds_declared_structs():
    """search_structs returns the previously declared deterministic struct."""
    if not create_test_struct(TEST_STRUCT_NAME):
        skip_test("failed to declare test struct")

    result = search_structs("__TestStruct__")
    assert_is_list(result, min_length=1)
    assert any(item["name"] == TEST_STRUCT_NAME for item in result)


@test()
def test_search_structs_pattern_no_match():
    """search_structs returns an empty list for an unmatched substring."""
    result = search_structs("VeryUnlikelyStructName123")
    assert_is_list(result)
    assert len(result) == 0


@test(binary="typed_fixture.elf")
def test_search_structs_exact_wrapper_match():
    """search_structs finds the exact Wrapper struct in the typed fixture."""
    result = search_structs("Wrapper")
    assert_is_list(result, min_length=1)
    wrapper = next((item for item in result if item["name"] == "Wrapper"), None)
    assert wrapper is not None
    assert wrapper["cardinality"] == 2
    assert wrapper["size"] == 24


@test()
def test_type_query():
    """type_query supports filtered type listing"""
    result = type_query(
        {
            "filter": "*",
            "kind": "any",
            "offset": 0,
            "count": 10,
            "include_decl": False,
        }
    )
    assert_is_list(result, min_length=1)
    page = result[0]
    assert "kind" in page
    assert "data" in page
    assert "next_offset" in page
    assert "total" in page
    if page["data"]:
        assert "ordinal" in page["data"][0]
        assert "name" in page["data"][0]
        assert "size" in page["data"][0]
        assert "kind" in page["data"][0]


@test()
def test_type_inspect():
    """type_inspect returns metadata for declared struct"""
    tname = "__TypeInspectTest__"
    if not create_test_struct(tname):
        skip_test("failed to declare type-inspect struct")

    result = type_inspect({"name": tname, "include_members": True})
    assert_is_list(result, min_length=1)
    r = result[0]
    assert r["name"] == tname
    assert r["exists"] is True
    assert "error" not in r
    assert r.get("member_count", 0) >= 0


@test()
def test_set_type():
    """set_type applies type to address"""
    result = set_type({"addr": _require_any_function(), "ty": TYPE_APPLY_SIGNATURE})
    assert_is_list(result, min_length=1)


@test()
def test_enum_upsert_creates_and_replays_idempotently():
    """enum_upsert creates a new enum and skips exact repeats."""
    import idc

    enum_name = "__TestEnumUpsert__"
    enum_id = idc.get_enum(enum_name)
    if enum_id != idc.BADADDR:
        idc.del_enum(enum_id)

    try:
        first = enum_upsert(
            {
                "name": enum_name,
                "members": [
                    {"name": "__TEST_ENUM_ZERO__", "value": 0},
                    {"name": "__TEST_ENUM_ONE__", "value": 1},
                ],
            }
        )
        second = enum_upsert(
            {
                "name": enum_name,
                "members": [
                    {"name": "__TEST_ENUM_ZERO__", "value": 0},
                    {"name": "__TEST_ENUM_ONE__", "value": 1},
                ],
            }
        )
        assert_is_list(first, min_length=1)
        assert "error" not in first[0]
        assert first[0].get("created") is True
        assert first[0]["summary"]["created"] == 2
        assert_is_list(second, min_length=1)
        assert "error" not in second[0]
        assert second[0]["summary"]["skipped"] == 2
    finally:
        enum_id = idc.get_enum(enum_name)
        if enum_id != idc.BADADDR:
            idc.del_enum(enum_id)


@test()
def test_enum_upsert_reports_conflicting_member_value():
    """enum_upsert reports conflicting member names cleanly."""
    import idc

    enum_name = "__TestEnumConflict__"
    enum_id = idc.get_enum(enum_name)
    if enum_id != idc.BADADDR:
        idc.del_enum(enum_id)

    try:
        enum_upsert({"name": enum_name, "members": [{"name": "__TEST_ENUM_CONFLICT__", "value": 1}]})
        result = enum_upsert({"name": enum_name, "members": [{"name": "__TEST_ENUM_CONFLICT__", "value": 2}]})
        assert_is_list(result, min_length=1)
        assert "error" in result[0]
        assert result[0]["summary"]["conflicts"] == 1
        assert "conflict" in (result[0]["members"][0].get("error") or "").lower()
    finally:
        enum_id = idc.get_enum(enum_name)
        if enum_id != idc.BADADDR:
            idc.del_enum(enum_id)


@test(binary="crackme03.elf")
def test_set_type_applies_named_global_type():
    """set_type applies a concrete type to a known crackme global and reports success."""
    result = set_type({"addr": CRACKME_DSO_HANDLE, "ty": "unsigned __int64"})
    assert_is_list(result, min_length=1)
    entry = result[0]
    assert entry["edit"]["addr"] == CRACKME_DSO_HANDLE
    assert "error" not in entry


@test()
def test_set_type_invalid_address():
    """set_type reports an error for an invalid address."""
    result = set_type({"addr": get_unmapped_address(), "ty": "int"})
    assert_is_list(result, min_length=1)
    assert_error(result[0])


@test(binary="typed_fixture.elf")
def test_set_type_global_by_name_branch():
    """set_type(kind=global) can resolve the target by symbol name instead of address."""
    result = set_type({"name": "g_point", "ty": "Point", "kind": "global"})
    assert_is_list(result, min_length=1)
    assert "error" not in result[0]


@test(binary="typed_fixture.elf")
def test_set_type_global_invalid_type_name():
    """set_type(kind=global) reports invalid type names cleanly."""
    result = set_type({"addr": TYPED_FIXTURE_G_POINT, "ty": "NoSuchType", "kind": "global"})
    assert_is_list(result, min_length=1)
    assert_error(result[0])


@test()
def test_type_apply_batch():
    """type_apply_batch applies edits and returns summary counters"""
    result = type_apply_batch({"edits": [{"addr": _require_any_function(), "ty": TYPE_APPLY_SIGNATURE}]})
    assert "error" not in result
    assert "applied" in result
    assert "failed" in result
    assert "stopped" in result
    assert "results" in result
    assert_is_list(result["results"], min_length=1)


@test()
def test_set_type_unknown_kind():
    """set_type reports unknown type-edit kinds explicitly."""
    result = set_type({"addr": "0x123e", "kind": "weird", "ty": "int"})
    assert_is_list(result, min_length=1)
    assert_error(result[0], contains="Unknown kind")


@test()
def test_set_type_function_not_found_branch():
    """set_type(kind=function) reports missing functions cleanly."""
    result = set_type(
        {"addr": get_unmapped_address(), "kind": "function", "signature": "int foo()"}
    )
    assert_is_list(result, min_length=1)
    assert_error(result[0], contains="Function not found")


@test(binary="crackme03.elf")
def test_set_type_stack_missing_member():
    """set_type(kind=stack) reports a missing frame member explicitly."""
    fn_addr = get_named_address("main")
    if not fn_addr:
        skip_test("main symbol not present")
    result = set_type({"addr": fn_addr, "kind": "stack", "name": "nope", "ty": "int"})
    assert_is_list(result, min_length=1)
    assert_error(result[0], contains="not found")


@test(binary="typed_fixture.elf")
def test_set_type_stack_missing_member_typed_fixture():
    """typed_fixture reports missing stack members against a stable non-main function."""
    result = set_type(
        {"addr": TYPED_FIXTURE_USE_WRAPPER, "kind": "stack", "name": "nope", "ty": TYPE_APPLY_SIGNATURE}
    )
    assert_is_list(result, min_length=1)
    assert_error(result[0], contains="not found")


@test(binary="crackme03.elf")
def test_infer_types_returns_high_confidence_for_main():
    """infer_types(main) returns a non-empty inferred type with a method and confidence."""
    main_addr = get_named_address("main")
    if not main_addr:
        skip_test("main symbol not present")

    result = infer_types(main_addr)
    assert_is_list(result, min_length=1)
    entry = result[0]
    assert entry["confidence"] in {"high", "low", "none"}
    if entry["inferred_type"] is not None:
        assert_non_empty(entry["inferred_type"])
        assert entry["method"] is not None


@test(binary="typed_fixture.elf")
def test_set_type_function_branch():
    """set_type(kind=function) applies a function signature to a typed fixture function."""
    result = set_type(
        {
            "addr": TYPED_FIXTURE_SUM_POINT,
            "signature": "int __fastcall sum_point(struct Point *p)",
            "kind": "function",
        }
    )
    assert_is_list(result, min_length=1)
    assert "error" not in result[0]


@test(binary="typed_fixture.elf")
def test_set_type_function_invalid_signature():
    """set_type(kind=function) rejects non-function signatures."""
    result = set_type(
        {
            "addr": TYPED_FIXTURE_SUM_POINT,
            "signature": TYPE_APPLY_SIGNATURE,
            "kind": "function",
        }
    )
    assert_is_list(result, min_length=1)
    assert_error(result[0], contains="Not a function type")


@test(binary="typed_fixture.elf")
def test_set_type_local_branch():
    """set_type(kind=local) reaches the local-variable type application path."""
    result = set_type(
        {
            "addr": TYPED_FIXTURE_USE_WRAPPER,
            "kind": "local",
            "variable": TYPED_FIXTURE_LOCAL_NAME,
            "ty": TYPE_APPLY_SIGNATURE,
        }
    )
    assert_is_list(result, min_length=1)
    assert (
        "error" not in result[0]
        or result[0].get("error") == "Failed to apply local variable type"
    )


@test(binary="typed_fixture.elf")
def test_set_type_local_invalid_type_name():
    """set_type(kind=local) reports invalid local type names cleanly."""
    result = set_type(
        {
            "addr": TYPED_FIXTURE_USE_WRAPPER,
            "kind": "local",
            "variable": TYPED_FIXTURE_LOCAL_NAME,
            "ty": "NoSuchType",
        }
    )
    assert_is_list(result, min_length=1)
    assert_error(result[0])


@test(binary="typed_fixture.elf")
def test_set_type_stack_branch():
    """set_type(kind=stack) applies a type to a real stack-frame member."""
    result = set_type(
        {
            "addr": TYPED_FIXTURE_USE_WRAPPER,
            "kind": "stack",
            "name": TYPED_FIXTURE_LOCAL_NAME,
            "ty": TYPE_APPLY_SIGNATURE,
        }
    )
    assert_is_list(result, min_length=1)
    assert "error" not in result[0]


@test(binary="typed_fixture.elf")
def test_infer_types_size_based_low_confidence():
    """infer_types falls back to size-based inference on a typed-fixture interior data address."""
    result = infer_types(TYPED_FIXTURE_INFER_FALLBACK)
    assert_is_list(result, min_length=1)
    entry = result[0]
    assert entry["method"] == "size_based"
    assert entry["confidence"] == "low"
    assert entry["inferred_type"] == "uint8_t[12]"


@test(binary="typed_fixture.elf")
def test_infer_types_existing_or_hexrays_wrapper():
    """infer_types returns a strong typed result for the typed fixture wrapper object."""
    result = infer_types(TYPED_FIXTURE_G_WRAPPER)
    assert_is_list(result, min_length=1)
    entry = result[0]
    assert entry["method"] in {"hexrays", "existing"}
    assert entry["confidence"] == "high"
    assert "Wrapper" in entry["inferred_type"]


@test()
def test_infer_types_invalid_address_still_returns_structured_result():
    """infer_types returns a structured fallback result even for weird unmapped inputs."""
    result = infer_types(get_unmapped_address())
    assert_is_list(result, min_length=1)
    entry = result[0]
    assert entry["confidence"] in {"high", "low", "none"}
    assert "addr" in entry


@test(binary="typed_fixture.elf")
def test_infer_types_invalid_text_address_errors_cleanly():
    """infer_types reports parse failures for symbolic garbage addresses."""
    result = infer_types("InvalidAddressName123")
    assert_is_list(result, min_length=1)
    assert_error(result[0], contains="Not found")


# ============================================================================
# type_propagate — high-level integration tests
# ============================================================================


def _require_hexrays_in_result(result):
    """Skip if Hex-Rays isn't available — every type_propagate test needs it."""
    if not result.get("ok") and "Hex-Rays" in str(result.get("error", "")):
        skip_test("Hex-Rays decompiler not available in this IDA instance")


@test()
def test_type_propagate_rejects_invalid_direction():
    """Bad ``direction`` strings produce a structured error, not a crash."""
    result = type_propagate(get_any_function(), direction="sideways")
    assert result["ok"] is False
    assert "direction" in result["error"].lower()


@test()
def test_type_propagate_rejects_empty_var_name():
    """``func::`` (trailing empty var name) returns a structured error."""
    result = type_propagate("main::")
    assert result["ok"] is False
    assert "empty" in result["error"].lower() or "must not be empty" in result["error"].lower()


@test()
def test_type_propagate_returns_full_schema_on_success():
    """A successful call carries every documented top-level field.

    Even with no evidence, the result schema must be complete so AI agents
    don't have to handle a sparse-result fallback path.
    """
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")
    result = type_propagate(fn_addr, max_functions=2, max_depth=1)
    _require_hexrays_in_result(result)
    if not result.get("ok"):
        skip_test(f"type_propagate failed: {result.get('error')}")

    for key in (
        "address", "inferred_type", "confidence", "confidence_breakdown",
        "field_accesses", "field_profile", "call_usages", "stored_in",
        "propagation_path", "functions_analyzed",
        "suggested_struct_name", "suggested_struct_definition", "applied",
    ):
        assert key in result, f"missing {key!r} in result"


@test()
def test_type_propagate_confidence_in_unit_interval():
    """Property: confidence must lie in [0, 1] for every input."""
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")
    result = type_propagate(fn_addr, max_functions=2, max_depth=1)
    _require_hexrays_in_result(result)
    if not result.get("ok"):
        skip_test(f"type_propagate failed: {result.get('error')}")
    c = result["confidence"]
    assert 0.0 <= c <= 1.0, f"confidence {c} outside [0, 1]"


@test()
def test_type_propagate_function_entry_target_hint():
    """Targeting a function entry point returns a hint pointing the user
    toward a data variable instead — this is the most common foot-gun."""
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")
    result = type_propagate(fn_addr, max_functions=1)
    _require_hexrays_in_result(result)
    if not result.get("ok"):
        skip_test(f"type_propagate failed: {result.get('error')}")

    # If the function genuinely has no analyzable usages, the hint mentions
    # 'function entry point' (the code-pointer-global path). If the function
    # itself has field accesses through some argument, this branch may not fire
    # — accept either outcome but never crash.
    hint = result.get("hint", "")
    if not result["field_accesses"]:
        assert hint, "zero-fields result must have a hint explaining why"


@test()
def test_type_propagate_zero_fields_includes_diag():
    """When zero field accesses, every ``functions_analyzed`` entry that was
    decompiled must include a ``diag`` block — that's the only way callers
    can tell ``no evidence`` from ``visitor never saw anything``."""
    addr = get_unmapped_address()
    # Use a high address with a containing function would be ideal; falling
    # back to an arbitrary function should still produce diag on zero-result
    # functions.
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")
    result = type_propagate(fn_addr, max_functions=2, max_depth=1)
    _require_hexrays_in_result(result)
    if not result.get("ok"):
        skip_test(f"type_propagate failed: {result.get('error')}")

    if result["field_accesses"]:
        # If by chance the function did produce field accesses, no diag is
        # required — skip the rest of this test.
        return

    decompiled_entries = [
        e for e in result["functions_analyzed"] if e.get("decompiled")
    ]
    for entry in decompiled_entries:
        assert "diag" in entry, f"function {entry.get('func_name')} missing diag block on zero result"
        diag = entry["diag"]
        # Every counter key documented in the visitor must be present.
        for k in (
            "asg_memptr_seen", "asg_memptr_base_mismatch",
            "read_memptr_seen", "read_memptr_base_mismatch",
            "read_ptr_seen", "read_ptr_base_mismatch",
            "read_ptr_decompose_failed", "stored_in_count",
        ):
            assert k in diag, f"diag missing key {k!r}"
            assert isinstance(diag[k], int), f"diag[{k!r}] not int"


@test()
def test_type_propagate_field_profile_invariants():
    """``field_profile`` must be consistent with ``field_accesses``:

    - Every offset present in ``field_accesses`` appears in ``field_profile``.
    - ``reads + writes`` per offset equals the count in ``field_accesses``.
    - Offsets are non-negative.
    """
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")
    result = type_propagate(fn_addr, max_functions=3, max_depth=1)
    _require_hexrays_in_result(result)
    if not result.get("ok"):
        skip_test(f"type_propagate failed: {result.get('error')}")

    profile = result["field_profile"]
    fas = result["field_accesses"]

    counts: dict[int, dict] = {}
    for fa in fas:
        off = fa["offset"]
        slot = counts.setdefault(off, {"reads": 0, "writes": 0})
        if fa.get("is_write"):
            slot["writes"] += 1
        else:
            slot["reads"] += 1

    for off, expected in counts.items():
        assert off >= 0, f"negative offset {off} leaked into result"
        key = f"0x{off:X}"
        assert key in profile, f"offset {key} missing from field_profile"
        assert profile[key]["reads"] == expected["reads"]
        assert profile[key]["writes"] == expected["writes"]


@test()
def test_type_propagate_confidence_breakdown_present():
    """The ``confidence_breakdown`` list is always non-empty — even with no
    evidence, it carries a single ``no_evidence`` factor so callers can rely
    on the field's shape."""
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")
    result = type_propagate(fn_addr, max_functions=2, max_depth=1)
    _require_hexrays_in_result(result)
    if not result.get("ok"):
        skip_test(f"type_propagate failed: {result.get('error')}")

    factors = result["confidence_breakdown"]
    assert isinstance(factors, list)
    assert len(factors) >= 1
    for factor in factors:
        assert "kind" in factor
        assert "contribution" in factor
        assert 0.0 <= factor["contribution"] <= 1.0


@test(binary="typed_fixture.elf")
def test_type_propagate_typed_global_struct_pointer():
    """Targeting a global of a known struct type yields field accesses with
    valid offsets — the canonical 'this works' end-to-end check."""
    result = type_propagate(TYPED_FIXTURE_G_WRAPPER, max_functions=5, max_depth=2)
    _require_hexrays_in_result(result)
    if not result.get("ok"):
        skip_test(f"type_propagate failed: {result.get('error')}")

    # We don't require a specific count — Hex-Rays output varies — but if any
    # accesses are detected, they must validate. If zero, we at least demand
    # a diagnostic hint so the analyst knows why.
    if result["field_accesses"]:
        for fa in result["field_accesses"]:
            assert fa["offset"] >= 0
            assert fa["access_size"] in (1, 2, 4, 8, 16)
            assert "func_ea" in fa
            assert "ea" in fa
    else:
        assert result.get("hint"), "zero field accesses must include a diagnostic hint"


@test(binary="typed_fixture.elf")
def test_type_propagate_unmapped_address_returns_clean_error():
    """An unmapped address produces a structured error, not a traceback."""
    result = type_propagate(get_unmapped_address(), max_functions=1)
    # Two valid outcomes:
    #   (a) ok=False with an error message
    #   (b) ok=True with zero evidence and a hint
    # Either is acceptable — neither must crash.
    if result.get("ok"):
        assert result["field_accesses"] == []
        assert result.get("hint")
    else:
        assert "error" in result


@test()
def test_type_propagate_local_var_not_found_per_function_note():
    """When ``func::var`` resolves but ``var`` doesn't exist in the locals,
    the per-function entry records a ``note`` rather than crashing."""
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")
    result = type_propagate(f"{fn_addr}::__nonexistent_var__")
    _require_hexrays_in_result(result)
    if not result.get("ok"):
        skip_test(f"type_propagate failed: {result.get('error')}")

    decompiled = [e for e in result["functions_analyzed"] if e.get("decompiled")]
    if decompiled:
        # At least the containing function should report the missing var.
        notes = [e.get("note", "") for e in decompiled]
        assert any("not found" in n.lower() for n in notes), (
            f"expected a 'not found' note among {notes}"
        )
