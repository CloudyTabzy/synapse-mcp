"""Unit tests for the ctree-shape helpers used by ``type_propagate``.

These tests exercise the pure-Python helpers in ``api_types`` that decompose
Hex-Rays ctree expressions — ``_unwrap_casts``, ``_const_value``, and
``_decompose_ptr_access``. Real ``cexpr_t`` objects are hard to construct
synthetically (they're SWIG-wrapped C++ types backed by the decompiler), so
we use a ``MockExpr`` plain-Python class that has the attributes the helpers
actually read: ``op``, ``x``, ``y``, ``n._value``, ``obj_ea``, ``v.idx``,
``ptrsize``, ``m``, ``ea``.

This isn't a substitute for end-to-end testing against a real binary, but it
catches the bulk of ctree-shape regressions in milliseconds without an IDA
roundtrip — exactly where the visitor has historically broken.
"""

from types import SimpleNamespace

import ida_hexrays

from ..api_types import (
    _unwrap_casts,
    _const_value,
    _decompose_ptr_access,
    _build_field_profile,
)
from ..framework import test


class MockExpr:
    """Plain-Python stand-in for a Hex-Rays ``cexpr_t``.

    Only carries the attributes the helpers under test actually read. Lets us
    construct arbitrary ctree shapes (nested casts, raw pointer arithmetic,
    array indexing) without invoking the real decompiler.
    """

    __slots__ = ("op", "x", "y", "n", "v", "obj_ea", "m", "ptrsize", "ea")

    def __init__(
        self,
        op: int,
        x: "MockExpr | None" = None,
        y: "MockExpr | None" = None,
        n_value: int | None = None,
        obj_ea: int | None = None,
        var_idx: int | None = None,
        ptrsize: int = 8,
        m: int = 0,
        ea: int = 0,
    ):
        self.op = op
        self.x = x
        self.y = y
        self.n = SimpleNamespace(_value=n_value) if n_value is not None else None
        self.v = SimpleNamespace(idx=var_idx) if var_idx is not None else None
        self.obj_ea = obj_ea
        self.ptrsize = ptrsize
        self.m = m
        self.ea = ea


# ---------------------------------------------------------------------------
# _unwrap_casts
# ---------------------------------------------------------------------------


@test()
def test_unwrap_casts_passes_through_plain_expr():
    """Plain expressions (no cast/ref) come back unchanged."""
    expr = MockExpr(ida_hexrays.cot_obj, obj_ea=0x1000)
    assert _unwrap_casts(expr) is expr


@test()
def test_unwrap_casts_strips_single_cast():
    """``(T*)x`` → ``x``."""
    inner = MockExpr(ida_hexrays.cot_obj, obj_ea=0x1000)
    cast = MockExpr(ida_hexrays.cot_cast, x=inner)
    result = _unwrap_casts(cast)
    assert result is inner
    assert result.obj_ea == 0x1000


@test()
def test_unwrap_casts_strips_nested_casts():
    """``(T*)(U*)x`` → ``x`` (compiler/decompiler can stack casts)."""
    inner = MockExpr(ida_hexrays.cot_obj, obj_ea=0x2000)
    cast1 = MockExpr(ida_hexrays.cot_cast, x=inner)
    cast2 = MockExpr(ida_hexrays.cot_cast, x=cast1)
    assert _unwrap_casts(cast2) is inner


@test()
def test_unwrap_casts_strips_cot_ref():
    """``&x`` wrapper is also stripped (rare but possible in address-of patterns)."""
    inner = MockExpr(ida_hexrays.cot_obj, obj_ea=0x3000)
    ref = MockExpr(ida_hexrays.cot_ref, x=inner)
    assert _unwrap_casts(ref) is inner


@test()
def test_unwrap_casts_strips_mixed_cast_and_ref():
    """``(T*)&x`` → ``x``."""
    inner = MockExpr(ida_hexrays.cot_obj, obj_ea=0x4000)
    ref = MockExpr(ida_hexrays.cot_ref, x=inner)
    cast = MockExpr(ida_hexrays.cot_cast, x=ref)
    assert _unwrap_casts(cast) is inner


@test()
def test_unwrap_casts_handles_none():
    """Defensive: ``None`` in → ``None`` out (no crash)."""
    assert _unwrap_casts(None) is None


@test()
def test_unwrap_casts_terminates_on_empty_chain():
    """A cast wrapping None terminates without infinite loop."""
    cast = MockExpr(ida_hexrays.cot_cast, x=None)
    assert _unwrap_casts(cast) is None


# ---------------------------------------------------------------------------
# _const_value
# ---------------------------------------------------------------------------


@test()
def test_const_value_positive():
    num = MockExpr(ida_hexrays.cot_num, n_value=24)
    assert _const_value(num) == 24


@test()
def test_const_value_zero():
    num = MockExpr(ida_hexrays.cot_num, n_value=0)
    assert _const_value(num) == 0


@test()
def test_const_value_sign_extension():
    """``cnumber_t._value`` is uint64; values >= 2^63 are negative offsets.

    ``-4`` is stored as ``0xFFFFFFFFFFFFFFFC``. The helper must sign-extend.
    """
    raw = (1 << 64) - 4
    num = MockExpr(ida_hexrays.cot_num, n_value=raw)
    assert _const_value(num) == -4


@test()
def test_const_value_non_num_returns_none():
    obj = MockExpr(ida_hexrays.cot_obj, obj_ea=0x1000)
    assert _const_value(obj) is None


@test()
def test_const_value_none_input():
    assert _const_value(None) is None


# ---------------------------------------------------------------------------
# _decompose_ptr_access
# ---------------------------------------------------------------------------


@test()
def test_decompose_simple_deref():
    """``*ptr`` → ``(ptr, 0, ptrsize)``."""
    base = MockExpr(ida_hexrays.cot_var, var_idx=3)
    ptr = MockExpr(ida_hexrays.cot_ptr, x=base, ptrsize=8)
    decomp = _decompose_ptr_access(ptr)
    assert decomp is not None
    target_expr, offset, size = decomp
    assert target_expr is base
    assert offset == 0
    assert size == 8


@test()
def test_decompose_cast_deref():
    """``*(T*)ptr`` → ``(ptr, 0, ptrsize)`` — cast stripped."""
    base = MockExpr(ida_hexrays.cot_var, var_idx=3)
    cast = MockExpr(ida_hexrays.cot_cast, x=base)
    ptr = MockExpr(ida_hexrays.cot_ptr, x=cast, ptrsize=4)
    decomp = _decompose_ptr_access(ptr)
    assert decomp is not None
    target_expr, offset, size = decomp
    assert target_expr is base
    assert offset == 0
    assert size == 4


@test()
def test_decompose_add_const_rhs():
    """``*(T*)(ptr + N)`` with N on the right → ``(ptr, N, size)``."""
    base = MockExpr(ida_hexrays.cot_var, var_idx=8)
    num = MockExpr(ida_hexrays.cot_num, n_value=24)
    add = MockExpr(ida_hexrays.cot_add, x=base, y=num)
    cast = MockExpr(ida_hexrays.cot_cast, x=add)
    ptr = MockExpr(ida_hexrays.cot_ptr, x=cast, ptrsize=8)
    decomp = _decompose_ptr_access(ptr)
    assert decomp is not None
    target_expr, offset, size = decomp
    assert target_expr is base
    assert offset == 24
    assert size == 8


@test()
def test_decompose_add_const_lhs():
    """``*(T*)(N + ptr)`` (operand-swapped) — commutative add."""
    base = MockExpr(ida_hexrays.cot_var, var_idx=8)
    num = MockExpr(ida_hexrays.cot_num, n_value=16)
    add = MockExpr(ida_hexrays.cot_add, x=num, y=base)
    cast = MockExpr(ida_hexrays.cot_cast, x=add)
    ptr = MockExpr(ida_hexrays.cot_ptr, x=cast, ptrsize=8)
    decomp = _decompose_ptr_access(ptr)
    assert decomp is not None
    target_expr, offset, size = decomp
    assert target_expr is base
    assert offset == 16


@test()
def test_decompose_add_two_vars_rejected():
    """``ptr + i`` with non-constant ``i`` is *not* a field access — return None."""
    base = MockExpr(ida_hexrays.cot_var, var_idx=8)
    idx_var = MockExpr(ida_hexrays.cot_var, var_idx=9)
    add = MockExpr(ida_hexrays.cot_add, x=base, y=idx_var)
    cast = MockExpr(ida_hexrays.cot_cast, x=add)
    ptr = MockExpr(ida_hexrays.cot_ptr, x=cast, ptrsize=8)
    assert _decompose_ptr_access(ptr) is None


@test()
def test_decompose_cot_idx_constant():
    """``ptr[5]`` → ``(ptr, 5 * ptrsize, ptrsize)``."""
    base = MockExpr(ida_hexrays.cot_var, var_idx=8)
    idx = MockExpr(ida_hexrays.cot_num, n_value=5)
    arr = MockExpr(ida_hexrays.cot_idx, x=base, y=idx, ptrsize=4)
    decomp = _decompose_ptr_access(arr)
    assert decomp is not None
    target_expr, offset, size = decomp
    assert target_expr is base
    assert offset == 20   # 5 * 4
    assert size == 4


@test()
def test_decompose_cot_idx_variable_rejected():
    """``ptr[i]`` with non-constant ``i`` — return None (no static offset)."""
    base = MockExpr(ida_hexrays.cot_var, var_idx=8)
    idx_var = MockExpr(ida_hexrays.cot_var, var_idx=9)
    arr = MockExpr(ida_hexrays.cot_idx, x=base, y=idx_var, ptrsize=4)
    assert _decompose_ptr_access(arr) is None


@test()
def test_decompose_non_pointer_op_returns_none():
    """``cot_add`` alone (no enclosing ptr/idx) isn't a field access."""
    base = MockExpr(ida_hexrays.cot_var, var_idx=8)
    num = MockExpr(ida_hexrays.cot_num, n_value=4)
    add = MockExpr(ida_hexrays.cot_add, x=base, y=num)
    assert _decompose_ptr_access(add) is None


@test()
def test_decompose_none_input():
    assert _decompose_ptr_access(None) is None


@test()
def test_decompose_default_ptrsize_when_zero():
    """If ``ptrsize`` is 0 (incomplete type), fall back to 8 — never report
    zero-byte field accesses, which would corrupt downstream struct inference."""
    base = MockExpr(ida_hexrays.cot_var, var_idx=8)
    ptr = MockExpr(ida_hexrays.cot_ptr, x=base, ptrsize=0)
    decomp = _decompose_ptr_access(ptr)
    assert decomp is not None
    _, _, size = decomp
    assert size == 8


# ---------------------------------------------------------------------------
# _build_field_profile
# ---------------------------------------------------------------------------


@test()
def test_field_profile_empty():
    assert _build_field_profile([]) == {}


@test()
def test_field_profile_single_access():
    fa = [{
        "offset": 0x18,
        "access_size": 8,
        "is_write": True,
        "func_ea": "0x1000",
    }]
    profile = _build_field_profile(fa)
    assert "0x18" in profile
    entry = profile["0x18"]
    assert entry["reads"] == 0
    assert entry["writes"] == 1
    assert entry["max_size"] == 8
    assert entry["function_count"] == 1


@test()
def test_field_profile_aggregates_by_offset():
    """Multiple accesses to the same offset roll up; different offsets stay separate."""
    fa = [
        {"offset": 0x18, "access_size": 8, "is_write": False, "func_ea": "0x1000"},
        {"offset": 0x18, "access_size": 8, "is_write": True,  "func_ea": "0x1000"},
        {"offset": 0x18, "access_size": 8, "is_write": False, "func_ea": "0x2000"},
        {"offset": 0x20, "access_size": 4, "is_write": False, "func_ea": "0x1000"},
    ]
    profile = _build_field_profile(fa)
    assert profile["0x18"]["reads"] == 2
    assert profile["0x18"]["writes"] == 1
    assert profile["0x18"]["function_count"] == 2
    assert profile["0x20"]["reads"] == 1
    assert profile["0x20"]["function_count"] == 1


@test()
def test_field_profile_tracks_size_range():
    """When the same offset is accessed at different widths, both extremes are recorded."""
    fa = [
        {"offset": 0x10, "access_size": 4, "is_write": False, "func_ea": "0x1000"},
        {"offset": 0x10, "access_size": 8, "is_write": True,  "func_ea": "0x1000"},
    ]
    profile = _build_field_profile(fa)
    assert profile["0x10"]["min_size"] == 4
    assert profile["0x10"]["max_size"] == 8


@test()
def test_field_profile_sort_order_is_stable():
    """Offsets returned in ascending order — required for deterministic struct builds."""
    fa = [
        {"offset": 0x20, "access_size": 4, "is_write": False, "func_ea": "0x1000"},
        {"offset": 0x08, "access_size": 8, "is_write": False, "func_ea": "0x1000"},
        {"offset": 0x18, "access_size": 8, "is_write": False, "func_ea": "0x1000"},
    ]
    keys = list(_build_field_profile(fa).keys())
    assert keys == ["0x8", "0x18", "0x20"]
