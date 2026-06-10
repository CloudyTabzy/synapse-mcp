"""angr_worker — the out-of-process angr engine.

This module is the program run inside a dedicated **child process** (spawned by
``angr_ipc.AngrWorker``). It contains the pure-angr logic that used to live
inline in ``api_angr.py``, with every IDA dependency removed: all IDA-derived
inputs (binary path, arch, image base, entry point, target/avoid addresses,
address→name maps) are passed in by the parent as plain data.

Why a separate process (see Feedbacks/angr-integration-V2-review-2026-05-31.md):

  * **Pickle bug.** angr SimStates hold native cffi handles (unicorn / pyvex,
    ``_cffi_backend._CDataBase``) that are not pickle/copy-safe. Inside IDA those
    objects crossed the ``execute_sync`` boundary and blew up with
    ``cannot pickle '_cffi_backend._CDataBase'``. Here, *only plain dicts* cross
    the process boundary, so a live angr object can never escape — the bug is
    impossible by construction.

  * **Thread starvation.** angr work is CPU-bound native code holding the GIL;
    running it on IDA's main thread froze the whole UI for minutes and could not
    be interrupted. A child process has its own GIL (IDA never starves) and can
    be force-killed on timeout (``proc.terminate()``), which a Python thread in
    native code cannot.

Protocol (length-prefixed pickle over a localhost TCP socket — see angr_ipc.py
for why not multiprocessing):
    child → parent : {"authkey": str}                      # handshake, first msg
    parent → child : {"op": str, "req_id": int, "payload": dict}
    child  → parent: {"req_id": int, "ok": bool, "result": dict}  # result is a
                     plain JSON-able dict; on failure ok=False and result holds
                     {"error", "error_type", "hint"}.
    ``{"op": "__ping__"}`` health-checks without importing angr; ``{"op":
    "__shutdown__"}`` ends the serve loop; a socket EOF (parent gone) also ends it.

Results mirror the TypedDict shapes in ``api_angr.py`` so the parent can pass
them straight back to the MCP client.
"""
from __future__ import annotations

import logging
import os
import re as _re
import time
from collections import OrderedDict
from typing import Any, Callable

logger = logging.getLogger("angr_worker")

# angr is imported lazily inside the child so importing this module on the
# parent side (e.g. for constants) never drags in the 200 MB dependency.
_angr = None
_claripy = None
_cle = None


def _ensure_angr() -> None:
    global _angr, _claripy, _cle
    if _angr is not None:
        return
    import angr  # noqa: PLC0415
    import claripy  # noqa: PLC0415
    import cle  # noqa: PLC0415

    _angr = angr
    _claripy = claripy
    _cle = cle
    for _noisy in ("angr", "cle", "claripy", "pyvex", "archinfo"):
        try:
            logging.getLogger(_noisy).setLevel(logging.ERROR)
        except Exception:
            pass


# ============================================================================
# Project cache (lives in the child, persists across requests)
# ============================================================================

_MAX_PROJECTS = 3
_projects: "OrderedDict[str, dict]" = OrderedDict()


def _evict() -> None:
    while len(_projects) > _MAX_PROJECTS:
        _projects.popitem(last=False)


def _get_entry(project_id: str | None) -> dict | None:
    if not _projects:
        return None
    if project_id is None:
        key = next(reversed(_projects))
        _projects.move_to_end(key)
        return _projects[key]
    ent = _projects.get(project_id)
    if ent is not None:
        _projects.move_to_end(project_id)
    return ent


def _project_id_for_entry(entry: dict) -> str:
    for pid, ent in _projects.items():
        if ent is entry:
            return pid
    return ""


# ============================================================================
# State option policy — strip the unicorn engine (see module docstring)
# ============================================================================

def _state_options():
    add = {
        _angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
        _angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
    }
    remove = set(_angr.options.unicorn) - add
    return add, remove


# ============================================================================
# Character-class constraints for symbolic stdin / argv
# ============================================================================

_PRINTABLE = bytes(range(0x20, 0x7F))
_ALNUM = bytes(
    list(range(ord("0"), ord("9") + 1))
    + list(range(ord("A"), ord("Z") + 1))
    + list(range(ord("a"), ord("z") + 1))
)
_HEX = bytes(
    list(range(ord("0"), ord("9") + 1))
    + list(range(ord("a"), ord("f") + 1))
    + list(range(ord("A"), ord("F") + 1))
)


def _parse_char_spec(spec: str) -> bytes:
    s = (spec or "").strip().lower()
    if s == "printable":
        return _PRINTABLE
    if s == "alphanumeric":
        return _ALNUM
    if s == "hex":
        return _HEX
    raw = (spec or "").strip()
    if not raw:
        return _PRINTABLE
    chars: set[int] = set()
    parts = raw.split(",")
    cleaned: list[str] = []
    i = 0
    while i < len(parts):
        part = parts[i]
        if part.endswith("{") and i + 1 < len(parts) and parts[i + 1].startswith("}"):
            cleaned.append(part)
            cleaned.append(parts[i + 1])
            i += 2
            continue
        cleaned.append(part)
        i += 1
    for part in cleaned:
        p = part.strip()
        if not p:
            continue
        if len(p) == 3 and p[1] == "-":
            lo, hi = ord(p[0]), ord(p[2])
            if lo <= hi <= 0xFF:
                for c in range(lo, hi + 1):
                    chars.add(c)
        elif len(p) == 1:
            chars.add(ord(p))
        else:
            for c in p:
                if ord(c) <= 0xFF:
                    chars.add(ord(c))
    return bytes(sorted(chars)) if chars else _PRINTABLE


def _apply_byte_constraints(state, sym_bv, size_bytes: int, allowed: bytes) -> None:
    if not allowed:
        return
    bits_total = sym_bv.size()
    for i in range(size_bytes):
        if (i + 1) * 8 > bits_total:
            break
        byte_i = sym_bv.get_byte(i)
        clauses = [byte_i == c for c in allowed]
        if len(clauses) == 1:
            state.solver.add(clauses[0])
        else:
            state.solver.add(_claripy.Or(*clauses))


# ============================================================================
# Helpers
# ============================================================================

def _err(exc: Exception | str, error_type: str = "internal_error", hint: str = "") -> dict:
    msg = exc if isinstance(exc, str) else f"{type(exc).__name__}: {exc}"
    out: dict = {"ok": False, "error": msg, "error_type": error_type}
    if hint:
        out["hint"] = hint
    return out


def _is_cle_backend_error(e: BaseException) -> bool:
    backend_errs = tuple(
        c for c in (
            getattr(_cle.errors, "CLECompatibilityError", None),
            getattr(_cle.errors, "CLEUnknownFormatError", None),
        ) if isinstance(c, type)
    )
    if backend_errs and isinstance(e, backend_errs):
        return True
    m = str(e).lower()
    return "loader backend" in m or "unable to find a loader" in m


def _summarize_regions(proj) -> list[dict]:
    regions: list[dict] = []
    try:
        for seg in getattr(proj.loader.main_object, "segments", []):
            regions.append({
                "name": getattr(seg, "name", "") or "",
                "start": hex(getattr(seg, "vaddr", 0)),
                "size": int(getattr(seg, "memsize", 0)),
            })
        if not regions:
            for sec in getattr(proj.loader.main_object, "sections", []):
                regions.append({
                    "name": getattr(sec, "name", "") or "",
                    "start": hex(getattr(sec, "vaddr", 0)),
                    "size": int(getattr(sec, "memsize", 0)),
                })
    except Exception:
        pass
    return regions[:32]


def _resolve_addr(value: Any) -> int:
    """Parse a hex/int address. Addresses are pre-resolved by the parent, so
    this only needs to handle '0x...'/decimal forms, not IDA symbols."""
    if isinstance(value, int):
        return value
    s = str(value).strip()
    return int(s, 16) if s.lower().startswith("0x") else int(s, 0)


# ============================================================================
# Operations — each takes a payload dict, returns a plain result dict
# ============================================================================

def op_load(payload: dict) -> dict:
    """Load a binary into a cached angr Project, with blob auto-fallback.

    payload: binary_path, arch, base_addr (int|None), entry_point (int|None),
             project_id (str|None)
    """
    path = payload.get("binary_path") or ""
    if not path or not os.path.exists(path):
        return _err(f"Binary path not found: {path!r}", "not_found")

    for pid, ent in _projects.items():
        if ent.get("binary_path") == path:
            _projects.move_to_end(pid)
            proj = ent["project"]
            lb = ent.get("loader_backend", "")
            return {
                "ok": True, "project_id": pid, "binary_path": path,
                "arch": proj.arch.name, "bits": proj.arch.bits,
                "entry_point": hex(proj.entry),
                "image_base": hex(proj.loader.main_object.mapped_base),
                "memory_regions": _summarize_regions(proj),
                "symbol_count": len(list(proj.loader.main_object.symbols)),
                "loader_backend": lb, "fallback_used": lb == "blob",
                "note": "Project already cached for this binary.",
            }

    arch = payload.get("arch")
    base_addr = payload.get("base_addr")
    entry_point = payload.get("entry_point")

    forced = {"auto_load_libs": False}
    main_opts: dict = {}
    if arch:
        main_opts["arch"] = arch
    if base_addr is not None:
        main_opts["base_addr"] = int(base_addr)
    load_options = dict(forced)
    if main_opts:
        load_options["main_opts"] = main_opts

    proj = None
    loader_backend = ""
    fallback_used = False
    try:
        proj = _angr.Project(path, load_options=load_options)
        loader_backend = type(proj.loader.main_object).__name__
    except Exception as e_auto:
        if not _is_cle_backend_error(e_auto):
            return _err(
                e_auto, "internal_error",
                "angr could not load this binary and it is not a headerless blob "
                "(handled automatically). Likely corrupt or an unsupported arch.",
            )
        blob_opts = dict(main_opts)
        blob_opts["backend"] = "blob"
        if arch:
            blob_opts["arch"] = arch
        if base_addr is not None:
            blob_opts["base_addr"] = int(base_addr)
        if entry_point is not None:
            blob_opts["entry_point"] = int(entry_point)
        try:
            proj = _angr.Project(path, load_options={**forced, "main_opts": blob_opts})
            loader_backend = "blob"
            fallback_used = True
        except Exception as e_blob:
            return _err(
                e_blob, "internal_error",
                "Blob fallback failed; pass an explicit arch and/or base_address.",
            )

    pid = payload.get("project_id") or f"proj_{len(_projects)}"
    _projects[pid] = {
        "project": proj, "binary_path": path, "loader_backend": loader_backend,
        "cfg": None, "snapshots": {}, "hooks": {}, "hook_log": [],
        "last_found_states": [],
    }
    _projects.move_to_end(pid)
    _evict()

    note = (
        "Loaded via angr 'blob' backend (raw binary, no symbols), rebased to "
        "IDA's imagebase. Prefer angr_cfg_from_ida for CFG data; use angr for "
        "symbolic execution."
        if fallback_used else
        "Project cached. Call angr_cfg_fast to build a CFG."
    )
    return {
        "ok": True, "project_id": pid, "binary_path": path,
        "arch": proj.arch.name, "bits": proj.arch.bits,
        "entry_point": hex(proj.entry),
        "image_base": hex(proj.loader.main_object.mapped_base),
        "memory_regions": _summarize_regions(proj),
        "symbol_count": len(list(proj.loader.main_object.symbols)),
        "loader_backend": loader_backend, "fallback_used": fallback_used,
        "note": note,
    }


def _ensure_project(payload: dict):
    """Return (entry, proj), auto-loading from payload['load'] hints if needed."""
    ent = _get_entry(payload.get("project_id"))
    if ent is None:
        load_hint = payload.get("load") or {}
        res = op_load(load_hint)
        if not res.get("ok"):
            raise RuntimeError(res.get("error", "load failed"))
        ent = _get_entry(res.get("project_id"))
        if ent is None:
            raise RuntimeError("load ok but project not cached")
    return ent, ent["project"]


def op_cfg_fast(payload: dict) -> dict:
    entry, proj = _ensure_project(payload)
    resolve_ij = bool(payload.get("resolve_indirect_jumps", True))
    force_complete = bool(payload.get("force_complete_scan", False))
    max_functions = int(payload.get("max_functions", 200))
    cfg = proj.analyses.CFGFast(
        normalize=True,
        resolve_indirect_jumps=resolve_ij,
        force_complete_scan=force_complete,
    )
    entry["cfg"] = cfg

    funcs: list[dict] = []
    for addr, func in cfg.kb.functions.items():
        call_targets: list[str] = []
        try:
            get_ct = getattr(func, "get_call_targets", None)
            if callable(get_ct):
                for t in get_ct() or []:
                    call_targets.append(hex(t))
        except Exception:
            call_targets = []
        funcs.append({
            "addr": hex(addr),
            "name": func.name or f"sub_{addr:X}",
            "block_count": (
                len(func.block_addrs_set) if hasattr(func, "block_addrs_set")
                else len(list(func.block_addrs))
            ),
            "call_targets": call_targets[:20],
            "is_returning": bool(func.returning) if func.returning is not None else False,
            "has_unresolved_calls": bool(getattr(func, "has_unresolved_calls", False)),
            "has_unresolved_jumps": bool(getattr(func, "has_unresolved_jumps", False)),
        })
    funcs_sorted = sorted(funcs, key=lambda f: f["block_count"], reverse=True)

    graph = cfg.model.graph
    try:
        block_count = graph.number_of_nodes()
    except Exception:
        block_count = len(list(graph.nodes()))
    try:
        edge_count = graph.number_of_edges()
    except Exception:
        edge_count = len(list(graph.edges()))
    resolved_ij = unresolved_ij = 0
    try:
        for ij in cfg.indirect_jumps.values():
            if getattr(ij, "resolved_targets", None):
                resolved_ij += 1
            else:
                unresolved_ij += 1
    except Exception:
        pass

    is_blob = entry.get("loader_backend") == "blob"
    if is_blob and not force_complete and len(funcs) == 0:
        note = ("CFGFast found no functions on this blob (no symbols). Prefer "
                "angr_cfg_from_ida, or retry with force_complete_scan=True.")
    elif is_blob:
        note = ("CFGFast on a blob is heuristic — cross-check angr_cfg_from_ida "
                "for ground-truth function data.")
    else:
        note = "CFGFast is static — indirect jumps resolved heuristically."

    return {
        "ok": True, "project_id": _project_id_for_entry(entry),
        "function_count": len(funcs), "block_count": block_count,
        "edge_count": edge_count, "indirect_jumps_resolved": resolved_ij,
        "unresolved_indirect_jumps": unresolved_ij,
        "functions": funcs_sorted[:max_functions],
        "top_by_complexity": funcs_sorted[:10], "note": note,
    }


def op_find_paths(payload: dict) -> dict:
    entry, proj = _ensure_project(payload)
    target_ea = _resolve_addr(payload["target_address"])
    source = payload.get("source_address", "entry")
    source_ea = proj.entry if (not source or source == "entry") else _resolve_addr(source)
    input_mode = payload.get("input_mode", "stdin")
    input_size = int(payload.get("input_size", 64))
    char_constraint = payload.get("char_constraint")
    max_paths = int(payload.get("max_paths", 5))
    loop_bound = int(payload.get("loop_bound", 10))
    use_dfs = bool(payload.get("use_dfs", False))
    use_veritesting = bool(payload.get("use_veritesting", False))

    avoid_eas: list[int] = []
    for a in payload.get("avoid_addresses", []) or []:
        try:
            avoid_eas.append(_resolve_addr(a))
        except Exception:
            continue

    add_opts, rem_opts = _state_options()
    sym_input = None
    try:
        if input_mode == "stdin":
            sym_input = _claripy.BVS("stdin_input", max(8, input_size) * 8)
            stdin_file = _angr.SimFileStream(name="stdin", content=sym_input, has_end=True)
            if not source or source == "entry":
                state = proj.factory.entry_state(
                    stdin=stdin_file, add_options=add_opts, remove_options=rem_opts)
            else:
                state = proj.factory.blank_state(
                    addr=source_ea, stdin=stdin_file,
                    add_options=add_opts, remove_options=rem_opts)
        elif input_mode == "argv":
            sym_input = _claripy.BVS("argv1", max(8, input_size) * 8)
            state = proj.factory.entry_state(
                args=[proj.filename, sym_input],
                add_options=add_opts, remove_options=rem_opts)
        elif input_mode == "register":
            state = proj.factory.blank_state(
                addr=source_ea, add_options=add_opts, remove_options=rem_opts)
            for reg in ("rdi", "rsi", "rdx", "rcx", "r8", "r9"):
                try:
                    setattr(state.regs, reg, _claripy.BVS(f"reg_{reg}", proj.arch.bits))
                except Exception:
                    continue
            try:
                sym_input = state.regs.rdi
            except Exception:
                sym_input = None
        else:
            return _err(f"Unknown input_mode: {input_mode!r}", "invalid_input",
                        "Use 'stdin', 'argv', or 'register'.")
    except Exception as e:
        return _err(e, "internal_error", "state setup failed")

    char_used = None
    if char_constraint and sym_input is not None and input_mode in ("stdin", "argv"):
        try:
            _apply_byte_constraints(state, sym_input, input_size, _parse_char_spec(char_constraint))
            char_used = char_constraint
        except Exception:
            pass

    simgr = proj.factory.simgr(state)
    try:
        if use_dfs:
            simgr.use_technique(_angr.exploration_techniques.DFS())
        if use_veritesting:
            simgr.use_technique(_angr.exploration_techniques.Veritesting())
        simgr.use_technique(_angr.exploration_techniques.LoopSeer(bound=max(1, loop_bound)))
    except Exception:
        pass

    start = time.time()
    try:
        simgr.explore(find=target_ea, avoid=avoid_eas or None, num_find=max(1, max_paths))
    except Exception as ex:
        logger.warning("explore raised: %s", ex)
    elapsed_ms = int((time.time() - start) * 1000)

    found_states = list(getattr(simgr, "found", []) or [])[:max(1, max_paths)]
    entry["last_found_states"] = found_states

    paths: list[dict] = []
    for i, fs in enumerate(found_states):
        try:
            if input_mode == "stdin":
                try:
                    solution_bv = fs.posix.stdin.load(0, fs.posix.stdin.size)
                except Exception:
                    solution_bv = sym_input
            elif input_mode == "register":
                try:
                    solution_bv = fs.regs.rdi
                except Exception:
                    solution_bv = sym_input
            else:
                solution_bv = sym_input
            sol_bytes = fs.solver.eval(solution_bv, cast_to=bytes)
            if input_mode == "stdin":
                sol_bytes = sol_bytes[:input_size]
            try:
                decoded = sol_bytes.decode("ascii", errors="replace")
                decoded = "".join(
                    c if (0x20 <= ord(c) < 0x7F or c in "\n\r\t") else f"\\x{ord(c):02x}"
                    for c in decoded
                )
            except Exception:
                decoded = repr(sol_bytes)
            paths.append({
                "path_id": i,
                "path_length": len(list(fs.history.bbl_addrs)),
                "input_bytes": decoded,
                "input_hex": sol_bytes.hex(" "),
                "constraint_count": len(fs.solver.constraints),
                "satisfiable": True,
            })
        except Exception as e:
            paths.append({"path_id": i, "error": f"solver_eval_failed: {e}"})

    def _n(name):
        return len(list(getattr(simgr, name, []) or []))

    note_parts = []
    if not paths:
        note_parts.append("No paths found. Try increasing input_size, removing "
                          "char_constraint, or supplying explicit avoid_addresses.")
    else:
        note_parts.append(f"Solved in {elapsed_ms}ms.")

    return {
        "ok": True, "source_address": hex(source_ea), "target_address": hex(target_ea),
        "avoid_addresses": [hex(a) for a in avoid_eas], "input_mode": input_mode,
        "input_size": input_size, "char_constraint_used": char_used,
        "paths_found": len(paths), "paths": paths,
        "states_explored": _n("found") + _n("active") + _n("deadended") + _n("avoid"),
        "states_active": _n("active"), "states_deadended": _n("deadended"),
        "elapsed_ms": elapsed_ms, "note": " ".join(note_parts),
    }


def op_enumerate_reachable(payload: dict) -> dict:
    entry, proj = _ensure_project(payload)
    cfg = entry.get("cfg")
    if cfg is None:
        cfg = proj.analyses.CFGFast(normalize=True, resolve_indirect_jumps=True)
        entry["cfg"] = cfg
    source = payload.get("source_address", "entry")
    src_ea = proj.entry if (not source or source == "entry") else _resolve_addr(source)
    max_depth = int(payload.get("max_depth", 15))
    max_nodes = int(payload.get("max_nodes", 2000))
    flag = [s.lower() for s in (payload.get("flag_strings") or []) if s]

    src_node = cfg.model.get_any_node(src_ea)
    if src_node is None:
        return _err(f"No CFG node at {hex(src_ea)}.", "not_found")

    from collections import deque
    graph = cfg.model.graph
    nodes_out: list[dict] = []
    interesting: list[str] = []
    seen: set[int] = set()
    q: deque = deque([(src_node, 0)])
    while q and len(nodes_out) < max_nodes:
        n, depth = q.popleft()
        addr = getattr(n, "addr", None)
        if addr is None or addr in seen:
            continue
        seen.add(addr)
        fname = None
        try:
            f = cfg.kb.functions.get(getattr(n, "function_address", 0))
            if f is not None:
                fname = f.name
        except Exception:
            pass
        is_int = bool(flag and fname and any(k in fname.lower() for k in flag))
        nodes_out.append({"addr": hex(addr), "depth": depth,
                          "function_name": fname or "", "is_interesting": is_int})
        if is_int:
            interesting.append(hex(addr))
        if depth < max_depth:
            try:
                for succ in graph.successors(n):
                    sa = getattr(succ, "addr", None)
                    if sa is not None and sa not in seen:
                        q.append((succ, depth + 1))
            except Exception:
                pass
    return {"ok": True, "source_address": hex(src_ea), "reachable_count": len(nodes_out),
            "nodes": nodes_out, "interesting_addresses": interesting,
            "note": "BFS over CFGFast graph (no symbolic execution)."}


def op_state_evaluate(payload: dict) -> dict:
    entry, proj = _ensure_project(payload)
    at_ea = _resolve_addr(payload["at_address"])
    expr = str(payload["expression"]).strip()
    add_opts, rem_opts = _state_options()
    state = proj.factory.blank_state(addr=at_ea, add_options=add_opts, remove_options=rem_opts)
    for rname, rval in (payload.get("initial_registers") or {}).items():
        try:
            ival = _resolve_addr(rval) if isinstance(rval, str) else int(rval)
            setattr(state.regs, rname.lower(), _claripy.BVV(ival, proj.arch.bits))
        except Exception:
            continue
    mem_match = _re.match(r"^mem:([^:]+):(\d+)$", expr, _re.IGNORECASE)
    if mem_match:
        result_bv = state.memory.load(_resolve_addr(mem_match.group(1)), int(mem_match.group(2)))
    else:
        ns: dict = {}
        for reg_name in dir(state.regs):
            if reg_name.startswith("_"):
                continue
            try:
                val = getattr(state.regs, reg_name)
                ns[reg_name] = val
                ns[reg_name.upper()] = val
            except Exception:
                continue
        try:
            result_bv = eval(expr, {"__builtins__": {}}, ns)  # noqa: S307
        except Exception as e:
            return _err(e, "invalid_input",
                        "Use register names like 'rax', arithmetic, or 'mem:0x401000:8'.")
    if hasattr(result_bv, "symbolic"):
        is_sym = bool(result_bv.symbolic)
        try:
            val = state.solver.eval(result_bv)
        except Exception as e:
            return _err(e, "internal_error")
        return {"ok": True, "at_address": hex(at_ea), "expression": expr,
                "result": hex(val), "result_decimal": str(val), "is_symbolic": is_sym,
                "bit_width": result_bv.size(),
                "note": "symbolic — one possible value" if is_sym else "concrete"}
    return {"ok": True, "at_address": hex(at_ea), "expression": expr,
            "result": str(result_bv), "result_decimal": str(result_bv),
            "is_symbolic": False, "bit_width": 0, "note": "non-bitvector result"}


def op_value_set(payload: dict) -> dict:
    entry, proj = _ensure_project(payload)
    func_ea = _resolve_addr(payload["function_address"])
    at_ea = _resolve_addr(payload["at_address"])
    register = str(payload["register"])
    max_examples = int(payload.get("max_examples", 5))
    add_opts, rem_opts = _state_options()
    state = proj.factory.blank_state(addr=func_ea, add_options=add_opts, remove_options=rem_opts)
    simgr = proj.factory.simgr(state)
    simgr.explore(find=at_ea)
    found = list(getattr(simgr, "found", []) or [])
    if not found:
        return _err(f"No path reached {hex(at_ea)} from {hex(func_ea)}.", "not_found")
    fs = found[0]
    try:
        reg_bv = getattr(fs.regs, register.lower())
    except Exception as e:
        return _err(e, "invalid_input", f"Unknown register: {register!r}.")
    if not reg_bv.symbolic:
        val = fs.solver.eval(reg_bv)
        return {"ok": True, "function_address": hex(func_ea), "at_address": hex(at_ea),
                "register": register,
                "bounds": {"type": "concrete", "is_concrete": True, "concrete_value": hex(val),
                           "lower_bound": hex(val), "upper_bound": hex(val)},
                "concrete_examples": [hex(val)], "note": "Register concretely determined."}
    try:
        lo, hi = fs.solver.min(reg_bv), fs.solver.max(reg_bv)
    except Exception:
        lo = hi = fs.solver.eval(reg_bv)
    examples = []
    try:
        examples = [hex(v) for v in fs.solver.eval_upto(reg_bv, max_examples)]
    except Exception:
        pass
    return {"ok": True, "function_address": hex(func_ea), "at_address": hex(at_ea),
            "register": register,
            "bounds": {"type": "interval", "is_concrete": False,
                       "lower_bound": hex(lo), "upper_bound": hex(hi)},
            "concrete_examples": examples, "note": "Register symbolic — min/max from solver."}


def op_backward_slice(payload: dict) -> dict:
    """Compute a backward slice; returns bare addresses. The PARENT enriches
    each with IDA mnemonic/function name (those need the IDB)."""
    entry, proj = _ensure_project(payload)
    target_ea = _resolve_addr(payload["target_address"])
    max_results = int(payload.get("max_results", 200))
    cfg = entry.get("cfg")
    if cfg is None:
        cfg = proj.analyses.CFGFast(normalize=True, resolve_indirect_jumps=True)
        entry["cfg"] = cfg
    target_node = cfg.model.get_any_node(target_ea)
    if target_node is None:
        return _err(f"No CFG node at {hex(target_ea)}.", "not_found")
    bs = proj.analyses.BackwardSlice(cfg, None, None, control_flow_slice=True,
                                     targets=[(target_node, -1)])
    addrs: list[str] = []
    try:
        for node in bs.runs_in_slice.nodes():
            a = getattr(node, "addr", node) if not isinstance(node, int) else node
            addrs.append(hex(a) if isinstance(a, int) else str(a))
            if len(addrs) >= max_results:
                break
    except Exception:
        pass
    return {"ok": True, "target_address": hex(target_ea), "target_reg": payload.get("target_reg") or "",
            "slice_addresses": addrs, "slice_size": len(addrs),
            "note": "CFG-only slice (control flow only)."}


def op_hook(payload: dict) -> dict:
    entry, proj = _ensure_project(payload)
    func_ea = _resolve_addr(payload["function_address"])
    hook_type = payload["hook_type"]
    bits = int(payload.get("return_bits") or 0) or proj.arch.bits
    if hook_type == "unhook":
        try:
            proj.unhook(func_ea)
        except Exception as e:
            return _err(e, "internal_error")
        entry.setdefault("hooks", {}).pop(func_ea, None)
        return {"ok": True, "function_address": hex(func_ea), "hook_type": "unhook",
                "hook_id": f"hook_{func_ea:X}", "note": "Hook removed."}
    if hook_type == "skip":
        try:
            ret_int = _resolve_addr(payload.get("return_value", "0x0"))
        except Exception:
            ret_int = 0

        class _SkipHook(_angr.SimProcedure):  # noqa: N801
            def run(self):  # type: ignore[override]
                return _claripy.BVV(ret_int, bits)

        proj.hook(func_ea, _SkipHook())
        entry.setdefault("hooks", {})[func_ea] = "skip"
        return {"ok": True, "function_address": hex(func_ea), "hook_type": "skip",
                "hook_id": f"hook_{func_ea:X}",
                "note": f"Function will return {hex(ret_int)} ({bits}-bit)."}
    if hook_type == "observe":
        log = entry.setdefault("hook_log", [])

        class _ObserveHook(_angr.SimProcedure):  # noqa: N801
            NO_RET = False

            def run(self):  # type: ignore[override]
                try:
                    args = []
                    for r in ("rdi", "rsi", "rdx", "rcx", "r8", "r9"):
                        try:
                            args.append(str(getattr(self.state.regs, r)))
                        except Exception:
                            break
                    log.append({"addr": hex(func_ea), "args": args})
                except Exception:
                    pass
                return _claripy.BVS("observe_ret", bits)

        proj.hook(func_ea, _ObserveHook())
        entry.setdefault("hooks", {})[func_ea] = "observe"
        return {"ok": True, "function_address": hex(func_ea), "hook_type": "observe",
                "hook_id": f"hook_{func_ea:X}", "note": "Calls logged; returns symbolic value."}
    return _err(f"unknown hook_type {hook_type!r}", "invalid_input",
                "hook_type must be 'skip', 'observe', or 'unhook'.")


def op_snapshot_save(payload: dict) -> dict:
    entry, proj = _ensure_project(payload)
    label = payload.get("label", "")
    idx = int(payload.get("from_path_id", 0))
    states = entry.get("last_found_states") or []
    if not states or idx >= len(states):
        return _err(f"No state at from_path_id={idx}. Run find_paths first.", "not_found")
    snap_state = states[idx].copy()
    snap_id = f"snap_{len(entry.get('snapshots', {}))}"
    entry.setdefault("snapshots", {})[snap_id] = {
        "label": label, "state": snap_state,
        "addr": getattr(snap_state, "addr", 0),
        "constraints": len(snap_state.solver.constraints),
    }
    return {"ok": True, "snapshot_id": snap_id, "label": label,
            "project_id": _project_id_for_entry(entry),
            "addr": hex(getattr(snap_state, "addr", 0) or 0),
            "constraint_count": len(snap_state.solver.constraints),
            "note": "Snapshot saved."}


def op_snapshot_restore(payload: dict) -> dict:
    entry, _ = _ensure_project(payload)
    snap_id = payload["snapshot_id"]
    snap = (entry.get("snapshots", {}) or {}).get(snap_id)
    if snap is None:
        return _err(f"Unknown snapshot_id: {snap_id!r}", "not_found")
    entry["last_found_states"] = [snap["state"].copy()]
    return {"ok": True, "snapshot_id": snap_id, "label": snap.get("label", ""),
            "project_id": _project_id_for_entry(entry),
            "addr": hex(snap.get("addr", 0) or 0),
            "constraint_count": int(snap.get("constraints", 0)),
            "note": "Snapshot restored — available as path 0."}


def op_z3_formula(payload: dict) -> dict:
    entry, _ = _ensure_project(payload)
    path_id = int(payload.get("path_id", 0))
    include_full = bool(payload.get("include_full_smt2", False))
    states = entry.get("last_found_states") or []
    if path_id >= len(states):
        return _err(f"No found state at path_id={path_id}. Run find_paths first.", "not_found")
    fs = states[path_id]
    constraints = list(fs.solver.constraints)
    smt2 = ""
    if include_full:
        try:
            bz = _claripy.backends.z3
            solver = bz.solver()
            for c in constraints:
                solver.add(bz.convert(c))
            smt2 = solver.to_smt2()
        except Exception:
            smt2 = ""
    variables: list[str] = []
    try:
        for c in constraints[:32]:
            for v in c.variables:
                if v not in variables:
                    variables.append(str(v))
    except Exception:
        pass
    return {"ok": True, "smt2_formula": smt2 if include_full else "",
            "constraint_count": len(constraints), "variables": variables[:50],
            "note": ("Full SMT-LIB2 omitted (include_full_smt2=False)" if not include_full
                     else "Full SMT-LIB2 included — may be very large.")}


# Registry of operations the serve loop can dispatch.
_OPS: dict[str, Callable[[dict], dict]] = {
    "load": op_load,
    "cfg_fast": op_cfg_fast,
    "find_paths": op_find_paths,
    "enumerate_reachable": op_enumerate_reachable,
    "state_evaluate": op_state_evaluate,
    "value_set": op_value_set,
    "backward_slice": op_backward_slice,
    "hook": op_hook,
    "snapshot_save": op_snapshot_save,
    "snapshot_restore": op_snapshot_restore,
    "z3_formula": op_z3_formula,
}


def _handle(op: str, payload: dict) -> dict:
    fn = _OPS.get(op)
    if fn is None:
        return _err(f"Unknown op: {op!r}", "invalid_input")
    # angr is imported lazily on the first real op so a __ping__ health check
    # never pays the multi-second import cost, and an import failure surfaces
    # as a clean op error rather than a dead worker.
    try:
        _ensure_angr()
    except Exception as e:
        return _err(e, "internal_error", "angr failed to import inside the worker process.")
    try:
        return fn(payload)
    except Exception as e:
        return _err(e, "internal_error", f"op {op!r} raised")


# ============================================================================
# Wire protocol — length-prefixed pickle over a localhost socket.
# Only plain dicts are ever sent, so pickle never touches a live angr/cffi
# object. Shared by both ends: the parent imports these via the package; the
# child loads this file by path. One definition, no drift.
# ============================================================================

import socket as _socket  # noqa: E402
import struct as _struct  # noqa: E402
import pickle as _pickle  # noqa: E402


def send_msg(sock, obj) -> None:
    data = _pickle.dumps(obj, protocol=_pickle.HIGHEST_PROTOCOL)
    sock.sendall(_struct.pack(">I", len(data)) + data)


def _recv_exact(sock, n: int):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


def recv_msg(sock):
    header = _recv_exact(sock, 4)
    if header is None:
        return None
    (length,) = _struct.unpack(">I", header)
    if length == 0:
        return None
    body = _recv_exact(sock, length)
    if body is None:
        return None
    return _pickle.loads(body)


def serve(sock) -> None:
    """Dispatch requests over an established socket until EOF/shutdown.

    A clean EOF (parent process gone) ends the loop, so the worker never
    outlives IDA even if IDA crashes without calling shutdown().
    """
    while True:
        try:
            msg = recv_msg(sock)
        except Exception:
            break
        if msg is None:  # EOF — parent closed the socket
            break
        if not isinstance(msg, dict):
            continue
        op = msg.get("op")
        if op == "__shutdown__":
            break
        if op == "__ping__":
            try:
                send_msg(sock, {"req_id": msg.get("req_id"), "ok": True,
                                "result": {"ok": True, "pong": True}})
            except Exception:
                break
            continue
        result = _handle(op, msg.get("payload") or {})
        try:
            send_msg(sock, {"req_id": msg.get("req_id"),
                            "ok": bool(result.get("ok")), "result": result})
        except Exception:
            break


def connect_and_serve(host: str, port, authkey) -> None:
    """Child entry point: connect back to the parent, authenticate, then serve.

    Invoked by the ``-c`` bootstrap in angr_ipc.py, which loads THIS file by
    path (so no package import / sys.path games / http.py shadowing).
    """
    if isinstance(authkey, str):
        authkey = authkey.encode()
    sock = _socket.create_connection((host, int(port)), timeout=30)
    sock.settimeout(None)
    # Send the shared secret first so the parent can reject stray connections.
    send_msg(sock, {"authkey": authkey.decode("latin-1")})
    try:
        serve(sock)
    finally:
        try:
            sock.close()
        except Exception:
            pass
