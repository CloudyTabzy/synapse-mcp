from typing import Annotated, Any, NotRequired, TypedDict

import idaapi
import idautils
import idc
import ida_hexrays
import ida_bytes
import ida_typeinf
import ida_frame
import ida_dirtree
import ida_funcs
import ida_ua
import ida_auto
import ida_xref

from .compat import tinfo_get_udm
import ida_nalt
import ida_xref

from .rpc import tool, unsafe
from .sync import idasync, IDAError
from .utils import (
    parse_address,
    decompile_checked,
    refresh_decompiler_ctext,
    CommentOp,
    CommentAppendOp,
    AsmPatchOp,
    FunctionRename,
    GlobalRename,
    LocalRename,
    StackRename,
    RenameBatch,
    DefineOp,
    UndefineOp,
    tool_error,
    item_error,
)


class CommentResult(TypedDict):
    addr: str
    error: NotRequired[str]
    error_type: NotRequired[str]
    hint: NotRequired[str]


class AppendCommentResult(TypedDict):
    addr: str
    scope: NotRequired[str]
    appended: NotRequired[bool]
    skipped: NotRequired[bool]
    error: NotRequired[str]
    error_type: NotRequired[str]
    hint: NotRequired[str]


class PatchAsmResult(TypedDict, total=False):
    addr: str
    verified: bool
    error: str
    error_type: str
    hint: str


class RenameItemResult(TypedDict, total=False):
    addr: str
    func_addr: str
    old: str
    new: str | None
    name: str
    dir: str
    dir_error: str
    dry_run: bool
    error: str
    error_type: str
    hint: str


class RenameSummaryResult(TypedDict, total=False):
    total: int
    ok: int
    failed: int
    stopped: bool
    dry_run: bool
    allow_overwrite: bool
    stop_on_error: bool
    stopped_at: str


class RenameResult(TypedDict, total=False):
    func: list[RenameItemResult]
    data: list[RenameItemResult]
    global_alias: list[RenameItemResult]
    local: list[RenameItemResult]
    stack: list[RenameItemResult]
    summary: RenameSummaryResult


class DefineResult(TypedDict, total=False):
    addr: str
    ea: str
    start: str
    end: str
    size: int
    length: int
    existed: bool
    error: str
    error_type: str
    hint: str


class XrefItem(TypedDict, total=False):
    frm: str
    to: str
    type: str
    ok: bool
    error: str
    error_type: str
    hint: str


# ============================================================================
# Modification Operations
# ============================================================================


@tool
@idasync
def set_comments(items: list[CommentOp] | CommentOp) -> list[CommentResult]:
    """Set comments at addresses (both disassembly and decompiler views)"""
    if isinstance(items, dict):
        items = [items]

    results = []
    for item in items:
        addr_str = item.get("addr", "")
        comment = item.get("comment", "")

        try:
            ea = parse_address(addr_str)

            if not idaapi.set_cmt(ea, comment, False):
                results.append(
                    {
                        "addr": addr_str,
                        "error": f"Failed to set disassembly comment at {hex(ea)}",
                    }
                )
                continue

            if not ida_hexrays.init_hexrays_plugin():
                results.append({"addr": addr_str})
                continue

            try:
                cfunc = decompile_checked(ea)
            except IDAError:
                results.append({"addr": addr_str})
                continue

            if ea == cfunc.entry_ea:
                idc.set_func_cmt(ea, comment, True)
                cfunc.refresh_func_ctext()
                results.append({"addr": addr_str})
                continue

            eamap = cfunc.get_eamap()
            if ea not in eamap:
                results.append(
                    {
                        "addr": addr_str,
                        "error": f"Failed to set decompiler comment at {hex(ea)}",
                    }
                )
                continue
            nearest_ea = eamap[ea][0].ea

            if cfunc.has_orphan_cmts():
                cfunc.del_orphan_cmts()
                cfunc.save_user_cmts()

            tl = idaapi.treeloc_t()
            tl.ea = nearest_ea
            for itp in range(idaapi.ITP_SEMI, idaapi.ITP_COLON):
                tl.itp = itp
                cfunc.set_user_cmt(tl, comment)
                cfunc.save_user_cmts()
                cfunc.refresh_func_ctext()
                if not cfunc.has_orphan_cmts():
                    results.append({"addr": addr_str})
                    break
                cfunc.del_orphan_cmts()
                cfunc.save_user_cmts()
            else:
                results.append(
                    {
                        "addr": addr_str,
                        "error": f"Failed to set decompiler comment at {hex(ea)}",
                    }
                )
        except Exception as e:
            results.append({"addr": addr_str, **item_error(e, f"set comment at {addr_str}")})

    return results


@tool
@idasync
def append_comments(
    items: list[CommentAppendOp] | CommentAppendOp,
) -> list[AppendCommentResult]:
    """Append comments at addresses, deduping exact text by default."""
    if isinstance(items, dict):
        items = [items]

    results = []
    for item in items:
        addr_str = item.get("addr", "")
        comment = item.get("comment", "")
        scope = str(item.get("scope", "auto") or "auto").lower()
        dedupe = bool(item.get("dedupe", True))

        try:
            ea = parse_address(addr_str)
            if scope not in {"auto", "func", "line"}:
                results.append({"addr": addr_str, "error": f"Unsupported scope: {scope}"})
                continue

            fn = idaapi.get_func(ea)
            use_func_comment = scope == "func" or (
                scope == "auto" and fn is not None and fn.start_ea == ea
            )

            if use_func_comment:
                if fn is None:
                    results.append({"addr": addr_str, "error": f"No function found at {hex(ea)}"})
                    continue
                target_ea = fn.start_ea
                current = idc.get_func_cmt(target_ea, False) or ""
                new_comment, skipped = _append_comment_text(current, comment, dedupe=dedupe)
                if skipped:
                    results.append({"addr": addr_str, "scope": "func", "skipped": True})
                    continue
                if not idc.set_func_cmt(target_ea, new_comment, False):
                    results.append(
                        {
                            "addr": addr_str,
                            "error": f"Failed to set function comment at {hex(target_ea)}",
                        }
                    )
                    continue
                results.append({"addr": addr_str, "scope": "func", "appended": True})
                continue

            current = idaapi.get_cmt(ea, False) or ""
            new_comment, skipped = _append_comment_text(current, comment, dedupe=dedupe)
            if skipped:
                results.append({"addr": addr_str, "scope": "line", "skipped": True})
                continue
            if not idaapi.set_cmt(ea, new_comment, False):
                results.append(
                    {
                        "addr": addr_str,
                        "error": f"Failed to set disassembly comment at {hex(ea)}",
                    }
                )
                continue
            results.append({"addr": addr_str, "scope": "line", "appended": True})
        except Exception as e:
            results.append({"addr": addr_str, **item_error(e, f"append comment at {addr_str}")})

    return results


def _append_comment_text(current: str, new_text: str, *, dedupe: bool) -> tuple[str, bool]:
    normalized_new = new_text.strip()
    if dedupe and normalized_new:
        existing_entries = [line.strip() for line in current.splitlines()]
        if normalized_new in existing_entries:
            return current, True
    if not current:
        return new_text, False
    if not new_text:
        return current, False
    joiner = "" if current.endswith("\n") else "\n"
    return f"{current}{joiner}{new_text}", False


@tool
@idasync
def patch_asm(items: list[AsmPatchOp] | AsmPatchOp) -> list[PatchAsmResult]:
    """Patch assembly instructions at addresses"""
    if isinstance(items, dict):
        items = [items]

    results = []
    for item in items:
        addr_str = item.get("addr", "")
        instructions = item.get("asm", "")
        expected_bytes_str: str | None = item.get("expected_bytes")  # type: ignore[assignment]

        try:
            ea = parse_address(addr_str)

            # Pre-flight byte verification
            if expected_bytes_str:
                expected = bytes(
                    int(b, 16)
                    for b in expected_bytes_str.strip().split()
                )
                live = ida_bytes.get_bytes(ea, len(expected))
                if live != expected:
                    results.append({
                        "addr": addr_str,
                        "verified": False,
                        "error": (
                            f"Byte mismatch at {hex(ea)}: "
                            f"expected {expected_bytes_str.upper()}, "
                            f"found {' '.join(f'{b:02X}' for b in (live or b''))}"
                        ),
                    })
                    continue
                results_entry: PatchAsmResult = {"addr": addr_str, "verified": True}
            else:
                results_entry = {"addr": addr_str}

            assembles = instructions.split(";")
            for assemble in assembles:
                assemble = assemble.strip()
                try:
                    (check_assemble, bytes_to_patch) = idautils.Assemble(ea, assemble)
                    if not check_assemble:
                        results_entry["error"] = f"Failed to assemble: {assemble}"
                        break
                    ida_bytes.patch_bytes(ea, bytes_to_patch)
                    ea += len(bytes_to_patch)
                except Exception as e:
                    results_entry["error"] = f"Failed at {hex(ea)}: {e}"
                    break
            results.append(results_entry)
        except Exception as e:
            results.append({"addr": addr_str, **item_error(e, f"patch asm at {addr_str}")})

    return results


@tool
@idasync
def rename(
    batch: Annotated[
        RenameBatch,
        "Rename batch with func/data/local/stack fields (at least one required)",
    ],
) -> RenameResult:
    """Batch-rename funcs/globals/locals/stack vars with dry-run options."""

    stop_on_error = bool(batch.get("stop_on_error", False))
    dry_run = bool(batch.get("dry_run", False))
    allow_overwrite = bool(batch.get("allow_overwrite", False))

    def _normalize_items(items):
        if items is None:
            return []
        if isinstance(items, dict):
            return [items]
        if isinstance(items, list):
            return [item for item in items if isinstance(item, dict)]
        return []

    def _has_user_name(ea: int) -> bool:
        flags = idaapi.get_flags(ea)
        checker = getattr(idaapi, "has_user_name", None)
        if checker is not None:
            return checker(flags)
        try:
            import ida_name

            checker = getattr(ida_name, "has_user_name", None)
            if checker is not None:
                return checker(flags)
        except Exception:
            pass
        return False

    def _set_name_checked(ea: int, new_name: str) -> tuple[bool, str | None]:
        conflict_ea = idaapi.get_name_ea(idaapi.BADADDR, new_name)
        if (
            conflict_ea != idaapi.BADADDR
            and conflict_ea != ea
            and not allow_overwrite
        ):
            return False, f"Name already exists at {hex(conflict_ea)}"

        if dry_run:
            return True, None

        flags = idaapi.SN_CHECK
        if allow_overwrite:
            flags = idaapi.SN_CHECK | int(getattr(idaapi, "SN_FORCE", 0))
        ok = idaapi.set_name(ea, new_name, flags)
        if not ok:
            return False, "Rename failed"
        return True, None

    def _place_func_in_vibe_dir(ea: int) -> tuple[bool, str | None]:
        if dry_run:
            return True, None

        tree = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_FUNCS)
        if tree is None:
            return False, "Function dirtree not available"
        if not tree.load():
            return False, "Failed to load function dirtree"

        vibe_path = "/vibe/"
        if not tree.isdir(vibe_path):
            err = tree.mkdir(vibe_path)
            if err not in (ida_dirtree.DTE_OK, ida_dirtree.DTE_ALREADY_EXISTS):
                return False, f"mkdir failed: {err}"

        old_cwd = tree.getcwd()
        try:
            if tree.chdir(vibe_path) != ida_dirtree.DTE_OK:
                return False, "Failed to chdir to vibe"
            err = tree.link(ea)
            if err not in (ida_dirtree.DTE_OK, ida_dirtree.DTE_ALREADY_EXISTS):
                return False, f"link failed: {err}"
            if not tree.save():
                return False, "Failed to save function dirtree"
        finally:
            if old_cwd:
                tree.chdir(old_cwd)

        return True, None

    def _rename_funcs(items: list[FunctionRename]) -> tuple[list[dict], bool]:
        results: list[dict] = []
        halted = False
        for item in items:
            try:
                addr_text = item.get("addr") or item.get("func_addr") or item.get("func")
                new_name = item.get("name") or item.get("new") or item.get("new_name")
                if not addr_text or not new_name:
                    result = {
                        "addr": addr_text,
                        "name": new_name,
                        "error": "Function rename requires addr + name",
                    }
                    results.append(result)
                    if stop_on_error:
                        halted = True
                        break
                    continue

                ea = parse_address(addr_text)
                func = idaapi.get_func(ea)
                if not func:
                    result = {
                        "addr": addr_text,
                        "name": new_name,
                        "error": "Function not found",
                    }
                    results.append(result)
                    if stop_on_error:
                        halted = True
                        break
                    continue

                old_name = idaapi.get_name(func.start_ea) or None
                had_user_name = _has_user_name(func.start_ea)
                success, error = _set_name_checked(func.start_ea, str(new_name))

                placed, place_error = None, None
                if success and not had_user_name:
                    placed, place_error = _place_func_in_vibe_dir(func.start_ea)
                if success and not dry_run:
                    refresh_decompiler_ctext(func.start_ea)

                result = {
                    "addr": addr_text,
                    "old": old_name,
                    "name": str(new_name),
                }
                if error:
                    result["error"] = error
                if success and placed:
                    result["dir"] = "vibe"
                if place_error and success:
                    result["dir_error"] = place_error
                if dry_run:
                    result["dry_run"] = True
                results.append(result)
                if not success and stop_on_error:
                    halted = True
                    break
            except Exception as e:
                results.append({"addr": item.get("addr"), **item_error(e, "rename function")})
                if stop_on_error:
                    halted = True
                    break
        return results, halted

    def _rename_globals(items: list[GlobalRename]) -> tuple[list[dict], bool]:
        results: list[dict] = []
        halted = False
        for item in items:
            try:
                addr_text = item.get("addr")
                old_name = item.get("old") or item.get("old_name")
                new_name = item.get("new") or item.get("new_name")

                # Backward-compatible forms:
                # 1) {addr, name} => rename by address
                # 2) {name, new_name} => old=name, new=new_name
                if new_name is None and addr_text is not None and item.get("name"):
                    new_name = item.get("name")
                if old_name is None and new_name is not None and item.get("name") and not addr_text:
                    old_name = item.get("name")

                if not new_name:
                    result = {
                        "old": old_name,
                        "new": None,
                        "error": "Global rename requires target and new name",
                    }
                    results.append(result)
                    if stop_on_error:
                        halted = True
                        break
                    continue

                ea = idaapi.BADADDR
                if addr_text:
                    ea = parse_address(str(addr_text))
                    old_name = old_name or (idaapi.get_name(ea) or None)
                elif old_name:
                    ea = idaapi.get_name_ea(idaapi.BADADDR, str(old_name))

                if ea == idaapi.BADADDR:
                    result = {
                        "old": old_name,
                        "new": str(new_name),
                        "error": f"Global '{old_name}' not found",
                    }
                    results.append(result)
                    if stop_on_error:
                        halted = True
                        break
                    continue

                success, error = _set_name_checked(ea, str(new_name))
                result = {
                    "addr": hex(ea),
                    "old": old_name,
                    "new": str(new_name),
                }
                if error:
                    result["error"] = error
                if dry_run:
                    result["dry_run"] = True
                results.append(result)
                if not success and stop_on_error:
                    halted = True
                    break
            except Exception as e:
                results.append({"old": item.get("old"), **item_error(e, "rename global")})
                if stop_on_error:
                    halted = True
                    break
        return results, halted

    def _rename_locals(items: list[LocalRename]) -> tuple[list[dict], bool]:
        results: list[dict] = []
        halted = False
        for item in items:
            try:
                func_addr = item.get("func_addr") or item.get("func")
                old_name = item.get("old") or item.get("name")
                new_name = item.get("new") or item.get("new_name")
                if not func_addr or not old_name or not new_name:
                    result = {
                        "func_addr": func_addr,
                        "old": old_name,
                        "new": new_name,
                        "error": "Local rename requires func_addr + old + new",
                    }
                    results.append(result)
                    if stop_on_error:
                        halted = True
                        break
                    continue

                func = idaapi.get_func(parse_address(func_addr))
                if not func:
                    result = {
                        "func_addr": func_addr,
                        "old": old_name,
                        "new": new_name,
                        "error": "No function found",
                    }
                    results.append(result)
                    if stop_on_error:
                        halted = True
                        break
                    continue

                success = True
                error = None
                if not dry_run:
                    success = ida_hexrays.rename_lvar(func.start_ea, old_name, new_name)
                    if success:
                        refresh_decompiler_ctext(func.start_ea)
                if not success:
                    error = "Rename failed"

                result = {
                    "func_addr": func_addr,
                    "old": old_name,
                    "new": new_name,
                }
                if error:
                    result["error"] = error
                if dry_run:
                    result["dry_run"] = True
                results.append(result)
                if not success and stop_on_error:
                    halted = True
                    break
            except Exception as e:
                results.append({"func_addr": item.get("func_addr"), **item_error(e, "rename local var")})
                if stop_on_error:
                    halted = True
                    break
        return results, halted

    def _rename_stack(items: list[StackRename]) -> tuple[list[dict], bool]:
        results: list[dict] = []
        halted = False
        for item in items:
            try:
                func_addr = item.get("func_addr") or item.get("func")
                old_name = item.get("old") or item.get("name")
                new_name = item.get("new") or item.get("new_name")
                if not func_addr or not old_name or not new_name:
                    result = {
                        "func_addr": func_addr,
                        "old": old_name,
                        "new": new_name,
                        "error": "Stack rename requires func_addr + old + new",
                    }
                    results.append(result)
                    if stop_on_error:
                        halted = True
                        break
                    continue

                func = idaapi.get_func(parse_address(func_addr))
                if not func:
                    result = {
                        "func_addr": func_addr,
                        "old": old_name,
                        "new": new_name,
                        "error": "No function found",
                    }
                    results.append(result)
                    if stop_on_error:
                        halted = True
                        break
                    continue

                frame_tif = ida_typeinf.tinfo_t()
                if not ida_frame.get_func_frame(frame_tif, func):
                    result = {
                        "func_addr": func_addr,
                        "old": old_name,
                        "new": new_name,
                        "error": "No frame",
                    }
                    results.append(result)
                    if stop_on_error:
                        halted = True
                        break
                    continue

                idx, udm = tinfo_get_udm(frame_tif, old_name)
                if not udm:
                    result = {
                        "func_addr": func_addr,
                        "old": old_name,
                        "new": new_name,
                        "error": f"'{old_name}' not found",
                    }
                    results.append(result)
                    if stop_on_error:
                        halted = True
                        break
                    continue

                tid = frame_tif.get_udm_tid(idx)
                if ida_frame.is_special_frame_member(tid):
                    result = {
                        "func_addr": func_addr,
                        "old": old_name,
                        "new": new_name,
                        "error": "Special frame member",
                    }
                    results.append(result)
                    if stop_on_error:
                        halted = True
                        break
                    continue

                udm = ida_typeinf.udm_t()
                frame_tif.get_udm_by_tid(udm, tid)
                offset = udm.offset // 8
                if ida_frame.is_funcarg_off(func, offset):
                    result = {
                        "func_addr": func_addr,
                        "old": old_name,
                        "new": new_name,
                        "error": "Argument member",
                    }
                    results.append(result)
                    if stop_on_error:
                        halted = True
                        break
                    continue

                success = True
                error = None
                if not dry_run:
                    sval = ida_frame.soff_to_fpoff(func, offset)
                    success = ida_frame.define_stkvar(func, new_name, sval, udm.type)
                if not success:
                    error = "Rename failed"

                result = {
                    "func_addr": func_addr,
                    "old": old_name,
                    "new": new_name,
                }
                if error:
                    result["error"] = error
                if dry_run:
                    result["dry_run"] = True
                results.append(result)
                if not success and stop_on_error:
                    halted = True
                    break
            except Exception as e:
                results.append({"func_addr": item.get("func_addr"), **item_error(e, "rename stack var")})
                if stop_on_error:
                    halted = True
                    break
        return results, halted
    data_items = []
    data_items.extend(_normalize_items(batch.get("data")))
    data_items.extend(_normalize_items(batch.get("global")))
    data_items.extend(_normalize_items(batch.get("globals")))

    requested = {
        "func": "func" in batch,
        "data": any(key in batch for key in ("data", "global", "globals")),
        "local": "local" in batch,
        "stack": "stack" in batch,
        "global_alias": any(key in batch for key in ("global", "globals")),
    }

    result: dict = {}
    stopped = False
    stopped_at = None

    if requested["func"]:
        result["func"], halted = _rename_funcs(_normalize_items(batch.get("func")))
        if halted:
            stopped = True
            stopped_at = "func"

    if requested["data"] and not stopped:
        result["data"], halted = _rename_globals(data_items)
        if requested["global_alias"]:
            result["global"] = list(result["data"])
        if halted:
            stopped = True
            stopped_at = "data"

    if requested["local"] and not stopped:
        result["local"], halted = _rename_locals(_normalize_items(batch.get("local")))
        if halted:
            stopped = True
            stopped_at = "local"

    if requested["stack"] and not stopped:
        result["stack"], halted = _rename_stack(_normalize_items(batch.get("stack")))
        if halted:
            stopped = True
            stopped_at = "stack"

    total = 0
    ok = 0
    failed = 0
    for key in ("func", "data", "local", "stack"):
        for item in result.get(key, []):
            total += 1
            if "error" not in item:
                ok += 1
            else:
                failed += 1

    summary: dict = {
        "total": total,
        "ok": ok,
        "failed": failed,
        "stopped": stopped,
    }
    if dry_run:
        summary["dry_run"] = True
    if allow_overwrite:
        summary["allow_overwrite"] = True
    if stop_on_error:
        summary["stop_on_error"] = True
    if stopped:
        summary["stopped_at"] = stopped_at
    result["summary"] = summary
    return result


def _diagnose_add_func_failure(start_ea: int, end_ea: int) -> str:
    """Build a human-readable hint explaining why add_func failed."""
    parts: list[str] = []
    seg = idaapi.getseg(start_ea)
    if seg is None:
        return "address is not in any known segment"
    seg_name = idaapi.get_segm_name(seg) or "?"
    if seg.type == idaapi.SEG_DATA:
        parts.append(f"segment '{seg_name}' is typed as DATA")
    elif seg.type == idaapi.SEG_BSS:
        parts.append(f"segment '{seg_name}' is typed as BSS")
    flags = idc.get_full_flags(start_ea)
    if idc.is_unknown(flags):
        parts.append("bytes are undefined (try force=True to run analysis first)")
    elif idc.is_data(flags):
        parts.append("bytes are currently typed as data (try force=True with del_items=True)")
    overlap = idaapi.get_func(start_ea)
    if overlap:
        parts.append(
            f"overlaps existing function {hex(overlap.start_ea)}–{hex(overlap.end_ea)}"
        )
    if not parts:
        parts.append("IDA declined to create the function (bounds may be ambiguous; supply end=)")
    return "; ".join(parts)


@tool
@idasync
def define_func(items: list[DefineOp] | DefineOp) -> list[DefineResult]:
    """Define functions at one or more addresses.

    IDA infers bounds unless ``end`` is supplied. If the function already
    exists at the start address the call succeeds (``existed: true``).

    **force=true** — runs ``ida_auto.plan_and_wait(start, end)`` before
    ``add_func``, forcing IDA to analyse and disassemble the range first.
    This is essential for encrypted or unanalysed regions where ``add_func``
    would otherwise silently fail.

    **del_items=true** (requires ``force=true``) — clears existing
    code/data definitions before re-analysis via ``ida_bytes.del_items``.
    Use this when IDA previously misidentified bytes as data.
    """
    if isinstance(items, dict):
        items = [items]

    results = []
    for item in items:
        addr_str = item.get("addr", "")
        end_str = item.get("end", "")
        force = bool(item.get("force", False))
        do_del = bool(item.get("del_items", False)) and force

        try:
            start_ea = parse_address(addr_str)
            end_ea = parse_address(end_str) if end_str else idaapi.BADADDR

            # Already a function → success, no-op
            existing = idaapi.get_func(start_ea)
            if existing and existing.start_ea == start_ea:
                results.append(
                    {
                        "addr": addr_str,
                        "start": hex(existing.start_ea),
                        "end": hex(existing.end_ea),
                        "existed": True,
                    }
                )
                continue

            if force:
                plan_end = end_ea if end_ea != idaapi.BADADDR else start_ea + 0x200
                if do_del:
                    ida_bytes.del_items(start_ea, 0, plan_end - start_ea)
                ida_auto.plan_and_wait(start_ea, plan_end)

            success = ida_funcs.add_func(start_ea, end_ea)
            if success:
                func = idaapi.get_func(start_ea)
                results.append(
                    {
                        "addr": addr_str,
                        "start": hex(func.start_ea),
                        "end": hex(func.end_ea),
                    }
                )
            else:
                hint = _diagnose_add_func_failure(start_ea, end_ea)
                results.append(
                    {
                        "addr": addr_str,
                        "start": hex(start_ea),
                        "error": "define_func failed",
                        "hint": hint,
                    }
                )
        except Exception as e:
            results.append({"addr": addr_str, **item_error(e, f"define function at {addr_str}")})

    return results


@tool
@idasync
def analyze_range(
    start: Annotated[str, "Start address of range to force-analyse"],
    end: Annotated[str, "End address (exclusive) of range to force-analyse"],
) -> dict:
    """Force IDA to analyse an address range and rebuild the xref database for it.

    Calls ``ida_auto.plan_and_wait(start, end)``, which processes all queued
    analysis requests for the range: it disassembles bytes, creates xrefs, and
    defines data items. After this call, ``xrefs_to`` / ``xrefs_from`` will
    return results for code that lives in the range.

    This is useful for encrypted or packed sections that IDA skipped during
    the initial auto-analysis pass. Note that the bytes must already be
    decrypted in the IDA database (via patching or a custom loader) before
    this tool can produce correct results.
    """
    try:
        start_ea = parse_address(start)
        end_ea = parse_address(end)
        if end_ea <= start_ea:
            return {"ok": False, "error": "end must be greater than start", "error_type": "invalid_input"}
        ida_auto.plan_and_wait(start_ea, end_ea)
        func_count = sum(1 for _ in idautils.Functions(start_ea, end_ea))
        return {
            "ok": True,
            "start": hex(start_ea),
            "end": hex(end_ea),
            "size": end_ea - start_ea,
            "functions_in_range": func_count,
            "note": "Analysis complete. xrefs_to / xrefs_from should now reflect this range.",
        }
    except Exception as e:
        return tool_error(e, "analyze_range")


@tool
@idasync
def scan_and_define_funcs(
    start: Annotated[str, "Start address of range to scan"],
    end: Annotated[str, "End address (exclusive) of range to scan"],
    force: Annotated[
        bool,
        "Run plan_and_wait on the range before scanning (needed for unanalysed regions)",
    ] = True,
    del_items: Annotated[
        bool,
        "Clear existing definitions before analysis (use with force=True when IDA "
        "previously misidentified bytes as data)",
    ] = False,
) -> dict:
    """Scan an address range, force IDA analysis, and define all functions found.

    Workflow:
    1. Optionally clear existing definitions (``del_items=true``).
    2. Run ``plan_and_wait`` to disassemble the range (``force=true``).
    3. Walk every code head not already inside a function and call ``add_func``.
    4. Return a summary of created and failed function definitions.

    Ideal for encrypted/obfuscated sections that have been decrypted in-place
    and need batch function recovery without manual IDA interaction.
    """
    try:
        start_ea = parse_address(start)
        end_ea = parse_address(end)
        if end_ea <= start_ea:
            return {"ok": False, "error": "end must be greater than start", "error_type": "invalid_input"}

        if force:
            if del_items:
                ida_bytes.del_items(start_ea, 0, end_ea - start_ea)
            ida_auto.plan_and_wait(start_ea, end_ea)

        created: list[dict] = []
        failed: list[str] = []

        ea = start_ea
        while ea < end_ea and ea != idaapi.BADADDR:
            fn = idaapi.get_func(ea)
            if fn:
                # Skip to end of existing function
                ea = fn.end_ea
                continue
            flags = idc.get_full_flags(ea)
            if idc.is_code(flags):
                ok = ida_funcs.add_func(ea)
                if ok:
                    fn2 = idaapi.get_func(ea)
                    if fn2:
                        created.append({"start": hex(fn2.start_ea), "end": hex(fn2.end_ea)})
                        ea = fn2.end_ea
                        continue
                    else:
                        created.append({"start": hex(ea), "end": None})
                else:
                    failed.append(hex(ea))
            next_ea = idc.next_head(ea, end_ea)
            if next_ea == idaapi.BADADDR or next_ea <= ea:
                break
            ea = next_ea

        return {
            "ok": True,
            "start": hex(start_ea),
            "end": hex(end_ea),
            "created_count": len(created),
            "failed_count": len(failed),
            "created": created,
            "failed": failed,
        }
    except Exception as e:
        return tool_error(e, "scan_and_define_funcs")


@unsafe
@tool
@idasync
def add_xref(
    items: Annotated[
        list[dict] | dict,
        "List of {from, to, type} dicts. type: 'call' (default), 'jump', 'call_far', "
        "'jump_far', 'data_read', 'data_write'",
    ],
) -> list[XrefItem]:
    """Manually add cross-references between addresses.

    Use when IDA has not detected a call/jump relationship, e.g. when the
    caller lives in encrypted or undefined code that IDA has not analysed.
    All xrefs are tagged ``XREF_USER`` so they survive IDA reanalysis.

    After adding xrefs, ``xrefs_to(target)`` will return these entries.
    """
    if isinstance(items, dict):
        items = [items]

    results: list[XrefItem] = []
    for item in items:
        frm_str = str(item.get("from", "") or item.get("frm", ""))
        to_str = str(item.get("to", ""))
        xref_type = str(item.get("type", "call")).lower().replace("-", "_")

        try:
            frm_ea = parse_address(frm_str)
            to_ea = parse_address(to_str)

            if xref_type in ("call", "call_near"):
                ok = ida_xref.add_cref(frm_ea, to_ea, ida_xref.fl_CN | ida_xref.XREF_USER)
            elif xref_type in ("jump", "jump_near"):
                ok = ida_xref.add_cref(frm_ea, to_ea, ida_xref.fl_JN | ida_xref.XREF_USER)
            elif xref_type == "call_far":
                ok = ida_xref.add_cref(frm_ea, to_ea, ida_xref.fl_CF | ida_xref.XREF_USER)
            elif xref_type == "jump_far":
                ok = ida_xref.add_cref(frm_ea, to_ea, ida_xref.fl_JF | ida_xref.XREF_USER)
            elif xref_type == "data_write":
                ok = ida_xref.add_dref(frm_ea, to_ea, ida_xref.dr_W | ida_xref.XREF_USER)
            else:
                # data_read and anything unrecognised
                ok = ida_xref.add_dref(frm_ea, to_ea, ida_xref.dr_R | ida_xref.XREF_USER)

            results.append({"frm": hex(frm_ea), "to": hex(to_ea), "type": xref_type, "ok": ok})
        except Exception as e:
            results.append({"frm": frm_str, "to": to_str, **item_error(e, f"add_xref {frm_str}->{to_str}")})  # type: ignore[arg-type]

    return results


@tool
@idasync
def define_code(items: list[DefineOp] | DefineOp) -> list[DefineResult]:
    """Convert bytes to code instruction(s) at address(es)."""
    if isinstance(items, dict):
        items = [items]

    results = []
    for item in items:
        addr_str = item.get("addr", "")

        try:
            ea = parse_address(addr_str)
            length = ida_ua.create_insn(ea)
            if length > 0:
                results.append(
                    {"addr": addr_str, "ea": hex(ea), "length": length}
                )
            else:
                results.append(
                    {
                        "addr": addr_str,
                        "ea": hex(ea),
                        "error": "Failed to create instruction",
                    }
                )
        except Exception as e:
            results.append({"addr": addr_str, **item_error(e, f"create instruction at {addr_str}")})

    return results


@tool
@idasync
def undefine(items: list[UndefineOp] | UndefineOp) -> list[DefineResult]:
    """Undefine item(s) at address(es), converting back to raw bytes."""
    if isinstance(items, dict):
        items = [items]

    results = []
    for item in items:
        addr_str = item.get("addr", "")
        end_str = item.get("end", "")
        size = item.get("size", 0)

        try:
            start_ea = parse_address(addr_str)

            # Determine size from end address or explicit size
            if end_str:
                end_ea = parse_address(end_str)
                nbytes = end_ea - start_ea
            elif size:
                nbytes = size
            else:
                # Default: undefine single item
                nbytes = 1

            success = ida_bytes.del_items(start_ea, ida_bytes.DELIT_EXPAND, nbytes)
            if success:
                results.append(
                    {
                        "addr": addr_str,
                        "start": hex(start_ea),
                        "size": nbytes,
                    }
                )
            else:
                results.append(
                    {
                        "addr": addr_str,
                        "start": hex(start_ea),
                        "error": "undefine failed",
                    }
                )
        except Exception as e:
            results.append({"addr": addr_str, **item_error(e, f"undefine at {addr_str}")})

    return results


# ============================================================================
# Xref creation
# ============================================================================


class AddXrefResult(TypedDict, total=False):
    ok: bool
    from_addr: str
    to_addr: str
    xref_type: str
    error: str


_CODE_XREF_TYPES = {
    "call_near":  ida_xref.fl_CN,
    "call_far":   ida_xref.fl_CF,
    "jump_near":  ida_xref.fl_JN,
    "jump_far":   ida_xref.fl_JF,
    "flow":       ida_xref.fl_F,
}
_DATA_XREF_TYPES = {
    "data_offset": ida_xref.dr_O,
    "data_read":   ida_xref.dr_R,
    "data_write":  ida_xref.dr_W,
}


@unsafe
@tool
@idasync
def add_xref(
    from_addr: Annotated[str, "Source address of the cross-reference"],
    to_addr: Annotated[str, "Target address of the cross-reference"],
    xref_type: Annotated[
        str,
        "Reference type. Code: 'call_near', 'call_far', 'jump_near', 'jump_far', 'flow'. "
        "Data: 'data_offset', 'data_read', 'data_write'. Default: 'call_near'.",
    ] = "call_near",
) -> AddXrefResult:
    """Add a user-defined cross-reference between two addresses.

    User xrefs (XREF_USER flag) persist across IDA reanalysis unlike
    auto-generated ones. Incorrect xrefs corrupt analysis — use with care.
    """
    try:
        frm = parse_address(from_addr)
        to  = parse_address(to_addr)
        xtype = xref_type.lower().strip()

        if xtype in _CODE_XREF_TYPES:
            ok = ida_xref.add_cref(frm, to, _CODE_XREF_TYPES[xtype] | ida_xref.XREF_USER)
        elif xtype in _DATA_XREF_TYPES:
            ok = ida_xref.add_dref(frm, to, _DATA_XREF_TYPES[xtype] | ida_xref.XREF_USER)
        else:
            valid = list(_CODE_XREF_TYPES) + list(_DATA_XREF_TYPES)
            return {"ok": False, "error": f"Unknown xref_type '{xref_type}'. Valid: {valid}"}

        if not ok:
            return {
                "ok": False,
                "from_addr": from_addr,
                "to_addr": to_addr,
                "error": "IDA rejected the xref (addresses may be invalid or xref already exists)",
            }

        return {"ok": True, "from_addr": hex(frm), "to_addr": hex(to), "xref_type": xtype}

    except Exception as e:
        return tool_error(e, "add_xref")


# ============================================================================
# Type removal
# ============================================================================


class RemoveTypeResult(TypedDict, total=False):
    ok: bool
    addr: str
    error: str


@tool
@idasync
def remove_type(
    addr: Annotated[str, "Address to remove type information from"],
) -> RemoveTypeResult:
    """Remove the type annotation applied to an address or function.

    Clears the stored tinfo_t so IDA reverts to auto-inferred type.
    Useful after applying an incorrect type via set_type or the decompiler.
    Also invalidates the Hex-Rays decompiler cache for the owning function.
    """
    try:
        ea = parse_address(addr)
        ida_nalt.del_tinfo(ea)
        try:
            if ida_hexrays.init_hexrays_plugin():
                ida_hexrays.clear_cached_cfuncs()
        except Exception:
            pass
        return {"ok": True, "addr": hex(ea)}
    except Exception as e:
        return {**tool_error(e, f"remove_type at {addr}"), "addr": addr}
