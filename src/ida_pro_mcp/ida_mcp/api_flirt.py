"""FLIRT signature and type library tools for IDA Pro MCP.

FLIRT (Fast Library Identification and Recognition Technology) signatures allow
IDA to automatically identify library functions in stripped binaries.

Type libraries (.til) provide rich struct/enum/prototype definitions for system
APIs, enriching decompiler output with named types instead of raw integers.
"""

import logging
import os
from typing import Annotated, NotRequired, TypedDict

import ida_auto
import ida_funcs
import ida_typeinf
import idautils

from .rpc import tool
from .sync import idasync

logger = logging.getLogger(__name__)


# ============================================================================
# Result types
# ============================================================================


class ApplyFlirtResult(TypedDict, total=False):
    ok: bool
    signature_name: str
    sig_count: int
    lib_functions_before: int
    lib_functions_after: int
    new_lib_functions: int
    error: str


class LoadTilResult(TypedDict, total=False):
    ok: bool
    name: str
    description: str
    error: str


class TilInfo(TypedDict, total=False):
    name: str
    description: str


class ListTilResult(TypedDict, total=False):
    ok: bool
    libraries: list[TilInfo]
    count: int
    error: str


# ============================================================================
# Internal helpers
# ============================================================================


def _count_lib_funcs() -> int:
    """Count functions currently marked as library functions."""
    count = 0
    for ea in idautils.Functions():
        f = ida_funcs.get_func(ea)
        if f and (f.flags & ida_funcs.FUNC_LIB):
            count += 1
    return count


def _resolve_sig_name(raw: str) -> tuple[str, str | None]:
    """Return (bare_name, error_or_None).

    Accepts:
    - A bare name like 'vc32rtf' or 'vc32rtf.sig' — IDA looks in its sig/ dir.
    - A full absolute path to a .sig file — we extract the basename.

    Returns the name without extension that plan_to_apply_idasgn expects.
    """
    raw = raw.strip()
    if not raw:
        return "", "Signature name must not be empty"

    # Detect full path: contains a directory separator
    if os.sep in raw or (os.altsep and os.altsep in raw) or raw.startswith("/"):
        if not os.path.isfile(raw):
            return "", f"File not found: {raw}"
        return os.path.splitext(os.path.basename(raw))[0], None

    # Bare name: just strip the extension if present
    return os.path.splitext(raw)[0], None


# ============================================================================
# Tools
# ============================================================================


@tool
@idasync
def apply_flirt_signature(
    sig_name: Annotated[
        str,
        "Signature name without extension searched in IDA's sig/ directory "
        "(e.g. 'vc32rtf'), or full path to a .sig file on disk.",
    ],
) -> ApplyFlirtResult:
    """Apply a FLIRT signature file to identify library functions in the current IDB.

    IDA looks up bare names (no extension) in its own sig/ directory.
    Pass a full path when the .sig file lives outside IDA's installation.
    After scheduling the signature, IDA's auto-analysis runs to completion
    before the tool returns, so new_lib_functions reflects the actual delta.

    Note: .pat (pattern) files must first be compiled to .sig using the
    sigmake tool before they can be applied here.
    """
    try:
        fname, err = _resolve_sig_name(sig_name)
        if err:
            return {"ok": False, "error": err}

        before = _count_lib_funcs()

        sig_count = ida_funcs.plan_to_apply_idasgn(fname)
        if sig_count <= 0:
            return {
                "ok": False,
                "error": (
                    f"Failed to load signature '{fname}' "
                    f"(plan_to_apply_idasgn returned {sig_count}). "
                    "Ensure the .sig file exists in IDA's sig/ directory."
                ),
            }

        # Wait for IDA's auto-analysis to process the newly scheduled sigs.
        ida_auto.auto_wait()

        after = _count_lib_funcs()
        return {
            "ok": True,
            "signature_name": fname,
            "sig_count": sig_count,
            "lib_functions_before": before,
            "lib_functions_after": after,
            "new_lib_functions": after - before,
        }

    except Exception as e:
        logger.exception("apply_flirt_signature failed")
        return {"ok": False, "error": str(e)}


@tool
@idasync
def load_type_library(
    name: Annotated[
        str,
        "Type library name without extension searched in IDA's til/ directory "
        "(e.g. 'mssdk64_win10'), or full path to a .til file.",
    ],
) -> LoadTilResult:
    """Load a type library (.til) into the current IDB.

    Type libraries provide struct/enum/prototype definitions for system APIs.
    Loading one enriches decompiler output with proper named types (HANDLE,
    LPCWSTR, etc.) instead of raw integers.

    IDA searches its own til/ directory for bare names. Supply a full path
    when the file is outside IDA's installation.

    Return codes from IDA:
    - ADDTIL_OK (1): successfully added.
    - ADDTIL_COMP (2): already loaded as a dependency of another library.
    - ADDTIL_FAILED (0): not found or incompatible.
    """
    try:
        raw = name.strip()
        if not raw:
            return {"ok": False, "error": "Name must not be empty"}

        if os.sep in raw or (os.altsep and os.altsep in raw) or raw.startswith("/"):
            if not os.path.isfile(raw):
                return {"ok": False, "error": f"File not found: {raw}"}
            til_name = os.path.splitext(os.path.basename(raw))[0]
        else:
            til_name = os.path.splitext(raw)[0]

        # ADDTIL_FAILED=0, ADDTIL_OK=1, ADDTIL_COMP=2
        rc = ida_typeinf.add_til(til_name, 0)
        if rc == 0:
            return {
                "ok": False,
                "error": (
                    f"Failed to load type library '{til_name}'. "
                    "Ensure it exists in IDA's til/ directory and is compatible with the current architecture."
                ),
            }

        # Retrieve the description from the newly loaded TIL if available.
        description = ""
        try:
            # get_idati() returns the local IDB type library; walk its bases
            # to find the one we just loaded by name.
            til = ida_typeinf.get_idati()
            if til is not None:
                queue = [til]
                seen: set[int] = set()
                while queue:
                    t = queue.pop(0)
                    if id(t) in seen:
                        continue
                    seen.add(id(t))
                    if (t.name or "").lower() == til_name.lower():
                        description = t.desc or ""
                        break
                    for i in range(t.nbases):
                        dep = t.base(i)
                        if dep is not None:
                            queue.append(dep)
        except Exception:
            pass

        already = rc == 2  # ADDTIL_COMP
        return {
            "ok": True,
            "name": til_name,
            "description": description,
            **({"note": "Already loaded as a dependency"} if already else {}),
        }

    except Exception as e:
        logger.exception("load_type_library failed")
        return {"ok": False, "error": str(e)}


@tool
@idasync
def list_type_libraries() -> ListTilResult:
    """List all type libraries currently active in the IDB.

    Returns the name and description of every TIL loaded into the current
    database, including transitive dependencies. Use load_type_library to
    add more.
    """
    try:
        til = ida_typeinf.get_idati()
        if til is None:
            return {"ok": True, "libraries": [], "count": 0}

        libs: list[TilInfo] = []
        seen: set[int] = set()
        queue = [til]

        while queue:
            t = queue.pop(0)
            if id(t) in seen:
                continue
            seen.add(id(t))
            libs.append({"name": t.name or "", "description": t.desc or ""})
            for i in range(t.nbases):
                dep = t.base(i)
                if dep is not None:
                    queue.append(dep)

        return {"ok": True, "libraries": libs, "count": len(libs)}

    except Exception as e:
        logger.exception("list_type_libraries failed")
        return {"ok": False, "error": str(e)}
