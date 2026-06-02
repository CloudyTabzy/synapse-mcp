"""Optional TOON tabular encoding for large uniform-array tool responses.

When ``toon_format`` is installed in the SAME interpreter that serializes the
tool response, results containing a uniform flat array are re-encoded into
TOON's compact tabular form, cutting agent context tokens by ~40-65%.

Where this runs matters:
- Direct HTTP transport (client → IDA plugin on :13337): the IDA plugin's
  zeromcp server serializes the result, so ``toon_format`` must live in IDA's
  embedded Python.
- stdio proxy (client → ``synapse-mcp`` → IDA): ``server.py`` post-processes the
  proxied response, so ``toon_format`` must live in the server's Python.

Both paths import this module and fall back to plain JSON silently whenever
``toon_format`` is absent or the response doesn't qualify.

Schema compatibility
--------------------
Every tool advertises an ``outputSchema`` (derived from its TypedDict return
type). The MCP spec requires that such tools always return ``structuredContent``.

TOON and schema are made compatible by shipping *both*:
- ``content[0].text`` = TOON string  (compact representation the model reads)
- ``structuredContent`` = original dict  (schema validation; never dropped)

The model's context window receives ``content``, so it sees the compact TOON
form and saves tokens.  The client framework validates against ``structuredContent``
and never raises ``-32600``.  Neither breaks the other.

TOON output format example (self-documenting):
    _format: TOON_TABULAR
    ok: true
    data[100]{addr,name,size,is_thunk,is_library}:
      0x401000,sub_401000,0x6,false,false
      0x401010,sub_401010,0x6,false,false
    total: 600
"""
from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

try:
    from toon_format import encode as _toon_encode
    TOON_AVAILABLE = True
    logger.debug("toon_format loaded — TOON response compression active")
except ImportError:
    TOON_AVAILABLE = False
    logger.debug("toon_format not found — responses will be plain JSON")

# TOON is enabled by default when toon_format is installed.
# Override with SYNAPSE_MCP_TOON=0 / false / no / off to disable.
TOON_ENABLED = os.environ.get("SYNAPSE_MCP_TOON", "1").strip().lower() not in (
    "0", "false", "no", "off",
)

# Minimum qualifying array length.  Below this the per-row savings don't
# outweigh the header overhead.  At 20+ rows savings are consistently ~40-65%.
TOON_MIN_ROWS = 20

_PRIMITIVE = (str, int, float, bool, type(None))


def _is_uniform_flat_array(lst: list) -> bool:
    """True when every item is a dict with identical keys and all-primitive values."""
    if not lst or not isinstance(lst[0], dict):
        return False
    first_keys = set(lst[0].keys())
    if not first_keys:
        return False
    for item in lst:
        if not isinstance(item, dict):
            return False
        if set(item.keys()) != first_keys:
            return False
        if not all(isinstance(v, _PRIMITIVE) for v in item.values()):
            return False
    return True


def toon_qualifies(data: Any) -> bool:
    """True when ``data`` is a dict holding at least one qualifying uniform flat array."""
    if not isinstance(data, dict):
        return False
    for v in data.values():
        if isinstance(v, list) and len(v) >= TOON_MIN_ROWS and _is_uniform_flat_array(v):
            return True
    return False


def encode_result_to_toon(data: dict) -> str:
    """Encode a qualifying result dict to a TOON string.

    Prepends ``_format: TOON_TABULAR`` so agents immediately know the encoding.
    Arrays are written as ``key[N]{field1,field2,...}:`` followed by CSV rows.
    """
    annotated = {"_format": "TOON_TABULAR", **data}
    return _toon_encode(annotated)


def maybe_toon_encode_result(data: Any) -> str | None:
    """Return a TOON string when ``data`` qualifies and TOON is available, else None.

    Callers MUST keep ``structuredContent`` intact alongside the returned TOON
    string in the MCP response — never drop it.  This ensures schema-enforcing
    clients (MCP spec: tools with outputSchema must return structuredContent)
    never see a ``-32600`` error, while the model still receives the compact TOON
    text via ``content[0].text``.

    Tools can opt out by including ``"_toon_skip": True`` in their result dict.
    The marker is always consumed (popped) here so it never leaks into the
    agent-visible structured response, regardless of whether TOON fires.
    """
    # Always consume the opt-out marker so it cannot leak into structuredContent.
    skip = bool(isinstance(data, dict) and data.pop("_toon_skip", False))
    if not TOON_ENABLED or not TOON_AVAILABLE:
        return None
    if skip:
        return None
    if not toon_qualifies(data):
        return None
    try:
        encoded = encode_result_to_toon(data)
        logger.debug("TOON: compressed response to %d chars", len(encoded))
        return encoded
    except Exception as exc:
        logger.warning("TOON encode failed: %s", exc)
        return None
