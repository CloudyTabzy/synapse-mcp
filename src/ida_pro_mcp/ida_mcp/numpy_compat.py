"""Shared NumPy availability guard and entropy primitive.

NumPy is an optional accelerator. Centralizing the import here gives a single
source of truth for ``NUMPY_AVAILABLE`` so that any module which wants a
vectorized fast-path (api_numpy today, possibly others later) shares one guard
and one canonical entropy implementation rather than each re-deriving it and
drifting apart.

Consumers MUST degrade gracefully when ``NUMPY_AVAILABLE`` is False — this
module never raises on import even when numpy is missing.
"""

try:
    import numpy as np  # type: ignore
    NUMPY_AVAILABLE = True
    NUMPY_VERSION = getattr(np, "__version__", "unknown")
except Exception:  # ImportError, or a rare native-load failure
    np = None  # type: ignore[assignment]
    NUMPY_AVAILABLE = False
    NUMPY_VERSION = ""


def np_entropy(data) -> float:
    """Shannon entropy in bits/byte (0.0–8.0) of a bytes-like buffer.

    Vectorized via ``np.bincount`` + ``np.log2`` — for multi-megabyte buffers
    this is ~10–50× faster than a pure-Python frequency loop. Returns 0.0 for
    empty input.

    Caller must ensure ``NUMPY_AVAILABLE`` is True before calling.
    """
    if not data:
        return 0.0
    arr = np.frombuffer(data, dtype=np.uint8)
    counts = np.bincount(arr, minlength=256).astype(np.float64)
    n = arr.size
    nz = counts[counts > 0]
    p = nz / n
    return float(-np.sum(p * np.log2(p)))
