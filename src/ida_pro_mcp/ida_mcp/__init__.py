"""IDA Pro MCP Plugin - Modular Package Version

This package provides MCP (Model Context Protocol) integration for IDA Pro,
enabling AI assistants to interact with IDA's disassembler and decompiler.

Architecture:
- rpc.py: JSON-RPC infrastructure and registry
- mcp.py: MCP protocol server (HTTP/SSE)
- sync.py: IDA synchronization decorator (@idasync)
- utils.py: Shared helpers and TypedDict definitions
- api_*.py: Modular API implementations
- api_flirt.py: FLIRT signature and type library tools
- api_triton.py: Triton symbolic execution tools (optional, requires triton-library)
- api_miasm.py: Miasm IR analysis tools (optional, requires miasm)
"""

# Ignore SIGPIPE to prevent IDA from being killed when an MCP client
# disconnects while the HTTP server is writing a response. IDA's embedded
# Python may not preserve CPython's default SIG_IGN for SIGPIPE.
import logging as _logging
import signal
import traceback as _traceback

if hasattr(signal, "SIGPIPE"):
    signal.signal(signal.SIGPIPE, signal.SIG_IGN)

_log = _logging.getLogger(__name__)

# Import infrastructure modules
from . import rpc
from . import sync
from . import utils

# Import all API modules to register @tool functions and @resource functions
from . import api_core
from . import api_analysis
from . import api_memory
from . import api_types
from . import api_modify
from . import api_stack
from . import api_debug
from . import api_python
from . import api_resources
from . import api_survey
from . import api_composite
from . import api_discovery
from . import trace as trace
from . import api_sigmaker
from . import api_flirt
from . import api_recon
from . import api_tasks

# Optional analysis engine modules — load only when dependencies are present.
# ImportError / AttributeError from missing packages is silently swallowed so
# the plugin remains fully operational without them.
try:
    from . import api_triton
except Exception as _e:
    _log.warning(
        "api_triton failed to load (%s: %s) — all triton_* tools unavailable. "
        "Install with: pip install triton-library\n%s",
        type(_e).__name__, _e, _traceback.format_exc(),
    )
    api_triton = None  # type: ignore[assignment]

try:
    from . import api_miasm
except Exception as _e:
    _log.warning(
        "api_miasm failed to load (%s: %s) — all miasm_* tools unavailable. "
        "Install with: pip install miasm future\n%s",
        type(_e).__name__, _e, _traceback.format_exc(),
    )
    api_miasm = None  # type: ignore[assignment]

try:
    from . import api_construct
except Exception as _e:
    _log.warning(
        "api_construct failed to load (%s: %s) — all construct_* tools unavailable. "
        "Install with: pip install construct\n%s",
        type(_e).__name__, _e, _traceback.format_exc(),
    )
    api_construct = None  # type: ignore[assignment]

try:
    from . import api_cstruct
except Exception as _e:
    _log.warning(
        "api_cstruct failed to load (%s: %s) — all cstruct_* tools unavailable. "
        "Install with: pip install dissect.cstruct\n%s",
        type(_e).__name__, _e, _traceback.format_exc(),
    )
    api_cstruct = None  # type: ignore[assignment]

try:
    from . import api_filetype
except Exception as _e:
    _log.warning(
        "api_filetype failed to load (%s: %s) — all filetype_* tools unavailable. "
        "Install with: pip install filetype\n%s",
        type(_e).__name__, _e, _traceback.format_exc(),
    )
    api_filetype = None  # type: ignore[assignment]

try:
    from . import api_lief
except Exception as _e:
    _log.warning(
        "api_lief failed to load (%s: %s) — all lief_* tools unavailable. "
        "Install with: pip install lief\n%s",
        type(_e).__name__, _e, _traceback.format_exc(),
    )
    api_lief = None  # type: ignore[assignment]

try:
    from . import api_yara
except Exception as _e:
    _log.warning(
        "api_yara failed to load (%s: %s) — all yara_* tools unavailable. "
        "Install with: pip install yara-python\n%s",
        type(_e).__name__, _e, _traceback.format_exc(),
    )
    api_yara = None  # type: ignore[assignment]

try:
    from . import api_angr
except Exception as _e:
    _log.warning(
        "api_angr failed to load (%s: %s) — all angr_* tools unavailable. "
        "Install with: pip install angr  (large ~200 MB)\n%s",
        type(_e).__name__, _e, _traceback.format_exc(),
    )
    api_angr = None  # type: ignore[assignment]

try:
    from . import api_networkx
except Exception as _e:
    _log.warning(
        "api_networkx failed to load (%s: %s) — all nx_* tools unavailable. "
        "Install with: pip install networkx>=3.0\n%s",
        type(_e).__name__, _e, _traceback.format_exc(),
    )
    api_networkx = None  # type: ignore[assignment]

try:
    from . import api_unicorn
except Exception as _e:
    _log.warning(
        "api_unicorn failed to load (%s: %s) — all unicorn_* tools unavailable. "
        "Install with: pip install unicorn\n%s",
        type(_e).__name__, _e, _traceback.format_exc(),
    )
    api_unicorn = None  # type: ignore[assignment]

try:
    from . import api_numpy
except Exception as _e:
    _log.warning(
        "api_numpy failed to load (%s: %s) — numpy_* tools unavailable. "
        "Install with: pip install numpy\n%s",
        type(_e).__name__, _e, _traceback.format_exc(),
    )
    api_numpy = None  # type: ignore[assignment]

try:
    from . import api_elf
except Exception as _e:
    _log.warning(
        "api_elf failed to load (%s: %s) — all elf_* tools unavailable. "
        "Install with: pip install pyelftools>=0.31\n%s",
        type(_e).__name__, _e, _traceback.format_exc(),
    )
    api_elf = None  # type: ignore[assignment]

# Build tool profiles after all api_*.py modules have loaded and registered tools.
# Profiles group tools into logical domains used by server_health and lazy mode.
from .rpc import MCP_SERVER, register_profile, get_tool_group  # noqa: E402


def _build_profiles() -> None:
    """Dynamically assign every registered tool to a profile group."""
    all_tools = set(MCP_SERVER.tools.methods.keys())
    groups: dict[str, set[str]] = {
        "core": set(),
        "analysis": set(),
        "modify": set(),
        "symbolic": set(),
        "formats": set(),
        "recon": set(),
    }
    for name in all_tools:
        groups[get_tool_group(name)].add(name)
    for group, tools in groups.items():
        if tools:
            register_profile(group, tools)
    register_profile("all", all_tools)


_build_profiles()

# Re-export key components for external use
from .sync import idasync, IDAError, IDASyncError, CancelledError
from .rpc import MCP_UNSAFE, tool, unsafe, resource
from .http import IdaMcpHttpRequestHandler
from .api_core import init_caches
from .api_discovery import set_local_instance

# Tracing is always on: every tools/call is recorded into the IDB netnode.
trace.configure_idb()

__all__ = [
    # Infrastructure modules
    "rpc",
    "sync",
    "utils",
    # API modules
    "api_core",
    "api_analysis",
    "api_memory",
    "api_types",
    "api_modify",
    "api_stack",
    "api_debug",
    "api_python",
    "api_resources",
    "api_survey",
    "api_composite",
    "api_discovery",
    "api_sigmaker",
    "api_flirt",
    "api_recon",
    # Optional analysis engines (None when deps absent)
    "api_triton",
    "api_miasm",
    "api_lief",
    "api_yara",
    "api_angr",
    "api_networkx",
    "api_unicorn",
    "api_numpy",
    "api_elf",
    # Re-exported components
    "idasync",
    "IDAError",
    "IDASyncError",
    "CancelledError",
    "MCP_SERVER",
    "MCP_UNSAFE",
    "MCP_PROFILES",
    "MCP_DEFAULT_PROFILE",
    "tool",
    "unsafe",
    "resource",
    "register_profile",
    "get_tool_group",
    "IdaMcpHttpRequestHandler",
    "init_caches",
    "set_local_instance",
]
