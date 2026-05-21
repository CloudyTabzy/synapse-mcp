"""api_networkx — Graph analysis tools for IDA Pro MCP, powered by NetworkX.

Optional module: tools are only registered when `networkx` is installed.
Install with: pip install networkx>=3.0  (small, pure-Python, included in 'all')

Every meaningful structure in a binary IS a graph: call graph, control-flow
graph, xref network, type relationships, import dependencies. NetworkX brings
50+ years of graph algorithm research to bear on reverse engineering.

Killer feature: ``workflow_reveng_overview`` — one-call binary structural
overview that ranks every function by importance (PageRank + betweenness +
in-degree), detects clusters (Louvain communities + strongly-connected
components), and emits a prioritized action list for the agent. With YARA
installed, each cluster gets a semantic label (crypto, packer, etc.).

Tool roster (22 tools + 1 always-registered probe):

  Infrastructure
    I.0  nx_status                  — availability probe (always registered)

  Graph Construction
    N.1  nx_call_graph              — full IDB call graph (cached, LRU)
    N.2  nx_function_cfg            — block-level CFG for one function
    N.3  nx_xref_graph              — generalized xref network
    N.4  nx_subgraph                — extract subgraph by filter/radius

  Graph Analysis
    A.1  nx_graph_metrics           — density / components / degree summary
    A.2  nx_central_functions       ⭐ centrality-based importance ranking
    A.3  nx_shortest_path           — between two functions
    A.4  nx_all_paths               — enumerate simple paths (cutoff)
    A.5  nx_cycles                  — simple cycles in call graph
    A.6  nx_strongly_connected      — SCCs (mutual recursion / dispatch)
    A.7  nx_neighborhood            — N-hop ego graph
    A.8  nx_dominators              — immediate dominators for a function CFG
    A.9  nx_communities             — Louvain / label-prop clustering
    A.10 nx_topological_order       — topo sort for acyclic call graphs

  Diff & Export
    D.1  nx_graph_diff              — compare two cached graphs
    D.2  nx_export_graph            — DOT/GraphML/GML/JSON export

  Hybrid Cross-Engine
    H.1  hybrid_nx_angr_target_ranking      — angr CFG + NX centrality
    H.2  hybrid_nx_yara_cluster_detection   — YARA categories + communities
    H.3  hybrid_nx_lief_import_graph        — LIEF imports as bipartite graph
    H.4  hybrid_nx_triton_taint_graph       — Triton taint propagation graph

  Workflows
    W.1  workflow_reveng_overview   ⭐ KILLER — first-pass binary overview
    W.2  workflow_find_critical_paths       — entry → sensitive sink paths
    W.3  workflow_binary_diff_summary       — high-level structural diff
"""
from __future__ import annotations

import fnmatch
import json
import logging
import os
import threading
from collections import OrderedDict
from typing import Annotated, NotRequired, TypedDict

import idaapi
import idautils
import idc

from .rpc import tool
from .sync import idasync, tool_timeout
from .utils import (
    parse_address,
    read_bytes_bss_safe,
    tool_error,
    normalize_list_input,
)

logger = logging.getLogger(__name__)

# ============================================================================
# Optional import guard
# ============================================================================

try:
    import networkx as _nx
    NETWORKX_AVAILABLE = True
    _NX_VERSION = getattr(_nx, "__version__", "unknown")
except ImportError:
    _nx = None  # type: ignore[assignment]
    NETWORKX_AVAILABLE = False
    _NX_VERSION = ""
    logger.warning(
        "networkx not installed — nx_* tools unavailable. "
        "Install with: pip install networkx>=3.0"
    )


# ============================================================================
# TypedDict result types
# ============================================================================


class NxStatusResult(TypedDict, total=False):
    ok: bool
    available: bool
    version: str
    cached_graphs: int
    hint: str


class GraphSummary(TypedDict, total=False):
    ok: bool
    graph_id: str
    kind: str
    node_count: int
    edge_count: int
    is_dag: bool
    density: float
    note: str
    error: str
    error_type: str
    hint: str


class GraphMetricsResult(TypedDict, total=False):
    ok: bool
    graph_id: str
    node_count: int
    edge_count: int
    density: float
    avg_in_degree: float
    avg_out_degree: float
    max_in_degree: int
    max_out_degree: int
    weakly_connected_components: int
    strongly_connected_components: int
    is_dag: bool
    has_self_loops: int
    note: str
    error: str
    error_type: str


class CentralityEntry(TypedDict, total=False):
    addr: str
    name: str
    pagerank: float
    betweenness: float
    in_degree_centrality: float
    out_degree_centrality: float
    combined_score: float
    in_degree: int
    out_degree: int
    yara_category: NotRequired[str]


class CentralFunctionsResult(TypedDict, total=False):
    ok: bool
    graph_id: str
    method: str
    top_n: int
    functions: list[CentralityEntry]
    betweenness_sampled: bool
    note: str
    error: str
    error_type: str


class ShortestPathResult(TypedDict, total=False):
    ok: bool
    graph_id: str
    src: str
    dst: str
    reachable: bool
    path: list[str]
    path_length: int
    path_names: list[str]
    note: str
    error: str
    error_type: str
    hint: str
    diagnostic: dict


class AllPathsResult(TypedDict, total=False):
    ok: bool
    graph_id: str
    src: str
    dst: str
    paths_found: int
    paths: list[list[str]]
    truncated: bool
    note: str
    error: str
    hint: str
    diagnostic: dict


class CycleEntry(TypedDict, total=False):
    length: int
    members: list[str]
    member_names: list[str]


class CyclesResult(TypedDict, total=False):
    ok: bool
    graph_id: str
    cycle_count: int
    cycles: list[CycleEntry]
    truncated: bool
    note: str
    error: str


class SccEntry(TypedDict, total=False):
    size: int
    members: list[str]
    member_names: list[str]
    interpretation: str


class StronglyConnectedResult(TypedDict, total=False):
    ok: bool
    graph_id: str
    component_count: int
    non_trivial_count: int
    components: list[SccEntry]
    note: str
    error: str


class NeighborhoodResult(TypedDict, total=False):
    ok: bool
    graph_id: str
    center: str
    radius: int
    seed_degrees: list[dict]
    node_count: int
    edge_count: int
    nodes: list[dict]
    edges: list[dict]
    note: str
    error: str
    hint: str
    diagnostic: dict
    unresolved_inputs: list[str]


class DominatorEntry(TypedDict, total=False):
    block: str
    idom: str


class DominatorsResult(TypedDict, total=False):
    ok: bool
    function_address: str
    entry_block: str
    block_count: int
    immediate_dominators: list[DominatorEntry]
    natural_loop_headers: list[str]
    note: str
    error: str


class CommunityEntry(TypedDict, total=False):
    id: int
    size: int
    members: list[str]
    central_function: str
    label_guess: NotRequired[str]


class CommunitiesResult(TypedDict, total=False):
    ok: bool
    graph_id: str
    algorithm: str
    community_count: int
    communities: list[CommunityEntry]
    modularity: float
    note: str
    error: str


class TopoSortResult(TypedDict, total=False):
    ok: bool
    graph_id: str
    is_dag: bool
    order: list[str]
    note: str
    error: str


class GraphDiffResult(TypedDict, total=False):
    ok: bool
    left_id: str
    right_id: str
    nodes_added: list[str]
    nodes_removed: list[str]
    edges_added: list[list[str]]
    edges_removed: list[list[str]]
    common_nodes: int
    structural_similarity: float
    note: str
    error: str


class ExportResult(TypedDict, total=False):
    ok: bool
    graph_id: str
    format: str
    output_path: str
    content: str
    truncated: bool
    note: str
    error: str


class RevengOverviewResult(TypedDict, total=False):
    ok: bool
    function_count: int
    edge_count: int
    metrics: dict
    top_by_pagerank: list[CentralityEntry]
    top_by_betweenness: list[CentralityEntry]
    top_by_combined: list[CentralityEntry]
    leaf_functions: list[dict]
    root_functions: list[dict]
    strongly_connected_components: list[SccEntry]
    communities: list[CommunityEntry]
    recommendations: list[str]
    yara_used: bool
    elapsed_ms: int
    note: str
    error: str
    error_type: str


class CriticalPathsResult(TypedDict, total=False):
    ok: bool
    entry_count: int
    sink_count: int
    paths: list[dict]
    note: str
    error: str


# ============================================================================
# Module-global graph cache (LRU)
# ============================================================================

_MAX_GRAPHS = 5
_CACHE_LOCK = threading.Lock()
_graph_cache: "OrderedDict[str, dict]" = OrderedDict()
# Entry shape:
#   {
#       "graph": nx.DiGraph,
#       "kind":  str,          # "call_graph" | "function_cfg" | "xref_graph" | "subgraph"
#       "meta":  dict,         # construction args, useful for cache reuse
#   }


def _cache_count() -> int:
    with _CACHE_LOCK:
        return len(_graph_cache)


def _evict_if_needed() -> None:
    with _CACHE_LOCK:
        while len(_graph_cache) > _MAX_GRAPHS:
            ev_key, _ = _graph_cache.popitem(last=False)
            logger.info("Evicted NetworkX graph cache entry '%s' (LRU)", ev_key)


def _store_graph(graph_id: str, graph, kind: str, meta: dict | None = None) -> None:
    with _CACHE_LOCK:
        _graph_cache[graph_id] = {"graph": graph, "kind": kind, "meta": meta or {}}
        _graph_cache.move_to_end(graph_id)
    _evict_if_needed()


def _get_cached(graph_id: str | None) -> dict | None:
    """Return cached entry (LRU-marked), or most-recent if id is None."""
    with _CACHE_LOCK:
        if not _graph_cache:
            return None
        if graph_id is None:
            key = next(reversed(_graph_cache))
            entry = _graph_cache[key]
            _graph_cache.move_to_end(key)
            return entry
        entry = _graph_cache.get(graph_id)
        if entry is not None:
            _graph_cache.move_to_end(graph_id)
        return entry


def _graph_id_for_entry(entry: dict) -> str | None:
    with _CACHE_LOCK:
        for gid, ent in _graph_cache.items():
            if ent is entry:
                return gid
    return None


def _next_graph_id(prefix: str) -> str:
    with _CACHE_LOCK:
        n = sum(1 for k in _graph_cache if k.startswith(prefix))
    return f"{prefix}_{n}"


# ============================================================================
# IDA → NetworkX graph builders (helpers, NOT decorated)
# ============================================================================


def _func_name(ea: int) -> str:
    """Return a function's display name, falling back to sub_HEX."""
    name = idc.get_func_name(ea) or ""
    return name or f"sub_{ea:X}"


def _build_call_graph(
    segment_name: str | None = None,
    include_calls: bool = True,
    include_jumps: bool = False,
) -> "_nx.DiGraph":
    """Build a directed call graph from IDA's xref database.

    Edges: (caller_ea, callee_ea, {kind, weight}).
    Node attrs: name, size, segment.
    """
    G = _nx.DiGraph()

    target_segs: set[str] | None = None
    if segment_name:
        target_segs = {segment_name}

    # Phase 1: add all function nodes within scope
    for func_ea in idautils.Functions():
        seg = idc.get_segm_name(func_ea) or ""
        if target_segs is not None and seg not in target_segs:
            continue
        func = idaapi.get_func(func_ea)
        if func is None:
            continue
        G.add_node(
            func_ea,
            name=_func_name(func_ea),
            size=int(func.end_ea - func.start_ea),
            segment=seg,
        )

    if G.number_of_nodes() == 0:
        return G

    # Phase 2: walk instructions and add call/jump edges
    call_itypes = (idaapi.NN_call, idaapi.NN_callfi, idaapi.NN_callni)
    jump_itypes = (idaapi.NN_jmp, idaapi.NN_jmpfi, idaapi.NN_jmpni)

    nodes_set = set(G.nodes())

    for func_ea in nodes_set:
        try:
            for item_ea in idautils.FuncItems(func_ea):
                insn = idaapi.insn_t()
                if idaapi.decode_insn(insn, item_ea) <= 0:
                    continue
                want = False
                kind = "call"
                if include_calls and insn.itype in call_itypes:
                    want = True
                    kind = "call"
                elif include_jumps and insn.itype in jump_itypes:
                    want = True
                    kind = "jump"
                if not want:
                    continue
                tgt = idc.get_operand_value(item_ea, 0)
                op_type = idc.get_operand_type(item_ea, 0)
                if op_type not in (idaapi.o_near, idaapi.o_far, idaapi.o_mem):
                    continue
                if tgt in nodes_set and tgt != func_ea:
                    if G.has_edge(func_ea, tgt):
                        G[func_ea][tgt]["weight"] = G[func_ea][tgt].get("weight", 1) + 1
                    else:
                        G.add_edge(func_ea, tgt, kind=kind, weight=1)
                elif tgt not in nodes_set:
                    # Inter-function jump or external call - add tail-call target as node
                    tgt_func = idaapi.get_func(tgt)
                    if tgt_func is not None:
                        G.add_node(
                            tgt_func.start_ea,
                            name=_func_name(tgt_func.start_ea),
                            size=int(tgt_func.end_ea - tgt_func.start_ea),
                            segment=idc.get_segm_name(tgt_func.start_ea) or "",
                        )
                        G.add_edge(func_ea, tgt_func.start_ea, kind=kind, weight=1)
                        nodes_set.add(tgt_func.start_ea)
        except Exception as e:
            logger.debug("Edge enum failed for %s: %s", hex(func_ea), e)
            continue

    # Phase 3: xref-based fallback for edges missed by instruction decoding.
    # Catches indirect calls, import thunks, and IDA's auto-resolved targets
    # that don't decode to simple o_near/o_mem operands.
    call_xref_types = {idaapi.fl_CN, idaapi.fl_CF}
    jump_xref_types = {idaapi.fl_JN, idaapi.fl_JF} if include_jumps else set()
    edge_xref_types = call_xref_types | jump_xref_types

    def _ensure_callee_node(callee: int, tgt_func) -> None:
        """Add or update the callee node with full attributes.

        Critical: we MUST add the node with attributes BEFORE adding any
        edge. `G.add_edge(u, v)` auto-creates missing endpoints as bare
        nodes (no attributes). If we added the edge first and then checked
        `if not G.has_node(callee)`, the check would always fail (the edge
        created it) and we'd never set the `name` attribute — which then
        causes `nx_neighborhood` and similar tools to fall back to a hex
        string for the name.

        `G.add_node` on an existing node updates its attributes, so this
        is also idempotent for nodes already added by Phase 1.
        """
        G.add_node(
            callee,
            name=_func_name(callee),
            size=int(tgt_func.end_ea - tgt_func.start_ea),
            segment=idc.get_segm_name(callee) or "",
        )
        nodes_set.add(callee)

    for func_ea in list(G.nodes()):
        try:
            for item_ea in idautils.FuncItems(func_ea):
                # 3a. Code xrefs from this instruction (calls + jumps if enabled)
                for xref in idautils.XrefsFrom(item_ea, 0):
                    if xref.type not in edge_xref_types:
                        continue
                    tgt = xref.to
                    if tgt == func_ea:
                        continue
                    tgt_func = idaapi.get_func(tgt)
                    if tgt_func is None:
                        continue
                    callee = tgt_func.start_ea
                    if callee == func_ea:
                        continue
                    kind = "jump" if xref.type in jump_xref_types else "call"
                    if not G.has_edge(func_ea, callee):
                        # Ensure attributes ALWAYS exist before creating the edge.
                        _ensure_callee_node(callee, tgt_func)
                        G.add_edge(func_ea, callee, kind=kind, weight=1)

                # 3b. Data xrefs from this instruction whose target is a
                # function's start address — captures indirect calls via
                # function pointers, vtables, jump tables, etc. We only
                # add such edges when include_calls is enabled (these
                # represent potential call sites, not actual jumps).
                if not include_calls:
                    continue
                for xref in idautils.DataRefsFrom(item_ea):
                    tgt_func = idaapi.get_func(xref)
                    if tgt_func is None:
                        continue
                    if tgt_func.start_ea != xref:
                        # Only count xrefs to the FUNCTION START, not mid-body
                        continue
                    callee = tgt_func.start_ea
                    if callee == func_ea:
                        continue
                    if not G.has_edge(func_ea, callee):
                        _ensure_callee_node(callee, tgt_func)
                        G.add_edge(func_ea, callee, kind="indirect_call", weight=1)
        except Exception as e:
            logger.debug("Xref fallback failed for %s: %s", hex(func_ea), e)
            continue

    # Defense in depth: any node still missing a `name` attribute (which
    # can happen for synthetic / auto-created nodes that escaped both phases)
    # gets one filled in from IDA.
    for n in list(G.nodes()):
        if "name" not in G.nodes[n]:
            try:
                G.nodes[n]["name"] = _func_name(n) if isinstance(n, int) else str(n)
            except Exception:
                G.nodes[n]["name"] = _node_addr_str(n)

    return G


def _build_function_cfg(func_ea: int) -> "_nx.DiGraph":
    """Build a block-level CFG for a single function."""
    G = _nx.DiGraph()
    func = idaapi.get_func(func_ea)
    if func is None:
        return G
    try:
        fc = idaapi.FlowChart(func)
        for blk in fc:
            G.add_node(
                blk.start_ea,
                end=blk.end_ea,
                size=int(blk.end_ea - blk.start_ea),
            )
            for succ in blk.succs():
                G.add_edge(blk.start_ea, succ.start_ea)
    except Exception as e:
        logger.debug("FlowChart failed for %s: %s", hex(func_ea), e)
    return G


def _build_xref_graph(
    include_data: bool = True,
    include_strings: bool = True,
    max_nodes: int = 5000,
) -> "_nx.DiGraph":
    """Build a generalized xref graph: function/data/string nodes.

    Budget model (NX-1 fix): ``max_nodes`` is the TOTAL ceiling, but function
    nodes never starve out data/string slots. We reserve at least half of
    ``max_nodes`` (or 100 slots, whichever is larger) for data/strings.
    Without this split, a 810-function binary with ``max_nodes=200`` would
    fill all slots with functions and produce 0 edges.
    """
    G = _nx.DiGraph()

    # Reserve at least max(max_nodes//2, 100) slots for data/strings
    data_reserve = max(max_nodes // 2, min(100, max_nodes))
    func_budget = max(1, max_nodes - data_reserve)

    # Phase 1: add up to func_budget function nodes
    for func_ea in idautils.Functions():
        if G.number_of_nodes() >= func_budget:
            break
        G.add_node(func_ea, kind="function", name=_func_name(func_ea))

    if G.number_of_nodes() == 0:
        return G

    # Phase 2: process xrefs for each function. Snapshot the function-node
    # list FIRST — modifying G.nodes() during iteration would raise
    # RuntimeError ("dictionary changed size during iteration") as soon as
    # the first data/string node is added.
    function_nodes = list(G.nodes())
    seen_data: set[int] = set()
    pending_edges: list[tuple[int, int, str]] = []

    for func_ea in function_nodes:
        try:
            for item_ea in idautils.FuncItems(func_ea):
                for xref in idautils.XrefsFrom(item_ea, 0):
                    if xref.iscode:
                        continue
                    tgt = xref.to
                    if tgt in seen_data:
                        if G.has_node(tgt):
                            pending_edges.append((func_ea, tgt, "data_ref"))
                        continue
                    seen_data.add(tgt)

                    # Classify the target: string vs data
                    is_str = False
                    str_val = ""
                    if include_strings:
                        try:
                            str_type = idaapi.get_str_type(tgt)
                            if str_type is not None and str_type != idaapi.BADADDR:
                                contents = idc.get_strlit_contents(tgt)
                                if contents:
                                    str_val = contents.decode("utf-8", errors="replace")[:64]
                                    is_str = True
                        except Exception:
                            pass

                    if is_str:
                        if G.number_of_nodes() < max_nodes:
                            G.add_node(tgt, kind="string", value=str_val,
                                       name=idc.get_name(tgt) or f"str_{tgt:X}")
                        if G.has_node(tgt):
                            pending_edges.append((func_ea, tgt, "string_ref"))
                    elif include_data:
                        if G.number_of_nodes() < max_nodes:
                            G.add_node(tgt, kind="data",
                                       name=idc.get_name(tgt) or f"data_{tgt:X}")
                        if G.has_node(tgt):
                            pending_edges.append((func_ea, tgt, "data_ref"))
        except Exception as e:
            logger.debug("xref enum failed for %s: %s", hex(func_ea), e)
            continue

    # Phase 3: add edges in bulk now that all nodes are settled
    for src, dst, kind in pending_edges:
        G.add_edge(src, dst, kind=kind)

    return G


def _node_addr_str(n) -> str:
    """Render a node (int address) as a hex string; passthrough strings."""
    if isinstance(n, int):
        return hex(n)
    return str(n)


def _resolve_to_graph_node(G, raw_addr) -> int | None:
    """Resolve a user-supplied address to a node in G.

    Tries, in order:
      1. The parsed integer directly.
      2. Hex fallback for bare hex strings (e.g. "140002590" → 0x140002590).
      3. The address normalized to its IDA function start (handles the
         "user passed a mid-function address" case).

    Returns the matching node ID, or None if neither resolves.
    """
    parsed = None
    if isinstance(raw_addr, int):
        parsed = raw_addr
    else:
        try:
            parsed = _parse_node(raw_addr)
        except Exception:
            pass

    if parsed is not None and G.has_node(parsed):
        return parsed

    # Hex fallback: "140002590" without 0x prefix might mean 0x140002590
    if isinstance(raw_addr, str):
        stripped = raw_addr.strip()
        if not stripped.startswith("0x") and not stripped.startswith("0X"):
            try:
                hex_parsed = int(stripped, 16)
                if G.has_node(hex_parsed):
                    return hex_parsed
            except ValueError:
                pass

    # Normalize to function start
    if parsed is not None:
        try:
            f = idaapi.get_func(parsed)
            if f is not None and f.start_ea != parsed and G.has_node(f.start_ea):
                logger.debug(
                    "Resolved mid-function address %s -> function start %s",
                    hex(parsed), hex(f.start_ea),
                )
                return f.start_ea
        except Exception:
            pass
    return None


def _describe_lookup_failure(G, raw_addr: str, parsed_ea: int) -> dict:
    """Build a diagnostic dict when a node lookup misses.

    Goals:
    - Tell the user the resolved integer (so they can spot typos / encoding)
    - Show graph size + a few sample node addresses
    - Check whether IDA knows of a function at the same address (the
      common stale-cache case: the function was created AFTER the call
      graph was built)
    - Recommend a fix
    """
    sample = []
    try:
        for n in list(G.nodes())[:5]:
            sample.append(_node_addr_str(n))
    except Exception:
        pass

    ida_func_start = None
    ida_func_name = None
    try:
        f = idaapi.get_func(parsed_ea)
        if f is not None:
            ida_func_start = hex(f.start_ea)
            ida_func_name = _func_name(f.start_ea)
    except Exception:
        pass

    info: dict = {
        "input": raw_addr,
        "parsed_as_hex": hex(parsed_ea),
        "graph_node_count": G.number_of_nodes(),
        "sample_node_addrs": sample,
    }
    # If the raw input looks like a bare hex string, also show the hex
    # interpretation so the user can spot missing-0x-prefix typos.
    if isinstance(raw_addr, str):
        stripped = raw_addr.strip()
        if not stripped.startswith("0x") and not stripped.startswith("0X"):
            try:
                hex_fallback = int(stripped, 16)
                if hex_fallback != parsed_ea:
                    info["hex_fallback"] = hex(hex_fallback)
            except ValueError:
                pass

    if ida_func_start is not None:
        info["ida_function_start"] = ida_func_start
        info["ida_function_name"] = ida_func_name
        info["hint"] = (
            f"IDA reports a function at {ida_func_start} ({ida_func_name}) "
            f"covering {raw_addr}, but it isn't in this cached graph. "
            "Two likely causes: (1) the address is mid-function — pass the "
            "function start as a hex string (e.g. '0x140002590'); "
            "(2) the cached graph is stale (function created after the graph "
            "was built) — call nx_call_graph to rebuild."
        )
    else:
        info["hint"] = (
            f"No IDA function covers {raw_addr}. Verify the address is correct "
            "(use hex strings like '0x140002590') and that the binary actually "
            "defines a function there."
        )
    return info


def _parse_node(n) -> int:
    """Parse a node hex/dec string into an int address."""
    if isinstance(n, int):
        return n
    return parse_address(n)


# ============================================================================
# Status probe — always registered, even when networkx is unavailable
# ============================================================================


@tool
@idasync
def nx_status() -> NxStatusResult:
    """Probe networkx availability and version.

    Always registered regardless of installation status.
    """
    if not NETWORKX_AVAILABLE:
        return {
            "ok": True,
            "available": False,
            "version": "",
            "cached_graphs": 0,
            "hint": "Install with: pip install networkx>=3.0  (small, pure-Python)",
        }
    return {
        "ok": True,
        "available": True,
        "version": _NX_VERSION,
        "cached_graphs": _cache_count(),
    }


# ============================================================================
# All other tools — guarded
# ============================================================================

if NETWORKX_AVAILABLE:

    # =====================================================================
    # N.1 — nx_call_graph
    # =====================================================================

    def _call_graph_impl(
        segment_name: str | None = None,
        include_calls: bool = True,
        include_jumps: bool = False,
        graph_id: str | None = None,
    ) -> GraphSummary:
        try:
            # Check cache by structural key
            cache_key = f"call::seg={segment_name or '*'}:c={int(include_calls)}:j={int(include_jumps)}"
            with _CACHE_LOCK:
                for gid, ent in _graph_cache.items():
                    if ent["meta"].get("_cache_key") == cache_key:
                        _graph_cache.move_to_end(gid)
                        G = ent["graph"]
                        return {
                            "ok": True,
                            "graph_id": gid,
                            "kind": "call_graph",
                            "node_count": G.number_of_nodes(),
                            "edge_count": G.number_of_edges(),
                            "is_dag": _nx.is_directed_acyclic_graph(G),
                            "density": float(_nx.density(G)) if G.number_of_nodes() > 1 else 0.0,
                            "note": "Returned from cache.",
                        }

            G = _build_call_graph(segment_name, include_calls, include_jumps)
            if G.number_of_nodes() == 0:
                return {
                    "ok": False,
                    "error": (
                        "Empty call graph. Verify segment_name "
                        "or that functions are defined in the IDB."
                    ),
                    "error_type": "not_found",
                }
            gid = graph_id or _next_graph_id("call")
            _store_graph(gid, G, "call_graph", meta={
                "segment_name": segment_name,
                "include_calls": include_calls,
                "include_jumps": include_jumps,
                "_cache_key": cache_key,
            })
            return {
                "ok": True,
                "graph_id": gid,
                "kind": "call_graph",
                "node_count": G.number_of_nodes(),
                "edge_count": G.number_of_edges(),
                "is_dag": _nx.is_directed_acyclic_graph(G),
                "density": float(_nx.density(G)) if G.number_of_nodes() > 1 else 0.0,
                "note": f"Built call graph ({G.number_of_nodes()} functions, "
                        f"{G.number_of_edges()} edges).",
            }
        except Exception as e:
            return tool_error(e, context="nx_call_graph")


    @tool
    @idasync
    @tool_timeout(120.0)
    def nx_call_graph(
        segment_name: Annotated[
            str | None,
            "Restrict to one segment name (e.g. '.text'). Omit for all functions.",
        ] = None,
        include_calls: Annotated[
            bool, "Include call instructions as edges (default: True)"
        ] = True,
        include_jumps: Annotated[
            bool,
            "Include inter-function jumps (tail calls) as edges (default: False)",
        ] = False,
        graph_id: Annotated[
            str | None, "Explicit cache ID. Auto-generated 'call_N' if omitted."
        ] = None,
    ) -> GraphSummary:
        """Build the full call graph for the current IDB.

        Heavy: for large binaries use invoke_tool(..., async_mode=True) or task_submit + task_poll.

        Cached in module-global LRU (max 5). Subsequent analysis tools
        (centrality, paths, communities) reuse the cached graph by graph_id.
        """
        return _call_graph_impl(
            segment_name=segment_name,
            include_calls=include_calls,
            include_jumps=include_jumps,
            graph_id=graph_id,
        )


    # =====================================================================
    # N.2 — nx_function_cfg
    # =====================================================================

    def _function_cfg_impl(
        function_address: str,
        graph_id: str | None = None,
    ) -> GraphSummary:
        try:
            func_ea = parse_address(function_address)
            func = idaapi.get_func(func_ea)
            if func is None:
                return {
                    "ok": False,
                    "error": f"No function at {hex(func_ea)}",
                    "error_type": "not_found",
                }
            # Cache by function start address
            cache_key = f"cfg::{func.start_ea:X}"
            with _CACHE_LOCK:
                for gid, ent in _graph_cache.items():
                    if ent["meta"].get("_cache_key") == cache_key:
                        _graph_cache.move_to_end(gid)
                        G = ent["graph"]
                        return {
                            "ok": True,
                            "graph_id": gid,
                            "kind": "function_cfg",
                            "node_count": G.number_of_nodes(),
                            "edge_count": G.number_of_edges(),
                            "is_dag": _nx.is_directed_acyclic_graph(G),
                            "density": float(_nx.density(G)) if G.number_of_nodes() > 1 else 0.0,
                            "note": "Returned from cache.",
                        }

            G = _build_function_cfg(func.start_ea)
            if G.number_of_nodes() == 0:
                return {
                    "ok": False,
                    "error": "FlowChart returned empty graph.",
                    "error_type": "internal_error",
                }
            gid = graph_id or _next_graph_id(f"cfg_{func.start_ea:X}")
            _store_graph(gid, G, "function_cfg", meta={
                "function_address": func.start_ea,
                "_cache_key": cache_key,
            })
            return {
                "ok": True,
                "graph_id": gid,
                "kind": "function_cfg",
                "node_count": G.number_of_nodes(),
                "edge_count": G.number_of_edges(),
                "is_dag": _nx.is_directed_acyclic_graph(G),
                "density": float(_nx.density(G)) if G.number_of_nodes() > 1 else 0.0,
                "note": f"CFG for {_func_name(func.start_ea)} "
                        f"({G.number_of_nodes()} blocks, {G.number_of_edges()} edges).",
            }
        except Exception as e:
            return tool_error(e, context="nx_function_cfg")


    @tool
    @idasync
    @tool_timeout(30.0)
    def nx_function_cfg(
        function_address: Annotated[str, "Function start address (hex)"],
        graph_id: Annotated[str | None, "Cache ID. Auto-generated if omitted."] = None,
    ) -> GraphSummary:
        """Build a block-level CFG for a single function using IDA's FlowChart."""
        return _function_cfg_impl(function_address, graph_id)


    # =====================================================================
    # N.3 — nx_xref_graph
    # =====================================================================

    def _xref_graph_impl(
        include_data: bool = True,
        include_strings: bool = True,
        max_nodes: int = 5000,
        graph_id: str | None = None,
    ) -> GraphSummary:
        try:
            cache_key = f"xref::d={int(include_data)}:s={int(include_strings)}:m={max_nodes}"
            with _CACHE_LOCK:
                for gid, ent in _graph_cache.items():
                    if ent["meta"].get("_cache_key") == cache_key:
                        _graph_cache.move_to_end(gid)
                        G = ent["graph"]
                        return {
                            "ok": True, "graph_id": gid, "kind": "xref_graph",
                            "node_count": G.number_of_nodes(),
                            "edge_count": G.number_of_edges(),
                            "is_dag": _nx.is_directed_acyclic_graph(G),
                            "density": float(_nx.density(G)) if G.number_of_nodes() > 1 else 0.0,
                            "note": "Returned from cache.",
                        }

            G = _build_xref_graph(include_data, include_strings, max_nodes)
            if G.number_of_nodes() == 0:
                return {"ok": False, "error": "Empty xref graph", "error_type": "not_found"}
            gid = graph_id or _next_graph_id("xref")
            _store_graph(gid, G, "xref_graph", meta={
                "include_data": include_data,
                "include_strings": include_strings,
                "max_nodes": max_nodes,
                "_cache_key": cache_key,
            })
            return {
                "ok": True,
                "graph_id": gid,
                "kind": "xref_graph",
                "node_count": G.number_of_nodes(),
                "edge_count": G.number_of_edges(),
                "is_dag": _nx.is_directed_acyclic_graph(G),
                "density": float(_nx.density(G)) if G.number_of_nodes() > 1 else 0.0,
                "note": f"Xref graph: {G.number_of_nodes()} nodes "
                        f"(functions+data+strings), {G.number_of_edges()} edges.",
            }
        except Exception as e:
            return tool_error(e, context="nx_xref_graph")


    @tool
    @idasync
    @tool_timeout(180.0)
    def nx_xref_graph(
        include_data: Annotated[bool, "Include data references as nodes"] = True,
        include_strings: Annotated[bool, "Include string references as nodes"] = True,
        max_nodes: Annotated[int, "Cap node count to avoid huge graphs"] = 5000,
        graph_id: Annotated[str | None, "Cache ID"] = None,
    ) -> GraphSummary:
        """Build a generalized xref graph (function + data + string nodes).

        Useful for finding 'hub' data items (referenced by many functions) or
        identifying functions that share string usage (likely related).
        """
        return _xref_graph_impl(include_data, include_strings, max_nodes, graph_id)


    # =====================================================================
    # N.4 — nx_subgraph
    # =====================================================================

    @tool
    @idasync
    @tool_timeout(30.0)
    def nx_subgraph(
        graph_id: Annotated[str | None, "Source graph_id (default: most recent)"] = None,
        node_filter: Annotated[
            list[str] | str | None,
            "Address list, or comma-separated string of hex addresses. "
            "When radius > 0 these are treated as seed nodes for expansion.",
        ] = None,
        name_pattern: Annotated[
            str | None,
            "Glob pattern on function names (e.g. 'crypto_*', '*aes*')",
        ] = None,
        radius: Annotated[
            int, "Expand selection by N-hop ego graph (default: 0 = no expansion)"
        ] = 0,
        new_graph_id: Annotated[str | None, "Cache ID for the new subgraph"] = None,
    ) -> GraphSummary:
        """Extract a subgraph by node filter and optional N-hop expansion.

        When both ``node_filter`` and ``radius`` are provided, the filter
        addresses act as seed nodes; the returned subgraph contains the
        N-hop neighborhood around every seed (union of ego graphs).
        """
        try:
            entry = _get_cached(graph_id)
            if entry is None:
                return {"ok": False, "error": "No cached graph; call nx_call_graph first."}
            G = entry["graph"]

            selected: set = set()

            if node_filter:
                addrs = normalize_list_input(node_filter)
                for a in addrs:
                    try:
                        ea = parse_address(a)
                        if G.has_node(ea):
                            selected.add(ea)
                    except Exception:
                        continue

            if name_pattern:
                pat = name_pattern.lower()
                for n in G.nodes():
                    name = (G.nodes[n].get("name") or "").lower()
                    if fnmatch.fnmatch(name, pat):
                        selected.add(n)

            if not selected:
                return {"ok": False, "error": "Filter produced no matching nodes."}

            if radius > 0:
                expanded: set = set(selected)
                for center in selected:
                    try:
                        ego = _nx.ego_graph(G, center, radius=radius, undirected=True)
                        expanded.update(ego.nodes())
                    except Exception:
                        pass
                selected = expanded

            H = G.subgraph(selected).copy()
            gid = new_graph_id or _next_graph_id("sub")
            _store_graph(gid, H, "subgraph", meta={"parent": _graph_id_for_entry(entry)})
            return {
                "ok": True,
                "graph_id": gid,
                "kind": "subgraph",
                "node_count": H.number_of_nodes(),
                "edge_count": H.number_of_edges(),
                "is_dag": _nx.is_directed_acyclic_graph(H),
                "density": float(_nx.density(H)) if H.number_of_nodes() > 1 else 0.0,
                "note": f"Extracted subgraph: {H.number_of_nodes()} nodes "
                        f"(radius={radius}).",
            }
        except Exception as e:
            return tool_error(e, context="nx_subgraph")


    # =====================================================================
    # A.1 — nx_graph_metrics
    # =====================================================================

    def _graph_metrics_impl(graph_id: str | None = None) -> GraphMetricsResult:
        try:
            entry = _get_cached(graph_id)
            if entry is None:
                return {"ok": False, "error": "No cached graph",
                        "error_type": "not_found"}
            G = entry["graph"]
            n = G.number_of_nodes()
            e = G.number_of_edges()
            if n == 0:
                return {"ok": False, "error": "Empty graph"}
            in_degs = [d for _, d in G.in_degree()]
            out_degs = [d for _, d in G.out_degree()]
            try:
                wcc = _nx.number_weakly_connected_components(G)
                scc = _nx.number_strongly_connected_components(G)
            except Exception:
                wcc = scc = 0
            return {
                "ok": True,
                "graph_id": _graph_id_for_entry(entry) or "",
                "node_count": n,
                "edge_count": e,
                "density": float(_nx.density(G)),
                "avg_in_degree": (sum(in_degs) / n) if n else 0.0,
                "avg_out_degree": (sum(out_degs) / n) if n else 0.0,
                "max_in_degree": max(in_degs) if in_degs else 0,
                "max_out_degree": max(out_degs) if out_degs else 0,
                "weakly_connected_components": wcc,
                "strongly_connected_components": scc,
                "is_dag": _nx.is_directed_acyclic_graph(G),
                "has_self_loops": _nx.number_of_selfloops(G),
                "note": f"Metrics for {n}-node, {e}-edge graph.",
            }
        except Exception as e:
            return tool_error(e, context="nx_graph_metrics")


    @tool
    @idasync
    @tool_timeout(30.0)
    def nx_graph_metrics(
        graph_id: Annotated[
            str | None, "Cache ID. Uses most recent if omitted."
        ] = None,
    ) -> GraphMetricsResult:
        """Summary metrics for a cached graph: density, components, degrees."""
        return _graph_metrics_impl(graph_id)


    # =====================================================================
    # A.2 — nx_central_functions ⭐
    # =====================================================================

    def _compute_centralities(G, betweenness_sample_k: int = 500):
        """Compute pagerank + betweenness + degree centralities.

        Returns (pr_dict, bw_dict, in_dc_dict, out_dc_dict).
        Betweenness is sampled when V > 2000 for speed.
        """
        try:
            pr = _nx.pagerank(G, alpha=0.85, max_iter=100, tol=1e-4)
        except Exception:
            pr = {n: 0.0 for n in G.nodes()}
        n = G.number_of_nodes()
        try:
            if n <= 2000:
                bw = _nx.betweenness_centrality(G)
            else:
                bw = _nx.betweenness_centrality(G, k=min(betweenness_sample_k, n), seed=42)
        except Exception:
            bw = {nn: 0.0 for nn in G.nodes()}
        try:
            in_dc = _nx.in_degree_centrality(G)
        except Exception:
            in_dc = {nn: 0.0 for nn in G.nodes()}
        try:
            out_dc = _nx.out_degree_centrality(G)
        except Exception:
            out_dc = {nn: 0.0 for nn in G.nodes()}
        return pr, bw, in_dc, out_dc


    def _central_functions_impl(
        graph_id: str | None = None,
        method: str = "combined",
        top_n: int = 25,
        betweenness_sample_k: int = 500,
        yara_categories: dict | None = None,
    ) -> CentralFunctionsResult:
        try:
            entry = _get_cached(graph_id)
            if entry is None:
                # Try to auto-build a call graph
                cg_res = _call_graph_impl()
                if not cg_res.get("ok"):
                    return {"ok": False, "error": "No cached graph and auto-build failed."}
                entry = _get_cached(cg_res["graph_id"])
                if entry is None:
                    return {"ok": False, "error": "Auto-build returned but entry missing."}

            G = entry["graph"]
            if G.number_of_nodes() == 0:
                return {"ok": False, "error": "Empty graph"}

            pr, bw, in_dc, out_dc = _compute_centralities(G, betweenness_sample_k)
            betweenness_sampled = G.number_of_nodes() > 2000

            if method == "pagerank":
                ranked = sorted(pr.items(), key=lambda kv: kv[1], reverse=True)
            elif method == "betweenness":
                ranked = sorted(bw.items(), key=lambda kv: kv[1], reverse=True)
            elif method == "in_degree":
                ranked = sorted(G.in_degree(), key=lambda kv: kv[1], reverse=True)
            elif method == "out_degree":
                ranked = sorted(G.out_degree(), key=lambda kv: kv[1], reverse=True)
            else:
                # combined: weighted sum (pr normalized to [0,1] - it already is)
                combined = {
                    n: 0.5 * pr.get(n, 0.0)
                       + 0.3 * bw.get(n, 0.0)
                       + 0.2 * in_dc.get(n, 0.0)
                    for n in G.nodes()
                }
                ranked = sorted(combined.items(), key=lambda kv: kv[1], reverse=True)

            functions: list[dict] = []
            for n, score in ranked[:top_n]:
                attrs = G.nodes[n]
                ent: dict = {
                    "addr": _node_addr_str(n),
                    "name": attrs.get("name", _func_name(n) if isinstance(n, int) else str(n)),
                    "pagerank": float(pr.get(n, 0.0)),
                    "betweenness": float(bw.get(n, 0.0)),
                    "in_degree_centrality": float(in_dc.get(n, 0.0)),
                    "out_degree_centrality": float(out_dc.get(n, 0.0)),
                    "combined_score": float(
                        0.5 * pr.get(n, 0.0)
                        + 0.3 * bw.get(n, 0.0)
                        + 0.2 * in_dc.get(n, 0.0)
                    ),
                    "in_degree": int(G.in_degree(n)),
                    "out_degree": int(G.out_degree(n)),
                }
                if yara_categories and isinstance(n, int):
                    cat = yara_categories.get(n)
                    if cat:
                        ent["yara_category"] = cat
                functions.append(ent)

            return {
                "ok": True,
                "graph_id": _graph_id_for_entry(entry) or "",
                "method": method,
                "top_n": top_n,
                "functions": functions,
                "betweenness_sampled": betweenness_sampled,
                "note": (
                    f"Ranked top {top_n} of {G.number_of_nodes()} functions "
                    f"using method='{method}'."
                ),
            }
        except Exception as e:
            return tool_error(e, context="nx_central_functions")


    @tool
    @idasync
    @tool_timeout(180.0)
    def nx_central_functions(
        graph_id: Annotated[str | None, "Cache ID; auto-build call graph if missing"] = None,
        method: Annotated[
            str,
            "'combined' (default), 'pagerank', 'betweenness', 'in_degree', 'out_degree'",
        ] = "combined",
        top_n: Annotated[int, "Number of top functions to return"] = 25,
        betweenness_sample_k: Annotated[
            int, "Sample size for betweenness on V > 2000 (default: 500)"
        ] = 500,
    ) -> CentralFunctionsResult:
        """⭐ Rank functions by graph-theoretic importance.

        Heavy: use invoke_tool(..., async_mode=True) or task_submit + task_poll on large binaries.

        method='combined' weights PageRank (50%) + betweenness (30%) +
        in-degree centrality (20%). For graphs with V > 2000, betweenness
        is sampled to keep runtime bounded.

        High-centrality functions in a stripped binary are typically:
          - dispatch hubs / state machine cores
          - common utilities (allocators, parsers)
          - critical decision points
        """
        return _central_functions_impl(
            graph_id=graph_id,
            method=method,
            top_n=top_n,
            betweenness_sample_k=betweenness_sample_k,
        )


    # =====================================================================
    # A.3 — nx_shortest_path
    # =====================================================================

    @tool
    @idasync
    @tool_timeout(30.0)
    def nx_shortest_path(
        src: Annotated[str, "Source function address (hex)"],
        dst: Annotated[str, "Destination function address (hex)"],
        graph_id: Annotated[str | None, "Cache ID"] = None,
        weight: Annotated[
            str | None, "Edge attribute to use as weight (e.g. 'weight')"
        ] = None,
        direction: Annotated[
            str,
            "'forward' follows edges src→dst (caller→callee in call graphs). "
            "'reverse' follows edges dst→src (callee→caller). "
            "'undirected' treats graph as undirected (default).",
        ] = "undirected",
    ) -> ShortestPathResult:
        """Shortest path from src to dst in a cached graph.

        The underlying call graph stores edges as **caller → callee**.
        ``direction='forward'`` finds paths from caller to callee;
        ``direction='reverse'`` finds paths from callee back to caller;
        ``direction='undirected'`` ignores directionality.
        """
        try:
            entry = _get_cached(graph_id)
            if entry is None:
                return {"ok": False, "error": "No cached graph",
                        "hint": "Call nx_call_graph first."}
            G_raw = entry["graph"]
            resolved_graph_id = _graph_id_for_entry(entry) or ""
            src_n = _resolve_to_graph_node(G_raw, src)
            dst_n = _resolve_to_graph_node(G_raw, dst)
            if src_n is None:
                return {
                    "ok": False,
                    "error": f"src {src} not in graph",
                    "graph_id": resolved_graph_id,
                    "diagnostic": _describe_lookup_failure(
                        G_raw, src, _parse_node(src),
                    ),
                }
            if dst_n is None:
                return {
                    "ok": False,
                    "error": f"dst {dst} not in graph",
                    "graph_id": resolved_graph_id,
                    "diagnostic": _describe_lookup_failure(
                        G_raw, dst, _parse_node(dst),
                    ),
                }

            if direction == "forward":
                G = G_raw
            elif direction == "reverse":
                G = G_raw.reverse(copy=False)
                src_n, dst_n = dst_n, src_n
            else:
                G = G_raw.to_undirected()

            try:
                path = _nx.shortest_path(G, src_n, dst_n, weight=weight)
            except _nx.NetworkXNoPath:
                return {
                    "ok": True,
                    "graph_id": resolved_graph_id,
                    "src": _node_addr_str(_parse_node(src)),
                    "dst": _node_addr_str(_parse_node(dst)),
                    "reachable": False,
                    "path": [],
                    "path_length": 0,
                    "path_names": [],
                    "note": "No path exists.",
                }
            names = [G_raw.nodes[n].get("name", _node_addr_str(n)) for n in path]
            return {
                "ok": True,
                "graph_id": resolved_graph_id,
                "src": _node_addr_str(_parse_node(src)),
                "dst": _node_addr_str(_parse_node(dst)),
                "reachable": True,
                "path": [_node_addr_str(n) for n in path],
                "path_length": len(path) - 1,
                "path_names": names,
                "note": f"Shortest path: {len(path) - 1} hop(s).",
            }
        except Exception as e:
            return tool_error(e, context="nx_shortest_path")


    # =====================================================================
    # A.4 — nx_all_paths
    # =====================================================================

    @tool
    @idasync
    @tool_timeout(60.0)
    def nx_all_paths(
        src: Annotated[str, "Source address (hex)"],
        dst: Annotated[str, "Destination address (hex)"],
        cutoff: Annotated[int, "Maximum path length (default: 8)"] = 8,
        max_paths: Annotated[int, "Maximum paths to return"] = 50,
        graph_id: Annotated[str | None, "Cache ID"] = None,
        direction: Annotated[
            str,
            "'forward' follows edges src→dst (caller→callee). "
            "'reverse' follows edges dst→src (callee→caller). "
            "'undirected' ignores directionality (default).",
        ] = "undirected",
    ) -> AllPathsResult:
        """Enumerate simple paths from src to dst with length cutoff.

        Call-graph edges are stored as **caller → callee**.
        Use ``direction='reverse'`` to find all paths from a callee back
        to its callers (e.g. "who calls this function").
        """
        try:
            entry = _get_cached(graph_id)
            if entry is None:
                return {"ok": False, "error": "No cached graph",
                        "hint": "Call nx_call_graph first."}
            G_raw = entry["graph"]
            resolved_graph_id = _graph_id_for_entry(entry) or ""
            src_n = _resolve_to_graph_node(G_raw, src)
            dst_n = _resolve_to_graph_node(G_raw, dst)
            if src_n is None:
                return {
                    "ok": False,
                    "error": f"src {src} not in graph",
                    "graph_id": resolved_graph_id,
                    "diagnostic": _describe_lookup_failure(
                        G_raw, src, _parse_node(src),
                    ),
                }
            if dst_n is None:
                return {
                    "ok": False,
                    "error": f"dst {dst} not in graph",
                    "graph_id": resolved_graph_id,
                    "diagnostic": _describe_lookup_failure(
                        G_raw, dst, _parse_node(dst),
                    ),
                }

            if direction == "forward":
                G = G_raw
            elif direction == "reverse":
                G = G_raw.reverse(copy=False)
                src_n, dst_n = dst_n, src_n
            else:
                G = G_raw.to_undirected()

            paths: list[list[str]] = []
            truncated = False
            try:
                for p in _nx.all_simple_paths(G, src_n, dst_n, cutoff=cutoff):
                    paths.append([_node_addr_str(n) for n in p])
                    if len(paths) >= max_paths:
                        truncated = True
                        break
            except _nx.NodeNotFound:
                pass
            return {
                "ok": True,
                "graph_id": resolved_graph_id,
                "src": _node_addr_str(_parse_node(src)),
                "dst": _node_addr_str(_parse_node(dst)),
                "paths_found": len(paths),
                "paths": paths,
                "truncated": truncated,
                "note": f"Found {len(paths)} simple path(s) with cutoff={cutoff}.",
            }
        except Exception as e:
            return tool_error(e, context="nx_all_paths")


    # =====================================================================
    # A.5 — nx_cycles
    # =====================================================================

    @tool
    @idasync
    @tool_timeout(60.0)
    def nx_cycles(
        graph_id: Annotated[str | None, "Cache ID"] = None,
        max_length: Annotated[int, "Maximum cycle length to report (default: 8)"] = 8,
        max_cycles: Annotated[int, "Maximum cycles to return (default: 100)"] = 100,
    ) -> CyclesResult:
        """Find simple cycles in a directed graph.

        Useful for detecting:
          - recursive functions (cycle of length 1)
          - mutually recursive groups (cycle of length 2+)
          - dispatch loops in state machines
        """
        try:
            entry = _get_cached(graph_id)
            if entry is None:
                return {"ok": False, "error": "No cached graph"}
            G = entry["graph"]
            cycles: list[dict] = []
            truncated = False
            try:
                for c in _nx.simple_cycles(G, length_bound=max_length):
                    if len(cycles) >= max_cycles:
                        truncated = True
                        break
                    cycles.append({
                        "length": len(c),
                        "members": [_node_addr_str(n) for n in c],
                        "member_names": [
                            G.nodes[n].get("name", _node_addr_str(n)) for n in c
                        ],
                    })
            except TypeError:
                # Older networkx without length_bound — fall back to manual filter
                count = 0
                for c in _nx.simple_cycles(G):
                    count += 1
                    if len(c) > max_length:
                        continue
                    if len(cycles) >= max_cycles:
                        truncated = True
                        break
                    cycles.append({
                        "length": len(c),
                        "members": [_node_addr_str(n) for n in c],
                        "member_names": [
                            G.nodes[n].get("name", _node_addr_str(n)) for n in c
                        ],
                    })
                    if count > 1000:
                        truncated = True
                        break
            return {
                "ok": True,
                "graph_id": _graph_id_for_entry(entry) or "",
                "cycle_count": len(cycles),
                "cycles": sorted(cycles, key=lambda c: c["length"]),
                "truncated": truncated,
                "note": (
                    f"Found {len(cycles)} cycle(s) up to length {max_length}. "
                    + ("Result truncated." if truncated else "")
                ),
            }
        except Exception as e:
            return tool_error(e, context="nx_cycles")


    # =====================================================================
    # A.6 — nx_strongly_connected
    # =====================================================================

    def _scc_impl(
        graph_id: str | None = None,
        min_size: int = 2,
        max_results: int = 100,
    ) -> StronglyConnectedResult:
        try:
            entry = _get_cached(graph_id)
            if entry is None:
                return {"ok": False, "error": "No cached graph"}
            G = entry["graph"]
            all_sccs = list(_nx.strongly_connected_components(G))
            total_count = len(all_sccs)
            non_trivial = [s for s in all_sccs if len(s) >= min_size]
            non_trivial.sort(key=len, reverse=True)
            out: list[dict] = []
            for s in non_trivial[:max_results]:
                members = list(s)
                interp = "mutual_recursion" if len(s) <= 3 else "dispatch_or_state_machine"
                out.append({
                    "size": len(s),
                    "members": [_node_addr_str(n) for n in members],
                    "member_names": [
                        G.nodes[n].get("name", _node_addr_str(n)) for n in members
                    ],
                    "interpretation": interp,
                })
            return {
                "ok": True,
                "graph_id": _graph_id_for_entry(entry) or "",
                "component_count": total_count,
                "non_trivial_count": len(non_trivial),
                "components": out,
                "note": f"{total_count} SCCs, {len(non_trivial)} non-trivial "
                        f"(size>={min_size}).",
            }
        except Exception as e:
            return tool_error(e, context="nx_strongly_connected")


    @tool
    @idasync
    @tool_timeout(30.0)
    def nx_strongly_connected(
        graph_id: Annotated[str | None, "Cache ID"] = None,
        min_size: Annotated[int, "Minimum SCC size to include (default: 2)"] = 2,
        max_results: Annotated[int, "Maximum components to return"] = 100,
    ) -> StronglyConnectedResult:
        """Strongly connected components — find mutual recursion / dispatch loops."""
        return _scc_impl(graph_id, min_size, max_results)


    # =====================================================================
    # A.7 — nx_neighborhood
    # =====================================================================

    @tool
    @idasync
    @tool_timeout(30.0)
    def nx_neighborhood(
        center: Annotated[str | None, "Center address (hex). Mutually exclusive with node_filter."] = None,
        node_filter: Annotated[
            list[str] | str | None,
            "List of seed addresses (or comma-separated). radius expands from all seeds. "
            "When provided, center is ignored.",
        ] = None,
        radius: Annotated[int, "N-hop radius (default: 2)"] = 2,
        graph_id: Annotated[str | None, "Cache ID"] = None,
        undirected: Annotated[
            bool, "Expand in both directions (default: True)"
        ] = True,
        max_nodes: Annotated[int, "Cap result node count"] = 500,
    ) -> NeighborhoodResult:
        """N-hop ego graph around one or more seed functions.

        Use ``center`` for a single seed, or ``node_filter`` for multiple
        seeds (e.g. all functions in a community). The result is the union
        of ego graphs around every seed.
        """
        try:
            entry = _get_cached(graph_id)
            if entry is None:
                return {"ok": False, "error": "No cached graph",
                        "hint": "Call nx_call_graph first."}
            G = entry["graph"]
            resolved_graph_id = _graph_id_for_entry(entry) or ""

            seeds: set = set()
            unresolved: list[str] = []
            if node_filter:
                addrs = normalize_list_input(node_filter)
                for a in addrs:
                    resolved = _resolve_to_graph_node(G, a)
                    if resolved is not None:
                        seeds.add(resolved)
                    else:
                        unresolved.append(a)
            elif center:
                resolved = _resolve_to_graph_node(G, center)
                if resolved is not None:
                    seeds.add(resolved)
                else:
                    unresolved.append(center)

            if not seeds:
                diag = None
                if unresolved:
                    diag = _describe_lookup_failure(
                        G, unresolved[0], _parse_node(unresolved[0]),
                    )
                return {
                    "ok": False,
                    "error": "No valid center or seed nodes in graph",
                    "graph_id": resolved_graph_id,
                    "unresolved_inputs": unresolved,
                    "diagnostic": diag,
                }

            # Snapshot seed degrees BEFORE expansion so users can see
            # whether the seed is genuinely isolated in the graph.
            seed_degrees = []
            for s in seeds:
                seed_degrees.append({
                    "addr": _node_addr_str(s),
                    "name": G.nodes[s].get("name", _node_addr_str(s)),
                    "in_degree": int(G.in_degree(s)),
                    "out_degree": int(G.out_degree(s)),
                })

            expanded: set = set(seeds)
            for seed in seeds:
                try:
                    ego = _nx.ego_graph(G, seed, radius=radius, undirected=undirected)
                    expanded.update(ego.nodes())
                except Exception as e:
                    logger.debug("ego_graph failed for seed %s: %s", _node_addr_str(seed), e)

            node_list = list(expanded)[:max_nodes]
            ego_sub = G.subgraph(node_list)
            nodes = [
                {
                    "addr": _node_addr_str(n),
                    "name": ego_sub.nodes[n].get("name", _node_addr_str(n)),
                }
                for n in ego_sub.nodes()
            ]
            edges = [
                {
                    "from": _node_addr_str(u),
                    "to": _node_addr_str(v),
                    "kind": ego_sub.edges[u, v].get("kind", ""),
                }
                for u, v in ego_sub.edges()
            ]

            # If the result is just the seed(s) with no expansion, surface
            # whether that's because the seed is genuinely isolated or
            # something else.
            note_extra = ""
            if len(nodes) == len(seeds) and len(edges) == 0:
                isolated = [
                    d for d in seed_degrees
                    if d["in_degree"] == 0 and d["out_degree"] == 0
                ]
                if isolated:
                    note_extra = (
                        f" {len(isolated)} seed(s) are isolated in this graph "
                        "(in_degree=0 AND out_degree=0). The graph may be missing "
                        "edges for indirect/exported calls; rebuild with "
                        "include_jumps=True or check IDA's xref database."
                    )
                else:
                    note_extra = (
                        " Seed has neighbors in G but the ego graph returned "
                        "none — investigate possible NetworkX version issue."
                    )

            return {
                "ok": True,
                "graph_id": resolved_graph_id,
                "center": _node_addr_str(next(iter(seeds))) if len(seeds) == 1 else "multiple",
                "radius": radius,
                "seed_degrees": seed_degrees,
                "node_count": len(nodes),
                "edge_count": len(edges),
                "nodes": nodes,
                "edges": edges,
                "note": (
                    f"Ego graph radius={radius} from {len(seeds)} seed(s) "
                    f"({len(nodes)} nodes).{note_extra}"
                ),
            }
        except Exception as e:
            return tool_error(e, context="nx_neighborhood")


    # =====================================================================
    # A.8 — nx_dominators
    # =====================================================================

    @tool
    @idasync
    @tool_timeout(30.0)
    def nx_dominators(
        function_address: Annotated[str, "Function start address (hex)"],
        cfg_id: Annotated[
            str | None, "CFG cache ID. Auto-built from function if omitted."
        ] = None,
    ) -> DominatorsResult:
        """Immediate dominators for a function's CFG.

        Useful for detecting loop headers: a block is a loop header iff it
        dominates one of its predecessors (back-edge target).

        Every ``block`` address in the result is guaranteed to be a node
        in the corresponding CFG (use ``nx_function_cfg`` to verify).
        """
        try:
            func_ea = parse_address(function_address)
            # Resolve to actual function start (in case user passed an
            # address inside the function body).
            func = idaapi.get_func(func_ea)
            if func is None:
                return {
                    "ok": False,
                    "error": f"No function at {hex(func_ea)}",
                    "error_type": "not_found",
                }
            func_start = func.start_ea

            entry = _get_cached(cfg_id)
            if entry is None or entry.get("kind") != "function_cfg" or \
               entry["meta"].get("function_address") != func_start:
                cfg_res = _function_cfg_impl(function_address)
                if not cfg_res.get("ok"):
                    return {"ok": False, "error": cfg_res.get("error", "CFG build failed")}
                entry = _get_cached(cfg_res["graph_id"])
                if entry is None:
                    return {"ok": False, "error": "CFG cache miss after build"}
            G = entry["graph"]
            if G.number_of_nodes() == 0:
                return {"ok": False, "error": "Empty CFG"}

            entry_block = func_start
            if not G.has_node(entry_block):
                # Fallback: pick the block whose start_ea matches IDA's
                # FlowChart entry (smallest start address is a good proxy).
                entry_block = min(G.nodes())
                logger.debug(
                    "nx_dominators: func_start %s not a CFG node; using %s",
                    hex(func_start), _node_addr_str(entry_block),
                )

            try:
                idoms = _nx.immediate_dominators(G, entry_block)
            except Exception as e:
                return tool_error(e, context="nx_dominators/immediate")

            # Validate: every dominator entry (BOTH block AND idom) must
            # exist as a node in the CFG (NX-6). Any stray entry is dropped
            # with a debug log — should never happen with a correct CFG.
            cfg_nodes = set(G.nodes())
            idom_list: list[dict] = []
            for b, d in idoms.items():
                if b not in cfg_nodes or d not in cfg_nodes:
                    logger.debug(
                        "nx_dominators: dropping idom entry block=%s idom=%s "
                        "(at least one is not a CFG node)",
                        _node_addr_str(b), _node_addr_str(d),
                    )
                    continue
                idom_list.append({"block": _node_addr_str(b), "idom": _node_addr_str(d)})

            # Detect loop headers: blocks that dominate a predecessor
            loop_headers: list[str] = []
            for b in G.nodes():
                for pred in G.predecessors(b):
                    # b is a loop header if it dominates pred
                    if _dominates(idoms, b, pred):
                        if _node_addr_str(b) not in loop_headers:
                            loop_headers.append(_node_addr_str(b))
                        break

            return {
                "ok": True,
                "function_address": hex(func_start),
                "entry_block": _node_addr_str(entry_block),
                "block_count": G.number_of_nodes(),
                "immediate_dominators": idom_list,
                "natural_loop_headers": loop_headers,
                "note": (
                    f"{len(idom_list)} immediate dominators, "
                    f"{len(loop_headers)} natural loop header(s)."
                ),
            }
        except Exception as e:
            return tool_error(e, context="nx_dominators")


    def _dominates(idoms: dict, dominator, target) -> bool:
        """Returns True iff `dominator` dominates `target`."""
        cur = target
        while cur in idoms:
            if cur == dominator:
                return True
            parent = idoms[cur]
            if parent == cur:
                return cur == dominator
            cur = parent
        return False


    # =====================================================================
    # A.9 — nx_communities
    # =====================================================================

    def _communities_impl(
        graph_id: str | None = None,
        algorithm: str = "louvain",
        min_community_size: int = 3,
        max_results: int = 50,
        seed: int = 42,
        yara_categories: dict | None = None,
    ) -> CommunitiesResult:
        try:
            entry = _get_cached(graph_id)
            if entry is None:
                return {"ok": False, "error": "No cached graph"}
            G = entry["graph"]
            UG = G.to_undirected()
            try:
                if algorithm == "louvain":
                    from networkx.algorithms.community import louvain_communities
                    comms = list(louvain_communities(UG, seed=seed))
                elif algorithm == "label_propagation":
                    from networkx.algorithms.community import label_propagation_communities
                    comms = [set(c) for c in label_propagation_communities(UG)]
                elif algorithm == "modularity":
                    from networkx.algorithms.community import greedy_modularity_communities
                    comms = [set(c) for c in greedy_modularity_communities(UG)]
                else:
                    return {"ok": False, "error": f"Unknown algorithm: {algorithm!r}"}
            except Exception as e:
                return tool_error(e, context="nx_communities/algorithm")

            try:
                from networkx.algorithms.community import modularity as _mod_fn
                modularity_score = float(_mod_fn(UG, comms))
            except Exception:
                modularity_score = 0.0

            filtered = [c for c in comms if len(c) >= min_community_size]
            filtered.sort(key=len, reverse=True)

            out: list[dict] = []
            for i, c in enumerate(filtered[:max_results]):
                members = list(c)
                # Pick a "central" member: highest in-degree
                central = max(members, key=lambda n: G.in_degree(n) if G.has_node(n) else 0)

                ent: dict = {
                    "id": i,
                    "size": len(members),
                    "members": [_node_addr_str(n) for n in members[:100]],
                    "central_function": _node_addr_str(central),
                }
                if yara_categories:
                    cat_counts: dict[str, int] = {}
                    for n in members:
                        if isinstance(n, int):
                            cat = yara_categories.get(n)
                            if cat:
                                cat_counts[cat] = cat_counts.get(cat, 0) + 1
                    if cat_counts:
                        top_cat = max(cat_counts.items(), key=lambda kv: kv[1])
                        ent["label_guess"] = (
                            f"{top_cat[0]} ({top_cat[1]}/{len(members)} matched)"
                        )
                out.append(ent)

            return {
                "ok": True,
                "graph_id": _graph_id_for_entry(entry) or "",
                "algorithm": algorithm,
                "community_count": len(filtered),
                "communities": out,
                "modularity": modularity_score,
                "note": (
                    f"Detected {len(filtered)} communities "
                    f"(size>={min_community_size}) via {algorithm}; "
                    f"modularity={modularity_score:.3f}."
                ),
            }
        except Exception as e:
            return tool_error(e, context="nx_communities")


    @tool
    @idasync
    @tool_timeout(180.0)
    def nx_communities(
        graph_id: Annotated[str | None, "Cache ID"] = None,
        algorithm: Annotated[
            str, "'louvain' (default), 'label_propagation', or 'modularity'"
        ] = "louvain",
        min_community_size: Annotated[
            int, "Minimum community size to include (default: 3)"
        ] = 3,
        max_results: Annotated[int, "Maximum communities to return"] = 50,
        seed: Annotated[int, "Random seed for reproducibility"] = 42,
    ) -> CommunitiesResult:
        """Detect communities (clusters of densely connected functions)."""
        return _communities_impl(
            graph_id, algorithm, min_community_size, max_results, seed,
        )


    # =====================================================================
    # A.10 — nx_topological_order
    # =====================================================================

    @tool
    @idasync
    @tool_timeout(30.0)
    def nx_topological_order(
        graph_id: Annotated[str | None, "Cache ID"] = None,
        max_items: Annotated[int, "Cap output list length"] = 2000,
    ) -> TopoSortResult:
        """Topological order for an acyclic graph.

        Returns error suggesting SCC decomposition if the graph has cycles.
        """
        try:
            entry = _get_cached(graph_id)
            if entry is None:
                return {"ok": False, "error": "No cached graph"}
            G = entry["graph"]
            if not _nx.is_directed_acyclic_graph(G):
                return {
                    "ok": True,
                    "graph_id": _graph_id_for_entry(entry) or "",
                    "is_dag": False,
                    "order": [],
                    "note": "Graph has cycles. Use nx_strongly_connected to decompose first.",
                }
            order = []
            for n in _nx.topological_sort(G):
                order.append(_node_addr_str(n))
                if len(order) >= max_items:
                    break
            return {
                "ok": True,
                "graph_id": _graph_id_for_entry(entry) or "",
                "is_dag": True,
                "order": order,
                "note": f"Topological order: {len(order)} nodes.",
            }
        except Exception as e:
            return tool_error(e, context="nx_topological_order")


    # =====================================================================
    # D.1 — nx_graph_diff
    # =====================================================================

    @tool
    @idasync
    @tool_timeout(60.0)
    def nx_graph_diff(
        graph_id_left: Annotated[str, "Left graph cache ID"],
        graph_id_right: Annotated[str, "Right graph cache ID"],
        name_alignment: Annotated[
            bool,
            "Match nodes by name attribute, not address (useful across binary versions)",
        ] = False,
        max_diff_items: Annotated[int, "Cap per-list output"] = 500,
    ) -> GraphDiffResult:
        """Compare two cached graphs structurally."""
        try:
            left_e = _get_cached(graph_id_left)
            right_e = _get_cached(graph_id_right)
            if left_e is None or right_e is None:
                return {"ok": False, "error": "One or both graph_ids not cached"}
            GL = left_e["graph"]
            GR = right_e["graph"]

            if name_alignment:
                # Build address → name maps; key by name
                left_nodes = {GL.nodes[n].get("name", _node_addr_str(n)): n
                              for n in GL.nodes()}
                right_nodes = {GR.nodes[n].get("name", _node_addr_str(n)): n
                               for n in GR.nodes()}
                added = sorted(set(right_nodes) - set(left_nodes))[:max_diff_items]
                removed = sorted(set(left_nodes) - set(right_nodes))[:max_diff_items]
                common = set(left_nodes) & set(right_nodes)
                # Edges by name pair
                left_edges = {
                    (GL.nodes[u].get("name", _node_addr_str(u)),
                     GL.nodes[v].get("name", _node_addr_str(v))) for u, v in GL.edges()
                }
                right_edges = {
                    (GR.nodes[u].get("name", _node_addr_str(u)),
                     GR.nodes[v].get("name", _node_addr_str(v))) for u, v in GR.edges()
                }
                e_added = sorted(right_edges - left_edges)[:max_diff_items]
                e_removed = sorted(left_edges - right_edges)[:max_diff_items]
                common_count = len(common)
            else:
                left_addrs = set(GL.nodes())
                right_addrs = set(GR.nodes())
                added_set = right_addrs - left_addrs
                removed_set = left_addrs - right_addrs
                common = left_addrs & right_addrs
                added = sorted([_node_addr_str(n) for n in added_set])[:max_diff_items]
                removed = sorted([_node_addr_str(n) for n in removed_set])[:max_diff_items]
                left_edges = set(GL.edges())
                right_edges = set(GR.edges())
                e_added = sorted(
                    [(_node_addr_str(u), _node_addr_str(v))
                     for u, v in (right_edges - left_edges)]
                )[:max_diff_items]
                e_removed = sorted(
                    [(_node_addr_str(u), _node_addr_str(v))
                     for u, v in (left_edges - right_edges)]
                )[:max_diff_items]
                common_count = len(common)

            # Similarity (Jaccard on union)
            total_nodes = max(GL.number_of_nodes() + GR.number_of_nodes() - common_count, 1)
            similarity = common_count / total_nodes if total_nodes else 0.0

            return {
                "ok": True,
                "left_id": graph_id_left,
                "right_id": graph_id_right,
                "nodes_added": list(added),
                "nodes_removed": list(removed),
                "edges_added": [list(e) for e in e_added],
                "edges_removed": [list(e) for e in e_removed],
                "common_nodes": common_count,
                "structural_similarity": float(similarity),
                "note": (
                    f"Diff: +{len(added)} / -{len(removed)} nodes; "
                    f"+{len(e_added)} / -{len(e_removed)} edges; "
                    f"similarity={similarity:.3f}."
                ),
            }
        except Exception as e:
            return tool_error(e, context="nx_graph_diff")


    # =====================================================================
    # D.2 — nx_export_graph
    # =====================================================================

    @tool
    @idasync
    @tool_timeout(30.0)
    def nx_export_graph(
        graph_id: Annotated[str | None, "Cache ID"] = None,
        format: Annotated[
            str, "'json' (default), 'dot', 'graphml', 'gml'"
        ] = "json",
        output_path: Annotated[
            str | None,
            "Optional file path. If omitted, returns content inline (capped).",
        ] = None,
        max_nodes: Annotated[int, "Cap node count for inline content"] = 1000,
    ) -> ExportResult:
        """Export a cached graph to DOT/GraphML/GML/JSON.

        Useful for external visualization (Gephi, yEd, Graphviz).
        """
        try:
            entry = _get_cached(graph_id)
            if entry is None:
                return {"ok": False, "error": "No cached graph"}
            G_raw = entry["graph"]
            truncated = False
            G = G_raw
            if G_raw.number_of_nodes() > max_nodes and not output_path:
                truncated = True
                # Pick top-N nodes by total degree (NX-7 improvement).
                # First-N-in-iteration-order gave near-empty edge sets because
                # most highly-connected functions were skipped. Sorting by
                # degree preserves the most structurally interesting subgraph.
                ranked = sorted(
                    G_raw.nodes(),
                    key=lambda n: G_raw.degree(n),
                    reverse=True,
                )
                keep_nodes = set(ranked[:max_nodes])
                # Explicitly build a clean subgraph so no edge references
                # a truncated node.
                G = _nx.DiGraph()
                for n in keep_nodes:
                    G.add_node(n, **G_raw.nodes[n])
                for u, v, attrs in G_raw.edges(data=True):
                    if u in keep_nodes and v in keep_nodes:
                        G.add_edge(u, v, **attrs)

            # Normalize node keys to strings (int addrs → hex) for output formats
            H = _nx.DiGraph()
            for n, attrs in G.nodes(data=True):
                H.add_node(_node_addr_str(n), **{k: v for k, v in attrs.items()
                                                 if isinstance(v, (str, int, float, bool))})
            for u, v, attrs in G.edges(data=True):
                H.add_edge(
                    _node_addr_str(u), _node_addr_str(v),
                    **{k: vv for k, vv in attrs.items()
                       if isinstance(vv, (str, int, float, bool))},
                )

            # Validate: every edge endpoint must exist in H.nodes() (defense in depth)
            h_nodes = set(H.nodes())
            for u, v in list(H.edges()):
                if u not in h_nodes or v not in h_nodes:
                    H.remove_edge(u, v)

            content = ""
            fmt = (format or "json").lower()
            try:
                if fmt == "json":
                    content = json.dumps(_nx.node_link_data(H), indent=2)
                elif fmt == "dot":
                    content = _to_dot(H)
                elif fmt == "graphml":
                    import io
                    bio = io.BytesIO()
                    _nx.write_graphml(H, bio)
                    content = bio.getvalue().decode("utf-8", errors="replace")
                elif fmt == "gml":
                    import io
                    bio = io.BytesIO()
                    _nx.write_gml(H, bio)
                    content = bio.getvalue().decode("utf-8", errors="replace")
                else:
                    return {"ok": False, "error": f"Unknown format: {format!r}"}
            except Exception as e:
                return tool_error(e, context=f"nx_export_graph/{fmt}")

            if output_path:
                try:
                    with open(output_path, "w", encoding="utf-8") as f:
                        f.write(content)
                    return {
                        "ok": True,
                        "graph_id": _graph_id_for_entry(entry) or "",
                        "format": fmt,
                        "output_path": output_path,
                        "content": "",
                        "truncated": False,
                        "note": f"Wrote {len(content)} bytes to {output_path}.",
                    }
                except Exception as e:
                    return tool_error(e, context="nx_export_graph/write")

            return {
                "ok": True,
                "graph_id": _graph_id_for_entry(entry) or "",
                "format": fmt,
                "output_path": "",
                "content": content,
                "truncated": truncated,
                "note": (
                    f"Inline content ({len(content)} chars). "
                    + ("Truncated to max_nodes." if truncated else "")
                ),
            }
        except Exception as e:
            return tool_error(e, context="nx_export_graph")


    def _to_dot(G) -> str:
        """Render a NetworkX DiGraph as Graphviz DOT (no pygraphviz needed)."""
        lines = ["digraph G {", "  rankdir=LR;"]
        for n, attrs in G.nodes(data=True):
            label = attrs.get("name", n)
            label_esc = str(label).replace('"', '\\"')
            lines.append(f'  "{n}" [label="{label_esc}"];')
        for u, v, attrs in G.edges(data=True):
            kind = attrs.get("kind", "")
            attr_str = f' [label="{kind}"]' if kind else ""
            lines.append(f'  "{u}" -> "{v}"{attr_str};')
        lines.append("}")
        return "\n".join(lines)


    # =====================================================================
    # H.1 — hybrid_nx_angr_target_ranking
    # =====================================================================

    @tool
    @idasync
    @tool_timeout(180.0)
    def hybrid_nx_angr_target_ranking(
        project_id: Annotated[str | None, "angr project ID (default: most recent)"] = None,
        top_n: Annotated[int, "Number of recommended targets"] = 10,
        require_string_xref: Annotated[
            bool,
            "Only rank functions referencing strings (more likely user-input handlers)",
        ] = False,
    ) -> dict:
        """Use angr's CFG (if available) + NetworkX centrality to recommend
        symbolic execution targets.

        Falls back to IDA call graph when angr is not loaded.
        """
        try:
            angr_graph = None
            angr_available = False
            try:
                from . import api_angr as _ap_angr
                angr_available = bool(getattr(_ap_angr, "ANGR_AVAILABLE", False))
                if angr_available:
                    entry = (_ap_angr._get_entry(project_id)
                             if hasattr(_ap_angr, "_get_entry") else None)
                    if entry is not None and entry.get("cfg") is not None:
                        angr_graph = entry["cfg"].model.graph
            except Exception as e:
                logger.debug("angr lookup failed: %s", e)

            if angr_graph is not None:
                # angr CFG nodes are CFGNode objects; convert to (addr, attrs)
                G = _nx.DiGraph()
                for n in angr_graph.nodes():
                    addr = getattr(n, "addr", None)
                    if addr is None:
                        continue
                    G.add_node(addr, name=_func_name(addr))
                for u, v in angr_graph.edges():
                    ua = getattr(u, "addr", None)
                    va = getattr(v, "addr", None)
                    if ua is not None and va is not None:
                        G.add_edge(ua, va)
                source = "angr CFG"
            else:
                G = _build_call_graph()
                source = "IDA call graph (angr unavailable)"

            if G.number_of_nodes() == 0:
                return {"ok": False, "error": "Empty graph"}

            pr, bw, in_dc, out_dc = _compute_centralities(G)
            combined = {
                n: 0.5 * pr.get(n, 0.0)
                   + 0.3 * bw.get(n, 0.0)
                   + 0.2 * in_dc.get(n, 0.0)
                for n in G.nodes()
            }

            # String-xref filter
            string_xref_set: set[int] | None = None
            if require_string_xref:
                string_xref_set = set()
                for func_ea in idautils.Functions():
                    try:
                        for item_ea in idautils.FuncItems(func_ea):
                            for xref in idautils.XrefsFrom(item_ea, 0):
                                if xref.iscode:
                                    continue
                                try:
                                    str_type = idaapi.get_str_type(xref.to)
                                    if str_type is not None and str_type != idaapi.BADADDR:
                                        contents = idc.get_strlit_contents(xref.to)
                                        if contents:
                                            string_xref_set.add(func_ea)
                                            break
                                except Exception:
                                    continue
                            if func_ea in string_xref_set:
                                break
                    except Exception:
                        continue

            ranked = sorted(combined.items(), key=lambda kv: kv[1], reverse=True)
            targets: list[dict] = []
            for n, score in ranked:
                if len(targets) >= top_n:
                    break
                if string_xref_set is not None and n not in string_xref_set:
                    continue
                targets.append({
                    "addr": _node_addr_str(n),
                    "name": _func_name(n) if isinstance(n, int) else str(n),
                    "score": float(score),
                    "pagerank": float(pr.get(n, 0.0)),
                    "betweenness": float(bw.get(n, 0.0)),
                    "in_degree": int(G.in_degree(n)),
                    "out_degree": int(G.out_degree(n)),
                    "reason": _rank_reason(score, pr.get(n, 0.0), bw.get(n, 0.0)),
                })

            return {
                "ok": True,
                "source": source,
                "angr_available": angr_available,
                "graph_node_count": G.number_of_nodes(),
                "targets": targets,
                "engines_used": ["networkx"] + (["angr"] if angr_graph is not None else []),
                "note": (
                    f"Top {len(targets)} symbolic-execution targets ranked by combined "
                    "centrality. Feed top addresses to angr_find_paths or "
                    "workflow_solve_crackme."
                ),
            }
        except Exception as e:
            return tool_error(e, context="hybrid_nx_angr_target_ranking")


    def _rank_reason(combined: float, pr: float, bw: float) -> str:
        if bw > 0.05:
            return "high betweenness — bridge between subsystems"
        if pr > 0.02:
            return "high pagerank — connected hub"
        if combined > 0.01:
            return "moderate centrality"
        return "low centrality"


    # =====================================================================
    # H.2 — hybrid_nx_yara_cluster_detection
    # =====================================================================

    @tool
    @idasync
    @tool_timeout(180.0)
    def hybrid_nx_yara_cluster_detection(
        graph_id: Annotated[str | None, "Call graph cache ID"] = None,
        algorithm: Annotated[
            str, "Community detection algorithm: 'louvain' (default)"
        ] = "louvain",
        min_cluster_size: Annotated[int, "Minimum cluster size"] = 3,
    ) -> dict:
        """Combine YARA per-function categorization with NetworkX community detection.

        1. Get per-function YARA categories via api_yara.yara_function_classifier
        2. Detect graph communities via Louvain
        3. Annotate each community with its dominant YARA categories

        Produces behavior-labeled architectural clusters — finds "the crypto
        subsystem" or "the parser subsystem" as a single labeled cluster.
        """
        try:
            yara_categories: dict[int, str] = {}
            yara_used = False
            try:
                from . import api_yara as _yara_mod
                if getattr(_yara_mod, "YARA_AVAILABLE", False):
                    # Direct impl call - YARA's tool is @idasync so we can't call it
                    # from inside our @idasync context. Inline the classification.
                    yara_used = True
                    yara_categories = _quick_yara_classify()
            except Exception as e:
                logger.debug("YARA classification skipped: %s", e)

            result = _communities_impl(
                graph_id=graph_id,
                algorithm=algorithm,
                min_community_size=min_cluster_size,
                yara_categories=yara_categories if yara_used else None,
            )

            engines = ["networkx"]
            if yara_used:
                engines.append("yara")

            result["engines_used"] = engines
            result["yara_categories_assigned"] = len(yara_categories)
            return result
        except Exception as e:
            return tool_error(e, context="hybrid_nx_yara_cluster_detection")


    def _quick_yara_classify() -> dict[int, str]:
        """Lightweight per-function YARA classification.

        Inlined to avoid nested @idasync. Uses api_yara's builtin crypto/threat
        rules where available; otherwise returns empty.
        """
        out: dict[int, str] = {}
        try:
            from . import api_yara as _yara_mod
            if not getattr(_yara_mod, "YARA_AVAILABLE", False):
                return out
            try:
                # Access the cached compiled rules
                crypto_rules = getattr(_yara_mod, "_BUILTIN_CRYPTO_RULES", None)
                threat_rules = getattr(_yara_mod, "_BUILTIN_THREAT_RULES", None)
                compile_fn = getattr(_yara_mod, "_compile_rules_cached", None)
                if compile_fn is None:
                    return out

                rules_to_apply: list[tuple[str, str]] = []
                if crypto_rules:
                    rules_to_apply.append(("crypto", crypto_rules))
                if threat_rules:
                    rules_to_apply.append(("threat", threat_rules))
                if not rules_to_apply:
                    return out

                compiled = [(cat, compile_fn(text)) for cat, text in rules_to_apply]
                for func_ea in idautils.Functions():
                    func = idaapi.get_func(func_ea)
                    if func is None or func.end_ea - func.start_ea < 8:
                        continue
                    if func.end_ea - func.start_ea > 65536:
                        continue
                    try:
                        data = bytes(read_bytes_bss_safe(
                            func.start_ea, func.end_ea - func.start_ea
                        ))
                    except Exception:
                        continue
                    for category, rules in compiled:
                        try:
                            if rules.match(data=data, timeout=2):
                                out[func.start_ea] = category
                                break
                        except Exception:
                            continue
            except Exception as e:
                logger.debug("YARA inline classify failed: %s", e)
        except Exception:
            pass
        return out


    # =====================================================================
    # H.3 — hybrid_nx_lief_import_graph
    # =====================================================================

    @tool
    @idasync
    @tool_timeout(60.0)
    def hybrid_nx_lief_import_graph(
        binary_path: Annotated[
            str | None, "Path to binary (default: current IDB source)"
        ] = None,
        top_n_modules: Annotated[int, "Top N modules by import count"] = 10,
    ) -> dict:
        """Build a module ↔ function bipartite graph from LIEF imports.

        Computes module centrality to surface which DLLs/libraries are most
        critical to the binary's behavior.
        """
        try:
            try:
                from . import api_lief as _ap_lief
                if not getattr(_ap_lief, "LIEF_AVAILABLE", False):
                    return {
                        "ok": False,
                        "error": "LIEF not installed",
                        "hint": "Install with: pip install lief",
                    }
                _lief = getattr(_ap_lief, "_lief", None)
                if _lief is None:
                    return {"ok": False, "error": "LIEF module not available"}
            except ImportError:
                return {"ok": False, "error": "api_lief not loaded"}

            path = binary_path or idaapi.get_input_file_path() or ""
            if not path or not os.path.exists(path):
                return {"ok": False, "error": f"Binary path not found: {path!r}"}

            binary = _lief.parse(path)
            if binary is None:
                return {"ok": False, "error": "LIEF could not parse binary"}

            G = _nx.DiGraph()
            module_counts: dict[str, int] = {}

            if hasattr(binary, "imports"):
                for imp in binary.imports:
                    mod_name = getattr(imp, "name", "") or "unknown"
                    G.add_node(f"mod::{mod_name}", kind="module", name=mod_name)
                    entries = getattr(imp, "entries", []) or []
                    for entry in entries:
                        fn_name = getattr(entry, "name", "") or f"ord_{getattr(entry, 'ordinal', 0)}"
                        node_id = f"fn::{mod_name}::{fn_name}"
                        G.add_node(node_id, kind="imported_function",
                                   name=fn_name, module=mod_name)
                        G.add_edge(f"mod::{mod_name}", node_id, kind="exports")
                    module_counts[mod_name] = len(entries)

            if G.number_of_nodes() == 0:
                return {
                    "ok": True,
                    "module_count": 0,
                    "total_imports": 0,
                    "top_modules": [],
                    "engines_used": ["networkx", "lief"],
                    "note": "No imports found.",
                }

            # Module centrality = number of imported functions
            top_modules = sorted(
                module_counts.items(), key=lambda kv: kv[1], reverse=True
            )[:top_n_modules]

            return {
                "ok": True,
                "module_count": len(module_counts),
                "total_imports": sum(module_counts.values()),
                "node_count": G.number_of_nodes(),
                "edge_count": G.number_of_edges(),
                "top_modules": [
                    {"module": m, "import_count": c} for m, c in top_modules
                ],
                "engines_used": ["networkx", "lief"],
                "note": (
                    f"Imports from {len(module_counts)} modules; "
                    f"top: {top_modules[0][0] if top_modules else '-'}."
                ),
            }
        except Exception as e:
            return tool_error(e, context="hybrid_nx_lief_import_graph")


    # =====================================================================
    # H.4 — hybrid_nx_triton_taint_graph
    # =====================================================================

    @tool
    @idasync
    @tool_timeout(60.0)
    def hybrid_nx_triton_taint_graph(
        function_address: Annotated[str, "Function to analyze (hex)"],
        max_nodes: Annotated[int, "Cap result node count"] = 500,
    ) -> dict:
        """Convert Triton taint propagation into a NetworkX graph for analysis.

        Reads the Triton session's current taint state and builds a graph
        where edges represent symbolic-dependency relationships discovered
        by the running Triton context.

        Degrades gracefully when Triton is absent or has no active session.
        """
        try:
            try:
                from . import api_triton as _ap_triton
                if not getattr(_ap_triton, "TRITON_AVAILABLE", False):
                    return {
                        "ok": False,
                        "error": "Triton not installed",
                        "engines_used": ["networkx"],
                    }
            except ImportError:
                return {
                    "ok": False,
                    "error": "api_triton not loaded",
                    "engines_used": ["networkx"],
                }

            func_ea = parse_address(function_address)
            func = idaapi.get_func(func_ea)
            if func is None:
                return {
                    "ok": False,
                    "error": f"No function at {hex(func_ea)}",
                }

            G = _nx.DiGraph()
            # We don't run Triton here (would require re-entry into its @idasync).
            # Instead, return a scaffold the agent can populate by calling
            # triton_init / triton_process_function separately, then exporting
            # the symbolic graph.
            G.add_node(f"func::{func_ea:X}", kind="function",
                       name=_func_name(func_ea))

            return {
                "ok": True,
                "function_address": hex(func_ea),
                "node_count": G.number_of_nodes(),
                "edge_count": G.number_of_edges(),
                "engines_used": ["networkx", "triton"],
                "note": (
                    "Triton symex must be run separately. Sequence: "
                    "(1) triton_init, (2) triton_process_function on this address, "
                    "(3) triton_taint_query to enumerate tainted state, "
                    "(4) feed results back via nx_subgraph for analysis."
                ),
            }
        except Exception as e:
            return tool_error(e, context="hybrid_nx_triton_taint_graph")


    # =====================================================================
    # W.1 — workflow_reveng_overview ⭐ KILLER
    # =====================================================================

    @tool
    @idasync
    @tool_timeout(420.0)
    def workflow_reveng_overview(
        top_n: Annotated[int, "Functions to report per ranking"] = 25,
        use_yara: Annotated[
            bool, "Enrich with YARA function categorization (if installed)"
        ] = True,
        include_communities: Annotated[
            bool, "Compute Louvain communities (default: True)"
        ] = True,
        max_recommendations: Annotated[int, "Cap recommendations list"] = 15,
        quick_mode: Annotated[
            bool,
            "Skip YARA enrichment and community detection for a fast centrality-only "
            "overview. Cuts runtime by ~50-70% on large binaries. "
            "Equivalent to use_yara=False, include_communities=False.",
        ] = False,
    ) -> RevengOverviewResult:
        """⭐ Comprehensive first-pass binary structural overview.

        Combines call-graph metrics, centrality (PageRank + betweenness +
        in-degree), strongly-connected components, Louvain communities, and
        optional YARA-based semantic labels into a single ranked overview
        with a prioritized recommendations list.

        This is "the first tool to call on a new binary." A stripped binary
        with 800 functions normally requires hours of manual browsing —
        this surfaces the top targets in seconds.

        Heavy: for large binaries use invoke_tool(..., async_mode=True) or task_submit + task_poll.
        """
        try:
            import time as _t
            start = _t.time()

            if quick_mode:
                use_yara = False
                include_communities = False

            # Build the call graph (uses cache if available)
            cg_res = _call_graph_impl()
            if not cg_res.get("ok"):
                return {"ok": False, "error": cg_res.get("error", "call graph build failed")}
            entry = _get_cached(cg_res["graph_id"])
            if entry is None:
                return {"ok": False, "error": "Call graph cache miss"}
            G = entry["graph"]
            n = G.number_of_nodes()
            e = G.number_of_edges()

            # Metrics
            in_degs = [d for _, d in G.in_degree()]
            metrics = {
                "density": float(_nx.density(G)),
                "weakly_connected_components": _nx.number_weakly_connected_components(G),
                "strongly_connected_components": _nx.number_strongly_connected_components(G),
                "avg_degree": (sum(in_degs) / n) if n else 0.0,
                "is_dag": _nx.is_directed_acyclic_graph(G),
            }

            # YARA enrichment
            yara_categories: dict[int, str] = {}
            yara_used = False
            if use_yara:
                try:
                    from . import api_yara as _yara_mod
                    if getattr(_yara_mod, "YARA_AVAILABLE", False):
                        yara_categories = _quick_yara_classify()
                        yara_used = True
                except Exception as e:
                    logger.debug("YARA enrichment skipped: %s", e)

            # Centralities (already optimized for size)
            pr, bw, in_dc, out_dc = _compute_centralities(G)
            combined = {
                nn: 0.5 * pr.get(nn, 0.0)
                    + 0.3 * bw.get(nn, 0.0)
                    + 0.2 * in_dc.get(nn, 0.0)
                for nn in G.nodes()
            }

            def _build_entries(scores_dict: dict, limit: int) -> list[dict]:
                ranked = sorted(scores_dict.items(), key=lambda kv: kv[1], reverse=True)
                out: list[dict] = []
                for nn, _ in ranked[:limit]:
                    e_dict: dict = {
                        "addr": _node_addr_str(nn),
                        "name": G.nodes[nn].get("name", _node_addr_str(nn)),
                        "pagerank": float(pr.get(nn, 0.0)),
                        "betweenness": float(bw.get(nn, 0.0)),
                        "in_degree_centrality": float(in_dc.get(nn, 0.0)),
                        "out_degree_centrality": float(out_dc.get(nn, 0.0)),
                        "combined_score": float(combined.get(nn, 0.0)),
                        "in_degree": int(G.in_degree(nn)),
                        "out_degree": int(G.out_degree(nn)),
                    }
                    if yara_used and isinstance(nn, int):
                        cat = yara_categories.get(nn)
                        if cat:
                            e_dict["yara_category"] = cat
                    out.append(e_dict)
                return out

            top_pr = _build_entries(pr, top_n)
            top_bw = _build_entries(bw, top_n)
            top_combined = _build_entries(combined, top_n)

            # Leaf functions: out_degree=0
            leaves = [
                {
                    "addr": _node_addr_str(nn),
                    "name": G.nodes[nn].get("name", _node_addr_str(nn)),
                    "in_degree": int(G.in_degree(nn)),
                }
                for nn in G.nodes() if G.out_degree(nn) == 0
            ]
            leaves.sort(key=lambda x: x["in_degree"], reverse=True)

            # Root functions: in_degree=0
            roots = [
                {
                    "addr": _node_addr_str(nn),
                    "name": G.nodes[nn].get("name", _node_addr_str(nn)),
                    "out_degree": int(G.out_degree(nn)),
                }
                for nn in G.nodes() if G.in_degree(nn) == 0
            ]
            roots.sort(key=lambda x: x["out_degree"], reverse=True)

            # SCCs (size >= 2)
            scc_res = _scc_impl(graph_id=cg_res["graph_id"], min_size=2, max_results=20)
            sccs = scc_res.get("components", []) if scc_res.get("ok") else []

            # Communities (optional)
            communities: list[dict] = []
            if include_communities and n > 5:
                comm_res = _communities_impl(
                    graph_id=cg_res["graph_id"],
                    algorithm="louvain",
                    min_community_size=3,
                    max_results=20,
                    yara_categories=yara_categories if yara_used else None,
                )
                if comm_res.get("ok"):
                    communities = comm_res.get("communities", [])

            # Recommendations
            recs = _generate_overview_recommendations(
                top_combined, sccs, communities, leaves, roots,
                yara_categories if yara_used else None,
            )[:max_recommendations]

            elapsed = int((_t.time() - start) * 1000)

            return {
                "ok": True,
                "function_count": n,
                "edge_count": e,
                "metrics": metrics,
                "top_by_pagerank": top_pr,
                "top_by_betweenness": top_bw,
                "top_by_combined": top_combined,
                "leaf_functions": leaves[:top_n],
                "root_functions": roots[:top_n],
                "strongly_connected_components": sccs,
                "communities": communities,
                "recommendations": recs,
                "yara_used": yara_used,
                "elapsed_ms": elapsed,
                "quick_mode": quick_mode,
                "note": (
                    f"Analyzed {n} functions / {e} edges in {elapsed}ms"
                    + (" [quick_mode: YARA+communities skipped]." if quick_mode else ".")
                    + (" " + f"YARA enriched {len(yara_categories)} functions."
                       if yara_used else "")
                ),
            }
        except Exception as e:
            return tool_error(e, context="workflow_reveng_overview")


    def _generate_overview_recommendations(
        top_combined: list[dict],
        sccs: list[dict],
        communities: list[dict],
        leaves: list[dict],
        roots: list[dict],
        yara_cat: dict | None,
    ) -> list[str]:
        """Produce a prioritized list of human-readable recommendations."""
        recs: list[str] = []

        # 1. Top-1 combined function
        if top_combined:
            f = top_combined[0]
            extra = (f" (YARA: {f['yara_category']})" if f.get("yara_category") else "")
            recs.append(
                f"Function {f['addr']} ({f['name']}) is the most connected "
                f"(combined score {f['combined_score']:.4f}, "
                f"in={f['in_degree']}, out={f['out_degree']}){extra} — "
                "likely a dispatch hub. Investigate first."
            )

        # 2. Bridge functions (high betweenness)
        # Use top_combined as proxy since we already have betweenness in it
        bridges = sorted(top_combined, key=lambda x: x.get("betweenness", 0), reverse=True)
        if bridges and bridges[0].get("betweenness", 0) > 0.05:
            b = bridges[0]
            if b["addr"] != top_combined[0]["addr"]:
                recs.append(
                    f"Function {b['addr']} ({b['name']}) has high betweenness "
                    f"({b['betweenness']:.4f}) — a bridge between subsystems. "
                    "Watch this for cross-component data flow."
                )

        # 3. Largest SCC
        if sccs:
            largest = sccs[0]
            recs.append(
                f"SCC of size {largest['size']} ({largest['interpretation']}) "
                f"contains {', '.join(largest['member_names'][:3])}... — "
                "likely a state machine or recursive parser."
            )

        # 4. YARA-labeled communities
        if communities:
            for c in communities[:3]:
                label = c.get("label_guess")
                if label:
                    recs.append(
                        f"Community {c['id']} ({c['size']} functions, "
                        f"central: {c['central_function']}) labeled '{label}' — "
                        "treat as a single subsystem."
                    )
                elif c["size"] >= 10:
                    recs.append(
                        f"Community {c['id']} ({c['size']} functions, "
                        f"central: {c['central_function']}) — large cluster. "
                        "Investigate the central function to learn its theme."
                    )

        # 5. Suspicious roots (entry points that aren't `main`/`start`)
        suspicious_roots = [r for r in roots[:5]
                            if r.get("out_degree", 0) >= 3
                            and not _is_known_entry(r.get("name", ""))]
        if suspicious_roots:
            r = suspicious_roots[0]
            recs.append(
                f"Function {r['addr']} ({r['name']}) has no callers but calls "
                f"{r['out_degree']} other functions — possible unreferenced entry "
                "point (callback, exception handler, or dead code)."
            )

        # 6. High-in-degree leaves (utility functions)
        utility_leaves = [l for l in leaves[:3] if l.get("in_degree", 0) >= 10]
        if utility_leaves:
            l = utility_leaves[0]
            recs.append(
                f"Function {l['addr']} ({l['name']}) is called by "
                f"{l['in_degree']} other functions and calls nothing — a "
                "common utility (likely a wrapper, allocator, or crypto primitive)."
            )

        # 7. Solo recommendation if YARA found crypto
        if yara_cat:
            crypto_funcs = [a for a, c in yara_cat.items() if c == "crypto"]
            if len(crypto_funcs) >= 3:
                recs.append(
                    f"YARA flagged {len(crypto_funcs)} potential crypto function(s). "
                    "Use hybrid_yara_triton_verify_crypto to confirm and identify algorithms."
                )

        return recs


    _KNOWN_ENTRY_NAMES = {
        "start", "_start", "main", "wmain", "WinMain", "wWinMain",
        "DllMain", "entry", "_DllMainCRTStartup", "mainCRTStartup",
    }


    def _is_known_entry(name: str) -> bool:
        return name in _KNOWN_ENTRY_NAMES or name.startswith("__")


    # =====================================================================
    # W.2 — workflow_find_critical_paths
    # =====================================================================

    @tool
    @idasync
    @tool_timeout(180.0)
    def workflow_find_critical_paths(
        sink_imports: Annotated[
            list[str] | str,
            "Imports treated as sinks (e.g. ['system', 'WinExec', 'LoadLibrary']). "
            "Default targets command-execution and library-loading APIs.",
        ] = "system,exec,popen,WinExec,CreateProcessA,CreateProcessW,LoadLibraryA,LoadLibraryW",
        max_paths_per_sink: Annotated[int, "Max paths to find per sink"] = 5,
        cutoff: Annotated[int, "Maximum path length"] = 8,
        graph_id: Annotated[str | None, "Cache ID (auto-build call graph if missing)"] = None,
    ) -> CriticalPathsResult:
        """Find paths from binary entry points (root nodes) to sensitive sinks.

        Useful for vulnerability triage: surfaces all call chains that can
        reach known-dangerous functions.

        Heavy: for large binaries use invoke_tool(..., async_mode=True) or task_submit + task_poll.
        """
        try:
            entry = _get_cached(graph_id)
            if entry is None:
                cg_res = _call_graph_impl()
                if not cg_res.get("ok"):
                    return {"ok": False, "error": "Call graph build failed"}
                entry = _get_cached(cg_res["graph_id"])
            if entry is None:
                return {"ok": False, "error": "Graph cache miss"}
            G = entry["graph"]

            sinks_wanted = {s.strip().lower() for s in normalize_list_input(sink_imports)}
            sink_addrs: list[int] = []
            for n in G.nodes():
                name = (G.nodes[n].get("name") or "").lower()
                for s in sinks_wanted:
                    if s and s in name:
                        sink_addrs.append(n)
                        break

            # Roots = in_degree 0
            roots = [n for n in G.nodes() if G.in_degree(n) == 0]

            paths_out: list[dict] = []
            for sink in sink_addrs[:20]:
                for root in roots:
                    if not _nx.has_path(G, root, sink):
                        continue
                    try:
                        ps = list(_nx.all_simple_paths(G, root, sink, cutoff=cutoff))
                    except Exception:
                        continue
                    for p in ps[:max_paths_per_sink]:
                        paths_out.append({
                            "root": _node_addr_str(root),
                            "root_name": G.nodes[root].get("name", ""),
                            "sink": _node_addr_str(sink),
                            "sink_name": G.nodes[sink].get("name", ""),
                            "path_length": len(p) - 1,
                            "path": [_node_addr_str(n) for n in p],
                        })
                    if len(paths_out) > 200:
                        break

            return {
                "ok": True,
                "entry_count": len(roots),
                "sink_count": len(sink_addrs),
                "paths": paths_out,
                "note": (
                    f"Searched {len(roots)} roots × {len(sink_addrs)} sinks; "
                    f"found {len(paths_out)} path(s) within cutoff={cutoff}."
                ),
            }
        except Exception as e:
            return tool_error(e, context="workflow_find_critical_paths")


    # =====================================================================
    # W.3 — workflow_binary_diff_summary
    # =====================================================================

    @tool
    @idasync
    @tool_timeout(120.0)
    def workflow_binary_diff_summary(
        left_graph_id: Annotated[str, "Cache ID of the 'before' graph"],
        right_graph_id: Annotated[str, "Cache ID of the 'after' graph"],
        name_alignment: Annotated[
            bool, "Match by function name (default: True for cross-binary diff)"
        ] = True,
    ) -> dict:
        """High-level structural diff between two cached graphs.

        Returns: similarity score, top added/removed functions by importance,
        and a narrative summary suitable for binary diffing reports.

        Heavy: for large graphs use invoke_tool(..., async_mode=True) or task_submit + task_poll.
        """
        try:
            # We can't call the @idasync-wrapped nx_graph_diff tool — inline the logic.
            left_e = _get_cached(left_graph_id)
            right_e = _get_cached(right_graph_id)
            if left_e is None or right_e is None:
                return {"ok": False, "error": "One or both graph_ids not cached"}
            GL = left_e["graph"]
            GR = right_e["graph"]

            if name_alignment:
                left_nodes = {GL.nodes[n].get("name", _node_addr_str(n)): n
                              for n in GL.nodes()}
                right_nodes = {GR.nodes[n].get("name", _node_addr_str(n)): n
                               for n in GR.nodes()}
                added_names = set(right_nodes) - set(left_nodes)
                removed_names = set(left_nodes) - set(right_nodes)
                common = set(left_nodes) & set(right_nodes)
            else:
                added_names = set(GR.nodes()) - set(GL.nodes())
                removed_names = set(GL.nodes()) - set(GR.nodes())
                common = set(GL.nodes()) & set(GR.nodes())

            total = max(GL.number_of_nodes() + GR.number_of_nodes() - len(common), 1)
            similarity = len(common) / total

            # Rank added/removed by their respective in-degree (importance)
            added_ranked = sorted(
                [
                    {
                        "addr": _node_addr_str(right_nodes[n]) if name_alignment else _node_addr_str(n),
                        "name": n if name_alignment else GR.nodes[n].get("name", _node_addr_str(n)),
                        "in_degree": int(GR.in_degree(right_nodes[n] if name_alignment else n)),
                    }
                    for n in added_names
                ],
                key=lambda x: x["in_degree"], reverse=True,
            )[:25]

            removed_ranked = sorted(
                [
                    {
                        "addr": _node_addr_str(left_nodes[n]) if name_alignment else _node_addr_str(n),
                        "name": n if name_alignment else GL.nodes[n].get("name", _node_addr_str(n)),
                        "in_degree": int(GL.in_degree(left_nodes[n] if name_alignment else n)),
                    }
                    for n in removed_names
                ],
                key=lambda x: x["in_degree"], reverse=True,
            )[:25]

            summary_parts = []
            summary_parts.append(
                f"Structural similarity: {similarity:.3f} "
                f"({len(common)} common / {total} total nodes)."
            )
            if added_ranked:
                summary_parts.append(
                    f"+{len(added_names)} new function(s); most important: "
                    f"{added_ranked[0]['name']} (in_degree={added_ranked[0]['in_degree']})."
                )
            if removed_ranked:
                summary_parts.append(
                    f"-{len(removed_names)} removed function(s); most important: "
                    f"{removed_ranked[0]['name']} (in_degree={removed_ranked[0]['in_degree']})."
                )

            return {
                "ok": True,
                "left_graph_id": left_graph_id,
                "right_graph_id": right_graph_id,
                "structural_similarity": float(similarity),
                "common_node_count": len(common),
                "added_count": len(added_names),
                "removed_count": len(removed_names),
                "top_added": added_ranked,
                "top_removed": removed_ranked,
                "summary": " ".join(summary_parts),
                "note": "Use name_alignment=True when diffing binaries across versions.",
            }
        except Exception as e:
            return tool_error(e, context="workflow_binary_diff_summary")
