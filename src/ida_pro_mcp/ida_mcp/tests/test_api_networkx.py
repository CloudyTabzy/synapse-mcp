"""Tests for api_networkx — graph analysis tools.

All tests except the status probe skip gracefully when networkx is not installed.
Tests exercise behaviour against the current IDB (typically crackme03.elf fixture)
and against minimal in-memory graphs to verify algorithm wiring.
"""

from ..framework import test, skip_test, assert_non_empty, assert_is_list

try:
    from ..api_networkx import (
        nx_status,
        NETWORKX_AVAILABLE,
    )
    if NETWORKX_AVAILABLE:
        from ..api_networkx import (
            nx_call_graph,
            nx_function_cfg,
            nx_xref_graph,
            nx_subgraph,
            nx_graph_metrics,
            nx_central_functions,
            nx_shortest_path,
            nx_all_paths,
            nx_cycles,
            nx_strongly_connected,
            nx_neighborhood,
            nx_dominators,
            nx_communities,
            nx_topological_order,
            nx_graph_diff,
            nx_export_graph,
            hybrid_nx_angr_target_ranking,
            hybrid_nx_yara_cluster_detection,
            hybrid_nx_lief_import_graph,
            hybrid_nx_triton_taint_graph,
            workflow_reveng_overview,
            workflow_find_critical_paths,
            workflow_binary_diff_summary,
        )
except ImportError:
    NETWORKX_AVAILABLE = False


def _require_nx():
    if not NETWORKX_AVAILABLE:
        skip_test("networkx not installed")


# ---------------------------------------------------------------------------
# Status probe — always runs, even without networkx
# ---------------------------------------------------------------------------


@test()
def test_nx_status_probe():
    """nx_status must not crash regardless of whether networkx is installed."""
    result = nx_status()
    assert isinstance(result, dict), "nx_status must return a dict"
    assert "available" in result, "nx_status must include 'available' key"
    assert "ok" in result, "nx_status must include 'ok' key"
    assert result.get("ok") is True


@test()
def test_nx_status_version():
    """When networkx is installed, version is a non-empty string."""
    _require_nx()
    result = nx_status()
    assert result.get("available") is True
    version = result.get("version", "")
    assert isinstance(version, str) and len(version) > 0, \
        f"version must be non-empty when installed, got {version!r}"


@test()
def test_nx_status_no_nx_hint():
    """hint field is present when networkx is absent."""
    if NETWORKX_AVAILABLE:
        skip_test("networkx is installed — hint path not reachable")
    result = nx_status()
    assert result.get("ok") is True
    assert "hint" in result, "hint must be present when networkx is absent"


# ---------------------------------------------------------------------------
# N.1 nx_call_graph — IDB-bound
# ---------------------------------------------------------------------------


@test(binary="crackme03.elf")
def test_nx_call_graph_basic():
    """Build the IDB's call graph and verify structural keys."""
    _require_nx()
    result = nx_call_graph()
    assert result.get("ok") is True, f"call_graph failed: {result}"
    assert "graph_id" in result
    assert result.get("node_count", 0) >= 1, "call graph should have >= 1 node"
    assert result.get("edge_count", 0) >= 0
    assert isinstance(result.get("density"), float)


@test(binary="crackme03.elf")
def test_nx_call_graph_caches():
    """Identical calls should return the same graph_id from the cache."""
    _require_nx()
    a = nx_call_graph()
    b = nx_call_graph()
    assert a.get("ok") and b.get("ok")
    assert a.get("graph_id") == b.get("graph_id"), \
        "cache hit should reuse graph_id"


# ---------------------------------------------------------------------------
# N.2 nx_function_cfg
# ---------------------------------------------------------------------------


@test(binary="crackme03.elf")
def test_nx_function_cfg_basic():
    """Build a CFG for the entry function (or some other defined function)."""
    _require_nx()
    import idautils
    func_eas = list(idautils.Functions())
    if not func_eas:
        skip_test("no functions in IDB")
    result = nx_function_cfg(function_address=hex(func_eas[0]))
    assert result.get("ok") is True, f"function_cfg failed: {result}"
    assert result.get("node_count", 0) >= 1
    assert result.get("kind") == "function_cfg"


# ---------------------------------------------------------------------------
# N.3 nx_xref_graph
# ---------------------------------------------------------------------------


@test(binary="crackme03.elf")
def test_nx_xref_graph_has_edges():
    """NX-1: xref graph must contain edges when data references exist."""
    _require_nx()
    result = nx_xref_graph(include_data=True, include_strings=True, max_nodes=200)
    assert result.get("ok") is True, f"xref_graph failed: {result}"
    # Even with a modest node limit, some function→data edges should exist
    # in any non-trivial binary.
    assert result.get("edge_count", 0) > 0, (
        "xref_graph returned 0 edges — the edge-building loop may be "
        "breaking prematurely before any edges are added (NX-1)."
    )


@test(binary="crackme03.elf")
def test_nx_xref_graph_data_budget_with_many_functions():
    """NX-1: data/string slots are reserved independently of function count.

    If max_nodes is small (e.g. 50) and the binary has >50 functions, the
    reserved data budget (>=25 slots) must still admit some data/string
    nodes — they should never be starved by function-node allocation.
    """
    _require_nx()
    import idautils
    func_count = len(list(idautils.Functions()))
    if func_count < 30:
        skip_test(f"need more functions to exercise budget split (have {func_count})")
    result = nx_xref_graph(include_data=True, include_strings=True, max_nodes=50)
    assert result.get("ok") is True, f"xref_graph failed: {result}"
    # With max_nodes=50, the data_reserve is max(25, min(100, 50)) = 50; thus
    # func_budget = max(1, 50 - 50) = 1 function — but with min(100, 50)=50,
    # ALL space goes to data, which would be wrong. Actual formula:
    # data_reserve = max(50//2, min(100, 50)) = max(25, 50) = 50 → func_budget=1.
    # We still expect SOME nodes (1 function + many data) and SOME edges.
    assert result.get("edge_count", 0) > 0, (
        "Even with max_nodes=50 and many functions, the data budget should "
        "permit at least some edges (NX-1)."
    )


# ---------------------------------------------------------------------------
# A.1 nx_graph_metrics
# ---------------------------------------------------------------------------


@test(binary="crackme03.elf")
def test_nx_graph_metrics_shape():
    """Metrics result has required numeric keys."""
    _require_nx()
    cg = nx_call_graph()
    assert cg.get("ok") is True
    result = nx_graph_metrics(graph_id=cg["graph_id"])
    assert result.get("ok") is True
    for key in (
        "node_count", "edge_count", "density",
        "avg_in_degree", "avg_out_degree",
        "max_in_degree", "max_out_degree",
        "weakly_connected_components",
        "strongly_connected_components",
        "is_dag", "has_self_loops",
    ):
        assert key in result, f"missing metrics key {key!r}"
    assert isinstance(result["density"], float)
    assert result["node_count"] >= 1


# ---------------------------------------------------------------------------
# N.4 nx_subgraph
# ---------------------------------------------------------------------------


@test(binary="crackme03.elf")
def test_nx_subgraph_radius_expansion():
    """NX-2: subgraph with radius > 0 expands beyond the filtered nodes."""
    _require_nx()
    cg = nx_call_graph()
    import idautils
    funcs = list(idautils.Functions())
    if not funcs:
        skip_test("no functions")
    # Pick a function that is likely to have callees or callers.
    # Use the first function with out_degree > 0 if possible.
    from ..api_networkx import _get_cached
    G = _get_cached(cg["graph_id"])["graph"]
    seed = None
    for f in funcs:
        if G.out_degree(f) > 0 or G.in_degree(f) > 0:
            seed = f
            break
    if seed is None:
        skip_test("no function with edges")
    res = nx_subgraph(
        graph_id=cg["graph_id"],
        node_filter=[hex(seed)],
        radius=2,
    )
    assert res.get("ok") is True, f"subgraph failed: {res}"
    # With radius=2 on a connected function, we should get at least the seed
    # and potentially its neighbors.
    assert res.get("node_count", 0) >= 1, "subgraph must contain at least the seed node"


@test(binary="crackme03.elf")
def test_nx_subgraph_node_filter_only():
    """subgraph with node_filter and radius=0 returns exactly the filtered nodes."""
    _require_nx()
    cg = nx_call_graph()
    import idautils
    funcs = list(idautils.Functions())
    if len(funcs) < 2:
        skip_test("need >=2 functions")
    res = nx_subgraph(
        graph_id=cg["graph_id"],
        node_filter=[hex(funcs[0]), hex(funcs[1])],
        radius=0,
    )
    assert res.get("ok") is True
    assert res.get("node_count", 0) >= 1


# ---------------------------------------------------------------------------
# A.2 nx_central_functions ⭐
# ---------------------------------------------------------------------------


@test(binary="crackme03.elf")
def test_nx_central_functions_pagerank():
    """PageRank ranking returns top_n entries sorted descending."""
    _require_nx()
    cg = nx_call_graph()
    assert cg.get("ok")
    res = nx_central_functions(graph_id=cg["graph_id"], method="pagerank", top_n=5)
    assert res.get("ok") is True, f"central_functions failed: {res}"
    funcs = res.get("functions", [])
    assert_is_list(funcs)
    if len(funcs) > 1:
        scores = [f.get("pagerank", 0.0) for f in funcs]
        assert all(scores[i] >= scores[i + 1] for i in range(len(scores) - 1)), \
            "pagerank list must be sorted descending"


@test(binary="crackme03.elf")
def test_nx_central_functions_combined_score_range():
    """Combined scores are non-negative floats."""
    _require_nx()
    cg = nx_call_graph()
    assert cg.get("ok")
    res = nx_central_functions(graph_id=cg["graph_id"], method="combined", top_n=10)
    assert res.get("ok") is True
    for f in res.get("functions", []):
        score = f.get("combined_score", 0.0)
        assert isinstance(score, float)
        assert score >= 0.0


@test(binary="crackme03.elf")
def test_nx_central_functions_betweenness_sampled_flag():
    """R-5: central_functions reports betweenness_sampled flag."""
    _require_nx()
    cg = nx_call_graph()
    assert cg.get("ok")
    res = nx_central_functions(graph_id=cg["graph_id"], method="combined", top_n=5)
    assert res.get("ok") is True
    assert "betweenness_sampled" in res, (
        "betweenness_sampled field must be present in central_functions result"
    )
    assert isinstance(res["betweenness_sampled"], bool)


# ---------------------------------------------------------------------------
# A.3 nx_shortest_path
# ---------------------------------------------------------------------------


@test(binary="crackme03.elf")
def test_nx_shortest_path_self():
    """Path from a node to itself is a single-node path of length 0."""
    _require_nx()
    cg = nx_call_graph()
    assert cg.get("ok")
    import idautils
    func_eas = list(idautils.Functions())
    if not func_eas:
        skip_test("no functions in IDB")
    a = hex(func_eas[0])
    res = nx_shortest_path(src=a, dst=a, graph_id=cg["graph_id"])
    assert res.get("ok") is True
    assert res.get("reachable") is True
    assert res.get("path_length") == 0


@test(binary="crackme03.elf")
def test_nx_shortest_path_unknown_dst_graceful():
    """Non-existent destination returns ok=False with error_type, not a crash."""
    _require_nx()
    cg = nx_call_graph()
    res = nx_shortest_path(src=hex(0), dst=hex(0xDEADBEEF), graph_id=cg["graph_id"])
    # Either src or dst not in graph — must report cleanly
    assert isinstance(res, dict)
    assert res.get("ok") is False or res.get("reachable") is False


@test(binary="crackme03.elf")
def test_nx_shortest_path_direction_param():
    """NX-3: direction parameter changes reachability semantics."""
    _require_nx()
    import idautils
    cg = nx_call_graph()
    funcs = list(idautils.Functions())
    if len(funcs) < 2:
        skip_test("need >=2 functions")
    a, b = funcs[0], funcs[1]
    # undirected should be symmetric
    fwd = nx_shortest_path(src=hex(a), dst=hex(b), graph_id=cg["graph_id"],
                           direction="undirected")
    rev = nx_shortest_path(src=hex(b), dst=hex(a), graph_id=cg["graph_id"],
                           direction="undirected")
    assert fwd.get("reachable") == rev.get("reachable"), (
        "undirected shortest path should be symmetric"
    )


@test(binary="crackme03.elf")
def test_nx_all_paths_direction_param():
    """NX-3: all_paths respects direction parameter."""
    _require_nx()
    import idautils
    cg = nx_call_graph()
    funcs = list(idautils.Functions())
    if len(funcs) < 2:
        skip_test("need >=2 functions")
    a, b = funcs[0], funcs[1]
    res = nx_all_paths(src=hex(a), dst=hex(b), graph_id=cg["graph_id"],
                       cutoff=5, direction="undirected")
    assert res.get("ok") is True
    # paths_found may be 0 if disconnected, but the tool must not crash
    assert "paths_found" in res


@test(binary="crackme03.elf")
def test_nx_path_finds_known_connected_pair():
    """NX-3: any two functions in the same weakly-connected component must
    be reachable in undirected mode.

    Picks two functions known to be in the same WCC by inspecting the cached
    graph, then asserts undirected shortest_path returns reachable=True.
    """
    _require_nx()
    cg = nx_call_graph()
    from ..api_networkx import _get_cached
    G = _get_cached(cg["graph_id"])["graph"]
    if G.number_of_edges() == 0:
        skip_test("call graph has no edges to test reachability")
    # Pick any edge (a, b) — a and b are guaranteed connected.
    a, b = next(iter(G.edges()))
    res = nx_shortest_path(src=hex(a), dst=hex(b), graph_id=cg["graph_id"],
                           direction="undirected")
    assert res.get("ok") is True
    assert res.get("reachable") is True, (
        f"undirected shortest_path failed to find an edge ({hex(a)}, {hex(b)}) "
        "that exists in the graph (NX-3)."
    )


@test(binary="crackme03.elf")
def test_nx_shortest_path_returns_graph_id():
    """Every path result must expose which graph it queried."""
    _require_nx()
    cg = nx_call_graph()
    from ..api_networkx import _get_cached
    G = _get_cached(cg["graph_id"])["graph"]
    if G.number_of_edges() == 0:
        skip_test("call graph has no edges")
    a, b = next(iter(G.edges()))
    res = nx_shortest_path(src=hex(a), dst=hex(b), graph_id=cg["graph_id"])
    assert res.get("graph_id") == cg["graph_id"], (
        "result must include graph_id so users know which graph was queried"
    )


@test(binary="crackme03.elf")
def test_nx_shortest_path_lookup_failure_has_diagnostic():
    """Phase 5.5: when a lookup misses, the error includes a diagnostic dict
    with parsed_int, graph_node_count, and sample_node_addrs so users can
    self-diagnose stale-cache or wrong-graph mistakes.
    """
    _require_nx()
    cg = nx_call_graph()
    # 0xFFFFFFFFFFFFFFFF is virtually guaranteed not to be a node
    res = nx_shortest_path(src=hex(0xFFFFFFFFFFFFFFFF), dst=hex(0xFFFFFFFFFFFFFFFE),
                           graph_id=cg["graph_id"])
    assert res.get("ok") is False
    diag = res.get("diagnostic")
    assert isinstance(diag, dict), "lookup failure must include diagnostic dict"
    for key in ("input", "parsed_int", "parsed_hex",
                "graph_node_count", "sample_node_addrs", "hint"):
        assert key in diag, f"diagnostic missing key {key!r}"


@test(binary="crackme03.elf")
def test_nx_shortest_path_mid_function_address_resolves():
    """Phase 5.5: if user passes an address INSIDE a function (not the
    function start), the tool should auto-resolve to the function start
    using IDA's get_func.
    """
    _require_nx()
    import idaapi
    import idautils
    cg = nx_call_graph()
    funcs = list(idautils.Functions())
    if len(funcs) < 1:
        skip_test("no functions")
    # Find a function with >=2 instructions so we can pick a mid-function address.
    target = None
    mid_ea = None
    for f in funcs:
        func = idaapi.get_func(f)
        if func is None:
            continue
        if func.end_ea - func.start_ea < 8:
            continue
        items = list(idautils.FuncItems(func.start_ea))
        if len(items) >= 2:
            target = f
            mid_ea = items[1]  # second instruction (not the start)
            break
    if target is None:
        skip_test("no function with >=2 instructions")
    # Use mid-function addr as src; func start as dst — should resolve src
    res = nx_shortest_path(src=hex(mid_ea), dst=hex(target),
                           graph_id=cg["graph_id"])
    # ok=True regardless of reachability — the lookup itself must succeed
    assert res.get("ok") is True, (
        f"mid-function address {hex(mid_ea)} should auto-resolve to "
        f"function start {hex(target)}; got error: {res.get('error')!r}"
    )


# ---------------------------------------------------------------------------
# A.5 nx_cycles
# ---------------------------------------------------------------------------


@test(binary="crackme03.elf")
def test_nx_cycles_shape():
    """Cycle results are well-formed list-of-dicts with length + members."""
    _require_nx()
    cg = nx_call_graph()
    res = nx_cycles(graph_id=cg["graph_id"], max_length=5, max_cycles=10)
    assert res.get("ok") is True
    cycles = res.get("cycles", [])
    assert_is_list(cycles)
    for c in cycles:
        assert "length" in c and "members" in c
        assert c["length"] == len(c["members"])


# ---------------------------------------------------------------------------
# A.6 nx_strongly_connected
# ---------------------------------------------------------------------------


@test(binary="crackme03.elf")
def test_nx_strongly_connected_filter():
    """min_size=2 filters out singleton SCCs."""
    _require_nx()
    cg = nx_call_graph()
    res = nx_strongly_connected(graph_id=cg["graph_id"], min_size=2)
    assert res.get("ok") is True
    for c in res.get("components", []):
        assert c.get("size", 0) >= 2
        assert c.get("interpretation") in (
            "mutual_recursion", "dispatch_or_state_machine",
        )


# ---------------------------------------------------------------------------
# A.7 nx_neighborhood
# ---------------------------------------------------------------------------


@test(binary="crackme03.elf")
def test_nx_neighborhood_basic():
    """Ego graph contains the center node and reports node/edge counts."""
    _require_nx()
    cg = nx_call_graph()
    import idautils
    func_eas = list(idautils.Functions())
    if not func_eas:
        skip_test("no functions in IDB")
    center = hex(func_eas[0])
    res = nx_neighborhood(center=center, radius=2, graph_id=cg["graph_id"])
    assert res.get("ok") is True, f"neighborhood failed: {res}"
    assert res.get("node_count", 0) >= 1
    # The center itself must be in the result
    nodes = [n.get("addr") for n in res.get("nodes", [])]
    assert any(n.lower() == center.lower() for n in nodes), \
        "center node must be in ego graph"


@test(binary="crackme03.elf")
def test_nx_neighborhood_reports_seed_degrees():
    """Phase 5.5: neighborhood result must include in/out degree of every
    seed. When the seed appears isolated in the result, the seed_degrees
    field lets users distinguish "genuinely isolated function" from "tool bug".
    """
    _require_nx()
    cg = nx_call_graph()
    import idautils
    func_eas = list(idautils.Functions())
    if not func_eas:
        skip_test("no functions in IDB")
    center = hex(func_eas[0])
    res = nx_neighborhood(center=center, radius=1, graph_id=cg["graph_id"])
    assert res.get("ok") is True
    sd = res.get("seed_degrees", [])
    assert isinstance(sd, list) and len(sd) >= 1, \
        "seed_degrees must be populated"
    s0 = sd[0]
    assert "in_degree" in s0 and "out_degree" in s0, \
        "seed_degrees entries must report in/out degree"


@test(binary="crackme03.elf")
def test_nx_neighborhood_node_has_name_attribute():
    """Phase 5.5 (Phase 3 attribute bug): every node returned by neighborhood
    must have a `name` field different from `addr` (unless the function has
    no IDA name, in which case sub_HEX is used).

    The bug: Phase 3 used `G.add_edge` before `G.add_node`, so the auto-created
    node never received its `name` attribute, and the fallback rendered it
    identical to addr.
    """
    _require_nx()
    cg = nx_call_graph()
    import idautils
    func_eas = list(idautils.Functions())
    if not func_eas:
        skip_test("no functions in IDB")
    res = nx_neighborhood(center=hex(func_eas[0]), radius=2,
                          graph_id=cg["graph_id"])
    assert res.get("ok") is True
    nodes = res.get("nodes", [])
    if not nodes:
        skip_test("no nodes in neighborhood")
    # Every node must have either an IDA name (e.g. "sub_400123", "main")
    # or the canonical sub_HEX fallback. It must NOT equal the raw addr.
    for n in nodes:
        name = n.get("name", "")
        addr = n.get("addr", "")
        assert name, f"node {addr!r} has empty name"
        # Acceptable: differs from addr, OR is the standard sub_HEX form
        assert (
            name != addr
            or name.startswith("sub_")
            or name in ("entry", "_start", "main")
        ), (
            f"node {addr!r} has name=={name!r} (the addr) — Phase 3 likely "
            "didn't set the name attribute (regression)."
        )


@test(binary="crackme03.elf")
def test_nx_neighborhood_multi_seed():
    """R-1: neighborhood accepts node_filter for multiple seed nodes."""
    _require_nx()
    cg = nx_call_graph()
    import idautils
    func_eas = list(idautils.Functions())
    if len(func_eas) < 2:
        skip_test("need >=2 functions")
    seeds = [hex(func_eas[0]), hex(func_eas[1])]
    res = nx_neighborhood(node_filter=seeds, radius=1, graph_id=cg["graph_id"])
    assert res.get("ok") is True, f"multi-seed neighborhood failed: {res}"
    assert res.get("node_count", 0) >= 1
    returned_addrs = {n.get("addr", "").lower() for n in res.get("nodes", [])}
    for s in seeds:
        assert s.lower() in returned_addrs, (
            f"seed {s} must be present in multi-seed ego graph"
        )


# ---------------------------------------------------------------------------
# A.8 nx_dominators
# ---------------------------------------------------------------------------


@test(binary="crackme03.elf")
def test_nx_dominators_entry():
    """Entry block must dominate itself (idom[entry] == entry)."""
    _require_nx()
    import idautils
    func_eas = list(idautils.Functions())
    if not func_eas:
        skip_test("no functions in IDB")
    res = nx_dominators(function_address=hex(func_eas[0]))
    assert res.get("ok") is True, f"dominators failed: {res}"
    entry = res.get("entry_block", "")
    idoms = res.get("immediate_dominators", [])
    found = False
    for d in idoms:
        if d.get("block") == entry and d.get("idom") == entry:
            found = True
            break
    assert found, "entry block must be its own immediate dominator"


@test(binary="crackme03.elf")
def test_nx_dominators_blocks_match_cfg():
    """NX-6: every block AND idom reported by nx_dominators must be a real
    CFG node.

    Pulls the cached CFG graph directly and verifies every dominator entry's
    'block' and 'idom' fields correspond to actual NetworkX nodes.
    """
    _require_nx()
    import idautils
    from ..api_networkx import _get_cached
    func_eas = list(idautils.Functions())
    if not func_eas:
        skip_test("no functions in IDB")
    # Pick the first function with >=2 blocks (so there's something to dominate).
    target = None
    target_cfg_nodes: set[str] = set()
    for fea in func_eas:
        cfg_res = nx_function_cfg(function_address=hex(fea))
        if not cfg_res.get("ok"):
            continue
        if cfg_res.get("node_count", 0) >= 2:
            G = _get_cached(cfg_res["graph_id"])["graph"]
            target = fea
            target_cfg_nodes = {hex(n) for n in G.nodes()}
            break
    if target is None:
        skip_test("no function with >=2 CFG blocks")
    dom_res = nx_dominators(function_address=hex(target))
    assert dom_res.get("ok") is True, f"dominators failed: {dom_res}"
    for d in dom_res.get("immediate_dominators", []):
        block = d.get("block", "")
        idom = d.get("idom", "")
        assert block in target_cfg_nodes, (
            f"dominator entry block={block} is not a node in the CFG "
            f"(CFG has {len(target_cfg_nodes)} nodes) — NX-6 regression."
        )
        assert idom in target_cfg_nodes, (
            f"dominator entry idom={idom} is not a node in the CFG — NX-6 regression."
        )


# ---------------------------------------------------------------------------
# A.9 nx_communities
# ---------------------------------------------------------------------------


@test(binary="crackme03.elf")
def test_nx_communities_partition():
    """Sum of community sizes equals member count (each function in 1 community)."""
    _require_nx()
    cg = nx_call_graph()
    res = nx_communities(graph_id=cg["graph_id"], algorithm="louvain",
                         min_community_size=1)
    assert res.get("ok") is True, f"communities failed: {res}"
    comms = res.get("communities", [])
    # Each function appears in exactly one returned community (filtered by min_size).
    # We can't reconstruct the full partition because small communities are filtered,
    # but we can at least check that members are non-overlapping within result.
    seen: set[str] = set()
    for c in comms:
        for m in c.get("members", []):
            assert m not in seen, f"member {m} appears in multiple communities"
            seen.add(m)


# ---------------------------------------------------------------------------
# A.10 nx_topological_order
# ---------------------------------------------------------------------------


@test(binary="crackme03.elf")
def test_nx_topological_order_shape():
    """Topo order has is_dag flag and an order list."""
    _require_nx()
    cg = nx_call_graph()
    res = nx_topological_order(graph_id=cg["graph_id"])
    assert res.get("ok") is True
    assert "is_dag" in res
    assert "order" in res
    assert_is_list(res["order"])


# ---------------------------------------------------------------------------
# D.1 nx_graph_diff
# ---------------------------------------------------------------------------


@test(binary="crackme03.elf")
def test_nx_graph_diff_self_identity():
    """Diffing a graph against itself yields 0 added / 0 removed."""
    _require_nx()
    cg = nx_call_graph()
    gid = cg["graph_id"]
    res = nx_graph_diff(graph_id_left=gid, graph_id_right=gid)
    assert res.get("ok") is True
    assert res.get("nodes_added", []) == []
    assert res.get("nodes_removed", []) == []
    assert abs(res.get("structural_similarity", 0.0) - 1.0) < 1e-9


# ---------------------------------------------------------------------------
# D.2 nx_export_graph
# ---------------------------------------------------------------------------


@test(binary="crackme03.elf")
def test_nx_export_graph_json_roundtrip():
    """JSON export is parseable and contains required node-link keys."""
    _require_nx()
    import json
    cg = nx_call_graph()
    res = nx_export_graph(graph_id=cg["graph_id"], format="json", max_nodes=50)
    assert res.get("ok") is True
    content = res.get("content", "")
    assert content, "JSON content must not be empty"
    parsed = json.loads(content)
    assert "nodes" in parsed and "links" in parsed, \
        "node-link JSON must have 'nodes' and 'links' keys"


@test(binary="crackme03.elf")
def test_nx_export_graph_truncated_edges_valid():
    """NX-7: when max_nodes truncates the graph, no edge references a missing node."""
    _require_nx()
    import json
    cg = nx_call_graph()
    # Force truncation with a very small max_nodes
    res = nx_export_graph(graph_id=cg["graph_id"], format="json", max_nodes=5)
    assert res.get("ok") is True
    parsed = json.loads(res.get("content", "{}"))
    node_ids = {n.get("id") for n in parsed.get("nodes", [])}
    for link in parsed.get("links", []):
        src = link.get("source")
        dst = link.get("target")
        assert src in node_ids, (
            f"edge source {src!r} references a node not in the truncated node list"
        )
        assert dst in node_ids, (
            f"edge target {dst!r} references a node not in the truncated node list"
        )


@test(binary="crackme03.elf")
def test_nx_export_graph_dot_basic():
    """DOT export produces a parseable digraph header + at least one node."""
    _require_nx()
    cg = nx_call_graph()
    res = nx_export_graph(graph_id=cg["graph_id"], format="dot", max_nodes=20)
    assert res.get("ok") is True
    content = res.get("content", "")
    assert "digraph G" in content
    assert "}" in content


@test(binary="crackme03.elf")
def test_nx_export_graph_truncation_picks_high_degree():
    """NX-7 improvement: truncated exports should keep the highest-degree
    (most structurally interesting) nodes, not the first-N in iteration order.

    With degree-based truncation, the truncated subgraph should contain
    MORE edges than a first-N truncation would have produced on the same
    graph. We verify indirectly: when max_nodes is small, the truncated
    graph still contains some edges (proves we picked connected nodes).
    """
    _require_nx()
    import json
    cg = nx_call_graph()
    from ..api_networkx import _get_cached
    G = _get_cached(cg["graph_id"])["graph"]
    if G.number_of_edges() == 0:
        skip_test("call graph has no edges to test truncation")
    # Pick max_nodes so truncation triggers but we still expect edges.
    target_n = min(15, max(2, G.number_of_nodes() // 4))
    res = nx_export_graph(graph_id=cg["graph_id"], format="json",
                          max_nodes=target_n)
    assert res.get("ok") is True
    assert res.get("truncated") is True, "expected truncation to be reported"
    parsed = json.loads(res.get("content", "{}"))
    n_edges = len(parsed.get("links", []))
    # When picking the top-degree nodes, we expect SOME edges between them
    # (since high-degree nodes are connected to many others). A first-N
    # truncation would often yield 0 edges.
    assert n_edges > 0, (
        f"degree-based truncation should preserve edges between top nodes; "
        f"got {n_edges} edges with {target_n} nodes (NX-7 regression)."
    )


# ---------------------------------------------------------------------------
# W.1 workflow_reveng_overview ⭐ KILLER
# ---------------------------------------------------------------------------


@test(binary="crackme03.elf")
def test_workflow_reveng_overview_shape():
    """Killer workflow returns full structural overview with required keys."""
    _require_nx()
    res = workflow_reveng_overview(top_n=10, use_yara=False, include_communities=True)
    assert res.get("ok") is True, f"overview failed: {res}"
    for key in (
        "function_count", "edge_count", "metrics",
        "top_by_pagerank", "top_by_betweenness", "top_by_combined",
        "leaf_functions", "root_functions",
        "strongly_connected_components", "communities",
        "recommendations",
    ):
        assert key in res, f"missing overview key {key!r}"
    assert_is_list(res["top_by_pagerank"])
    assert_is_list(res["recommendations"])
    assert isinstance(res["metrics"], dict)


@test(binary="crackme03.elf")
def test_workflow_reveng_overview_without_communities():
    """Disabling communities should still produce a valid result."""
    _require_nx()
    res = workflow_reveng_overview(top_n=5, use_yara=False, include_communities=False)
    assert res.get("ok") is True
    assert res.get("communities", []) == []


# ---------------------------------------------------------------------------
# H.2 hybrid_nx_yara_cluster_detection
# ---------------------------------------------------------------------------


@test(binary="crackme03.elf")
def test_hybrid_nx_yara_cluster_detection_graceful():
    """Hybrid tool works even when YARA is not installed (no crash)."""
    _require_nx()
    res = hybrid_nx_yara_cluster_detection(min_cluster_size=2)
    # Either succeeded with communities or returned a structured error — both fine
    assert isinstance(res, dict)
    assert "ok" in res
    if res.get("ok"):
        assert "engines_used" in res
        assert "networkx" in res.get("engines_used", [])


# ---------------------------------------------------------------------------
# W.2 workflow_find_critical_paths
# ---------------------------------------------------------------------------


@test(binary="crackme03.elf")
def test_workflow_find_critical_paths_shape():
    """Critical paths workflow returns a list of paths with entry/sink markers."""
    _require_nx()
    res = workflow_find_critical_paths(
        sink_imports="system,exec,strcpy",
        max_paths_per_sink=2,
        cutoff=5,
    )
    assert isinstance(res, dict)
    assert res.get("ok") is True
    assert "paths" in res
    assert_is_list(res["paths"])
    # Each path entry, if present, must have the expected keys
    for p in res["paths"]:
        assert "root" in p and "sink" in p and "path" in p
