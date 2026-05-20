---
name: angr-symbolic-exec
description: Symbolic execution and path exploration with Angr inside IDA Pro. Use to model stdin/argv inputs, solve crackmes, recover control-flow graphs, perform backward slicing, and explore reachable code. Ideal for CTF challenges, license key validation, and complex path-dependent analysis where whole-program context matters.
allowed-tools: mcp__ida_pro_mcp__angr_status, mcp__ida_pro_mcp__angr_load_segment, mcp__ida_pro_mcp__angr_cfg_fast, mcp__ida_pro_mcp__angr_cfg_from_ida, mcp__ida_pro_mcp__angr_diff_cfg, mcp__ida_pro_mcp__angr_find_paths, mcp__ida_pro_mcp__angr_enumerate_reachable, mcp__ida_pro_mcp__angr_state_evaluate, mcp__ida_pro_mcp__angr_hook_function, mcp__ida_pro_mcp__angr_backward_slice, mcp__ida_pro_mcp__angr_value_set, mcp__ida_pro_mcp__angr_snapshot_save, mcp__ida_pro_mcp__angr_snapshot_restore, mcp__ida_pro_mcp__angr_snapshot_list, mcp__ida_pro_mcp__angr_snapshot_delete, mcp__ida_pro_mcp__hybrid_angr_triton_solve, mcp__ida_pro_mcp__hybrid_angr_stdin_fuzz, mcp__ida_pro_mcp__hybrid_angr_miasm_path, mcp__ida_pro_mcp__hybrid_angr_triton_decompile, mcp__ida_pro_mcp__hybrid_angr_z3_formula, mcp__ida_pro_mcp__workflow_solve_crackme, mcp__ida_pro_mcp__workflow_trace_data_flow, mcp__ida_pro_mcp__workflow_find_gadgets, mcp__ida_pro_mcp__workflow_enum_code_hints, mcp__ida_pro_mcp__lookup_funcs, mcp__ida_pro_mcp__decompile, mcp__ida_pro_mcp__disasm, mcp__ida_pro_mcp__basic_blocks, mcp__ida_pro_mcp__xrefs_to, mcp__ida_pro_mcp__int_convert, mcp__ida_pro_mcp__set_comments, mcp__ida_pro_mcp__get_bytes, Bash, Read, Write, AskUserQuestion
---

# angr-symbolic-exec

Use Angr symbolic execution to analyze binaries in IDA Pro. Model program inputs (stdin, argv, files), explore execution paths, solve for inputs that reach target code, recover control-flow graphs, and perform backward slicing — all from within IDA's analysis context.

> **Tool prefix note**: MCP tool names depend on your client configuration. If your server is named differently, adjust the prefix accordingly.

> **Dependency**: Requires `angr` to be installed (`pip install angr`). ~200 MB with native C extensions. NOT included in `--install-deps all`.

## Prerequisites

- Angr must be installed and available (`angr_status` returns `"available": true`)
- The target binary should be loaded in IDA Pro
- For CFG recovery, the binary should have at least one executable segment

## Instructions

### 1. Verify Angr availability

```
mcp__ida_pro_mcp__angr_status()
```

If `"available": false`, stop and tell the user to install Angr:
> Angr is not installed. Install it with `pip install angr` (~200 MB).

### 2. Load the binary into Angr

Angr needs its own view of the binary. Load from the current IDB segment:

```
mcp__ida_pro_mcp__angr_load_segment(
    segment_name=".text",
    base_address="auto"
)
```

Or load the entire binary:

```
mcp__ida_pro_mcp__angr_load_segment(
    segment_name="",
    base_address="auto"
)
```

Review the returned project info (arch, entry point, segments loaded).

### 3. Choose analysis mode

**Option A — Crackme solving (one-shot workflow):**
Use when you need to find the correct input (password, serial key) for a binary challenge.

**Option B — Path exploration (find target address):**
Use when you know a target address (e.g., success/failure block) and want inputs that reach it.

**Option C — CFG recovery and comparison:**
Use when IDA's CFG is incomplete (packed/encrypted code) and you need Angr's dynamic CFG.

**Option D — Backward slicing:**
Use when you want to know which instructions influence a specific variable or register.

**Option E — Reachable code enumeration:**
Use when you want to discover all code reachable from a given function under symbolic execution.

### Option A: Crackme solving

#### A1. Identify the target function

Use `mcp__ida_pro_mcp__decompile` or `mcp__ida_pro_mcp__lookup_funcs` to find the function that checks the input.

#### A2. Use the one-shot workflow (recommended)

```
mcp__ida_pro_mcp__workflow_solve_crackme(
    function_address="0x401000",
    input_type="auto",
    max_input_length=32,
    find_addrs=["0x401200"],
    avoid_addrs=["0x401300"]
)
```

Parameters:
- `function_address`: The address of the checking function
- `input_type`: `"auto"`, `"stdin"`, `"argv1"`, `"file"`, or `"register"`
- `max_input_length`: Maximum length of the input to search for
- `find_addrs`: Addresses to reach (success conditions)
- `avoid_addrs`: Addresses to avoid (failure conditions)

The workflow auto-detects input type if set to `"auto"`.

Review the returned solution. If found, it contains:
- `input_bytes`: The raw input bytes
- `input_string`: The input as a printable string (if valid ASCII)
- `path_length`: Number of basic blocks traversed

#### A3. Manual crackme solving (advanced)

If the workflow doesn't fit your case, use the hybrid tool directly:

```
mcp__ida_pro_mcp__hybrid_angr_stdin_fuzz(
    function_address="0x401000",
    max_length=32,
    find_addrs=["0x401200"],
    avoid_addrs=["0x401300"]
)
```

Or model argv[1] input:

```
mcp__ida_pro_mcp__hybrid_angr_triton_solve(
    function_address="0x401000",
    symbolize_args="rdi",
    find_addrs=["0x401200"],
    avoid_addrs=["0x401300"]
)
```

### Option B: Path exploration

#### B1. Define target and avoid addresses

Identify the addresses you want to reach and avoid:

```
mcp__ida_pro_mcp__angr_find_paths(
    start_address="0x401000",
    target_address="0x401200",
    avoid_addrs=["0x401300"],
    max_paths=5
)
```

This returns up to `max_paths` concrete paths from start to target, each with:
- A list of basic block addresses
- Input constraints for the path
- Whether the path is satisfiable

#### B2. Evaluate symbolic state at a point

After finding paths, inspect the symbolic state:

```
mcp__ida_pro_mcp__angr_state_evaluate(
    state_id="path_0",
    expression="rax",
    cast_to="bytes"
)
```

### Option C: CFG recovery and comparison

#### C1. Build Angr's CFG

```
mcp__ida_pro_mcp__angr_cfg_fast(
    start_address="0x401000",
    end_address="0x402000",
    normalize=true
)
```

#### C2. Compare with IDA's CFG

```
mcp__ida_pro_mcp__angr_diff_cfg(
    function_address="0x401000",
    include_details=true
)
```

This returns:
- Blocks only in Angr's CFG (may indicate undiscovered code)
- Blocks only in IDA's CFG (may indicate dead code or data misidentified as code)
- Matching blocks with confidence scores

### Option D: Backward slicing

#### D1. Choose a target instruction

Identify the instruction whose data dependencies you want to trace backward from.

#### D2. Run the slice

```
mcp__ida_pro_mcp__angr_backward_slice(
    target_address="0x401200",
    target_variable="rax",
    max_depth=20
)
```

This returns the slice graph — a list of instructions that contribute to the value of `rax` at `0x401200`.

### Option E: Reachable code enumeration

```
mcp__ida_pro_mcp__angr_enumerate_reachable(
    start_address="0x401000",
    max_depth=50,
    include_unsat=false
)
```

This enumerates all basic blocks reachable from the start address under symbolic execution, optionally including unsatisfiable paths.

### 4. Hook functions (optional)

To replace a function with a custom implementation during symbolic execution:

```
mcp__ida_pro_mcp__angr_hook_function(
    function_address="0x401500",
    hook_type="simproc",
    simproc_name="strlen"
)
```

Or use a custom return value:

```
mcp__ida_pro_mcp__angr_hook_function(
    function_address="0x401500",
    hook_type="return_constant",
    return_value=0
)
```

### 5. Snapshot management

Save and restore Angr states for complex exploration:

#### Save a state

```
mcp__ida_pro_mcp__angr_snapshot_save(
    state_id="before_loop",
    description="State before entering the validation loop"
)
```

#### Restore a state

```
mcp__ida_pro_mcp__angr_snapshot_restore(state_id="before_loop")
```

#### List snapshots

```
mcp__ida_pro_mcp__angr_snapshot_list()
```

#### Delete a snapshot

```
mcp__ida_pro_mcp__angr_snapshot_delete(state_id="before_loop")
```

### 6. Hybrid workflows

#### Angr + Triton: Cross-verify solutions

```
mcp__ida_pro_mcp__hybrid_angr_triton_solve(
    function_address="0x401000",
    symbolize_args="rdi",
    find_addrs=["0x401200"]
)
```

This runs Angr to find a path, then uses Triton to symbolically verify the solution.

#### Angr + Triton: Decompile path conditions

```
mcp__ida_pro_mcp__hybrid_angr_triton_decompile(
    function_address="0x401000",
    target_address="0x401200"
)
```

Returns a C-like pseudocode representation of the path constraints.

#### Angr + Z3: Extract SMT formula

```
mcp__ida_pro_mcp__hybrid_angr_z3_formula(
    function_address="0x401000",
    target_address="0x401200"
)
```

Returns the Z3 SMT-LIB2 formula for the path to the target.

#### Angr + Miasm: Path-guided deobfuscation

```
mcp__ida_pro_mcp__hybrid_angr_miasm_path(
    function_address="0x401000",
    target_address="0x401200"
)
```

Uses Angr to find the path, then Miasm to lift and simplify the instructions along that path.

### 7. Annotate findings in IDA

After finding solutions or interesting paths, write comments back to the database:

```
mcp__ida_pro_mcp__set_comments(
    items=[
        {"address": "0x401000", "comment": "Crackme entry - solution: 'secret123'"},
        {"address": "0x401200", "comment": "Success block reachable with input 'secret123'"}
    ]
)
```

### 8. Report results

Present findings to the user in a structured format:

```markdown
## Angr Analysis Results

### Target
- Function: `<name>` at `<addr>`
- Input type: `<stdin|argv|file|register>`

### Solution
- Input bytes: `<hex>`
- Input string: `<printable>`
- Path length: `<N>` basic blocks

### CFG Recovery (if applicable)
- Angr blocks found: `<N>`
- IDA blocks found: `<N>`
- New blocks discovered: `<N>`

### Backward Slice (if applicable)
- Target: `<variable>` at `<addr>`
- Instructions in slice: `<N>`
- Key dependencies: ...

### Reachable Code (if applicable)
- Start: `<addr>`
- Reachable blocks: `<N>`
- Unsatisfiable paths: `<N>` (if included)
```
