---
name: hybrid-deobfuscate
description: Cross-engine deobfuscation workflow combining Miasm IR simplification with Triton symbolic execution. Use for heavily obfuscated binaries where standard decompilation fails — Miasm cleans up the CFG first, then Triton explores the simplified paths with SMT solving.
allowed-tools: mcp__ida_pro_mcp__hybrid_analyze_function, mcp__ida_pro_mcp__hybrid_deobfuscate_and_patch, mcp__ida_pro_mcp__hybrid_iterative_deobfuscate, mcp__ida_pro_mcp__miasm_status, mcp__ida_pro_mcp__miasm_sync, mcp__ida_pro_mcp__miasm_lift_function, mcp__ida_pro_mcp__miasm_get_cfg_summary, mcp__ida_pro_mcp__miasm_deobfuscate_cfg, mcp__ida_pro_mcp__miasm_trace_data_flow, mcp__ida_pro_mcp__miasm_annotate_data_flow, mcp__ida_pro_mcp__miasm_find_paths, mcp__ida_pro_mcp__miasm_solve_path_constraints, mcp__ida_pro_mcp__triton_status, mcp__ida_pro_mcp__triton_init, mcp__ida_pro_mcp__triton_process_function, mcp__ida_pro_mcp__triton_process_instruction, mcp__ida_pro_mcp__triton_analyze_function, mcp__ida_pro_mcp__triton_find_input_for_branch, mcp__ida_pro_mcp__triton_annotate_function, mcp__ida_pro_mcp__triton_solve_path_constraints, mcp__ida_pro_mcp__triton_taint_register, mcp__ida_pro_mcp__triton_get_taint_summary, mcp__ida_pro_mcp__triton_snapshot_save, mcp__ida_pro_mcp__triton_snapshot_restore, mcp__ida_pro_mcp__lookup_funcs, mcp__ida_pro_mcp__decompile, mcp__ida_pro_mcp__disasm, mcp__ida_pro_mcp__basic_blocks, mcp__ida_pro_mcp__callgraph, mcp__ida_pro_mcp__set_comments, mcp__ida_pro_mcp__rename, mcp__ida_pro_mcp__get_bytes, mcp__ida_pro_mcp__find_regex, mcp__ida_pro_mcp__int_convert, Bash, Read, Write, AskUserQuestion
---

# hybrid-deobfuscate

Analyze and deobfuscate heavily obfuscated binary code by combining Miasm's IR simplification with Triton's symbolic execution. Miasm removes opaque predicates and dead code; Triton then symbolically executes the simplified paths to recover input constraints.

> **Tool prefix note**: MCP tool names depend on your client configuration. If your server is named differently, adjust the prefix accordingly.

> **Dependencies**: Requires both `triton-library` and `miasm` to be installed (`ida-pro-mcp --install-deps all`).

## Prerequisites

- Both Triton and Miasm must be available
- Target function must exhibit signs of obfuscation (flattened control flow, opaque predicates, excessive jumps, dead code)

## Instructions

### 1. Verify both engines are available

```
mcp__ida_pro_mcp__miasm_status()
mcp__ida_pro_mcp__triton_status()
```

If either returns `"available": false`, stop and instruct the user to install the missing engine.

### 2. Identify obfuscated target function

Signs of obfuscation to look for:
- **Control-flow flattening**: A large dispatcher block with switch-like jumps to basic blocks
- **Opaque predicates**: Conditions that always evaluate to true/false but look dynamic (e.g., `x*x >= 0` where `x` is signed)
- **Junk code**: Instructions that don't affect program state
- **Excessive basic blocks**: Function has 2–5x more blocks than equivalent clean code
- **Anti-decompilation**: IDA/Hex-Rays produces garbled or incomplete pseudocode

Use these tools to confirm:

```
mcp__ida_pro_mcp__decompile(addr="<func_addr>")
mcp__ida_pro_mcp__basic_blocks(addrs="<func_addr>")
mcp__ida_pro_mcp__miasm_get_cfg_summary(address="<func_addr>")
```

### 3. Phase 1 — Miasm deobfuscation

#### 3a. Sync Miasm

```
mcp__ida_pro_mcp__miasm_sync()
```

#### 3b. Lift to IR and get baseline

```
mcp__ida_pro_mcp__miasm_lift_function(address="<func_addr>")
mcp__ida_pro_mcp__miasm_get_cfg_summary(address="<func_addr>")
```

Record original block count and cyclomatic complexity.

#### 3c. Run deobfuscation pass

```
mcp__ida_pro_mcp__miasm_deobfuscate_cfg(address="<func_addr>")
```

#### 3d. Measure improvement

```
mcp__ida_pro_mcp__miasm_get_cfg_summary(address="<func_addr>")
```

Compare before/after. Look for:
- Significant block count reduction
- Lower cyclomatic complexity
- Simplified expressions

#### 3e. Identify dead/empty blocks

After deobfuscation, look for blocks that:
- Contain only a single unconditional jump
- Have no meaningful IR assignments
- Are unreachable from the entry point

Note their addresses for potential patching.

### 4. Phase 2 — Triton symbolic analysis

#### 4a. Initialize Triton

```
mcp__ida_pro_mcp__triton_init()
```

#### 4b. Run compound analysis on the simplified function

```
mcp__ida_pro_mcp__triton_analyze_function(
    function_address="<func_addr>",
    symbolize_args="all",
    solve_constraints=true
)
```

Review the symbolic execution results. The simplified CFG should yield:
- Clearer path constraints
- Fewer symbolic variables
- More solvable predicates

#### 4c. Solve for specific branches

If there are critical branches (e.g., success/failure paths in a crackme):

```
mcp__ida_pro_mcp__triton_find_input_for_branch(
    function_address="<func_addr>",
    target_address="<success_block_addr>",
    symbolize_args="all"
)
```

Repeat for failure paths to understand what inputs are rejected.

#### 4d. Taint analysis for data provenance

If the function processes an input buffer:

```
mcp__ida_pro_mcp__triton_taint_register(register="rdi")
mcp__ida_pro_mcp__triton_process_function(function_address="<func_addr>")
mcp__ida_pro_mcp__triton_get_taint_summary()
```

This shows which instructions are influenced by the input.

### 5. Phase 3 — Hybrid compound workflow (shortcut)

For a one-shot combined report, use the hybrid tool directly:

```
mcp__ida_pro_mcp__hybrid_analyze_function(
    function_address="<func_addr>",
    symbolize_args="all",
    solve_constraints=true
)
```

This internally runs:
1. Miasm deobfuscation
2. Triton symbolic execution on the simplified function
3. Z3 constraint solving
4. Unified report

Review the combined output for:
- Deobfuscation metrics
- Symbolic variable mapping
- Path constraints
- Concrete input solutions

### 6. Phase 4 — Optional patching

If Miasm identified dead/empty blocks that can be safely removed:

#### 6a. Preview patches (dry run)

```
mcp__ida_pro_mcp__hybrid_deobfuscate_and_patch(
    function_address="<func_addr>",
    dry_run=true
)
```

This reports which blocks would be patched without modifying the database.

#### 6b. Review preview

Show the user:
- Which addresses would be patched
- What bytes would be written (typically NOPs)
- Why each block was identified as dead

#### 6c. Apply patches (requires --unsafe)

> **Warning**: Only proceed if the user explicitly confirms. This modifies the IDA database.

```
mcp__ida_pro_mcp__hybrid_deobfuscate_and_patch(
    function_address="<func_addr>",
    dry_run=false
)
```

After patching, re-decompile the function to verify improved output.

### 7. Phase 5 — Annotation and cleanup

#### 7a. Annotate branches with Triton

```
mcp__ida_pro_mcp__triton_annotate_function(function_address="<func_addr>")
```

#### 7b. Annotate data flow with Miasm

For key registers identified during analysis:

```
mcp__ida_pro_mcp__miasm_annotate_data_flow(
    address="<addr>",
    register="RAX"
)
```

#### 7c. Rename deobfuscated function

```
mcp__ida_pro_mcp__rename(batch={"func": [{"address": "<func_addr>", "name": "deobfuscated_check_password"}]})
```

#### 7d. Add overview comment

```
mcp__ida_pro_mcp__set_comments(items=[{"address": "<func_addr>", "comment": "Deobfuscated: was control-flow flattened. Original blocks: N, simplified: M. Key checks: ..."}])
```

### 8. Generate report

Write a markdown report to `./reports/hybrid_deobfuscation_<func_name>.md`:

```markdown
# Hybrid Deobfuscation Report: <function_name>

## Original Function
- Address: `<addr>`
- Blocks: N
- Cyclomatic complexity: N
- Obfuscation indicators: <flattening / opaque predicates / junk code / ...>

## Miasm Deobfuscation
- Blocks after simplification: M
- Complexity after simplification: M
- Dead blocks removed: N
- Empty blocks identified: N

## Triton Symbolic Analysis
### Symbolic Variables
| Name | Type | Origin |
|---|---|---|
| ... | ... | ... |

### Path Constraints
1. `<constraint>`

### Concrete Solutions
| Target Block | Feasible | Input Values |
|---|---|---|
| Success | Yes/No | ... |
| Failure | Yes/No | ... |

## Patches Applied
| Address | Original | New | Reason |
|---|---|---|---|
| ... | ... | ... | ... |

## Database Improvements
- Function renamed to: ...
- Comments added at: ...
- Data-flow annotated for: ...
```

Present the report to the user.
