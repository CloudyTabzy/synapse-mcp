---
name: miasm-ir-analysis
description: Miasm IR lifting, SSA transformation, CFG analysis, and data-flow tracing inside IDA Pro. Use for deobfuscation, complexity analysis, understanding data provenance, and cross-architecture assembly. Ideal for obfuscated binaries, control-flow flattening, and opaque predicate removal.
allowed-tools: mcp__ida_pro_mcp__miasm_status, mcp__ida_pro_mcp__miasm_sync, mcp__ida_pro_mcp__miasm_init, mcp__ida_pro_mcp__miasm_get_context_info, mcp__ida_pro_mcp__miasm_reset, mcp__ida_pro_mcp__miasm_lift_function, mcp__ida_pro_mcp__miasm_lift_to_ir, mcp__ida_pro_mcp__miasm_get_ssa, mcp__ida_pro_mcp__miasm_get_cfg_dot, mcp__ida_pro_mcp__miasm_get_cfg_summary, mcp__ida_pro_mcp__miasm_deobfuscate_cfg, mcp__ida_pro_mcp__miasm_trace_data_flow, mcp__ida_pro_mcp__miasm_find_paths, mcp__ida_pro_mcp__miasm_solve_path_constraints, mcp__ida_pro_mcp__miasm_annotate_data_flow, mcp__ida_pro_mcp__miasm_assemble, mcp__ida_pro_mcp__miasm_patch_instruction, mcp__ida_pro_mcp__miasm_simplify_block, mcp__ida_pro_mcp__miasm_emulate_symbolic, mcp__ida_pro_mcp__miasm_get_function_side_effects, mcp__ida_pro_mcp__miasm_search_instruction_pattern, mcp__ida_pro_mcp__lookup_funcs, mcp__ida_pro_mcp__decompile, mcp__ida_pro_mcp__disasm, mcp__ida_pro_mcp__basic_blocks, mcp__ida_pro_mcp__set_comments, mcp__ida_pro_mcp__rename, mcp__ida_pro_mcp__get_bytes, mcp__ida_pro_mcp__int_convert, Bash, Read, Write, AskUserQuestion
---

# miasm-ir-analysis

Use Miasm's intermediate representation (IR) lifting and analysis capabilities inside IDA Pro. Lift functions to IR, apply SSA transformation, analyze CFG structure, deobfuscate control flow, trace data flow, and solve path constraints.

> **Tool prefix note**: MCP tool names depend on your client configuration. If your server is named differently, adjust the prefix accordingly.

> **Dependency**: Requires `miasm` and `future` to be installed (`ida-pro-mcp --install-deps miasm`).

## Prerequisites

- Miasm must be installed and available (`miasm_status` returns `"available": true`)
- Target function must be defined in IDA

## Instructions

### 1. Verify Miasm availability

```
mcp__ida_pro_mcp__miasm_status()
```

If `"available": false`, stop and tell the user to install Miasm:
> Miasm is not installed. Install it with `ida-pro-mcp --install-deps miasm`

### 2. Sync architecture

```
mcp__ida_pro_mcp__miasm_sync()
```

This ensures Miasm's internal Machine matches the current IDA database. Note the returned architecture, bitness, and endianness.

If the architecture changed (e.g., after rebase or loading a different file), call:

```
mcp__ida_pro_mcp__miasm_reset()
```

### 3. Choose analysis mode

**Option A — CFG structural analysis:** Understand function complexity, loops, and dead code.

**Option B — IR lifting and SSA:** View the function in Miasm's intermediate representation.

**Option C — Deobfuscation:** Remove opaque predicates, fold constants, eliminate dead code.

**Option D — Data-flow tracing:** Find where a register's value originates.

**Option E — Path constraint solving:** Find concrete inputs that reach a specific basic block.

**Option F — Cross-arch assembly:** Assemble instructions and patch the database.

### Option A: CFG structural analysis

#### A1. Lift the function

```
mcp__ida_pro_mcp__miasm_lift_function(address="<func_addr>")
```

This returns the IRCFG (IR Control Flow Graph) as JSON blocks and edges.

#### A2. Get CFG summary

```
mcp__ida_pro_mcp__miasm_get_cfg_summary(address="<func_addr>")
```

Review:
- **Block count** — total basic blocks
- **Edge count** — control flow edges
- **Cyclomatic complexity** — `edges - nodes + 2`
- **Loop count** — natural loops detected
- **Topological order** — linearized block ordering

High cyclomatic complexity (>10) suggests complex logic or obfuscation.

#### A3. Get CFG DOT

```
mcp__ida_pro_mcp__miasm_get_cfg_dot(address="<func_addr>")
```

Save the DOT output to a file and render it with Graphviz if available:

```
Bash("dot -Tpng cfg.dot -o cfg.png")
```

### Option B: IR lifting and SSA

#### B1. Lift to IR

```
mcp__ida_pro_mcp__miasm_lift_function(address="<func_addr>")
```

Review the IR blocks. Each assembly instruction is decomposed into atomic assignments (e.g., `RAX = RDI + 4`, `Mem[RBX] = RAX`).

#### B2. Apply SSA transformation

```
mcp__ida_pro_mcp__miasm_get_ssa(address="<func_addr>")
```

SSA form ensures each variable is assigned exactly once. This makes data-flow analysis much easier. Look for:
- Phi functions at merge points
- Clear def-use chains
- Simplified expressions

### Option C: Deobfuscation

#### C1. Get baseline CFG summary

```
mcp__ida_pro_mcp__miasm_get_cfg_summary(address="<func_addr>")
```

Record the original block count and complexity.

#### C2. Run deobfuscation pass

```
mcp__ida_pro_mcp__miasm_deobfuscate_cfg(address="<func_addr>")
```

This applies:
- Constant folding
- Dead code elimination
- Expression simplification

#### C3. Compare before/after

```
mcp__ida_pro_mcp__miasm_get_cfg_summary(address="<func_addr>")
```

Look for:
- Reduced block count (dead blocks eliminated)
- Reduced cyclomatic complexity
- Simplified expressions

#### C4. Find empty blocks

After deobfuscation, some blocks may be empty (just a jump). These are candidates for patching (see Option F).

### Option D: Data-flow tracing

#### D1. Choose register and address

Pick a register of interest (e.g., `RAX`) and an address where you want to know its origin.

#### D2. Trace data flow

```
mcp__ida_pro_mcp__miasm_trace_data_flow(
    address="<addr>",
    register="RAX",
    max_steps=50
)
```

This performs a backward slice to find where the register's value comes from.

Review the trace:
- Does it originate from a function argument?
- From a memory read?
- From a constant?
- From arithmetic on other registers?

#### D3. Annotate in IDA

```
mcp__ida_pro_mcp__miasm_annotate_data_flow(
    address="<addr>",
    register="RAX"
)
```

This writes IDA comments at each instruction in the data-flow path, showing the origin.

### Option E: Path constraint solving

#### E1. Identify target block

Use `mcp__ida_pro_mcp__basic_blocks` or `mcp__ida_pro_mcp__miasm_get_cfg_summary` to identify the address of the block you want to reach.

#### E2. Solve for path inputs

```
mcp__ida_pro_mcp__miasm_solve_path_constraints(
    start_address="<func_entry>",
    target_address="<target_block>",
    max_paths=10
)
```

This enumerates paths from start to target and uses Z3 to find register values that reach the target.

Review each path:
- Is it feasible?
- What register constraints are required?
- Can the constraints be satisfied?

### Option F: Cross-arch assembly and patching

#### F1. Assemble an instruction

```
mcp__ida_pro_mcp__miasm_assemble(instruction="NOP")
mcp__ida_pro_mcp__miasm_assemble(instruction="MOV RAX, 0x1234")
```

Miasm supports multiple architectures (x86, x64, ARM, AArch64, MIPS). The architecture is auto-detected from IDA.

#### F2. Patch into IDA (unsafe)

> **Warning**: This requires the `--unsafe` flag.

```
mcp__ida_pro_mcp__miasm_patch_instruction(
    address="<addr>",
    instruction="NOP",
    dry_run=true
)
```

Always use `dry_run=true` first to preview the patch without modifying the database.

If the preview looks correct and the user confirms:

```
mcp__ida_pro_mcp__miasm_patch_instruction(
    address="<addr>",
    instruction="NOP",
    dry_run=false
)
```

### 4. Report results

Present findings in a structured format:

```markdown
## Miasm IR Analysis Results

### Target
- Function: `<name>` at `<addr>`

### CFG Summary
- Blocks: N → M (after deobfuscation)
- Complexity: N → M
- Loops: ...

### IR/SSA Highlights
- <notable IR pattern>
- <phi functions at merge points>

### Data Flow (if traced)
- `<register>` at `<addr>` originates from: ...

### Path Constraints (if solved)
| Path | Feasible | Constraints |
|---|---|---|
| ... | ... | ... |

### Patches Applied (if any)
| Address | Original | New | Reason |
|---|---|---|---|
| ... | ... | ... | ... |
```
