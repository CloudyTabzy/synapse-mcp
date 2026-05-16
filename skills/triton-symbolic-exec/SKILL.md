---
name: triton-symbolic-exec
description: Symbolic execution and SMT constraint solving with Triton inside IDA Pro. Use to analyze function inputs, explore branch conditions, solve for concrete values that reach specific code paths, and perform taint analysis. Ideal for crackmes, input validation routines, and cryptographic checks.
allowed-tools: mcp__ida_pro_mcp__triton_status, mcp__ida_pro_mcp__triton_init, mcp__ida_pro_mcp__triton_reset, mcp__ida_pro_mcp__triton_get_context_info, mcp__ida_pro_mcp__triton_symbolize_register, mcp__ida_pro_mcp__triton_symbolize_memory, mcp__ida_pro_mcp__triton_batch_symbolize_registers, mcp__ida_pro_mcp__triton_set_concrete_register_value, mcp__ida_pro_mcp__triton_set_concrete_memory_value, mcp__ida_pro_mcp__triton_process_instruction, mcp__ida_pro_mcp__triton_process_function, mcp__ida_pro_mcp__triton_get_symbolic_variables, mcp__ida_pro_mcp__triton_get_symbolic_expressions, mcp__ida_pro_mcp__triton_get_path_constraints, mcp__ida_pro_mcp__triton_solve_path_constraints, mcp__ida_pro_mcp__triton_taint_register, mcp__ida_pro_mcp__triton_taint_memory, mcp__ida_pro_mcp__triton_get_taint_summary, mcp__ida_pro_mcp__triton_snapshot_save, mcp__ida_pro_mcp__triton_snapshot_restore, mcp__ida_pro_mcp__triton_snapshot_list, mcp__ida_pro_mcp__triton_snapshot_delete, mcp__ida_pro_mcp__triton_analyze_function, mcp__ida_pro_mcp__triton_find_input_for_branch, mcp__ida_pro_mcp__triton_annotate_function, mcp__ida_pro_mcp__triton_highlight_tainted_instructions, mcp__ida_pro_mcp__triton_get_ast_expression, mcp__ida_pro_mcp__triton_simplify_expression, mcp__ida_pro_mcp__triton_lift_to_smt, mcp__ida_pro_mcp__lookup_funcs, mcp__ida_pro_mcp__decompile, mcp__ida_pro_mcp__disasm, mcp__ida_pro_mcp__basic_blocks, mcp__ida_pro_mcp__xrefs_to, mcp__ida_pro_mcp__int_convert, mcp__ida_pro_mcp__set_comments, mcp__ida_pro_mcp__get_bytes, Bash, Read, Write, AskUserQuestion
---

# triton-symbolic-exec

Use Triton symbolic execution to analyze functions in IDA Pro. Symbolize inputs, execute instructions symbolically, accumulate path constraints, and use Z3 to solve for concrete values that drive execution down specific branches.

> **Tool prefix note**: MCP tool names depend on your client configuration. If your server is named differently, adjust the prefix accordingly.

> **Dependency**: Requires `triton-library` to be installed (`ida-pro-mcp --install-deps triton`).

## Prerequisites

- Triton must be installed and available (`triton_status` returns `"available": true`)
- A target function or code region must be identified
- For function-level analysis, the function should be fully defined in IDA

## Instructions

### 1. Verify Triton availability

```
mcp__ida_pro_mcp__triton_status()
```

If `"available": false`, stop and tell the user to install Triton:
> Triton is not installed. Install it with `ida-pro-mcp --install-deps triton`

### 2. Initialize Triton context

```
mcp__ida_pro_mcp__triton_init()
```

This auto-detects architecture from the current IDA database. Note the returned architecture and bitness.

If you need to reinitialize with a clean slate later:

```
mcp__ida_pro_mcp__triton_reset()
```

### 3. Choose analysis mode

**Option A — One-shot function analysis (simplest):**
Use when you want to symbolize arguments and run through an entire function.

**Option B — Instruction-by-instruction (finest control):**
Use when you need to control exactly which instructions are processed, seed specific concrete values mid-execution, or explore branches interactively.

**Option C — Taint analysis (data-flow tracking):**
Use when you want to know which instructions are influenced by a specific input (register or memory).

**Option D — Branch-target solving (input synthesis):**
Use when you need to find concrete inputs that reach a specific address.

### Option A: One-shot function analysis

#### A1. Identify target function

Resolve the function address via `mcp__ida_pro_mcp__lookup_funcs` or use a known address.

#### A2. Run compound analysis

```
mcp__ida_pro_mcp__triton_analyze_function(
    function_address="<addr>",
    symbolize_args="all",
    solve_constraints=true
)
```

This internally: initializes context → symbolizes arguments → processes all instructions → attempts Z3 solving.

Review the returned report. Look for:
- Symbolic variables created
- Path constraints accumulated
- Z3 model (concrete values for inputs)
- Any unsatisfiable constraints

#### A3. Find input for a specific branch

If you need inputs that reach a specific basic block or address:

```
mcp__ida_pro_mcp__triton_find_input_for_branch(
    function_address="<addr>",
    target_address="<branch_addr>",
    symbolize_args="all"
)
```

This uses IDA's FlowChart to find a path to the target, then asks Z3 for inputs that satisfy that path.

### Option B: Instruction-by-instruction analysis

#### B1. Symbolize inputs

**Symbolize registers:**

```
mcp__ida_pro_mcp__triton_symbolize_register(register="rdi")
mcp__ida_pro_mcp__triton_symbolize_register(register="rsi")
```

**Symbolize memory:**

```
mcp__ida_pro_mcp__triton_symbolize_memory(address="0x7fffffffe000", size=64)
```

**Batch symbolize:**

```
mcp__ida_pro_mcp__triton_batch_symbolize_registers(registers="rdi,rsi,rdx")
```

#### B2. Seed concrete values (optional)

If some inputs should have known concrete values:

```
mcp__ida_pro_mcp__triton_set_concrete_register_value(register="rcx", value=32)
mcp__ida_pro_mcp__triton_set_concrete_memory_value(address="0x7fffffffe000", values="48 65 6C 6C 6F")
```

#### B3. Process instructions

**Single instruction:**

```
mcp__ida_pro_mcp__triton_process_instruction(address="0x401000")
```

**Full function:**

```
mcp__ida_pro_mcp__triton_process_function(function_address="0x401000")
```

#### B4. Inspect symbolic state

```
mcp__ida_pro_mcp__triton_get_symbolic_variables()
mcp__ida_pro_mcp__triton_get_symbolic_expressions()
mcp__ida_pro_mcp__triton_get_path_constraints()
```

#### B5. Solve constraints

```
mcp__ida_pro_mcp__triton_solve_path_constraints()
```

To explore the *other* side of the last branch (negate the last constraint):

```
mcp__ida_pro_mcp__triton_solve_path_constraints(negate_last=true)
```

**Important**: After solving with `negate_last=true`, the Triton context is modified. If you want to return to the original path, restore from a snapshot (see Option B6).

#### B6. Snapshot workflow for branch exploration

To systematically explore both sides of branches:

1. Before a branch, save a snapshot:
   ```
   mcp__ida_pro_mcp__triton_snapshot_save(name="before_branch_1")
   ```

2. Process the branch instruction (Triton will follow one path)

3. Solve constraints for the current path:
   ```
   mcp__ida_pro_mcp__triton_solve_path_constraints()
   ```

4. Restore the snapshot to go back to the branch point:
   ```
   mcp__ida_pro_mcp__triton_snapshot_restore(name="before_branch_1")
   ```

5. Now negate the last constraint to explore the other path:
   ```
   mcp__ida_pro_mcp__triton_solve_path_constraints(negate_last=true)
   ```

6. List all snapshots:
   ```
   mcp__ida_pro_mcp__triton_snapshot_list()
   ```

7. Delete unneeded snapshots:
   ```
   mcp__ida_pro_mcp__triton_snapshot_delete(name="before_branch_1")
   ```

### Option C: Taint analysis

#### C1. Mark taint sources

```
mcp__ida_pro_mcp__triton_taint_register(register="rdi")
mcp__ida_pro_mcp__triton_taint_memory(address="0x7fffffffe000", size=64)
```

#### C2. Process instructions

```
mcp__ida_pro_mcp__triton_process_function(function_address="<addr>")
```

#### C3. Get taint summary

```
mcp__ida_pro_mcp__triton_get_taint_summary()
```

Review which registers and memory regions are tainted.

#### C4. Highlight tainted instructions in IDA

```
mcp__ida_pro_mcp__triton_highlight_tainted_instructions()
```

This adds color to instructions that operate on tainted data.

### Option D: Branch-target solving (input synthesis)

Use this when you know a specific address you want to reach (e.g., a success block in a crackme) but don't know what input gets there.

#### D1. Find the target function and branch address

Use `mcp__ida_pro_mcp__decompile` or `mcp__ida_pro_mcp__basic_blocks` to identify the target block address.

#### D2. Run CFG-guided search

```
mcp__ida_pro_mcp__triton_find_input_for_branch(
    function_address="<func_addr>",
    target_address="<target_addr>",
    symbolize_args="all"
)
```

This builds a path from function entry to the target block using IDA's FlowChart, then uses Z3 to find inputs satisfying all branch predicates along that path.

### 4. Annotate findings in IDA

After solving, write the path conditions back to the database as comments:

```
mcp__ida_pro_mcp__triton_annotate_function(function_address="<addr>")
```

This adds comments at each branch point showing the symbolic condition.

### 5. Inspect AST expressions (advanced)

For a specific symbolic variable, get its AST:

```
mcp__ida_pro_mcp__triton_get_ast_expression(symbolic_variable_id=0)
```

Simplify it:

```
mcp__ida_pro_mcp__triton_simplify_expression(address="<addr>", expression_id=0)
```

Export as SMT-LIB2:

```
mcp__ida_pro_mcp__triton_lift_to_smt(address="<addr>", expression_id=0)
```

### 6. Report results

Present findings to the user in a structured format:

```markdown
## Triton Analysis Results

### Target
- Function: `<name>` at `<addr>`

### Symbolic Inputs
| Variable | Type | Location |
|---|---|---|
| ... | ... | ... |

### Path Constraints
1. `<constraint 1>`
2. `<constraint 2>`

### Z3 Solution
| Variable | Concrete Value |
|---|---|
| ... | ... |

### Taint Summary (if applicable)
- Tainted registers: ...
- Tainted memory: ...
```
