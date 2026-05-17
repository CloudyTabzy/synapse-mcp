---
name: function-deep-dive
description: Thorough single-function analysis in IDA Pro. Decompile, disassemble, trace xrefs, analyze CFG, inspect stack frame, rename variables, apply types, and add comments. Use after binary-survey or stripped-binary-recovery has identified a target function.
allowed-tools: mcp__ida_pro_mcp__lookup_funcs, mcp__ida_pro_mcp__decompile, mcp__ida_pro_mcp__disasm, mcp__ida_pro_mcp__xrefs_to, mcp__ida_pro_mcp__xrefs_query, mcp__ida_pro_mcp__basic_blocks, mcp__ida_pro_mcp__callgraph, mcp__ida_pro_mcp__stack_frame, mcp__ida_pro_mcp__find_regex, mcp__ida_pro_mcp__find_bytes, mcp__ida_pro_mcp__find, mcp__ida_pro_mcp__get_bytes, mcp__ida_pro_mcp__get_int, mcp__ida_pro_mcp__get_string, mcp__ida_pro_mcp__func_profile, mcp__ida_pro_mcp__analyze_function, mcp__ida_pro_mcp__rename, mcp__ida_pro_mcp__set_comments, mcp__ida_pro_mcp__declare_type, mcp__ida_pro_mcp__apply_type_batch, mcp__ida_pro_mcp__infer_type, mcp__ida_pro_mcp__declare_stack, mcp__ida_pro_mcp__patch_asm, mcp__ida_pro_mcp__int_convert, mcp__ida_pro_mcp__survey_binary, Bash, Read, Write, AskUserQuestion
---

# function-deep-dive

Perform a deep, systematic analysis of a single function in IDA Pro. This skill produces a comprehensive understanding of what the function does, how it interacts with the rest of the program, and improves the database quality through renaming, typing, and commenting.

> **Tool prefix note**: MCP tool names depend on your client configuration. If your server is named differently, adjust the prefix accordingly.

## When to use this skill

- You have identified a specific function of interest (via survey, stripped recovery, or user direction)
- You need to understand a function's logic, inputs, outputs, and side effects
- You want to improve the database by adding types, comments, and better names

## Prerequisites

- Target function address or name is known
- Auto-analysis is complete

## Instructions

### 1. Resolve and profile the target

```
mcp__ida_pro_mcp__lookup_funcs(queries="<name_or_addr>")
mcp__ida_pro_mcp__func_profile(queries="<addr>")
```

Record:
- Exact address, size, and cross-reference count
- Instruction count and basic block count
- Caller count and callee count
- Strings and non-trivial constants referenced

### 2. Decompile and inspect pseudocode

```
mcp__ida_pro_mcp__decompile(addr="<addr>", include_addresses=true)
```

Analyze:
- **Function signature**: argument types, return type, calling convention
- **Local variables**: buffers, counters, flags, structs
- **Control flow**: loops, conditionals, switch statements
- **External calls**: which APIs are invoked and with what arguments
- **Attacker-controllable inputs**: which arguments or globals influence control flow

### 3. Cross-check with disassembly

```
mcp__ida_pro_mcp__disasm(addr="<addr>", max_instructions=200)
```

Look for:
- Anti-decompilation tricks (opaque predicates, bogus jumps)
- Inline assembly or compiler intrinsics
- Unusual instruction sequences not reflected in pseudocode
- Manually verify critical logic that looks suspicious in the decompilation

### 4. Trace callers and callees

```
mcp__ida_pro_mcp__xrefs_to(addrs="<addr>")
mcp__ida_pro_mcp__callgraph(roots="<addr>", max_depth=2)
```

Understand:
- **Who calls this function?** How many callers? From what contexts?
- **What does it call?** Deep callee chains may indicate complex logic
- **Is it a callback?** Zero callers but referenced in a vtable or function pointer array

### 5. Analyze control flow graph

```
mcp__ida_pro_mcp__basic_blocks(addrs="<addr>")
```

Note:
- Cyclomatic complexity (number of independent paths)
- Deeply nested conditions (possible state machines)
- Unreachable or suspiciously empty basic blocks (obfuscation hints)
- Back edges (loops)

### 6. Inspect stack frame

```
mcp__ida_pro_mcp__stack_frame(addrs="<addr>")
```

Look for:
- **Large buffers** (>64 bytes) — potential stack overflow targets
- **SEH frames** — exception handling setup
- **Alignment gaps** — compiler padding or optimization artifacts
- **Struct layouts** — arrays of objects, nested structures

### 7. Trace data sources

Find where key values come from:

- **String references**: `find_regex` near the function address for error messages, format strings
- **Constant references**: `find_bytes` for magic numbers, crypto constants
- **Global variables**: `get_bytes` / `get_int` at addresses referenced by the function

```
mcp__ida_pro_mcp__get_bytes(addrs="0x406000")
mcp__ida_pro_mcp__get_string(addrs="0x406100")
```

### 8. Rename and type the function

#### 8a. Rename the function

```
mcp__ida_pro_mcp__rename(batch={"func": [{"address": "<addr>", "name": "descriptive_name"}]})
```

Naming conventions:
- `process_xxx` — main logic / state machine
- `parse_xxx` / `decode_xxx` — format conversion
- `init_xxx` / `setup_xxx` — initialization
- `handle_xxx` / `on_xxx` — event/callback handlers
- `check_xxx` / `validate_xxx` — input validation
- `encrypt_xxx` / `hash_xxx` — crypto routines

#### 8b. Apply argument types

```
mcp__ida_pro_mcp__apply_type_batch(batch=[
    {"type": "int (__fastcall *)(const char *, size_t)", "target": "<addr>", "target_type": "function"}
])
```

#### 8c. Create/stack variable types

```
mcp__ida_pro_mcp__declare_stack(items=[
    {"func": "<addr>", "offset": -0x20, "name": "buffer", "type": "char[64]"}
])
```

### 9. Add comments

```
mcp__ida_pro_mcp__set_comments(items=[
    {"address": "<addr>", "comment": "Entry point: validates header magic"},
    {"address": "<addr>+0x45", "comment": "Loop: processes each record in the table"}
])
```

Comment strategically:
- **Function header**: one-line summary of purpose
- **Loops**: iteration variable and termination condition
- **Branches**: what condition is being tested
- **External calls**: what API does and why it's called
- **Crypto**: algorithm name, key size, mode

### 10. Generate analysis report

Write a markdown report to `./reports/function_analysis_<name>.md`:

```markdown
# Function Analysis: <name>

## Metadata
| Property | Value |
|---|---|
| Address | ... |
| Size | ... bytes |
| Instructions | ... |
| Basic Blocks | ... |
| Callers | ... |
| Callees | ... |

## Signature
```c
<return_type> <name>(<args>);
```

## Summary
<1-paragraph description of what the function does>

## Control Flow
- Entry checks: ...
- Main loop: ...
- Exit path: ...

## External APIs Called
| Address | API | Purpose |
|---|---|---|
| ... | ... | ... |

## Inputs and Outputs
- **Inputs**: ...
- **Outputs**: ...
- **Side effects**: ...

## Security Relevance
- <any vulnerability hints, buffer handling, untrusted input paths>

## Database Changes Applied
- Renamed to: `<name>`
- Types applied: ...
- Comments added at: ...
```

Present the report and ask: "Would you like to trace data flow from this function, patch it, or analyze a related function?"
