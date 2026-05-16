---
name: function-deep-dive
description: Deep analysis of a single function in IDA Pro. Decompile, disassemble, trace cross-references, analyze control flow, examine the stack frame, and improve database quality with renames, comments, and type applications. Use when you need to thoroughly understand one function's behavior.
allowed-tools: mcp__ida_pro_mcp__lookup_funcs, mcp__ida_pro_mcp__decompile, mcp__ida_pro_mcp__disasm, mcp__ida_pro_mcp__xrefs_to, mcp__ida_pro_mcp__xrefs_from, mcp__ida_pro_mcp__callees, mcp__ida_pro_mcp__callers, mcp__ida_pro_mcp__callgraph, mcp__ida_pro_mcp__basic_blocks, mcp__ida_pro_mcp__analyze_funcs, mcp__ida_pro_mcp__stack_frame, mcp__ida_pro_mcp__get_bytes, mcp__ida_pro_mcp__get_int, mcp__ida_pro_mcp__get_string, mcp__ida_pro_mcp__set_comments, mcp__ida_pro_mcp__rename, mcp__ida_pro_mcp__set_type, mcp__ida_pro_mcp__infer_types, mcp__ida_pro_mcp__int_convert, mcp__ida_pro_mcp__find_regex, mcp__ida_pro_mcp__py_eval, Bash, Read, Write, AskUserQuestion
---

# function-deep-dive

Thoroughly analyze a single function in IDA Pro. This skill walks through decompilation, disassembly, cross-reference analysis, control flow, stack frame examination, and database annotation.

> **Tool prefix note**: MCP tool names depend on your client configuration. If your server is named differently, adjust the prefix accordingly.

## Prerequisites

- Target function address or name
- IDA auto-analysis complete for the target function

## Instructions

### 1. Resolve target address

If given a name, resolve it:

```
mcp__ida_pro_mcp__lookup_funcs(queries="target_name")
```

If given an address string (hex), use `mcp__ida_pro_mcp__int_convert` to normalize it, then pass it directly.

Record the resolved address as `target_addr`.

### 2. Decompile

Call `mcp__ida_pro_mcp__decompile(addr=target_addr)` to get the Hex-Rays pseudocode.

Read the output carefully and note:
- **Function signature** — return type, parameter names/types
- **Local variables** — names, types, array vs pointer distinctions
- **Control flow** — loops, conditionals, switch statements
- **API calls** — which imported functions are called and with what arguments
- **String usage** — any string literals or format strings
- **Global variable access** — reads/writes to data sections
- **Arithmetic** — any integer operations that might overflow

### 3. Disassemble

Call `mcp__ida_pro_mcp__disasm(addr=target_addr)` to get the full assembly listing.

Cross-reference with the decompilation:
- Verify the compiler's optimizations (inlined functions, tail calls)
- Look for anti-decompilation tricks (opaque predicates, overlapping instructions, fake returns)
- Identify compiler-generated vs. hand-written code

### 4. Cross-reference analysis

#### 4a. Who calls this function?

```
mcp__ida_pro_mcp__xrefs_to(addrs=target_addr)
```

Note each caller's address and context. Is this function called from:
- Main logic?
- A library initialization routine?
- An export/DLL entry point?
- A callback registration?

#### 4b. What does this function call?

```
mcp__ida_pro_mcp__callees(addrs=target_addr)
```

Categorize callees:
- **Imported APIs** (from `imports`) — external behavior
- **Internal functions** — follow these for deeper analysis
- **Library/runtime functions** — stdlib, CRT, C++ STL

### 5. Control flow analysis

```
mcp__ida_pro_mcp__basic_blocks(addrs=target_addr)
```

Note:
- Number of basic blocks
- Cyclomatic complexity (blocks - edges + 2)
- Unreachable blocks
- Abnormal terminators (indirect jumps, exceptions)
- Loop structures (back edges)

For complex control flow, also call:

```
mcp__ida_pro_mcp__callgraph(roots=target_addr, max_depth=2)
```

### 6. Stack frame analysis

```
mcp__ida_pro_mcp__stack_frame(addrs=target_addr)
```

Note:
- Total stack frame size
- Buffer sizes (arrays, structs)
- Saved registers
- SEH frames (if present)
- Alignment padding

Look for:
- Large stack buffers (>256 bytes) — potential stack overflow targets
- Uninitialized variables used before assignment
- Format string buffers

### 7. Data references

Search for strings and constants referenced by this function:

```
mcp__ida_pro_mcp__find_regex(queries={"pattern": "...", "scope": "function", "function": target_addr})
```

Or use `mcp__ida_pro_mcp__get_string` at specific addresses found in the disassembly.

### 8. Improve database quality

Based on all findings, improve the IDA database:

#### 8a. Rename the function

```
mcp__ida_pro_mcp__rename(batch={"func": [{"address": target_addr, "name": "descriptive_name"}]})
```

Use a descriptive name that captures the function's purpose (e.g., `encrypt_payload`, `parse_config_file`, `validate_license_key`).

#### 8b. Rename variables and arguments

```
mcp__ida_pro_mcp__rename(batch={"local": [{"function": target_addr, "old_name": "a1", "new_name": "input_buffer"}]})
```

#### 8c. Apply types

```
mcp__ida_pro_mcp__set_type(edits=[{"address": target_addr, "type": "int __cdecl decrypt_payload(char *src, size_t len, char *dst)"}])
```

#### 8d. Add comments

```
mcp__ida_pro_mcp__set_comments(items=[{"address": target_addr, "comment": "Main decryption loop — XOR with rolling key 0x41"}])
```

Add comments at:
- Function entry (overview)
- Each major loop
- Each API call (explain why it's called)
- Each conditional branch (explain the decision)
- Each suspicious instruction

### 9. Generate analysis report

Write a markdown report to `./reports/function_analysis_<function_name>.md`:

```markdown
# Function Analysis: <name>

## Signature
```c
<decompiled signature>
```

## Overview
<1-2 paragraph summary of what this function does>

## Cross References
### Callers
| Address | Function | Context |
|---|---|---|
| ... | ... | ... |

### Callees
| Address | Function | Purpose |
|---|---|---|
| ... | ... | ... |

## Control Flow
- Basic blocks: N
- Cyclomatic complexity: N
- Loops: <description>
- Key branches: <description>

## Stack Frame
| Variable | Offset | Size | Type | Notes |
|---|---|---|---|---|
| ... | ... | ... | ... | ... |

## Key Behaviors
1. <behavior 1>
2. <behavior 2>

## Suspicious / Notable
- <anything unusual>

## Improvements Made
- Renamed function to: ...
- Renamed variables: ...
- Applied types: ...
- Added comments at: ...
```

Present the report to the user.
