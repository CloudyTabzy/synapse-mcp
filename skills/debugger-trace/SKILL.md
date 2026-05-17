---
name: debugger-trace
description: Debugger control and live analysis inside IDA Pro. Use to start a debug session, set breakpoints, read registers and memory, trace execution, and capture runtime state. Ideal for anti-debug bypass, dynamic unpacking, and verifying static analysis hypotheses.
allowed-tools: mcp__ida_pro_mcp__dbg_start, mcp__ida_pro_mcp__dbg_status, mcp__ida_pro_mcp__dbg_exit, mcp__ida_pro_mcp__dbg_continue, mcp__ida_pro_mcp__dbg_run_to, mcp__ida_pro_mcp__dbg_step_into, mcp__ida_pro_mcp__dbg_step_over, mcp__ida_pro_mcp__dbg_bps, mcp__ida_pro_mcp__dbg_add_bp, mcp__ida_pro_mcp__dbg_delete_bp, mcp__ida_pro_mcp__dbg_toggle_bp, mcp__ida_pro_mcp__dbg_set_bp_condition, mcp__ida_pro_mcp__dbg_regs, mcp__ida_pro_mcp__dbg_gpregs, mcp__ida_pro_mcp__dbg_regs_all, mcp__ida_pro_mcp__dbg_regs_named, mcp__ida_pro_mcp__dbg_stacktrace, mcp__ida_pro_mcp__dbg_read, mcp__ida_pro_mcp__dbg_write, mcp__ida_pro_mcp__lookup_funcs, mcp__ida_pro_mcp__decompile, mcp__ida_pro_mcp__disasm, mcp__ida_pro_mcp__get_bytes, mcp__ida_pro_mcp__get_int, mcp__ida_pro_mcp__get_string, mcp__ida_pro_mcp__patch, mcp__ida_pro_mcp__patch_asm, mcp__ida_pro_mcp__set_comments, mcp__ida_pro_mcp__int_convert, Bash, Read, Write, AskUserQuestion
---

# debugger-trace

Control the IDA Pro debugger through MCP tools. Start/stop execution, manage breakpoints, inspect registers and memory, and capture runtime state — all without leaving the MCP context.

> **Tool prefix note**: MCP tool names depend on your client configuration. If your server is named differently, adjust the prefix accordingly.

> **Extension requirement**: Debugger tools are hidden by default. The MCP client must connect with `?ext=dbg` (e.g., `http://127.0.0.1:13337/mcp?ext=dbg`). Some tools are also `@unsafe` and require `--unsafe` on the server.

## When to use this skill

- You need to bypass anti-debug checks dynamically
- You're unpacking a packed binary and need to dump decrypted code
- You want to verify a static analysis hypothesis with live execution
- You need to trace a specific function's register/memory behavior
- You're analyzing shellcode or self-modifying code

## Prerequisites

- Debugger is configured in IDA Pro (Local Windows debugger, Remote GDB, etc.)
- MCP client is connected with `?ext=dbg`
- Server started with `--unsafe` if patching during debug session

## Instructions

### 1. Start and verify debugger

```
mcp__ida_pro_mcp__dbg_start()
mcp__ida_pro_mcp__dbg_status()
```

Verify the process is running and the debugger is attached. If `dbg_start` fails, check IDA's debugger settings (Debugger → Select debugger).

### 2. Set strategic breakpoints

#### 2a. Break at entry point or specific function

```
mcp__ida_pro_mcp__dbg_add_bp(addrs="main")
mcp__ida_pro_mcp__dbg_add_bp(addrs="0x401000")
```

#### 2b. Hardware breakpoints

For code that checksums itself or uses anti-debug:

```
mcp__ida_pro_mcp__dbg_add_bp(
    addrs="0x401200",
    bpt_type="hardware",
    size=1
)
```

#### 2c. Conditional breakpoints

```
mcp__ida_pro_mcp__dbg_set_bp_condition(
    addr="0x401200",
    condition="EAX == 0xDEADBEEF"
)
```

#### 2d. List and manage breakpoints

```
mcp__ida_pro_mcp__dbg_bps()
mcp__ida_pro_mcp__dbg_toggle_bp(addrs="0x401000")
mcp__ida_pro_mcp__dbg_delete_bp(addrs="0x401000")
```

### 3. Run and step execution

#### 3a. Run to a specific address

```
mcp__ida_pro_mcp__dbg_run_to(addr="0x401500")
```

#### 3b. Continue until breakpoint

```
mcp__ida_pro_mcp__dbg_continue()
```

#### 3c. Step into / over

```
mcp__ida_pro_mcp__dbg_step_into()
mcp__ida_pro_mcp__dbg_step_over()
```

### 4. Inspect CPU state at breakpoints

#### 4a. General-purpose registers

```
mcp__ida_pro_mcp__dbg_gpregs()
```

#### 4b. Full register dump

```
mcp__ida_pro_mcp__dbg_regs()
```

#### 4c. Specific registers

```
mcp__ida_pro_mcp__dbg_regs_named(names="rax,rbx,rcx,rdx,rsi,rdi")
```

### 5. Inspect memory

#### 5a. Read from debugged process

```
mcp__ida_pro_mcp__dbg_read(regions="0x7fffffffe000-0x7fffffffe100")
```

#### 5b. Read strings

```
mcp__ida_pro_mcp__dbg_read(regions="0x405000-0x405100")
# Then interpret bytes as string or use get_string
```

#### 5c. Write to debugged process (optional)

```
mcp__ida_pro_mcp__dbg_write(items=[
    {"address": "0x7fffffffe000", "data": "48 65 6C 6C 6F"}
])
```

### 6. Stack trace

```
mcp__ida_pro_mcp__dbg_stacktrace()
```

Useful for:
- Understanding call chain at crash point
- Finding return-oriented programming (ROP) gadgets
- Tracing exception handlers

### 7. Anti-debug bypass workflow

If the binary has anti-debug checks:

#### 7a. Locate check (statically)

```
mcp__ida_pro_mcp__find_bytes(pattern="64 A1 30 00 00 00")  # PEB access
mcp__ida_pro_mcp__find_bytes(pattern="0F B6 40 02")        # BeingDebugged
```

#### 7b. Set breakpoint before check

```
mcp__ida_pro_mcp__dbg_add_bp(addrs="0x401200")
```

#### 7c. Patch check at runtime

When breakpoint hits, patch the flag in memory:

```
mcp__ida_pro_mcp__dbg_write(items=[
    {"address": "0x7fffffffe030", "data": "00"}  # Set BeingDebugged = 0
])
```

Or modify the register holding the result:

```
mcp__ida_pro_mcp__dbg_write(items=[
    {"address": "RAX", "data": "00 00 00 00 00 00 00 00"}
])
```

> Note: Direct register write via `dbg_write` may not be supported by all debugger backends. Use `py_eval` with `ida_dbg` APIs for advanced register manipulation if needed.

#### 7d. Continue past check

```
mcp__ida_pro_mcp__dbg_continue()
```

### 8. Dynamic unpacking workflow

For packed binaries:

#### 8a. Set breakpoint at OEP (Original Entry Point) or known unpack stub end

```
mcp__ida_pro_mcp__dbg_add_bp(addrs="0x401000")
```

#### 8b. Run until breakpoint

```
mcp__ida_pro_mcp__dbg_continue()
```

#### 8c. Dump decrypted code

```
mcp__ida_pro_mcp__dbg_read(regions="0x401000-0x402000")
```

#### 8d. Fix IDA database

Use `patch` or `patch_asm` to update the IDB with decrypted bytes, or create a new segment:

```
mcp__ida_pro_mcp__patch(patches=[
    {"address": "0x401000", "bytes": "<decrypted_hex>"}
])
```

### 9. Trace a function's behavior

To understand what a function does with live data:

#### 9a. Break at function entry

```
mcp__ida_pro_mcp__dbg_add_bp(addrs="0x401500")
```

#### 9b. Inspect arguments

At entry (x64 calling convention):
- RCX = arg1
- RDX = arg2
- R8 = arg3
- R9 = arg4

```
mcp__ida_pro_mcp__dbg_gpregs()
```

#### 9c. Step through and watch memory

```
mcp__ida_pro_mcp__dbg_step_over()  # step over calls
mcp__ida_pro_mcp__dbg_read(regions="<arg_addr>-<arg_addr+100>")
```

#### 9d. Inspect return value

At function exit (just before `ret`):
- RAX = return value

```
mcp__ida_pro_mcp__dbg_regs_named(names="rax")
```

### 10. Clean up and exit

```
mcp__ida_pro_mcp__dbg_delete_bp(addrs="*")  # remove all breakpoints
mcp__ida_pro_mcp__dbg_exit()
```

### 11. Generate debug trace report

Write `./reports/debug_trace.md`:

```markdown
# Debugger Trace Report

## Session Info
| Property | Value |
|---|---|
| Target | ... |
| Debugger | ... |
| Duration | ... |

## Breakpoints Hit
| Address | Hit Count | Register State | Notes |
|---|---|---|---|
| ... | ... | ... | ... |

## Memory Dumps
| Address | Size | Content Summary |
|---|---|---|
| ... | ... | ... |

## Anti-Debug Bypasses
| Check Address | Method | Result |
|---|---|---|
| ... | Patched PEB.BeingDebugged | Bypassed |

## Key Findings
- ...
```

Present the report and ask: "Would you like to set additional breakpoints, dump more memory regions, or switch back to static analysis?"
