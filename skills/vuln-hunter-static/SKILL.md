---
name: vuln-hunter-static
description: Static vulnerability hunting in IDA Pro. Use to find buffer overflows, format string bugs, integer overflows, use-after-free candidates, command injection, and other dangerous patterns. Combines import analysis, xref tracing, decompilation inspection, stack analysis, and byte-pattern scanning.
allowed-tools: mcp__ida_pro_mcp__imports, mcp__ida_pro_mcp__xrefs_to, mcp__ida_pro_mcp__xrefs_query, mcp__ida_pro_mcp__decompile, mcp__ida_pro_mcp__disasm, mcp__ida_pro_mcp__stack_frame, mcp__ida_pro_mcp__find_regex, mcp__ida_pro_mcp__find_bytes, mcp__ida_pro_mcp__find, mcp__ida_pro_mcp__basic_blocks, mcp__ida_pro_mcp__callgraph, mcp__ida_pro_mcp__lookup_funcs, mcp__ida_pro_mcp__analyze_function, mcp__ida_pro_mcp__func_profile, mcp__ida_pro_mcp__set_comments, mcp__ida_pro_mcp__rename, mcp__ida_pro_mcp__get_bytes, mcp__ida_pro_mcp__get_int, mcp__ida_pro_mcp__int_convert, mcp__ida_pro_mcp__py_eval, Bash, Read, Write, AskUserQuestion
---

# vuln-hunter-static

Hunt for common vulnerability classes in IDA Pro using static analysis. This skill focuses on identifying dangerous API usage, missing bounds checks, untrusted input flows, and suspicious code patterns.

> **Tool prefix note**: MCP tool names depend on your client configuration. If your server is named differently, adjust the prefix accordingly.

## When to use this skill

- You suspect a binary may have exploitable bugs
- You want to audit a specific component for security flaws
- You're analyzing malware and want to find its trigger conditions or payload logic
- You're doing a CTF/crackme and need to find the vulnerable path

## Prerequisites

- Binary loaded and auto-analysis complete
- You have a general idea of the attack surface (from `binary-survey`)

## Instructions

### 1. Enumerate dangerous APIs

Call `mcp__ida_pro_mcp__imports` and categorize high-risk functions:

| Vuln Class | Dangerous APIs |
|---|---|
| **Buffer overflow** | `strcpy`, `strcat`, `sprintf`, `wcscpy`, `lstrcpyA`, `memcpy` (unchecked size) |
| **Format string** | `printf`, `sprintf`, `fprintf`, `syslog`, `warnx` (user-controlled fmt arg) |
| **Integer overflow** | `malloc` with arithmetic on size, ` realloc`, multiplication before allocation |
| **Command injection** | `system`, `popen`, `ShellExecuteA`, `CreateProcessA`, `execve` |
| **Path traversal** | `fopen`, `CreateFileA`, `open` with user-controlled path |
| **Use-after-free** | `free` followed by dereference, `realloc` without null-check |
| **Double-free** | Multiple `free` on same pointer |
| **Info leak** | `strcpy` to output buffer, uninitialized memory reads |

For each dangerous API, find all xrefs:

```
mcp__ida_pro_mcp__xrefs_to(addrs="strcpy")
mcp__ida_pro_mcp__xrefs_to(addrs="sprintf")
```

### 2. Analyze each dangerous call site

For each xref, decompile the caller:

```
mcp__ida_pro_mcp__decompile(addr="<caller_addr>")
```

Check:
- **Buffer overflow**: Is the source buffer attacker-controlled? Is there a size check before copy?
- **Format string**: Is the format string user-controlled? (Look for `%s` `%n` in user input)
- **Integer overflow**: Is size computed with `+` or `*` on untrusted values before `malloc`?
- **Command injection**: Is the command string built with `sprintf`/`strcat` from user input?

### 3. Stack frame analysis for buffer sizes

For functions calling dangerous APIs:

```
mcp__ida_pro_mcp__stack_frame(addrs="<caller_addr>")
```

Look for:
- Large local buffers (>64 bytes) with no size validation
- `char buf[NNN]` near `strcpy`/`sprintf` calls
- Missing stack canaries (if binary is compiled without /GS)

### 4. Find suspicious instruction patterns

Use `mcp__ida_pro_mcp__find` and `mcp__ida_pro_mcp__find_bytes` to scan for:

- **Unchecked allocations**: `call malloc` followed immediately by use (no null check)
- **Stack cookies**: `__security_cookie` references — absence means no /GS
- **SEH overwrite targets**: Functions with `__except` handlers
- **ROP gadgets**: `ret` following `pop` sequences (advanced)

Common byte patterns:
```
mcp__ida_pro_mcp__find_bytes(pattern="E8 ?? ?? ?? ?? 48 85 C0")  # call; test rax, rax (null check)
mcp__ida_pro_mcp__find_bytes(pattern="E8 ?? ?? ?? ?? 48 8B 00")  # call; mov rax, [rax] (no null check → potential crash)
```

### 5. Trace input validation

For functions processing attacker-controlled input:

```
mcp__ida_pro_mcp__callgraph(roots="<handler_func>", max_depth=3)
```

Follow the call chain and look for:
- **Input sanitization**: `strlen`, `strnlen`, `memchr`, `isprint`, `isdigit`
- **Length checks**: comparisons against constants or computed lengths
- **Encoding/escaping**: `html_encode`, `url_encode`, `base64_encode`
- **Absence of the above** → red flag

### 6. Taint-like analysis with Triton (optional)

If Triton is installed, symbolize the input argument and process the function:

```
mcp__ida_pro_mcp__triton_init()
mcp__ida_pro_mcp__triton_symbolize_register(register="rdi")
mcp__ida_pro_mcp__triton_process_function(address="<handler_addr>")
mcp__ida_pro_mcp__triton_get_taint_summary()
```

See which instructions operate on the tainted input. If taint reaches a dangerous API call, that's a confirmed data-flow path.

### 7. Rank findings

Score each finding:

| Score | Criteria |
|---|---|
| 🔴 **Critical** | Attacker-controlled input → unchecked dangerous API (e.g., `strcpy` with user buf) |
| 🟠 **High** | Attacker-controlled input → dangerous API with partial checks (e.g., `sprintf` with fixed format but user arg) |
| 🟡 **Medium** | Dangerous API used, but input source is unclear or constrained |
| 🟢 **Low** | Dangerous API used, but input is hardcoded or strictly validated |

### 8. Annotate findings

```
mcp__ida_pro_mcp__set_comments(items=[
    {"address": "<addr>", "comment": "[CRIT] strcpy with attacker-controlled src, no bounds check"},
    {"address": "<addr>", "comment": "[HIGH] sprintf: format is fixed but arg 2 is user-controlled"}
])
```

### 9. Generate vulnerability report

Write `./reports/vuln_report_<timestamp>.md`:

```markdown
# Static Vulnerability Report: <binary_name>

## Summary
- Critical: N
- High: N
- Medium: N
- Low: N

## Critical Findings

### 1. <Title>
| Property | Value |
|---|---|
| Address | ... |
| Function | ... |
| Vuln Class | Buffer Overflow / Format String / etc. |
| Dangerous API | ... |
| Input Source | ... |
| Mitigation | None / Partial |

**Description:**
...

**Proof of concept idea:**
...

## High Findings
...

## Recommendations
1. ...
```

Present the report and ask: "Would you like to trace the input source for any finding, or generate a patch?"
