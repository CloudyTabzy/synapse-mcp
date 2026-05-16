---
name: vuln-hunter-static
description: Static vulnerability hunting in IDA Pro. Hunt for buffer overflows, format string vulnerabilities, integer overflows, use-after-free patterns, and logic flaws by analyzing dangerous API usage, input validation, and control flow. No debugger required.
allowed-tools: mcp__ida_pro_mcp__imports, mcp__ida_pro_mcp__exports, mcp__ida_pro_mcp__find_regex, mcp__ida_pro_mcp__find_bytes, mcp__ida_pro_mcp__find_insns, mcp__ida_pro_mcp__xrefs_to, mcp__ida_pro_mcp__xrefs_from, mcp__ida_pro_mcp__lookup_funcs, mcp__ida_pro_mcp__decompile, mcp__ida_pro_mcp__disasm, mcp__ida_pro_mcp__analyze_funcs, mcp__ida_pro_mcp__basic_blocks, mcp__ida_pro_mcp__stack_frame, mcp__ida_pro_mcp__get_string, mcp__ida_pro_mcp__get_bytes, mcp__ida_pro_mcp__get_int, mcp__ida_pro_mcp__list_globals, mcp__ida_pro_mcp__set_comments, mcp__ida_pro_mcp__rename, mcp__ida_pro_mcp__int_convert, mcp__ida_pro_mcp__py_eval, Bash, Read, Write, AskUserQuestion
---

# vuln-hunter-static

Hunt for vulnerabilities using static analysis in IDA Pro. Focuses on dangerous API usage, missing input validation, suspicious arithmetic, and control-flow weaknesses. No debugger is required.

> **Tool prefix note**: MCP tool names depend on your client configuration. If your server is named differently, adjust the prefix accordingly.

## Prerequisites

- Binary loaded and auto-analysis complete in IDA Pro
- Hex-Rays decompiler available (for decompilation-based analysis)

## Instructions

### 1. Enumerate dangerous imports

Call `mcp__ida_pro_mcp__imports` to get the full import table. Categorize by risk:

#### High-risk sinks (no bounds checking)
| API | Risk | Notes |
|---|---|---|
| `strcpy`, `strcpyA`, `strcpyW` | Buffer overflow | No length limit |
| `strcat`, `strcatA`, `strcatW` | Buffer overflow | No length limit |
| `sprintf`, `vsprintf`, `swprintf` | Format string / overflow | If format string is user-controlled → format string bug |
| `gets`, `gets_s` | Buffer overflow | `gets` is deprecated but still found |
| `wcscpy`, `wcscat` | Buffer overflow | Wide-character versions |
| `lstrcpyA`, `lstrcpyW`, `lstrcatA`, `lstrcatW` | Buffer overflow | Windows API equivalents |
| `memcpy` | Buffer overflow | If size is attacker-controlled or miscalculated |
| `memmove` | Buffer overflow | Same as memcpy if size wrong |

#### Medium-risk sinks (bounded but often misused)
| API | Risk | Notes |
|---|---|---|
| `strncpy`, `strncat` | Off-by-one / null termination | Does not guarantee null termination |
| `snprintf`, `vsnprintf` | Format string | If format string is user-controlled |
| `sscanf`, `vsscanf` | Format string / overflow | Can write arbitrary memory with `%n` |
| `MultiByteToWideChar` | Buffer overflow | If destination size is miscalculated |
| `WideCharToMultiByte` | Buffer overflow | Same |
| `read`, `fread`, `recv`, `recvfrom` | Buffer overflow | If length argument unchecked |

#### Dangerous integer operations
| API / Pattern | Risk | Notes |
|---|---|---|
| `malloc(size * count)` | Integer overflow | If `size * count` wraps around → small allocation, large copy |
| `alloca(n)` | Stack overflow | If `n` is large or attacker-controlled |
| `realloc(ptr, new_size)` | Integer overflow / UAF | Check return value |
| Signed/unsigned comparison | Logic flaw | `jl` vs `jb` confusion can bypass bounds checks |

#### Process execution (command injection)
| API | Risk | Notes |
|---|---|---|
| `system`, `popen`, `_popen` | Command injection | If argument contains user input |
| `WinExec`, `ShellExecuteA/W` | Command injection | Same |
| `CreateProcessA/W` | Command injection | If command line contains user input |

### 2. Find cross-references to dangerous APIs

For each high-risk import, find where it is called:

```
mcp__ida_pro_mcp__xrefs_to(addrs="<import_addr>")
```

Be selective. Focus on:
- Network-facing functions
- File-parsing functions
- Functions processing user input
- Functions with large stack frames

Do not enumerate xrefs for every import — that would bloat the context.

### 3. Analyze each caller function

For each xref to a dangerous API, analyze the calling function:

#### 3a. Decompile the caller

```
mcp__ida_pro_mcp__decompile(addr="<caller_func_addr>")
```

#### 3b. Identify the buffer and size

Look for:
- **Destination buffer**: Where does the dangerous API write?
  - Stack buffer? Check `sub rsp, N` or `alloca`
  - Heap buffer? Check `malloc`/`HeapAlloc` size
  - Global buffer? Check `.bss`/`.data` size
- **Source/size**: What controls how much data is written/copied?
  - Is it a fixed constant? (lower risk)
  - Is it derived from user input? (high risk)
  - Is it the result of arithmetic? (check for integer overflow)

#### 3c. Check for length validation

Look for guards before the dangerous call:
- `cmp` + conditional jump checking size
- `min()`-like patterns
- Early returns on oversized input

If there is NO length check, or the check is flawed (off-by-one, signed comparison, wrong variable), flag it.

#### 3d. Check for format string vulnerability

For `sprintf`/`printf` family calls:
- Is the format string argument a constant string? → safe
- Is the format string derived from user input / variable? → **format string vulnerability**

### 4. Search for suspicious patterns

#### 4a. Buffer overflow patterns

Use `mcp__ida_pro_mcp__find_insns` or `mcp__ida_pro_mcp__find_bytes` to search for:

- `sub rsp, N` with large N (>0x1000) — possible stack allocation
- `mov rcx, N` followed by `call malloc` — heap allocation
- `lea rdi, [rbp-N]` followed by `call strcpy` — stack destination

#### 4b. Integer overflow patterns

Look for arithmetic on sizes before allocation:
- `imul` or `shl` on a size value
- `add` on two size values
- Result used as `malloc`/`memcpy` size

#### 4c. SEH abuse patterns

- Multiple `__try` blocks in one function
- SEH handlers that point to non-standard locations
- `pop esp` / `pop ebp` in exception handlers

#### 4d. Anti-analysis patterns

Use `mcp__ida_pro_mcp__find_bytes`:
- `64 A1 30 00 00 00` (PEB access)
- `0F 31` (`rdtsc`)
- `0F 01 D0` (`xgetbv`)
- `EB FE` (infinite loop)

### 5. Stack frame analysis for buffer sizes

For functions calling dangerous APIs, check their stack frames:

```
mcp__ida_pro_mcp__stack_frame(addrs="<func_addr>")
```

Note:
- Large stack buffers (>256 bytes) near dangerous calls
- Missing stack cookies (`__security_cookie` checks)
- Variable-length arrays (VLAs) on the stack

### 6. Rank findings

For each potential vulnerability, assign a risk score:

| Factor | Weight |
|---|---|
| Dangerous API with no length check | High |
| User input reaches sink | High |
| Network-facing code path | High |
| Stack buffer as destination | High |
| Format string controlled by user | Critical |
| Integer overflow before allocation | High |
| Heap buffer with unchecked size | Medium |
| Local file input only | Medium |
| Length check present but flawed | Medium |

### 7. Generate vulnerability report

Write a markdown report to `./reports/vuln_report_<timestamp>.md`:

```markdown
# Static Vulnerability Report: <binary_name>

## Summary
- Total functions analyzed: N
- High-risk imports found: N
- Potential vulnerabilities: N

## Ranked Findings

### 1. <Vulnerability Type> at <address>
- **Function**: `<name>` (`<addr>`)
- **Sink API**: `<api_name>`
- **Risk**: Critical / High / Medium / Low
- **Description**: <what the bug is>
- **Trigger**: <how to trigger it>
- **Evidence**:
  - Decompiler snippet: ```c ... ```
  - No length check found: <explanation>
  - Buffer size: N bytes
  - Input source: <where attacker input comes from>

### 2. ...

## Mitigations Present
- ASLR: Yes/No
- DEP/NX: Yes/No
- Stack cookies: Yes/No
- SafeSEH: Yes/No
- CFG: Yes/No

## Recommendations
1. ...
```

### 8. Annotate the database

For each confirmed vulnerability:

```
mcp__ida_pro_mcp__set_comments(items=[
    {"address": "<sink_addr>", "comment": "VULN: strcpy to stack buffer without length check. Buffer: [rbp-0x40], size 64 bytes."},
    {"address": "<func_addr>", "comment": "VULN: vulnerable function — no input validation on recv buffer"}
])
```

Rename vulnerable functions:

```
mcp__ida_pro_mcp__rename(batch={"func": [{"address": "<addr>", "name": "vuln_recv_handler_no_bounds_check"}]})
```

Present the ranked list to the user and ask which findings they want to investigate further or develop PoCs for.
