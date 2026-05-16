---
name: stripped-binary-recovery
description: Recover semantics from stripped executables in IDA Pro. Use when a binary has no symbols, no debug info, and all functions appear as FUN_xxxx or sub_xxxx. Combines FLIRT signature scanning, code-gap discovery, string xref triage, call-graph hub analysis, constant matching, and structural similarity detection to rebuild a meaningful function map.
allowed-tools: mcp__ida_pro_mcp__get_metadata, mcp__ida_pro_mcp__list_segments, mcp__ida_pro_mcp__list_functions, mcp__ida_pro_mcp__list_functions_enhanced, mcp__ida_pro_mcp__find_code_gaps, mcp__ida_pro_mcp__find_next_undefined_function, mcp__ida_pro_mcp__find_undocumented_by_string, mcp__ida_pro_mcp__find_similar_functions, mcp__ida_pro_mcp__get_bulk_function_hashes, mcp__ida_pro_mcp__batch_string_anchor_report, mcp__ida_pro_mcp__get_function_signature, mcp__ida_pro_mcp__get_function_hash, mcp__ida_pro_mcp__get_function_call_graph, mcp__ida_pro_mcp__callgraph, mcp__ida_pro_mcp__analyze_function_complete, mcp__ida_pro_mcp__analyze_data_region, mcp__ida_pro_mcp__apply_data_classification, mcp__ida_pro_mcp__find_regex, mcp__ida_pro_mcp__find_bytes, mcp__ida_pro_mcp__find_insns, mcp__ida_pro_mcp__list_strings, mcp__ida_pro_mcp__xrefs_to, mcp__ida_pro_mcp__xrefs_from, mcp__ida_pro_mcp__lookup_funcs, mcp__ida_pro_mcp__decompile, mcp__ida_pro_mcp__disasm, mcp__ida_pro_mcp__basic_blocks, mcp__ida_pro_mcp__imports, mcp__ida_pro_mcp__exports, mcp__ida_pro_mcp__get_entry_points, mcp__ida_pro_mcp__set_comments, mcp__ida_pro_mcp__rename, mcp__ida_pro_mcp__int_convert, mcp__ida_pro_mcp__py_eval, Bash, Read, Write, AskUserQuestion
---

# stripped-binary-recovery

Recover function names, semantics, and structure from stripped binaries where all symbols have been removed. This skill systematically rebuilds a meaningful function map using signature matching, heuristics, string analysis, and graph analysis.

> **Tool prefix note**: MCP tool names depend on your client configuration. If your server is named differently, adjust the prefix accordingly.

## When to use this skill

- Binary shows only `FUN_xxxx` or `sub_xxxx` function names
- No debug symbols, PDB, or DWARF info
- Standard library functions appear as unnamed code
- You need to quickly separate "boring" library code from "interesting" application logic

## Prerequisites

- Binary loaded and auto-analysis complete in IDA Pro
- FLIRT signatures available (IDA ships with many; custom sigs can be added)

## Instructions

### 1. Assess what is stripped

Read metadata and get an overview:

```
mcp__ida_pro_mcp__get_metadata()
mcp__ida_pro_mcp__list_segments()
mcp__ida_pro_mcp__get_entry_points()
```

Check:
- **Symbol table**: Does the binary have a `.symtab` or `.dynsym`? If only `.dynsym`, dynamically-linked imports may still have names.
- **Debug sections**: `.debug_info`, `.debug_line`, `.pdb` — usually absent in stripped binaries.
- **Relocation info**: `.rel.dyn`, `.rela.dyn` — may hint at PLT/GOT structure.

Call `mcp__ida_pro_mcp__list_functions_enhanced` to see the ratio of named vs. unnamed functions:

```
mcp__ida_pro_mcp__list_functions_enhanced(limit=1000)
```

If >80% of functions are `FUN_*` or `sub_*`, this skill is appropriate.

### 2. Run FLIRT signature scans

IDA's Fast Library Identification and Recognition Technology (FLIRT) can recover standard library functions even in stripped binaries.

#### 2a. Scan with built-in signatures

Use the sigmaker tools to apply known signatures:

```
mcp__ida_pro_mcp__py_eval(code="""
import idaapi
import idautils
# Apply all available FLIRT signatures
for i in range(idaapi.get_sig_qty()):
    sig = idaapi.get_sig(i)
    if sig:
        idaapi.apply_sig(sig)
print(f'Applied {idaapi.get_sig_qty()} signatures')
""")
```

Wait for analysis to complete, then re-check `list_functions_enhanced` to see how many functions were renamed.

#### 2b. Scan with custom signatures

If you have custom `.sig` or `.pat` files for the target compiler (e.g., MSVC 2019, GCC 11, musl), load them:

```
mcp__ida_pro_mcp__py_eval(code="""
import idaapi
idaapi.plan_to_apply_idasgn('path/to/custom.sig')
ida_auto.auto_wait()
""")
```

After signature application, record:
- How many functions were renamed
- Which libraries were identified (CRT, STL, OpenSSL, zlib, etc.)

### 3. Discover missed functions

IDA's auto-analysis sometimes misses functions, especially in:
- Position-independent code (PIC) thunks
- Hand-written assembly
- Functions reached only via indirect jumps
- Firmware/embedded code with non-standard prologues

#### 3a. Find code gaps

```
mcp__ida_pro_mcp__find_code_gaps(min_size=16, limit=100)
```

For each gap:
- Disassemble the first few bytes
- Look for function prologues (`push rbp; mov rbp, rsp`, `sub rsp, N`, `push ebx`)
- If it looks like a function, create it with `mcp__ida_pro_mcp__create_function`

#### 3b. Find undefined functions near known code

```
mcp__ida_pro_mcp__find_next_undefined_function(
    start_address="<addr>",
    direction="forward",
    pattern="push",
    criteria="unexplored"
)
```

### 4. String cross-reference triage

Strings are the richest source of semantic hints in stripped binaries. Find which `FUN_*` functions reference interesting strings.

#### 4a. Batch string anchor report

```
mcp__ida_pro_mcp__batch_string_anchor_report(pattern=".cpp")
```

This maps source-file strings (e.g., `path/to/file.cpp`) to the `FUN_*` functions that reference them. Functions referencing the same source file are likely from the same compilation unit.

#### 4b. Find undocumented functions by string

For each interesting string address found in step 4a:

```
mcp__ida_pro_mcp__find_undocumented_by_string(address="<string_addr>")
```

This finds `FUN_*` functions that reference that string. Record the function addresses.

#### 4c. Categorize strings by security relevance

Use `mcp__ida_pro_mcp__find_regex` to search strings for:

| Category | Patterns |
|---|---|
| **Errors / logging** | `error`, `failed`, `invalid`, `cannot`, `unable` |
| **Crypto** | `AES`, `RSA`, `DES`, `SHA`, `MD5`, `HMAC`, `encrypt`, `decrypt` |
| **Network** | `http`, `tcp`, `socket`, `connect`, `bind`, `listen`, `wsa` |
| **File paths** | `\.exe`, `\.dll`, `\.txt`, `\.xml`, `\.json`, `C:\\`, `/tmp/` |
| **Registry** | `Software\\`, `HKLM`, `HKCU`, `Run`, `RunOnce` |
| **Commands** | `cmd`, `powershell`, `bash`, `sh -c`, `eval` |
| **Credentials** | `password`, `secret`, `token`, `api_key`, `auth` |
| **Debug** | `debug`, `trace`, `log`, `assert`, `TODO`, `FIXME` |

For each matching string, find its xrefs and note the calling `FUN_*` functions. These are your primary targets for manual analysis.

### 5. Entry point and initialization analysis

The entry point and initialization functions are rarely stripped and often call many application functions.

#### 5a. Analyze entry points

```
mcp__ida_pro_mcp__decompile(addr="<entry_point>")
mcp__ida_pro_mcp__callgraph(roots="<entry_point>", max_depth=3)
```

Look for:
- `__libc_start_main` or `main` wrapper (ELF)
- `WinMainCRTStartup` → `WinMain` (PE)
- `DllMainCRTStartup` → `DllMain` (DLL)
- Global constructors (`__init_array`, `.ctors`)
- TLS callbacks

#### 5b. Follow the call chain to find main logic

Trace from the entry point to the actual application logic:
1. Entry point → CRT initialization
2. CRT → `main` / `WinMain`
3. `main` → application functions

The functions called directly from `main` are likely high-level application logic.

### 6. Call graph hub analysis

Find "hub" functions — functions called by many others (likely utility/library code) vs. "leaf" functions that call few others (likely application-specific logic).

```
mcp__ida_pro_mcp__get_function_call_graph(depth=2, direction="both")
```

Alternatively, use `py_eval` to compute connectivity metrics:

```python
import idautils, ida_funcs, ida_xref

connectivity = {}
for func_ea in idautils.Functions():
    name = ida_funcs.get_func_name(func_ea)
    if not name.startswith("FUN_") and not name.startswith("sub_"):
        continue  # Skip already-named functions
    
    callers = len(list(idautils.XrefsTo(func_ea)))
    callees = len(list(idautils.XrefsFrom(func_ea)))
    connectivity[func_ea] = {"callers": callers, "callees": callees}

# Sort by caller count (hubs) and callee count (complex functions)
hubs = sorted(connectivity.items(), key=lambda x: x[1]["callers"], reverse=True)[:20]
complex_funcs = sorted(connectivity.items(), key=lambda x: x[1]["callees"], reverse=True)[:20]

print("=== Hub functions (many callers) ===")
for ea, info in hubs:
    print(f"{ea:#x}: {info['callers']} callers, {info['callees']} callees")

print("\n=== Complex functions (many callees) ===")
for ea, info in complex_funcs:
    print(f"{ea:#x}: {info['callers']} callers, {info['callees']} callees")
```

Functions with:
- **Many callers + few callees** → likely utility functions (memcpy wrappers, logging, error handling)
- **Few callers + many callees** → likely application logic (protocol handlers, file parsers)
- **Zero callers** → possibly dead code, callbacks, or dynamically resolved

### 7. Constant and pattern matching

#### 7a. Crypto constants

Search for known cryptographic constants:

```
mcp__ida_pro_mcp__find_bytes(patterns="63727970746f67726170686572")  # "cryptographer"
```

Better yet, search for common S-boxes, IVs, and magic numbers:
- MD5 initialization constants: `0x67452301`, `0xEFCDAB89`
- SHA-256 constants: `0x6a09e667`, `0xbb67ae85`
- AES S-box, Te0-Te4 tables
- CRC32 polynomial: `0xEDB88320`
- Base64 alphabet: `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/`

For each constant found:
1. Note the address
2. Find xrefs to that address
3. The xref-ing functions are likely crypto-related

#### 7b. Magic numbers and file signatures

Search for file format signatures:
- `MZ` (DOS/PE header)
- `PK\x03\x04` (ZIP)
- `\x7fELF` (ELF)
- `GIF87a`, `GIF89a`
- `\x89PNG`
- `\xff\xd8\xff` (JPEG)

Functions referencing these are likely file parsers or packers.

#### 7c. Instruction patterns

Find function prologues to discover missed functions:
- x64: `55 48 89 e5` (`push rbp; mov rbp, rsp`)
- x64: `48 89 5c 24` (`mov [rsp+8], rbx` — MSVC)
- x86: `55 89 e5` (`push ebp; mov ebp, esp`)
- ARM: `f0 4f 2d e9` (`push {r4-r11, lr}`)
- AArch64: `fd 7b bf a9` (`stp x29, x30, [sp, #-0x10]!`)

### 8. Structural similarity detection

Find groups of similar functions — these are often:
- Auto-generated code (protobuf, RPC stubs, dispatchers)
- Wrapper functions (error handling wrappers, API adapters)
- Compiler-generated constructors/destructors

#### 8a. Find similar functions locally

```
mcp__ida_pro_mcp__find_similar_functions(target_function="<addr>", threshold=0.8)
```

#### 8b. Bulk function hashing for clustering

```
mcp__ida_pro_mcp__get_bulk_function_hashes(filter="FUN_*", limit=500)
```

Group functions by hash similarity. Functions with identical or near-identical hashes are likely clones or wrappers.

### 9. Batch rename based on findings

After triage, apply systematic naming:

#### 9a. Rename recovered library functions

Functions identified by FLIRT signatures are already renamed. For any missed standard library functions, use the signature:

```
mcp__ida_pro_mcp__rename(batch={"func": [
    {"address": "<addr>", "name": "__libc_init_array"},
    {"address": "<addr>", "name": "_malloc"}
]})
```

#### 9b. Rename by string reference

Functions referenced by interesting strings get descriptive names:

```
mcp__ida_pro_mcp__rename(batch={"func": [
    {"address": "<addr>", "name": "handle_network_request"},
    {"address": "<addr>", "name": "parse_config_file"},
    {"address": "<addr>", "name": "encrypt_payload_aes"}
]})
```

#### 9c. Rename by pattern

Functions found via crypto constants:

```
mcp__ida_pro_mcp__rename(batch={"func": [
    {"address": "<addr>", "name": "md5_transform"},
    {"address": "<addr>", "name": "aes_encrypt_block"}
]})
```

### 10. Generate recovery report

Write a markdown report to `./reports/stripped_recovery.md`:

```markdown
# Stripped Binary Recovery Report: <binary_name>

## Stripping Assessment
| Property | Value |
|---|---|
| Symbol table | Present / Absent |
| Debug info | Present / Absent |
| Named functions | N / Total |
| Unnamed functions (FUN_*) | N / Total |

## FLIRT Signature Results
- Signatures applied: N
- Functions recovered: N
- Libraries identified: <list>

## Newly Discovered Functions
| Address | Method | Evidence | Proposed Name |
|---|---|---|---|
| ... | Code gap | Function prologue | ... |
| ... | String xref | References "config.json" | ... |
| ... | Crypto constant | References SHA-256 K table | ... |
| ... | Call graph hub | 45 callers, 2 callees | ... |

## Function Clusters
### Library / Utility functions
- ...

### Application logic functions
- ...

### Crypto / Encoding functions
- ...

### Network / File I/O functions
- ...

## Database Improvements Applied
- Renamed N functions
- Created N missed functions
- Added comments at: ...

## Remaining Unknown Functions
| Address | Size | Notes |
|---|---|---|
| ... | ... | ... |

## Recommended Next Steps
1. <suggest which functions to deep-dive first>
```

Present the report to the user and ask which recovered functions they want to analyze with `/function-deep-dive`.
