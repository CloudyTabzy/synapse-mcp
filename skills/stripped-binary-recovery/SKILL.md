---
name: stripped-binary-recovery
description: Recover semantics from stripped executables in IDA Pro. Use when a binary has no symbols, no debug info, and all functions appear as FUN_xxxx or sub_xxxx. Combines FLIRT signatures, prologue scanning, VTable discovery, string xref triage, call-graph hub analysis, and structural similarity detection to rebuild a meaningful function map.
allowed-tools: mcp__ida_pro_mcp__survey_binary, mcp__ida_pro_mcp__get_binary_sections, mcp__ida_pro_mcp__find_function_prologues, mcp__ida_pro_mcp__find_vtable_candidates, mcp__ida_pro_mcp__find_indirect_calls, mcp__ida_pro_mcp__identify_vtable_call, mcp__ida_pro_mcp__find_global_writers, mcp__ida_pro_mcp__analyze_cleanup_function, mcp__ida_pro_mcp__apply_flirt_signature, mcp__ida_pro_mcp__load_type_library, mcp__ida_pro_mcp__list_type_libraries, mcp__ida_pro_mcp__find_similar_functions, mcp__ida_pro_mcp__find_regex, mcp__ida_pro_mcp__find_bytes, mcp__ida_pro_mcp__find, mcp__ida_pro_mcp__list_funcs, mcp__ida_pro_mcp__xrefs_to, mcp__ida_pro_mcp__xrefs_query, mcp__ida_pro_mcp__lookup_funcs, mcp__ida_pro_mcp__decompile, mcp__ida_pro_mcp__disasm, mcp__ida_pro_mcp__basic_blocks, mcp__ida_pro_mcp__callgraph, mcp__ida_pro_mcp__imports, mcp__ida_pro_mcp__export_funcs, mcp__ida_pro_mcp__set_comments, mcp__ida_pro_mcp__rename, mcp__ida_pro_mcp__int_convert, mcp__ida_pro_mcp__py_eval, mcp__ida_pro_mcp__func_profile, mcp__ida_pro_mcp__analyze_function, Bash, Read, Write, AskUserQuestion
---

# stripped-binary-recovery

Recover function names, semantics, and structure from stripped binaries where all symbols have been removed. This skill systematically rebuilds a meaningful function map using FLIRT signatures, reconnaissance heuristics, string analysis, and graph analysis.

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

Run a quick survey and section enumeration:

```
mcp__ida_pro_mcp__survey_binary(detail_level="minimal")
mcp__ida_pro_mcp__get_binary_sections()
```

Check:
- **Symbol table**: Does the binary have a `.symtab` or `.dynsym`? If only `.dynsym`, dynamically-linked imports may still have names.
- **Debug sections**: `.debug_info`, `.debug_line`, `.pdb` — usually absent in stripped binaries.
- **Relocation info**: `.rel.dyn`, `.rela.dyn` — may hint at PLT/GOT structure.

Call `mcp__ida_pro_mcp__list_funcs` to see the ratio of named vs. unnamed functions. If >80% are `FUN_*` or `sub_*`, this skill is appropriate.

### 2. Run FLIRT signature scans

IDA's Fast Library Identification and Recognition Technology (FLIRT) can recover standard library functions even in stripped binaries.

#### 2a. Scan with built-in signatures

Apply known signatures and wait for analysis:

```
mcp__ida_pro_mcp__apply_flirt_signature(sig_name="vc64rtf")
mcp__ida_pro_mcp__apply_flirt_signature(sig_name="gnulnx_x64")
```

Use `py_eval` to list available signatures if unsure:

```python
mcp__ida_pro_mcp__py_eval(code="""
import idaapi
sigs = [idaapi.get_sig(i) for i in range(idaapi.get_sig_qty()) if idaapi.get_sig(i)]
print([str(s) for s in sigs[:20]])
""")
```

Re-check `list_funcs` after application to see how many functions were renamed.

#### 2b. Load type libraries

If FLIRT identified a compiler runtime, load its type library:

```
mcp__ida_pro_mcp__load_type_library(name="vc64rtf")
mcp__ida_pro_mcp__list_type_libraries()
```

### 3. Discover missed functions

IDA's auto-analysis sometimes misses functions, especially in:
- Position-independent code (PIC) thunks
- Hand-written assembly
- Functions reached only via indirect jumps
- Firmware/embedded code with non-standard prologues

#### 3a. Scan for function prologues

```
mcp__ida_pro_mcp__find_function_prologues(
    start="0x140000000",
    end="0x140010000",
    create=true
)
```

This scans for common x64/x86 prologue patterns and optionally materializes functions. Use `create=false` first to preview, then `create=true` (requires `--unsafe`) to apply.

#### 3b. List functions in ranges

For code gaps between known functions:

```
mcp__ida_pro_mcp__list_funcs(queries="0x140001000-0x140005000")
```

### 4. Object-oriented reconstruction (C++ binaries)

#### 4a. Find VTable candidates

```
mcp__ida_pro_mcp__find_vtable_candidates(section=".data", min_pointers=4)
```

Scan for arrays of consecutive executable code pointers. These are strong indicators of C++ virtual method tables.

#### 4b. Find indirect calls

```
mcp__ida_pro_mcp__find_indirect_calls(
    start="0x140001000",
    end="0x140005000",
    max_results=100
)
```

Find `call [reg+offset]` and `call [reg]` sites. The offset histogram helps identify common vtable displacements.

#### 4c. Trace vtable calls

For a specific indirect call, trace backwards to find the object-loading chain:

```
mcp__ida_pro_mcp__identify_vtable_call(call_addr="0x1400023a0", lookback=20)
```

### 5. String cross-reference triage

Strings are the richest source of semantic hints in stripped binaries. Find which `FUN_*` functions reference interesting strings.

#### 5a. Search for source-file and error strings

Use `find_regex` to locate:

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

#### 5b. Cross-reference strings to functions

For each interesting string address, find xrefs:

```
mcp__ida_pro_mcp__xrefs_to(addrs="0x405000")
```

Note the calling `FUN_*` functions. These are your primary targets for manual analysis.

### 6. Entry point and initialization analysis

The entry point and initialization functions are rarely stripped and often call many application functions.

#### 6a. Analyze entry points

```
mcp__ida_pro_mcp__decompile(addr="start")
mcp__ida_pro_mcp__callgraph(roots="start", max_depth=3)
```

Look for:
- `__libc_start_main` or `main` wrapper (ELF)
- `WinMainCRTStartup` → `WinMain` (PE)
- `DllMainCRTStartup` → `DllMain` (DLL)
- Global constructors (`__init_array`, `.ctors`)
- TLS callbacks

#### 6b. Profile key functions

For functions called directly from entry points:

```
mcp__ida_pro_mcp__func_profile(queries="0x140001000,0x140001200")
```

This gives instruction counts, basic blocks, callers, callees, strings, and constants — great for triage.

### 7. Call graph hub analysis

Find "hub" functions — functions called by many others (likely utility/library code) vs. "leaf" functions that call few others (likely application-specific logic).

Use `py_eval` to compute connectivity metrics:

```python
mcp__ida_pro_mcp__py_eval(code="""
import idautils, ida_funcs

connectivity = {}
for func_ea in idautils.Functions():
    name = ida_funcs.get_func_name(func_ea)
    if not name.startswith('FUN_') and not name.startswith('sub_'):
        continue
    callers = len(list(idautils.XrefsTo(func_ea)))
    callees = len(list(idautils.XrefsFrom(func_ea)))
    connectivity[func_ea] = {'callers': callers, 'callees': callees}

hubs = sorted(connectivity.items(), key=lambda x: x[1]['callers'], reverse=True)[:20]
complex_funcs = sorted(connectivity.items(), key=lambda x: x[1]['callees'], reverse=True)[:20]

print('=== Hub functions (many callers) ===')
for ea, info in hubs:
    print(f'{ea:#x}: {info[\"callers\"]} callers, {info[\"callees\"]} callees')

print('\\n=== Complex functions (many callees) ===')
for ea, info in complex_funcs:
    print(f'{ea:#x}: {info[\"callers\"]} callers, {info[\"callees\"]} callees')
""")
```

Functions with:
- **Many callers + few callees** → likely utility functions (memcpy wrappers, logging, error handling)
- **Few callers + many callees** → likely application logic (protocol handlers, file parsers)
- **Zero callers** → possibly dead code, callbacks, or dynamically resolved

### 8. Constant and pattern matching

#### 8a. Crypto constants

Search for known cryptographic constants:

```
mcp__ida_pro_mcp__find_bytes(pattern="67 45 23 01")
mcp__ida_pro_mcp__find_bytes(pattern="EF CD AB 89")
```

Common targets:
- MD5 initialization constants: `0x67452301`, `0xEFCDAB89`
- SHA-256 constants: `0x6a09e667`, `0xbb67ae85`
- AES S-box, Te0-Te4 tables
- CRC32 polynomial: `0xEDB88320`
- Base64 alphabet: `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/`

For each constant found:
1. Note the address
2. Find xrefs to that address
3. The xref-ing functions are likely crypto-related

#### 8b. Magic numbers and file signatures

Search for file format signatures:
- `MZ` (DOS/PE header)
- `PK\x03\x04` (ZIP)
- `\x7fELF` (ELF)
- `GIF87a`, `GIF89a`
- `\x89PNG`
- `\xff\xd8\xff` (JPEG)

Functions referencing these are likely file parsers or packers.

### 9. Structural similarity detection

Find groups of similar functions — these are often:
- Auto-generated code (protobuf, RPC stubs, dispatchers)
- Wrapper functions (error handling wrappers, API adapters)
- Compiler-generated constructors/destructors

```
mcp__ida_pro_mcp__find_similar_functions(targets="0x140001000", threshold=0.95)
```

### 10. Batch rename based on findings

After triage, apply systematic naming:

#### 10a. Rename recovered library functions

Functions identified by FLIRT signatures are already renamed. For any missed standard library functions:

```
mcp__ida_pro_mcp__rename(batch={"func": [
    {"address": "<addr>", "name": "__libc_init_array"},
    {"address": "<addr>", "name": "_malloc"}
]})
```

#### 10b. Rename by string reference

Functions referenced by interesting strings get descriptive names:

```
mcp__ida_pro_mcp__rename(batch={"func": [
    {"address": "<addr>", "name": "handle_network_request"},
    {"address": "<addr>", "name": "parse_config_file"},
    {"address": "<addr>", "name": "encrypt_payload_aes"}
]})
```

#### 10c. Rename by pattern

Functions found via crypto constants:

```
mcp__ida_pro_mcp__rename(batch={"func": [
    {"address": "<addr>", "name": "md5_transform"},
    {"address": "<addr>", "name": "aes_encrypt_block"}
]})
```

### 11. Generate recovery report

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
| ... | Prologue scan | Function prologue | ... |
| ... | String xref | References "config.json" | ... |
| ... | Crypto constant | References SHA-256 K table | ... |
| ... | Call graph hub | 45 callers, 2 callees | ... |

## VTable Candidates (C++ binaries)
| Address | Pointer Count | Section |
|---|---|---|
| ... | ... | ... |

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
