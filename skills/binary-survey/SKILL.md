---
name: binary-survey
description: Initial reconnaissance and survey of a binary loaded in IDA Pro. Use when first opening a file to understand its structure, entry points, imports, strings, exports, and key functions. Produces a structured markdown survey report.
allowed-tools: mcp__ida_pro_mcp__survey_binary, mcp__ida_pro_mcp__imports, mcp__ida_pro_mcp__export_funcs, mcp__ida_pro_mcp__find_regex, mcp__ida_pro_mcp__find_bytes, mcp__ida_pro_mcp__find, mcp__ida_pro_mcp__list_funcs, mcp__ida_pro_mcp__list_globals, mcp__ida_pro_mcp__lookup_funcs, mcp__ida_pro_mcp__decompile, mcp__ida_pro_mcp__disasm, mcp__ida_pro_mcp__int_convert, mcp__ida_pro_mcp__get_bytes, mcp__ida_pro_mcp__get_string, mcp__ida_pro_mcp__basic_blocks, mcp__ida_pro_mcp__callgraph, mcp__ida_pro_mcp__xrefs_to, mcp__ida_pro_mcp__analyze_function, mcp__ida_pro_mcp__scan_signature, mcp__ida_pro_mcp__filetype_identify_buffer, mcp__ida_pro_mcp__filetype_identify_ida_segment, mcp__ida_pro_mcp__filetype_list_supported, Bash, Read, Write, AskUserQuestion
---

# binary-survey

Perform initial reconnaissance on a binary loaded in IDA Pro. This skill produces a structured overview of the binary's architecture, segments, entry points, imports, exports, strings, and key functions.

> **Tool prefix note**: MCP tool names depend on your client configuration. If your server is named differently (e.g. `ida-pro-triton-miasm`), adjust the prefix accordingly.

## Prerequisites

- A binary must be loaded and analyzed in IDA Pro (auto-analysis should be complete)
- If running headless (`idalib-mcp`), the database must be open

## Instructions

### 1. Gather metadata

Read the IDB metadata resources and run `survey_binary` for a one-shot triage:

```
Read("ida://idb/metadata")
Read("ida://idb/segments")
Read("ida://idb/entrypoints")
mcp__ida_pro_mcp__survey_binary(detail_level="standard")
```

Record:
- Architecture, bitness, base address, image size, compiler, MD5/SHA256
- Number of segments and their permissions
- Entry points (main, TLS callbacks, exports, etc.)
- Top strings/functions by xref count, import categories

### 2. Enumerate imports

Call `mcp__ida_pro_mcp__imports` to list imported symbols. Categorize them by attack surface relevance:

| Category | Example APIs |
|---|---|
| **Network** | `recv`, `recvfrom`, `WSARecv`, `InternetReadFile`, `WinHttpReadData` |
| **File** | `ReadFile`, `CreateFileA/W`, `fread`, `fgets`, `MapViewOfFile` |
| **Registry** | `RegQueryValueExA/W`, `RegGetValueA/W` |
| **Environment** | `GetEnvironmentVariableA/W`, `getenv` |
| **Command line** | `GetCommandLineA/W`, `CommandLineToArgvW` |
| **Clipboard / UI** | `GetClipboardData`, `GetWindowTextA/W` |
| **Memory / String** | `memcpy`, `strcpy`, `strcat`, `sprintf`, `wcscat`, `lstrcpyA/W` |
| **Allocation** | `malloc`, `HeapAlloc`, `VirtualAlloc`, `LocalAlloc` |
| **Process / Thread** | `CreateProcessA/W`, `WinExec`, `ShellExecuteA/W`, `CreateThread` |
| **Crypto** | `CryptEncrypt`, `CryptDecrypt`, `BCryptEncrypt`, `NCryptEncrypt` |

Also note any `LoadLibraryA` + `GetProcAddress` pairs that may indicate dynamic API resolution.

### 3. Enumerate exports

Call `mcp__ida_pro_mcp__export_funcs` to list exported functions. These are externally callable entry points — especially relevant for DLLs.

```
mcp__ida_pro_mcp__export_funcs(addrs="*")
```

### 4. File type identification (optional)

If analyzing embedded blobs or unknown segments, use `filetype`:

```
mcp__ida_pro_mcp__filetype_identify_ida_segment(segment_name=".rsrc")
mcp__ida_pro_mcp__filetype_identify_buffer(address="0x405000", size=256)
```

### 5. Search strings

Use `mcp__ida_pro_mcp__find_regex` to search for interesting indicators:

1. **Network indicators**: `https?://`, IP addresses, domain names, User-Agent strings
2. **File paths**: `\.exe`, `\.dll`, `\.bat`, `\.ps1`, `C:\\`, `\\?\\`, `TEMP`, `APPDATA`
3. **Registry keys**: `Software\\`, `HKLM`, `HKCU`, `Run`, `RunOnce`
4. **Error messages**: `"failed"`, `"error"`, `"invalid"`, `"success"`, `"access denied"`
5. **Crypto hints**: `AES`, `RSA`, `DES`, `SHA`, `MD5`, `key`, `iv`, `salt`, `nonce`
6. **Debug / dev artifacts**: `debug`, `test`, `todo`, `fixme`, `password`, `secret`

Use a limit of 100–200 per search to avoid token bloat. Focus on unique/distinctive strings.

### 6. List and triage functions

Call `mcp__ida_pro_mcp__list_funcs` to get the function list. Identify:

- **Known entry points**: `main`, `WinMain`, `DllMain`, `wmain`, `start`
- **Export functions** (from step 3)
- **Large functions** (>500 instructions) — likely core logic
- **Small functions** (<10 instructions) — likely getters/setters/thunks
- **Functions with no xrefs** — possibly dead code or unreferenced callbacks

For the top 5–10 most interesting functions, call `mcp__ida_pro_mcp__lookup_funcs` to get their addresses and basic info.

### 7. Quick analysis of key functions

Analyze the most interesting functions identified in step 6:

```
mcp__ida_pro_mcp__analyze_function(addr="main")
mcp__ida_pro_mcp__decompile(addr="DllMain")
```

For each, note:
- What external APIs it calls (imports from step 2)
- Whether it handles attacker-controllable input
- Any obvious crypto, encoding, or obfuscation patterns

### 8. Identify interesting code patterns

Use `mcp__ida_pro_mcp__find_bytes` or `mcp__ida_pro_mcp__find` to detect:

- **Anti-debug**: `64 A1 30 00 00 00` (mov eax, fs:[30h] → PEB), followed by `0F B6 40 02` (movzx eax, byte ptr [eax+2] → BeingDebugged)
- **SEH setup**: `64 8B 0D 00 00 00 00` (mov ecx, fs:[0])
- **Common crypto constants**: S-boxes, IVs, lookup tables
- **Common instruction patterns**: `rdtsc`, `cpuid`, `int3`, `int 2dh`

Also scan for known signatures:
```
mcp__ida_pro_mcp__scan_signature(pattern="48 8B ?? ??")
```

### 9. Generate survey report

Write a markdown report to `./reports/binary_survey.md` with the following structure:

```markdown
# Binary Survey: <filename>

## Metadata
| Property | Value |
|---|---|
| Path | ... |
| Architecture | ... |
| Bitness | ... |
| Base Address | ... |
| Image Size | ... |
| Compiler | ... |
| SHA256 | ... |

## Segments
| Name | Start | End | Size | Permissions |
|---|---|---|---|---|
| ... | ... | ... | ... | ... |

## Entry Points
- ...

## Imports (Attack Surface)
### Network
- ...
### File
- ...
### Process / Execution
- ...
### Crypto
- ...

## Exports
- ...

## Interesting Strings
| Address | String | Context |
|---|---|---|
| ... | ... | ... |

## Key Functions
| Address | Name | Size | Description |
|---|---|---|---|
| ... | ... | ... | ... |

## Initial Assessment
<1-paragraph summary of what the binary appears to do, its apparent purpose, and any immediate red flags>
```

Present the report to the user and ask: "What would you like to investigate next?"
