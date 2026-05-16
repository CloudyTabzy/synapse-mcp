---
name: binary-survey
description: Initial reconnaissance and survey of a binary loaded in IDA Pro. Use when first opening a file to understand its structure, entry points, imports, strings, exports, and key functions. Produces a structured markdown survey report.
allowed-tools: mcp__ida_pro_mcp__get_metadata, mcp__ida_pro_mcp__list_segments, mcp__ida_pro_mcp__get_entry_points, mcp__ida_pro_mcp__imports, mcp__ida_pro_mcp__exports, mcp__ida_pro_mcp__find_regex, mcp__ida_pro_mcp__list_funcs, mcp__ida_pro_mcp__list_globals, mcp__ida_pro_mcp__lookup_funcs, mcp__ida_pro_mcp__decompile, mcp__ida_pro_mcp__disasm, mcp__ida_pro_mcp__int_convert, mcp__ida_pro_mcp__get_bytes, mcp__ida_pro_mcp__get_string, mcp__ida_pro_mcp__basic_blocks, mcp__ida_pro_mcp__callgraph, mcp__ida_pro_mcp__xrefs_to, mcp__ida_pro_mcp__analyze_funcs, Bash, Read, Write, AskUserQuestion
---

# binary-survey

Perform initial reconnaissance on a binary loaded in IDA Pro. This skill produces a structured overview of the binary's architecture, segments, entry points, imports, exports, strings, and key functions.

> **Tool prefix note**: MCP tool names depend on your client configuration. If your server is named differently (e.g. `ida-pro-triton-miasm`), adjust the prefix accordingly.

## Prerequisites

- A binary must be loaded and analyzed in IDA Pro (auto-analysis should be complete)
- If running headless (`idalib-mcp`), the database must be open

## Instructions

### 1. Gather metadata

Read the IDB metadata resource to get the binary's basic info:

```
Read("ida://idb/metadata")
Read("ida://idb/segments")
Read("ida://idb/entrypoints")
```

Record:
- Architecture, bitness, base address, image size
- Number of segments and their permissions
- Entry points (main, TLS callbacks, exports, etc.)

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

Call `mcp__ida_pro_mcp__exports` (or read `ida://exports`) to list exported functions. These are externally callable entry points — especially relevant for DLLs.

### 4. Search strings

Use `mcp__ida_pro_mcp__find_regex` to search for interesting indicators:

1. **Network indicators**: `https?://`, IP addresses, domain names, User-Agent strings
2. **File paths**: `\.exe`, `\.dll`, `\.bat`, `\.ps1`, `C:\\`, `\\?\\`, `TEMP`, `APPDATA`
3. **Registry keys**: `Software\\`, `HKLM`, `HKCU`, `Run`, `RunOnce`
4. **Error messages**: `"failed"`, `"error"`, `"invalid"`, `"success"`, `"access denied"`
5. **Crypto hints**: `AES`, `RSA`, `DES`, `SHA`, `MD5`, `key`, `iv`, `salt`, `nonce`
6. **Debug / dev artifacts**: `debug`, `test`, `todo`, `fixme`, `password`, `secret`

Use a limit of 100–200 per search to avoid token bloat. Focus on unique/distinctive strings.

### 5. List and triage functions

Call `mcp__ida_pro_mcp__list_funcs` to get the function list. Identify:

- **Known entry points**: `main`, `WinMain`, `DllMain`, `wmain`, `start`
- **Export functions** (from step 3)
- **Large functions** (>500 instructions) — likely core logic
- **Small functions** (<10 instructions) — likely getters/setters/thunks
- **Functions with no xrefs** — possibly dead code or unreferenced callbacks

For the top 5–10 most interesting functions, call `mcp__ida_pro_mcp__lookup_funcs` to get their addresses and basic info.

### 6. Quick decompile of key functions

Decompile the most interesting functions identified in step 5:

```
mcp__ida_pro_mcp__decompile(addr="main")
mcp__ida_pro_mcp__decompile(addr="DllMain")
```

For each, note:
- What external APIs it calls (imports from step 2)
- Whether it handles attacker-controllable input
- Any obvious crypto, encoding, or obfuscation patterns

### 7. Identify interesting code patterns

Use `mcp__ida_pro_mcp__find_bytes` or `mcp__ida_pro_mcp__find_insns` to detect:

- **Anti-debug**: `64 A1 30 00 00 00` (mov eax, fs:[30h] → PEB), followed by `0F B6 40 02` (movzx eax, byte ptr [eax+2] → BeingDebugged)
- **SEH setup**: `64 8B 0D 00 00 00 00` (mov ecx, fs:[0])
- **Common crypto constants**: S-boxes, IVs, lookup tables
- **Common instruction patterns**: `rdtsc`, `cpuid`, `int3`, `int 2dh`

### 8. Generate survey report

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
