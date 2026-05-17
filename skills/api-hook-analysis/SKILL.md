---
name: api-hook-analysis
description: Detect and analyze API hooks, inline patches, IAT hijacking, and detours in binaries. Use for analyzing rootkits, injectors, DRM, and malware that intercepts system or application APIs. Combines memory reads, byte-pattern scanning, import analysis, and cross-reference tracing.
allowed-tools: mcp__ida_pro_mcp__imports, mcp__ida_pro_mcp__imports_query, mcp__ida_pro_mcp__xrefs_to, mcp__ida_pro_mcp__xrefs_query, mcp__ida_pro_mcp__find_bytes, mcp__ida_pro_mcp__find, mcp__ida_pro_mcp__get_bytes, mcp__ida_pro_mcp__get_int, mcp__ida_pro_mcp__get_binary_sections, mcp__ida_pro_mcp__get_global_value, mcp__ida_pro_mcp__lookup_funcs, mcp__ida_pro_mcp__decompile, mcp__ida_pro_mcp__disasm, mcp__ida_pro_mcp__basic_blocks, mcp__ida_pro_mcp__callgraph, mcp__ida_pro_mcp__patch_asm, mcp__ida_pro_mcp__rename, mcp__ida_pro_mcp__set_comments, mcp__ida_pro_mcp__py_eval, mcp__ida_pro_mcp__int_convert, mcp__ida_pro_mcp__find_indirect_calls, mcp__ida_pro_mcp__find_global_writers, mcp__ida_pro_mcp__scan_signature, mcp__ida_pro_mcp__make_signature, Bash, Read, Write, AskUserQuestion
---

# api-hook-analysis

Detect and analyze API hooking techniques in binaries. This skill targets inline hooks, IAT (Import Address Table) hijacking, EAT (Export Address Table) patching, trampoline detours, and VTable hijacking — common in malware, rootkits, DRM, and security tools.

> **Tool prefix note**: MCP tool names depend on your client configuration. If your server is named differently, adjust the prefix accordingly.

## When to use this skill

- You suspect a binary hooks system APIs (e.g., `NtCreateFile`, `recv`, `send`)
- You're analyzing a rootkit or injector that intercepts calls
- You see suspicious indirect jumps (`jmp dword ptr [xxx]`) near imported functions
- You want to verify if a DLL is being subject to IAT hijacking
- You're reverse-engineering a game anti-cheat or DRM that detours APIs

## Instructions

### 1. Enumerate high-value import targets

Hooking typically targets these APIs:

| Category | Common Hook Targets |
|---|---|
| **Process/Thread** | `CreateProcessW`, `NtCreateThreadEx`, `CreateRemoteThread`, `VirtualAllocEx` |
| **Memory** | `VirtualAlloc`, `VirtualProtect`, `NtAllocateVirtualMemory`, `NtProtectVirtualMemory` |
| **File** | `CreateFileW`, `NtCreateFile`, `ReadFile`, `WriteFile`, `NtReadFile` |
| **Registry** | `RegOpenKeyExW`, `RegSetValueExW`, `NtOpenKey`, `NtSetValueKey` |
| **Network** | `WSASend`, `WSARecv`, `send`, `recv`, `connect`, `InternetReadFile` |
| **Synchronization** | `NtWaitForSingleObject`, `Sleep`, `SetTimer` |
| **Information** | `NtQuerySystemInformation`, `NtQueryInformationProcess` |
| **Debugging** | `NtDebugActiveProcess`, `CheckRemoteDebuggerPresent` |

List imports and filter for these:

```
mcp__ida_pro_mcp__imports(offset=0, count=500)
```

### 2. Detect IAT/EAT hijacking patterns

#### 2a. Look for IAT overwrite in data sections

IAT entries reside in the `.idata` section (PE) or `.plt`/`.got` (ELF). Search for writes to these regions:

```
mcp__ida_pro_mcp__find_global_writers(addr="<iat_section_start>", max_results=50)
```

Any write to the IAT/GOT after load time is suspicious.

#### 2b. Check for EAT redirection

For DLLs, the Export Address Table can be hijacked. Look for:
- Writes to the export directory RVA
- Forwarder strings being modified

Use `py_eval` to inspect the export directory:

```python
mcp__ida_pro_mcp__py_eval(code="""
import idautils, idaapi, ida_nalt

# Get export directory
ord_qty = idaapi.get_ordinal_qty()
for i in range(1, ord_qty):
    ea = idaapi.get_nlist_ea(i)
    name = idaapi.get_nlist_name(i)
    print(f'{ea:#x}: {name}')
""")
```

### 3. Detect inline hooks

Inline hooks overwrite the first 5+ bytes of a function with a `jmp` to the hook.

#### 3a. Scan for trampoline patterns

Common inline hook prologues:
- `E9 xx xx xx xx` — `jmp rel32` (5-byte hook)
- `FF 25 xx xx xx xx` — `jmp [rip+offset]` (6-byte x64 hook)
- `68 xx xx xx xx C3` — `push addr; ret` (old technique)
- `EB xx` — short `jmp` followed by more bytes

Search near imported functions:

```
mcp__ida_pro_mcp__find_bytes(pattern="E9 ?? ?? ?? ??")
mcp__ida_pro_mcp__find_bytes(pattern="FF 25 ?? ?? ?? ??")
```

#### 3b. Verify by reading the actual bytes at import addresses

```
mcp__ida_pro_mcp__get_bytes(addrs="<import_addr>-<import_addr+20>")
```

Compare what you read with the expected prologue of the real API. If it starts with `jmp` instead of `mov`/`sub`/`push`, it's likely hooked.

#### 3c. Check for detour trampolines

A detour typically:
1. Saves original bytes
2. Overwrites function start with `jmp hook`
3. The hook calls a trampoline that executes the original bytes, then jumps back

Look for small code stubs near the hook target that contain the original stolen bytes plus a `jmp` back.

### 4. Analyze hook implementations

Once a hook is found, decompile it:

```
mcp__ida_pro_mcp__decompile(addr="<hook_function_addr>")
mcp__ida_pro_mcp__disasm(addr="<hook_function_addr>", max_instructions=50)
```

Determine:
- **What API is being hooked?** (Trace back from the trampoline)
- **What does the hook do?**
  - Logging/interception? (saves args, calls original, returns)
  - Modification? (changes arguments before calling original)
  - Blocking? (returns error without calling original)
  - Faking? (returns fake result, never calls original)
- **Where is the original function preserved?** (trampoline address)

### 5. Detect VTable / COM hooking

For C++ binaries or COM objects:

#### 5a. Find VTable candidates

```
mcp__ida_pro_mcp__find_vtable_candidates(section=".data", min_pointers=4)
```

#### 5b. Check for VTable pointer overwrites

Look for writes to VTable pointers in object instances:

```
mcp__ida_pro_mcp__find_global_writers(addr="<vtable_ptr_addr>", max_results=20)
```

If a VTable pointer is overwritten with an attacker-controlled address, that's a VTable hijack.

### 6. Detect IAT hooking via LoadLibrary/GetProcAddress

Malware often resolves APIs dynamically to hook them:

```
mcp__ida_pro_mcp__xrefs_to(addrs="LoadLibraryA")
mcp__ida_pro_mcp__xrefs_to(addrs="GetProcAddress")
mcp__ida_pro_mcp__xrefs_to(addrs="GetModuleHandleA")
```

Decompile callers and look for:
- `LoadLibraryA("ntdll.dll")` → `GetProcAddress("NtCreateFile")` → overwrite
- `GetModuleHandleA("kernel32.dll")` → walk export table → hook

### 7. Trace hook installation

Find where hooks are installed by looking for:
- `VirtualProtect` calls that make code writable (`PAGE_EXECUTE_READWRITE`)
- `WriteProcessMemory` calls that patch other processes
- `NtMapViewOfSection` with write permissions

```
mcp__ida_pro_mcp__xrefs_to(addrs="VirtualProtect")
mcp__ida_pro_mcp__xrefs_to(addrs="WriteProcessMemory")
```

Decompile the installation function:
```
mcp__ida_pro_mcp__decompile(addr="<installer_addr>")
```

### 8. Build a hook map

Create a structured map of all hooks found:

```markdown
| Hooked API | Original Address | Hook Address | Type | Behavior |
|---|---|---|---|---|
| CreateFileW | 0x... | 0x... | Inline 5-byte jmp | Logs file paths |
| recv | 0x... | 0x... | IAT overwrite | Decrypts C2 traffic |
| NtCreateThreadEx | 0x... | 0x... | Inline | Blocks remote threads |
```

### 9. Rename and annotate

```
mcp__ida_pro_mcp__rename(batch={"func": [
    {"address": "<addr>", "name": "hook_CreateFileW"},
    {"address": "<addr>", "name": "trampoline_recv"},
    {"address": "<addr>", "name": "install_hooks"}
]})

mcp__ida_pro_mcp__set_comments(items=[
    {"address": "<hooked_api>", "comment": "Hooked: jumps to 0x... (inline detour)"},
    {"address": "<iat_entry>", "comment": "IAT overwritten at runtime by install_hooks"}
])
```

### 10. Generate hook analysis report

Write `./reports/api_hooks.md`:

```markdown
# API Hook Analysis Report: <binary_name>

## Hook Summary
| Hooked API | Type | Address | Purpose |
|---|---|---|---|
| ... | Inline | ... | ... |
| ... | IAT | ... | ... |
| ... | VTable | ... | ... |

## Hook Installation
| Function | Address | Method |
|---|---|---|
| ... | ... | VirtualProtect + memcpy |

## Anti-Analysis Techniques
- <list any anti-debug, anti-vm, or obfuscation found>

## Recovery
| Original API | Trampoline Address | Original Bytes |
|---|---|---|
| ... | ... | ... |

## Recommendations
- <how to bypass, dump clean code, or neutralize hooks>
```

Present the report and ask: "Would you like to dump the original unhooked bytes, trace the hook dynamically with the debugger, or analyze the payload the hook injects?"
