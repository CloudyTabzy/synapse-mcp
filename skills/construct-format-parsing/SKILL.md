---
name: construct-format-parsing
description: Declarative binary format parsing inside IDA Pro using Construct, dissect.cstruct, and filetype. Use to parse PE/ELF headers, protocol structures (TCP/UDP/DNS/TLS), embedded file blobs, and unknown data structures. Bridges IDA struct definitions to runtime parsers.
allowed-tools: mcp__ida_pro_mcp__construct_status, mcp__ida_pro_mcp__construct_parse_pe_headers, mcp__ida_pro_mcp__construct_parse_elf_headers, mcp__ida_pro_mcp__construct_parse_custom_struct, mcp__ida_pro_mcp__construct_build_struct, mcp__ida_pro_mcp__construct_parse_ida_struct, mcp__ida_pro_mcp__construct_guess_struct, mcp__ida_pro_mcp__construct_batch_parse_array, mcp__ida_pro_mcp__construct_extract_protocol_header, mcp__ida_pro_mcp__construct_scan_for_structs, mcp__ida_pro_mcp__cstruct_status, mcp__ida_pro_mcp__cstruct_parse_c_definition, mcp__ida_pro_mcp__cstruct_parse_at_address, mcp__ida_pro_mcp__cstruct_parse_ida_struct, mcp__ida_pro_mcp__cstruct_define_struct, mcp__ida_pro_mcp__cstruct_to_bytes, mcp__ida_pro_mcp__cstruct_list_defined_structs, mcp__ida_pro_mcp__cstruct_ida_struct_to_c, mcp__ida_pro_mcp__filetype_status, mcp__ida_pro_mcp__filetype_identify_buffer, mcp__ida_pro_mcp__filetype_identify_ida_segment, mcp__ida_pro_mcp__filetype_list_supported, mcp__ida_pro_mcp__get_bytes, mcp__ida_pro_mcp__get_int, mcp__ida_pro_mcp__read_struct, mcp__ida_pro_mcp__search_structs, mcp__ida_pro_mcp__survey_binary, mcp__ida_pro_mcp__get_binary_sections, mcp__ida_pro_mcp__int_convert, Bash, Read, Write, AskUserQuestion
---

# construct-format-parsing

Parse binary data structures inside IDA Pro using declarative templates. This skill covers PE/ELF headers, network protocols, file-type identification, and custom struct parsing — all without leaving the MCP context.

> **Tool prefix note**: MCP tool names depend on your client configuration. If your server is named differently, adjust the prefix accordingly.

> **Dependencies**: `pip install construct dissect.cstruct filetype`. Verify with `construct_status`, `cstruct_status`, and `filetype_status`.

## When to use this skill

- You need to parse a PE/ELF header at a specific offset
- You're reverse-engineering a protocol and want to decode packet structures
- You've found an embedded blob and want to know what file type it is
- You have a C struct definition and want to apply it to IDA memory
- You want to bridge an existing IDA struct type to a Construct parser

## Instructions

### 1. Verify parser availability

```
mcp__ida_pro_mcp__construct_status()
mcp__ida_pro_mcp__cstruct_status()
mcp__ida_pro_mcp__filetype_status()
```

If any returns `"available": false`, tell the user which package to install.

### 2. File type identification (for embedded blobs)

Before parsing an unknown blob, identify its format:

```
mcp__ida_pro_mcp__filetype_identify_buffer(address="0x405000", size=256)
```

Or check a specific segment:

```
mcp__ida_pro_mcp__filetype_identify_ida_segment(segment_name=".rsrc")
```

If the result is a known format (PE, ELF, ZIP, PNG, etc.), use the appropriate built-in parser. If unknown, proceed to heuristic guessing.

### 3. Parse PE headers

For a PE file (or embedded PE blob):

```
mcp__ida_pro_mcp__construct_parse_pe_headers(
    file_path="C:\\path\\to\\binary.exe",
    include_sections=true,
    include_data_dirs=true
)
```

If parsing from an IDA address instead of disk:

```
mcp__ida_pro_mcp__get_bytes(addrs="0x400000-0x400300")
# Then use construct_parse_custom_struct with a PE header template
```

Key fields to extract:
- `ImageBase`, `EntryPoint`, `Subsystem`
- Section names, virtual sizes, raw sizes, characteristics
- Data directories (Import, Export, Resource, Relocation, TLS)

### 4. Parse ELF headers

```
mcp__ida_pro_mcp__construct_parse_elf_headers(
    file_path="/path/to/binary",
    include_phdrs=true,
    include_shdrs=true
)
```

Key fields:
- `e_type` (ET_EXEC, ET_DYN, ET_REL), `e_machine`, `e_entry`
- Program headers (LOAD, DYNAMIC, INTERP, NOTE)
- Section headers (.text, .data, .bss, .dynamic, .dynsym)

### 5. Parse network protocol headers

For a buffer containing a packet (e.g., at an IDA address):

```
mcp__ida_pro_mcp__construct_extract_protocol_header(
    protocol="tcp",
    address="0x405000"
)
```

Supported protocols: `ipv4`, `tcp`, `udp`, `icmp`, `ethernet`, `dns`, `tls`.

For layered parsing (Ethernet → IP → TCP):
1. Parse Ethernet header → get EtherType offset
2. Parse IPv4 header → get protocol field and header length
3. Parse TCP/UDP header → get source/dest ports, sequence numbers

### 6. Heuristic structure guessing

When you don't know the layout:

```
mcp__ida_pro_mcp__construct_guess_struct(address="0x405000", size=256)
```

This returns a heuristic layout (strings, pointers, padding guesses). Use it as a starting point for a custom template.

### 7. Parse with custom Construct templates

For ad-hoc structures, use the safe DSL evaluator:

```
mcp__ida_pro_mcp__construct_parse_custom_struct(
    construct_template="Struct('header' / Int32ub, 'count' / Int16ul, 'flags' / Byte, 'name' / PaddedString(16, 'utf8'))",
    address="0x405000",
    count=3
)
```

The DSL uses an AST whitelist — only Construct types and Python literals are permitted.

### 8. Parse with C-syntax structs (dissect.cstruct)

For C-compatible definitions:

#### 8a. Define a struct from C syntax

```
mcp__ida_pro_mcp__cstruct_parse_c_definition(
    c_definition="""
    struct PacketHeader {
        uint32_t magic;
        uint16_t version;
        uint16_t flags;
        uint32_t payload_len;
        uint32_t checksum;
    };
    """,
    struct_name="PacketHeader"
)
```

#### 8b. Parse memory with the defined struct

```
mcp__ida_pro_mcp__cstruct_parse_at_address(
    struct_name="PacketHeader",
    address="0x405000",
    count=5
)
```

#### 8c. Bridge an existing IDA struct

If the struct is already defined in IDA's type library:

```
mcp__ida_pro_mcp__cstruct_parse_ida_struct(
    struct_name="MYSTRUCT",
    address="0x405000",
    count=1
)
```

Or convert an IDA struct to C syntax first:

```
mcp__ida_pro_mcp__cstruct_ida_struct_to_c(struct_name="MYSTRUCT")
```

### 9. Batch parse arrays (tables)

For consecutive records (e.g., import tables, section headers):

```
mcp__ida_pro_mcp__construct_batch_parse_array(
    construct_template="Struct('rva' / Int32ul, 'size' / Int32ul)",
    address="0x400200",
    count=16
)
```

### 10. Build / serialize structures

To craft a structure and get its byte representation:

```
mcp__ida_pro_mcp__construct_build_struct(
    construct_template="Struct('magic' / Const(b'\\x7fELF'), 'class' / Byte, 'data' / Byte)",
    data={"class": 2, "data": 1},
    return_only=true
)
```

Or with cstruct:

```
mcp__ida_pro_mcp__cstruct_to_bytes(
    struct_name="PacketHeader",
    data={"magic": 0xDEADBEEF, "version": 1, "flags": 0, "payload_len": 256, "checksum": 0}
)
```

### 11. Generate parsing report

Write `./reports/format_parsing.md`:

```markdown
# Format Parsing Report

## Target
| Property | Value |
|---|---|
| Address | ... |
| Size | ... |
| Identified Format | ... |

## Parsed Structure
| Field | Offset | Type | Value |
|---|---|---|---|
| ... | ... | ... | ... |

## Heuristic Guess (if used)
| Offset | Guessed Type | Confidence |
|---|---|---|
| ... | ... | ... |

## Custom Templates Defined
- ...

## Bytes Verified
<yes/no, and how>
```

Present the report and ask: "Would you like to parse additional structures, define a new template, or write a parser script?"
