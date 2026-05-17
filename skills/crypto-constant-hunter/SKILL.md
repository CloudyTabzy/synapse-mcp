---
name: crypto-constant-hunter
description: Hunt for cryptographic algorithms and encoding schemes in binaries using constant pattern matching. Identifies AES S-boxes, SHA initialization vectors, MD5 constants, CRC32 polynomials, Base64 alphabets, and custom crypto by searching for known magic numbers and lookup tables.
allowed-tools: mcp__ida_pro_mcp__find_bytes, mcp__ida_pro_mcp__find, mcp__ida_pro_mcp__find_regex, mcp__ida_pro_mcp__get_bytes, mcp__ida_pro_mcp__get_int, mcp__ida_pro_mcp__xrefs_to, mcp__ida_pro_mcp__xrefs_query, mcp__ida_pro_mcp__lookup_funcs, mcp__ida_pro_mcp__decompile, mcp__ida_pro_mcp__disasm, mcp__ida_pro_mcp__func_profile, mcp__ida_pro_mcp__analyze_function, mcp__ida_pro_mcp__rename, mcp__ida_pro_mcp__set_comments, mcp__ida_pro_mcp__int_convert, mcp__ida_pro_mcp__scan_signature, mcp__ida_pro_mcp__get_binary_sections, mcp__ida_pro_mcp__survey_binary, mcp__ida_pro_mcp__read_struct, Bash, Read, Write, AskUserQuestion
---

# crypto-constant-hunter

Identify cryptographic algorithms, hash functions, and encoding schemes in a binary by searching for their characteristic constants, S-boxes, initialization vectors, and lookup tables.

> **Tool prefix note**: MCP tool names depend on your client configuration. If your server is named differently, adjust the prefix accordingly.

## When to use this skill

- You suspect a binary uses encryption or hashing
- You need to identify the exact algorithm (AES-128? AES-256? ChaCha20?)
- You're analyzing malware and want to find its C2 encryption or payload hashing
- You're doing a CTF and need to locate the crypto check function
- You want to find hardcoded keys, IVs, or nonces

## Instructions

### 1. Search for common crypto constants

Search for algorithm-specific initialization values:

#### MD5
```
mcp__ida_pro_mcp__find_bytes(pattern="01 23 45 67")   # 0x67452301 (little-endian)
mcp__ida_pro_mcp__find_bytes(pattern="89 AB CD EF")   # 0xEFCDAB89
mcp__ida_pro_mcp__find_bytes(pattern="FE DC BA 98")   # 0x98BADCFE
mcp__ida_pro_mcp__find_bytes(pattern="76 54 32 10")   # 0x10325476
```

#### SHA-1
```
mcp__ida_pro_mcp__find_bytes(pattern="67 45 23 01")   # 0x67452301 (big-endian)
mcp__ida_pro_mcp__find_bytes(pattern="EF CD AB 89")   # 0xEFCDAB89
mcp__ida_pro_mcp__find_bytes(pattern="98 BA DC FE")   # 0x98BADCFE
mcp__ida_pro_mcp__find_bytes(pattern="10 32 54 76")   # 0x10325476
mcp__ida_pro_mcp__find_bytes(pattern="C3 D2 E1 F0")   # 0xC3D2E1F0
```

#### SHA-256
```
mcp__ida_pro_mcp__find_bytes(pattern="6A 09 E6 67")   # H0
mcp__ida_pro_mcp__find_bytes(pattern="BB 67 AE 85")   # H1
mcp__ida_pro_mcp__find_bytes(pattern="3C 6E F3 72")   # H2
mcp__ida_pro_mcp__find_bytes(pattern="A5 4F F5 3A")   # H3
```

#### SHA-512
```
mcp__ida_pro_mcp__find_bytes(pattern="6A 09 E6 67 F3 BC C9 08")   # H0
```

#### CRC32 (IEEE 802.3)
```
mcp__ida_pro_mcp__find_bytes(pattern="20 83 B8 ED")   # 0xEDB88320 (little-endian polynomial)
```

### 2. Search for AES S-boxes and tables

AES uses several identifiable tables:

#### Forward S-box (256 bytes)
The AES S-box starts with `63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76`.

```
mcp__ida_pro_mcp__find_bytes(pattern="63 7C 77 7B")
```

#### Inverse S-box (256 bytes)
Starts with `52 09 6A D5 30 36 A5 38`.

```
mcp__ida_pro_mcp__find_bytes(pattern="52 09 6A D5")
```

#### Te0/te4 tables (AES x86 implementations)
Look for 1024-byte tables starting with `C6 63 63 A5` or similar repeated patterns.

### 3. Search for ChaCha20 / Salsa20 constants

ChaCha20 uses the constant string `"expand 32-byte k"`:

```
mcp__ida_pro_mcp__find_regex(pattern="expand 32-byte k")
```

Salsa20 uses `"expand 32-byte k"` or `"expand 16-byte k"`.

### 4. Search for Base64 alphabets

Standard Base64 alphabet:

```
mcp__ida_pro_mcp__find_regex(pattern="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\\+\\/")
```

URL-safe variant ends with `-_` instead of `+/`.

### 5. Search for RSA / DH constants

#### DER-encoded RSA public key (OID 1.2.840.113549.1.1.1)
```
mcp__ida_pro_mcp__find_bytes(pattern="30 82")  # SEQUENCE
```

#### Common RSA exponent `0x10001`
```
mcp__ida_pro_mcp__find_bytes(pattern="01 00 01")
```

### 6. Search for Blowfish, RC4, and older ciphers

#### Blowfish P-array (18 32-bit words)
Starts with `0x243F6A88` (pi-derived). Search:
```
mcp__ida_pro_mcp__find_bytes(pattern="88 6A 3F 24")  # little-endian
```

#### RC4 KSA pattern
Look for 256-byte state array initialization (`S[i] = i` loop) followed by key mixing.

```
mcp__ida_pro_mcp__find_bytes(pattern="00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F")
```

### 7. Cross-reference constants to functions

For each constant found, trace which functions reference it:

```
mcp__ida_pro_mcp__xrefs_to(addrs="<constant_addr>")
```

Functions referencing crypto constants are likely:
- **Hash init functions** — set up MD5/SHA state
- **Key schedule functions** — expand AES keys
- **Round functions** — perform encryption/decryption rounds
- **Wrapper functions** — allocate buffers and call crypto primitives

### 8. Decompile and identify the algorithm

Decompile xref-ing functions:

```
mcp__ida_pro_mcp__decompile(addr="<func_addr>")
mcp__ida_pro_mcp__func_profile(queries="<func_addr>")
```

Look for:
- **Loop counts**: 10 rounds = AES-128, 12 = AES-192, 14 = AES-256
- **Block sizes**: 16-byte blocks → AES or SM4; 64-byte blocks → ChaCha20
- **Key sizes**: 16 bytes → AES-128; 32 bytes → AES-256 or ChaCha20
- **Table lookups**: AES uses T-tables or S-box lookups
- **Bitwise ops only**: ChaCha20 uses only ADD, XOR, ROTATE

### 9. Find hardcoded keys and IVs

Near crypto functions, look for:
- **Hardcoded 16/24/32-byte buffers** passed to the key schedule
- **16-byte IVs/nonces** passed alongside the key
- **Salt values** used in KDFs (PBKDF2, scrypt, bcrypt)

```
mcp__ida_pro_mcp__get_bytes(addrs="<key_addr>")
mcp__ida_pro_mcp__get_string(addrs="<key_addr>")  # if key is an ASCII string
```

### 10. Rename and annotate

```
mcp__ida_pro_mcp__rename(batch={"func": [
    {"address": "<addr>", "name": "aes128_encrypt_block"},
    {"address": "<addr>", "name": "sha256_init"},
    {"address": "<addr>", "name": "chacha20_crypt"}
]})

mcp__ida_pro_mcp__set_comments(items=[
    {"address": "<sbox_addr>", "comment": "AES forward S-box (256 bytes)"},
    {"address": "<iv_addr>", "comment": "Hardcoded AES IV: 16 bytes"}
])
```

### 11. Generate crypto hunting report

Write `./reports/crypto_hunt.md`:

```markdown
# Cryptographic Algorithm Hunt: <binary_name>

## Algorithms Identified
| Algorithm | Evidence | Function Address | Confidence |
|---|---|---|---|
| AES-256 | S-box + 14-round loop | 0x... | High |
| SHA-256 | Init constants H0-H7 | 0x... | High |
| ChaCha20 | "expand 32-byte k" | 0x... | High |

## Constants Found
| Address | Type | Value / First Bytes |
|---|---|---|
| ... | AES S-box | 63 7C 77 7B ... |
| ... | SHA-256 H0 | 6A 09 E6 67 |

## Hardcoded Material
| Address | Type | Size | Value |
|---|---|---|---|
| ... | Key | 32 bytes | ... |
| ... | IV | 16 bytes | ... |

## Functions to Analyze
1. ...

## Recommendations
- <suggest next steps: trace key derivation, find decryption routine, etc.>
```

Present the report and ask: "Would you like to trace the key schedule, set up a Triton symbolic analysis, or dump the encrypted data sections?"
