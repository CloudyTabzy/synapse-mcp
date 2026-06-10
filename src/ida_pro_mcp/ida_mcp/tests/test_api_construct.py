"""Tests for api_construct — Construct declarative binary parsing tools.

All tests skip gracefully when construct is not installed.
File-based tests use the crackme03.elf fixture.
"""

import os
from ..framework import (
    test,
    skip_test,
    assert_non_empty,
    assert_is_list,
)

try:
    from ..api_construct import (
        construct_status,
        CONSTRUCT_AVAILABLE,
    )
    if CONSTRUCT_AVAILABLE:
        from ..api_construct import (
            construct_parse_pe_headers,
            construct_parse_elf_headers,
            construct_parse_custom_struct,
            construct_build_struct,
            construct_parse_ida_struct,
            construct_guess_struct,
            construct_batch_parse_array,
            construct_extract_protocol_header,
            construct_scan_for_structs,
            _compile_dsl,
            _container_to_dict,
            DSLSecurityError,
        )
except ImportError:
    CONSTRUCT_AVAILABLE = False


def _require_construct():
    if not CONSTRUCT_AVAILABLE:
        skip_test("construct not installed")


# ============================================================================
# Status probe — always runs regardless of Construct availability
# ============================================================================


@test()
def test_construct_status_always_returns_dict():
    """construct_status should always return a dict whether or not construct is installed."""
    result = construct_status()
    assert isinstance(result, dict), f"expected dict, got {type(result)}"
    assert "available" in result, f'missing "available" key in {result}'


@test()
def test_construct_status_reports_availability():
    """construct_status reports availability clearly."""
    result = construct_status()
    assert isinstance(result, dict)
    assert "available" in result, f'missing "available" key in {result}'
    if CONSTRUCT_AVAILABLE:
        assert result["available"] is True
        assert "version" in result
        assert result.get("templates_loaded", 0) > 0


# ============================================================================
# Safe DSL evaluator
# ============================================================================


@test()
def test_compile_dsl_basic_struct():
    """_compile_dsl can parse a simple Construct Struct definition."""
    _require_construct()
    template = _compile_dsl('Struct("magic" / Const(b"MZ"), "count" / Int32ul)')
    assert template is not None
    result = template.parse(b"MZ\x05\x00\x00\x00")
    assert result.magic == b"MZ"
    assert result.count == 5


@test()
def test_compile_dsl_rejects_import():
    """_compile_dsl rejects templates containing __import__."""
    _require_construct()
    try:
        _compile_dsl("__import__('os').system('whoami')")
        assert False, "Expected DSLSecurityError for __import__"
    except DSLSecurityError:
        pass


@test()
def test_compile_dsl_rejects_eval():
    """_compile_dsl rejects templates containing eval()."""
    _require_construct()
    try:
        _compile_dsl("eval('1+1')")
        assert False, "Expected DSLSecurityError for eval"
    except DSLSecurityError:
        pass


@test()
def test_compile_dsl_rejects_open():
    """_compile_dsl rejects templates containing open()."""
    _require_construct()
    try:
        _compile_dsl("open('/etc/passwd')")
        assert False, "Expected DSLSecurityError for open"
    except DSLSecurityError:
        pass


# ============================================================================
# Container to dict conversion
# ============================================================================


@test()
def test_container_to_dict_bytes():
    """_container_to_dict converts bytes to hex + ascii preview."""
    _require_construct()
    from construct import Container
    c = Container(raw=b"hello\x00world")
    d = _container_to_dict(c)
    assert "raw" in d
    assert "_bytes" in d["raw"]
    assert d["raw"]["_bytes"] == "68656c6c6f00776f726c64"


# ============================================================================
# ELF header parsing (file-based, works without IDA address)
# ============================================================================


@test()
def test_construct_parse_elf_headers_crackme():
    """construct_parse_elf_headers parses the crackme03.elf fixture correctly."""
    _require_construct()
    # Find the fixture relative to this test file
    fixture = os.path.join(
        os.path.dirname(__file__), "..", "..", "..", "..", "..",
        "tests", "crackme03.elf"
    )
    fixture = os.path.abspath(fixture)
    assert os.path.exists(fixture), f"Fixture not found: {fixture}"

    result = construct_parse_elf_headers(file_path=fixture, include_phdrs=True, include_shdrs=True)
    assert isinstance(result, dict), f"expected dict, got {type(result)}"
    assert result.get("ok") is True, f"parse failed: {result.get('error')}"
    parsed = result["parsed"]
    assert "elf_header" in parsed
    hdr = parsed["elf_header"]
    assert hdr["e_ident"]["EI_MAG"]["_bytes"] == "7f454c46", "Invalid ELF magic"
    assert parsed.get("is_64bit") is True, "Expected 64-bit ELF"
    assert "program_headers" in parsed
    assert "section_headers" in parsed


@test()
def test_construct_parse_elf_headers_minimal():
    """construct_parse_elf_headers with no extra tables still returns header."""
    _require_construct()
    fixture = os.path.join(
        os.path.dirname(__file__), "..", "..", "..", "..", "..",
        "tests", "crackme03.elf"
    )
    fixture = os.path.abspath(fixture)
    result = construct_parse_elf_headers(file_path=fixture, include_phdrs=False, include_shdrs=False)
    assert result.get("ok") is True
    assert "elf_header" in result["parsed"]
    assert "program_headers" not in result["parsed"]


# ============================================================================
# Custom struct parsing (file-based)
# ============================================================================


@test()
def test_construct_parse_custom_struct_file():
    """construct_parse_custom_struct parses from a file offset."""
    _require_construct()
    fixture = os.path.join(
        os.path.dirname(__file__), "..", "..", "..", "..", "..",
        "tests", "crackme03.elf"
    )
    fixture = os.path.abspath(fixture)
    # Parse the ELF magic at offset 0
    result = construct_parse_custom_struct(
        construct_template='Struct("magic" / Const(b"\\x7fELF"), "cls" / Byte, "data" / Byte)',
        file_path=fixture,
        file_offset=0,
        size_hint=16,
    )
    assert isinstance(result, dict), f"expected dict, got {type(result)}"
    assert result.get("ok") is True, f"parse failed: {result.get('error')}"
    assert result["parsed"]["cls"] == 2  # ELFCLASS64
    assert result["parsed"]["data"] == 1  # ELFDATA2LSB


@test()
def test_construct_parse_custom_struct_invalid_template():
    """construct_parse_custom_struct returns error for invalid DSL."""
    _require_construct()
    fixture = os.path.join(
        os.path.dirname(__file__), "..", "..", "..", "..", "..",
        "tests", "crackme03.elf"
    )
    fixture = os.path.abspath(fixture)
    result = construct_parse_custom_struct(
        construct_template="not a valid template",
        file_path=fixture,
        file_offset=0,
    )
    assert result.get("ok") is False
    assert "error" in result


# ============================================================================
# Build struct
# ============================================================================


@test()
def test_construct_build_struct_returns_hex():
    """construct_build_struct returns hex bytes without patching."""
    _require_construct()
    result = construct_build_struct(
        construct_template='Struct("count" / Int32ul, "flag" / Byte)',
        data={"count": 42, "flag": 1},
        return_only=True,
    )
    assert isinstance(result, dict), f"expected dict, got {type(result)}"
    assert result.get("ok") is True, f"build failed: {result.get('error')}"
    assert "hex" in result
    assert result["size"] == 5
    assert result["hex"] == "2a00000001"


# ============================================================================
# Protocol headers
# ============================================================================


@test()
def test_construct_extract_protocol_ipv4():
    """construct_extract_protocol_header parses an IPv4 header from raw bytes."""
    _require_construct()
    # Minimal IPv4 header: version=4, IHL=5, TOS=0, total_length=20, ID=0, flags=0, frag=0,
    # TTL=64, proto=6 (TCP), checksum=0, src=192.168.1.1, dst=192.168.1.2
    ipv4_bytes = bytes([
        0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x06, 0x00, 0x00, 192, 168, 1, 1, 192, 168, 1, 2,
    ])
    import tempfile
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(ipv4_bytes)
        tmp = f.name
    try:
        result = construct_extract_protocol_header(protocol="ipv4", file_path=tmp, file_offset=0)
        assert result.get("ok") is True, f"parse failed: {result.get('error')}"
        assert result["protocol"] == "ipv4"
        parsed = result["parsed"]
        assert parsed.get("version") == 4
        assert parsed.get("ihl") == 5
        assert parsed.get("ttl") == 64
        assert parsed.get("protocol") == 6
        assert parsed.get("src_ip_readable") == "192.168.1.1"
        assert parsed.get("dst_ip_readable") == "192.168.1.2"
    finally:
        os.unlink(tmp)


@test()
def test_construct_extract_protocol_tcp():
    """construct_extract_protocol_header parses a TCP header."""
    _require_construct()
    tcp_bytes = bytes([
        0x00, 0x50,  # src port 80
        0x1F, 0x90,  # dst port 8080
        0x00, 0x00, 0x00, 0x01,  # seq
        0x00, 0x00, 0x00, 0x02,  # ack
        0x50, 0x02,  # data offset=5, flags=SYN
        0x20, 0x00,  # window
        0x00, 0x00,  # checksum
        0x00, 0x00,  # urgent
    ])
    import tempfile
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(tcp_bytes)
        tmp = f.name
    try:
        result = construct_extract_protocol_header(protocol="tcp", file_path=tmp, file_offset=0)
        assert result.get("ok") is True
        parsed = result["parsed"]
        assert parsed.get("src_port") == 80
        assert parsed.get("dst_port") == 8080
    finally:
        os.unlink(tmp)


@test()
def test_construct_extract_protocol_unknown():
    """construct_extract_protocol_header returns error for unknown protocol."""
    _require_construct()
    result = construct_extract_protocol_header(protocol="unknown_proto")
    assert result.get("ok") is False
    assert "error" in result


# ============================================================================
# Scan for structs
# ============================================================================


@test()
def test_construct_scan_for_structs_finds_pattern():
    """construct_scan_for_structs finds known patterns in a byte region."""
    _require_construct()
    import tempfile
    data = b"AAAA" + b"\x00\x50" + b"\x1f\x90" + b"\x00" * 16  # padding + TCP-like
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(data)
        tmp = f.name
    try:
        result = construct_scan_for_structs(
            construct_template='Struct("src_port" / Int16ub, "dst_port" / Int16ub)',
            start_address="0x0",
            end_address=hex(len(data)),
            alignment=1,
            max_results=10,
        )
        assert result.get("ok") is True
        assert "matches" in result
        assert isinstance(result["matches"], list)
        assert result["scan_attempts"] > 0
    finally:
        os.unlink(tmp)


@test()
def test_construct_scan_for_structs_with_validation():
    """construct_scan_for_structs validates a field value."""
    _require_construct()
    import tempfile
    data = b"\x00\x50\x1f\x90" + b"\x00" * 20  # src_port=80, dst_port=8080
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(data)
        tmp = f.name
    try:
        result = construct_scan_for_structs(
            construct_template='Struct("src_port" / Int16ub, "dst_port" / Int16ub)',
            start_address="0x0",
            end_address=hex(len(data)),
            alignment=1,
            max_results=10,
            validate_field="src_port",
            validate_value_hex="0050",
        )
        assert result.get("ok") is True
        # Should find the match at offset 0
        assert len(result["matches"]) >= 1
        assert result["matches"][0]["address"] == "0x0"
    finally:
        os.unlink(tmp)


# ============================================================================
# Batch parse array
# ============================================================================


@test()
def test_construct_batch_parse_array_from_file():
    """construct_batch_parse_array parses multiple elements from a file region."""
    _require_construct()
    import tempfile
    # Array of 3 structs: (count, flag)
    data = b"\x01\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00" + b"\x03\x00\x00\x00\x01"
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(data)
        tmp = f.name
    try:
        result = construct_batch_parse_array(
            construct_template='Struct("count" / Int32ul, "flag" / Byte)',
            address="0x0",
            count=3,
            max_size=len(data),
        )
        assert result.get("ok") is True
        assert result["count"] == 3
        assert len(result["elements"]) == 3
        assert result["elements"][0]["parsed"]["count"] == 1
        assert result["elements"][1]["parsed"]["count"] == 2
    finally:
        os.unlink(tmp)


# ============================================================================
# IDA struct bridge (requires IDA — skip if not in IDA context)
# ============================================================================


@test()
def test_construct_parse_ida_struct_skips_without_ida():
    """construct_parse_ida_struct gracefully handles missing IDA context."""
    _require_construct()
    # This test may fail if IDA is not present; we catch that gracefully
    try:
        import idaapi
    except ImportError:
        skip_test("IDA not available")
    # If we get here, IDA is available — try a known struct
    result = construct_parse_ida_struct("sockaddr_in", "0x0")
    # May succeed or fail depending on whether sockaddr_in exists in the IDB
    assert isinstance(result, dict)
    assert "ok" in result
