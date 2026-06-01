"""Tests for api_unicorn — Unicorn concrete emulation engine tools.

The status probe always runs. Pure-helper tests (entropy, string extraction,
page merging) run whenever unicorn is installed and need no IDB. Emulation
tests use the crackme03.elf fixture and skip gracefully when unicorn is absent.
"""

from ..framework import (
    test,
    skip_test,
    assert_ok,
    assert_has_keys,
    assert_is_list,
    get_any_function,
)

try:
    from ..api_unicorn import (
        unicorn_status,
        UNICORN_AVAILABLE,
    )
    if UNICORN_AVAILABLE:
        from ..api_unicorn import (
            unicorn_emulate,
            unicorn_trace,
            unicorn_call_function,
            unicorn_diff_memory,
            unicorn_find_memory_accesses,
            unicorn_recover_stackstrings,
            unicorn_emulate_shellcode,
            # pure helpers
            _shannon_entropy,
            _extract_ascii_strings,
            _extract_utf16le_strings,
            _merge_page_regions,
            _align_up,
            _align_down,
            UC_PROT_READ,
            UC_PROT_WRITE,
            UC_PROT_EXEC,
            UC_ARCH_X86,
            UC_MODE_32,
            UC_MODE_64,
            _register_map,
        )
except ImportError:
    UNICORN_AVAILABLE = False


def _require_unicorn():
    if not UNICORN_AVAILABLE:
        skip_test("unicorn not installed")


# ---------------------------------------------------------------------------
# Status probe — always runs, even without unicorn
# ---------------------------------------------------------------------------


@test()
def test_unicorn_status_probe():
    """unicorn_status must not crash regardless of whether unicorn is installed."""
    result = unicorn_status()
    assert isinstance(result, dict), "unicorn_status must return a dict"
    assert "available" in result, "must include 'available'"
    assert result.get("ok") is True


@test()
def test_unicorn_status_version():
    """version + arch list present when unicorn is available."""
    _require_unicorn()
    result = unicorn_status()
    assert result.get("available") is True
    assert isinstance(result.get("version"), str) and result["version"]
    assert_is_list(result.get("archs"), min_length=1)
    assert "x86" in result["archs"]


@test()
def test_unicorn_status_no_unicorn_hint():
    """hint present when unicorn is absent."""
    if UNICORN_AVAILABLE:
        skip_test("unicorn installed — no-unicorn path unreachable")
    result = unicorn_status()
    assert result.get("ok") is True
    assert "hint" in result


# ---------------------------------------------------------------------------
# Pure helpers — no IDB required
# ---------------------------------------------------------------------------


@test()
def test_entropy_bounds():
    _require_unicorn()
    assert _shannon_entropy(b"") == 0.0
    assert _shannon_entropy(b"\x00" * 256) == 0.0
    full = _shannon_entropy(bytes(range(256)))
    assert 7.99 <= full <= 8.0, f"uniform bytes should be ~8.0, got {full}"


@test()
def test_extract_ascii_strings():
    _require_unicorn()
    data = b"\x01\x02hello\x00world!\xff__"
    got = _extract_ascii_strings(data, 4)
    assert "hello" in got and "world!" in got, got
    # min_length filters short runs
    assert _extract_ascii_strings(b"\x00ab\x00", 4) == []


@test()
def test_extract_utf16le_strings():
    _require_unicorn()
    blob = "kernel32".encode("utf-16le")
    got = _extract_utf16le_strings(blob, 4)
    assert "kernel32" in got, got


@test()
def test_merge_page_regions_coalesces():
    """Two segments sharing a page merge into one mapped region with OR-ed perms."""
    _require_unicorn()
    segs = [
        {"start": 0x1000, "size": 0x40, "perms": UC_PROT_READ | UC_PROT_EXEC,
         "data": b"", "name": "a"},
        {"start": 0x1040, "size": 0x40, "perms": UC_PROT_READ | UC_PROT_WRITE,
         "data": b"", "name": "b"},
    ]
    regions = _merge_page_regions(segs)
    assert len(regions) == 1, regions
    assert regions[0]["base"] == 0x1000
    assert regions[0]["size"] == 0x1000
    assert regions[0]["perms"] & UC_PROT_WRITE
    assert regions[0]["perms"] & UC_PROT_EXEC


@test()
def test_align_helpers():
    _require_unicorn()
    assert _align_down(0x1234) == 0x1000
    assert _align_up(0x1001) == 0x2000
    assert _align_up(0x1000) == 0x1000


@test()
def test_register_map_x86():
    """x86-64 register map includes both 32- and 64-bit names; 32-bit excludes rax."""
    _require_unicorn()
    m64 = _register_map(UC_ARCH_X86, UC_MODE_64)
    assert "rax" in m64 and "eax" in m64 and "r15" in m64
    m32 = _register_map(UC_ARCH_X86, UC_MODE_32)
    assert "eax" in m32 and "rax" not in m32


# ---------------------------------------------------------------------------
# Emulation — needs the IDB
# ---------------------------------------------------------------------------


@test(binary="crackme03.elf")
def test_unicorn_emulate_runs():
    """unicorn_emulate maps segments and runs without crashing."""
    _require_unicorn()
    func = get_any_function()
    if not func:
        skip_test("no function found")
    # Bound tightly: emulate a handful of instructions from the function start.
    result = unicorn_emulate(start=func, end=func, max_insns=64, timeout_ms=3000)
    # end==start halts immediately (0 insns) but the call must still succeed
    # and report structured state.
    assert_ok(result)
    assert_has_keys(result, "insns_executed", "stop_reason", "regs",
                    "memory_writes", "unmapped_accesses")
    assert isinstance(result["regs"], dict)


@test(binary="crackme03.elf")
def test_unicorn_emulate_executes_instructions():
    """Emulating into a function with a far end executes some instructions."""
    _require_unicorn()
    func = get_any_function()
    if not func:
        skip_test("no function found")
    end = hex(int(func, 16) + 0x400)
    result = unicorn_emulate(start=func, end=end, max_insns=64, timeout_ms=3000)
    assert_ok(result)
    assert isinstance(result["insns_executed"], int)
    # The PC register should be present in the readback.
    regs = result["regs"]
    assert any(k in regs for k in ("rip", "eip", "pc")), regs


@test(binary="crackme03.elf")
def test_unicorn_trace_levels():
    """unicorn_trace returns a trace list and loop summary."""
    _require_unicorn()
    func = get_any_function()
    if not func:
        skip_test("no function found")
    end = hex(int(func, 16) + 0x400)
    result = unicorn_trace(start=func, end=end, trace_level="insns",
                           max_insns=64, timeout_ms=3000)
    assert_ok(result)
    assert_has_keys(result, "trace", "insns_executed", "unique_addrs",
                    "loops_detected")
    assert_is_list(result["trace"])
    assert_is_list(result["loops_detected"])


@test(binary="crackme03.elf")
def test_unicorn_call_function_returns_structured():
    """unicorn_call_function sets up a CC and returns a value field."""
    _require_unicorn()
    func = get_any_function()
    if not func:
        skip_test("no function found")
    result = unicorn_call_function(func_addr=func, args=["0x1", "0x2"],
                                   max_insns=2000, timeout_ms=3000)
    assert_ok(result)
    assert_has_keys(result, "return_value", "regs", "insns_executed",
                    "stop_reason")
    assert isinstance(result["return_value"], str)


@test(binary="crackme03.elf")
def test_unicorn_find_memory_accesses_structured():
    """unicorn_find_memory_accesses returns read/write tallies."""
    _require_unicorn()
    func = get_any_function()
    if not func:
        skip_test("no function found")
    end = hex(int(func, 16) + 0x400)
    result = unicorn_find_memory_accesses(start=func, end=end,
                                          max_insns=64, timeout_ms=3000)
    assert_ok(result)
    assert_has_keys(result, "accesses", "read_count", "write_count",
                    "hot_regions")
    assert isinstance(result["read_count"], int)


@test(binary="crackme03.elf")
def test_unicorn_recover_stackstrings_structured():
    """unicorn_recover_stackstrings returns a strings list without crashing."""
    _require_unicorn()
    func = get_any_function()
    if not func:
        skip_test("no function found")
    result = unicorn_recover_stackstrings(func_addr=func, min_length=4,
                                          max_insns=2000, timeout_ms=3000)
    assert_ok(result)
    assert_has_keys(result, "strings", "stack_write_count", "insns_executed")
    assert_is_list(result["strings"])


# ---------------------------------------------------------------------------
# Shellcode sandbox — self-contained (no IDB), but needs unicorn
# ---------------------------------------------------------------------------


@test()
def test_unicorn_emulate_shellcode_linux_write_exit():
    """A tiny linux_x86 write+exit shellcode is traced and its syscalls logged."""
    _require_unicorn()
    # 32-bit Linux: write(1, msg, len) ; exit(0)
    #   mov eax,4; mov ebx,1; mov ecx,<msg>; mov edx,2; int 0x80
    #   mov eax,1; xor ebx,ebx; int 0x80
    #   msg: "Hi"
    # We place msg right after the code at base+offset and use absolute addr.
    base = 0x1000000
    # Build: code then "Hi" bytes. Compute msg addr after assembling.
    # Pre-size code to know msg offset.
    # mov eax,4 (B8 04000000) mov ebx,1 (BB 01000000) mov ecx,IMM (B9 ....)
    # mov edx,2 (BA 02000000) int80 (CD80) mov eax,1 (B8 01000000)
    # xor ebx,ebx (31DB) int80 (CD80)  => total 2+? compute length
    head = bytes.fromhex("B804000000" "BB01000000")
    movecx = b"\xb9"  # + 4 byte imm
    tail = bytes.fromhex("BA02000000" "CD80" "B801000000" "31DB" "CD80")
    code_len = len(head) + 1 + 4 + len(tail)
    msg_addr = base + code_len
    code = head + movecx + msg_addr.to_bytes(4, "little") + tail + b"Hi"
    result = unicorn_emulate_shellcode(hex_bytes=code.hex(), os_type="linux_x86",
                                       address=hex(base), max_insns=200,
                                       timeout_ms=3000)
    assert_ok(result)
    assert_has_keys(result, "syscalls", "strings_extracted", "insns_executed",
                    "stop_reason")
    names = [s.get("name") for s in result["syscalls"]]
    assert "write" in names, names
    assert result["stop_reason"] in ("sys_exit", "max_insns", "end_reached", "timeout")
