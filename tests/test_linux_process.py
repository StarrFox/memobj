import ctypes
import os
import struct
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux only")

from memobj.process.linux.process import LinuxMemoryRegion, LinuxProcess
from memobj.process.linux.module import LinuxModule


@pytest.fixture(scope="module")
def proc() -> LinuxProcess:
    return LinuxProcess.from_id(os.getpid())


# ── construction ──────────────────────────────────────────────────────────────

def test_from_id(proc):
    assert proc.process_id == os.getpid()


def test_from_id_bad_pid():
    with pytest.raises(ValueError, match="No process"):
        LinuxProcess.from_id(999_999_999)


def test_from_name():
    comm = Path(f"/proc/{os.getpid()}/comm").read_text().strip()
    found = LinuxProcess.from_name(comm)
    found_comm = Path(f"/proc/{found.process_id}/comm").read_text().strip()
    assert found_comm == comm


def test_from_name_missing():
    with pytest.raises(ValueError, match="No process found"):
        LinuxProcess.from_name("__definitely_no_such_process__")


# ── process metadata ──────────────────────────────────────────────────────────

def test_process_id(proc):
    assert proc.process_id == os.getpid()


def test_process_64_bit(proc):
    assert proc.process_64_bit == proc.python_64_bit


def test_executable_path(proc):
    path = proc.executable_path
    assert path.exists()
    assert path.is_file()
    assert "python" in path.name.lower()


# ── memory read / write ───────────────────────────────────────────────────────

def test_read_memory(proc):
    data = b"memobj_read_test"
    buf = ctypes.create_string_buffer(data)
    result = proc.read_memory(ctypes.addressof(buf), len(data))
    assert result == data


def test_write_memory(proc):
    buf = ctypes.create_string_buffer(16)
    proc.write_memory(ctypes.addressof(buf), b"\xAB" * 16)
    assert buf.raw == b"\xAB" * 16


def test_read_formatted(proc):
    value = 1337
    buf = ctypes.c_int32(value)
    result = proc.read_formatted(ctypes.addressof(buf), "=i")
    assert result == value


def test_write_formatted(proc):
    buf = ctypes.c_int32(0)
    proc.write_formatted(ctypes.addressof(buf), "=i", 9999)
    assert buf.value == 9999


# ── allocation ────────────────────────────────────────────────────────────────

def test_allocate_free_memory(proc):
    addr = proc.allocate_memory(4096)
    assert addr > 0
    proc.write_memory(addr, b"\xDE\xAD\xBE\xEF")
    assert proc.read_memory(addr, 4) == b"\xDE\xAD\xBE\xEF"
    proc.free_memory(addr)


def test_free_untracked_raises(proc):
    with pytest.raises(ValueError, match="No tracked allocation"):
        proc.free_memory(0x1234)


def test_allocate_preferred_start(proc):
    # Request a hint; kernel may or may not honour it, but it must succeed
    addr = proc.allocate_memory(4096, preferred_start=0x7000_0000_0000)
    assert addr > 0
    proc.free_memory(addr)


# ── scan_memory ───────────────────────────────────────────────────────────────

def test_scan_memory_finds_pattern(proc):
    needle = b"\xCA\xFE\xBA\xBE\xDE\xAD"
    buf = ctypes.create_string_buffer(needle)
    matches = proc.scan_memory(needle)
    assert ctypes.addressof(buf) in matches


def test_scan_memory_regex(proc):
    import regex as re
    needle = b"\xFE\xED\xC0\xDE"
    buf = ctypes.create_string_buffer(needle)
    pattern = re.compile(b"\xfe\xed..", re.DOTALL)
    matches = proc.scan_memory(pattern)
    assert any(m == ctypes.addressof(buf) for m in matches)


def test_scan_memory_module_filter(proc):
    # Scanning within the base module should still find things in its code range
    base = proc.get_modules(True)
    # The module's base address region is code; scan for the ELF magic bytes
    results = proc.scan_memory(b"\x7fELF", module=base)
    assert len(results) >= 1


# ── virtual_query ─────────────────────────────────────────────────────────────

def test_virtual_query_stack(proc):
    local_var = ctypes.c_int(42)
    addr = ctypes.addressof(local_var)
    region = proc.virtual_query(addr)
    assert isinstance(region, LinuxMemoryRegion)
    assert region.base_address <= addr < region.base_address + region.size
    assert region.readable


def test_virtual_query_heap(proc):
    addr = proc.allocate_memory(4096)
    try:
        region = proc.virtual_query(addr)
        assert region.readable
        assert region.writable
    finally:
        proc.free_memory(addr)


def test_virtual_query_bad_address(proc):
    with pytest.raises(ValueError, match="No memory region"):
        proc.virtual_query(0x1)


# ── modules ───────────────────────────────────────────────────────────────────

def test_get_modules_returns_list(proc):
    modules = proc.get_modules()
    assert isinstance(modules, list)
    assert len(modules) > 0
    assert all(isinstance(m, LinuxModule) for m in modules)


def test_get_modules_contains_python(proc):
    modules = proc.get_modules()
    names = [m.name.lower() for m in modules]
    assert any("python" in n for n in names)


def test_get_modules_base_only(proc):
    base = proc.get_modules(base_only=True)
    assert isinstance(base, LinuxModule)
    assert "python" in base.name.lower()
    assert base.base_address > 0
    assert base.size > 0


def test_get_module_named(proc):
    base = proc.get_modules(base_only=True)
    found = proc.get_module_named(base.name)
    assert found.name == base.name
    assert found.base_address == base.base_address


def test_get_module_named_case_insensitive(proc):
    base = proc.get_modules(base_only=True)
    found = proc.get_module_named(base.name.upper())
    assert found.name == base.name


def test_get_module_named_missing(proc):
    with pytest.raises(ValueError, match="No module named"):
        proc.get_module_named("__no_such_module__.so")


def test_module_has_libc(proc):
    modules = proc.get_modules()
    libc_modules = [m for m in modules if "libc" in m.name.lower()]
    assert len(libc_modules) > 0


def test_module_base_address_and_size(proc):
    for module in proc.get_modules():
        assert module.base_address > 0
        assert module.size > 0
