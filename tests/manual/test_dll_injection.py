import subprocess
import pytest
from pathlib import Path

import memobj

import pytest


def test_dll_injection():
    # there is probably a better way to get this
    library_root = Path(__file__).parent.parent.parent

    assert library_root.name == "memobj"
    assert (library_root / "README.md").exists() is True

    dll_path = (
        library_root / "target/release/test_inject.dll"
    ).resolve()
    exe_path = (
        library_root / "target/release/inject_target.exe"
    ).resolve()

    if not dll_path.exists():
        pytest.skip(f"Test DLL not found at {dll_path}")
    if not exe_path.exists():
        pytest.skip(f"Test EXE not found at {exe_path}")

    proc = subprocess.Popen([str(exe_path)])
    try:
        process = memobj.WindowsProcess.from_id(proc.pid)
        assert process.inject_dll(dll_path), "DLL injection failed"

        module = process.get_module_named(dll_path.name)
        assert module is not None, "Failed to find injected DLL in remote process"
    finally:
        proc.terminate()
