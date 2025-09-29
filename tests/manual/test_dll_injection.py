import subprocess
import time
import pytest
from pathlib import Path
import ctypes

import memobj

import pytest


@pytest.fixture(autouse=True, scope="module")
def skip_if_not_manual(request):
    if not request.config.getoption("--run-manual"):
        pytest.skip("Manual test: run with pytest --run-manual")

def test_dll_injection(tmp_path_factory):
    test_file: Path = tmp_path_factory.mktemp("dll_inject") / "dll_injected_test.txt"
    dll_path = (Path(__file__).parent / "test_inject/target/release/test_inject.dll").resolve()
    exe_path = (Path(__file__).parent / "test_inject/target/release/inject_target.exe").resolve()

    if not dll_path.exists():
        pytest.skip(f"Test DLL not found at {dll_path}")
    if not exe_path.exists():
        pytest.skip(f"Test EXE not found at {exe_path}")

    proc = subprocess.Popen([str(exe_path)])
    try:
        time.sleep(1)
        process = memobj.WindowsProcess.from_id(proc.pid)

        assert process.inject_dll(dll_path), "DLL injection failed"
        time.sleep(1)

        module = process.get_module_named(dll_path.name)
        assert module is not None, "Failed to find injected DLL in remote process"

        symbol = module.get_symbol_with_name("create_file_at_path")
        assert symbol is not None, "Failed to get symbol offset for exported function"
        func_addr = module.base_address + symbol.offset

        remote_path_addr = process.allocate_memory(len(str(test_file)) + 1)
        process.write_memory(remote_path_addr, str(test_file).encode("utf-8") + b"\x00")

        thread_handle = process.create_remote_thread(func_addr, param_pointer=ctypes.c_void_p(remote_path_addr))
        assert thread_handle, "Failed to create remote thread for exported function"

        for _ in range(20):
            if test_file.exists():
                break
            time.sleep(0.25)
        else:
            assert False, f"Injected file {test_file} not found!"

        process.free_memory(remote_path_addr)
    finally:
        proc.terminate()
