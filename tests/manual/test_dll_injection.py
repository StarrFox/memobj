import subprocess
import sys

import pytest
import regex

import memobj
from memobj.utils import wait_for_value



def test_dll_injection(test_binaries):
    exe_path, dll_path = test_binaries

    proc = subprocess.Popen([str(exe_path)])
    try:
        if sys.platform == "win32":
            process = memobj.WindowsProcess.from_id(proc.pid)
            assert process.inject_dll(dll_path), "DLL injection failed"
        elif sys.platform == "linux":
            process = memobj.LinuxProcess.from_id(proc.pid)
            assert process.inject_so(dll_path), "SO injection failed"
        else:
            pytest.skip("Unsupported platform")

        module = process.get_module_named(dll_path.name)
        assert module is not None, "Failed to find injected library in remote process"
    finally:
        proc.terminate()
        proc.wait()


def _get_uses_player_pattern(process, module_name: str) -> bytes:
    """Read the first bytes of uses_player from the running process to use as a pattern."""
    module = process.get_module_named(module_name)
    symbols = module.get_symbols()
    uses_player_addr = symbols.get("uses_player")
    if uses_player_addr is None:
        pytest.skip("uses_player symbol not found in binary (compile with debug symbols?)")
    # Read enough bytes to cover the hook jump (14 bytes) plus some margin
    return process.read_memory(uses_player_addr, 32)


def test_create_capture_hook(test_binaries):
    exe_path, _ = test_binaries
    match sys.platform:
        case "win32":
            from iced_x86 import Register
            from memobj.hook import create_capture_hook, RegisterCaptureSettings

            # TODO: allow passing addresses so we can do a symbol lookup
            # note: the two 4 byte gaps are RIP-relative displacements to global data
            # (the health constant and the MUTATED static) which shift whenever the
            # binary is rebuilt, so they're wildcarded instead of hardcoded
            pattern_prefix = regex.escape(bytes.fromhex("48 83 EC 28 F3 0F 10 41 04 0F 2E 05"))
            pattern_mid = regex.escape(bytes.fromhex("76 0D 8B 09 E8 17 FF FF FF 01 05"))
            pattern_suffix = regex.escape(bytes.fromhex("48 83 C4 28 C3"))
            PlayerCaptureHook = create_capture_hook(
                pattern=pattern_prefix + b".{4}" + pattern_mid + b".{4}" + pattern_suffix,
                module="inject_target.exe",
                bitness=64,
                register_captures=[RegisterCaptureSettings(Register.RCX, derefference=False)],
            )

            proc = subprocess.Popen([str(exe_path)])
            try:
                process = memobj.WindowsProcess.from_id(proc.pid)
                hook = PlayerCaptureHook(process)
                hook.activate()
                rcx_capture = hook.get_variable("RCX_capture")
                address, _ = wait_for_value(
                    lambda: rcx_capture.read_typed(process.pointer_type), 0,
                    inverse=True, timeout=60,
                )
                assert address != 0
            finally:
                proc.terminate()
                proc.wait()

        case "linux":
            from iced_x86 import Register
            from memobj.hook import create_capture_hook, RegisterCaptureSettings

            proc = subprocess.Popen([str(exe_path)])
            try:
                process = memobj.LinuxProcess.from_id(proc.pid)
                module_name = exe_path.name  # "inject_target"

                pattern = regex.compile(
                    regex.escape(_get_uses_player_pattern(process, module_name)),
                    regex.DOTALL,
                )

                PlayerCaptureHook = create_capture_hook(
                    pattern=pattern,
                    module=module_name,
                    bitness=64,
                    # System V AMD64 ABI: first argument in RDI (not RCX)
                    register_captures=[RegisterCaptureSettings(Register.RDI, derefference=False)],
                )

                hook = PlayerCaptureHook(process)
                hook.activate()
                rdi_capture = hook.get_variable("RDI_capture")
                address, _ = wait_for_value(
                    lambda: rdi_capture.read_typed(process.pointer_type), 0,
                    inverse=True, timeout=60,
                )
                assert address != 0
            finally:
                proc.terminate()
                proc.wait()

        case _:
            pytest.skip("Unsupported platform")
