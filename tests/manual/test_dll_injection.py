import subprocess

from iced_x86 import Register
import regex

import memobj
from memobj.utils import wait_for_value
from memobj.hook import create_capture_hook, RegisterCaptureSettings


def test_dll_injection(test_binaries):
    exe_path, dll_path = test_binaries

    proc = subprocess.Popen([str(exe_path)])
    try:
        process = memobj.WindowsProcess.from_id(proc.pid)
        assert process.inject_dll(dll_path), "DLL injection failed"

        module = process.get_module_named(dll_path.name)
        assert module is not None, "Failed to find injected DLL in remote process"
    finally:
        proc.terminate()


def test_create_capture_hook(test_binaries):
    exe_path, _ = test_binaries

    # TODO: allow passing addresses so we can do a symbol lookup
    PlayerCaptureHook = create_capture_hook(
        pattern=regex.escape(bytes.fromhex("48 83 EC 28 F3 0F 10 41 04 0F 2E 05 40 52 01 00 76 0D 8B 09 E8 17 FF FF FF 01 05 21 D0 01 00 48 83 C4 28 C3")),
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
        address = wait_for_value(lambda: rcx_capture.read_typed(process.pointer_type), 0, inverse=True, timeout=60)

        assert address != 0
    finally:
        proc.terminate()

