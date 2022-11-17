import os

from memobj import WindowsProcess


def get_current_process() -> WindowsProcess:
    return WindowsProcess.from_id(os.getpid())


def test_get_module_name():
    process = get_current_process()

    base_module = process.get_modules(True)
    base_module_name = process.get_module_name(base_module)

    assert base_module_name == "python.exe"


def test_get_module_named():
    process = get_current_process()
    process.get_module_named("python.exe")

# TODO: find a version independent way to test this
# def test_scan_memory_module():
#     process = get_current_process()
#     test = process.scan_memory(
#         bytes.fromhex("40 53 48 83 EC 20 48 8B D9 33 C9 FF 15 6B 0D 00 00 48 8B CB FF 15 6A 0D 00 00"),
#         module=True,
#     )
#
#     assert len(test) == 1
#     assert test[0] == 0x7FF63D9612B4
