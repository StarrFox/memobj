import sys


def test_get_module_name(process):
    base_module = process.get_modules(True)
    if sys.platform == "win32":
        assert base_module.name == "python.exe"
    else:
        assert "python" in base_module.name.lower()


def test_get_module_named(process):
    if sys.platform == "win32":
        process.get_module_named("python.exe")
    else:
        base = process.get_modules(True)
        process.get_module_named(base.name)


# TODO: find a version independent way to test this
# def test_scan_memory_module(process):
#     test = process.scan_memory(
#         bytes.fromhex("40 53 48 83 EC 20 48 8B D9 33 C9 FF 15 6B 0D 00 00 48 8B CB FF 15 6A 0D 00 00"),
#         module=True,
#     )
#
#     assert len(test) == 1
#     assert test[0] == 0x7FF63D9612B4
