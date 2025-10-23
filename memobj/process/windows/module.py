"""


process.get_symbol_address("user32.dll", "GetCursorPos") -> int
process.get_module("user32.dll").get_symbols()["GetCursorPos"] -> int

Module(...)
    .name
    .get_symbols()
    .base_address
    .executable_path
    .size

    .handle (windows only)
    .process (multi-process helper)

"""

import ctypes
from typing import TYPE_CHECKING, Iterator, Self

from memobj.process import Module

from .utils import CheckWindowsOsError, ModuleEntry32

if TYPE_CHECKING:
    from .process import WindowsProcess


INVALID_HANDLE_VALUE: int = -1
TH32CS_SNAPMODULE: int = 0x8


class WindowsModule(Module):
    _symbols: dict[str, int] | None = None

    # TODO: make a user facing iterface to this copying the object so it isn't changed while they're using it
    # TODO: get wide character variants working
    # adapted to python from https://learn.microsoft.com/en-us/windows/win32/toolhelp/traversing-the-module-list
    @staticmethod
    def _iter_modules(process: "WindowsProcess") -> Iterator[ModuleEntry32]:
        """
        Note that the yielded modules are only valid for one iteration, i.e. references to them should not
        be stored
        """
        with CheckWindowsOsError():
            # https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot
            module_snapshot = ctypes.windll.kernel32.CreateToolhelp32Snapshot(
                TH32CS_SNAPMODULE, process.process_id
            )

            if module_snapshot == INVALID_HANDLE_VALUE:
                raise ValueError("Creating module snapshot failed")

            module_entry = ModuleEntry32()
            module_entry.dwSize = ctypes.sizeof(ModuleEntry32)

            # https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-module32first
            success = ctypes.windll.kernel32.Module32First(
                module_snapshot, ctypes.byref(module_entry)
            )

            if success == 0:
                raise ValueError("Get first module failed")

            yield module_entry

            # https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-module32next
            while (
                ctypes.windll.kernel32.Module32Next(
                    module_snapshot, ctypes.byref(module_entry)
                )
                != 0
            ):
                yield module_entry

            # https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle
            ctypes.windll.kernel32.CloseHandle(module_snapshot)

    @classmethod
    def from_name(
        cls, process: "WindowsProcess", name: str, *, ignore_case: bool = True
    ) -> Self:
        if ignore_case:
            name = name.lower()

        for module in cls._iter_modules(process):
            module_name = module.szModule.decode()

            # use another variable to preserve case in WindowsModule object
            if ignore_case:
                compare_name = module_name.lower()
            else:
                compare_name = module_name

            if compare_name == name:
                return cls(
                    name=module_name,
                    base_address=module.modBaseAddr,
                    executable_path=module.szExePath.decode(),
                    size=module.modBaseSize,
                    process=process,
                )

        raise ValueError(f"No modules named {name}")

    @classmethod
    def get_all_modules(cls, process: "WindowsProcess") -> list[Self]:
        modules: list[Self] = []

        for module in cls._iter_modules(process):
            module_name = module.szModule.decode()

            modules.append(
                cls(
                    name=module_name,
                    base_address=module.modBaseAddr,
                    executable_path=module.szExePath.decode(),
                    size=module.modBaseSize,
                    process=process,
                )
            )
        
        return modules

    def get_symbol_with_name(self, name: str) -> int:
        try:
            return self.get_symbols()[name]
        except KeyError:
            raise ValueError(f"No symbol named {name}")

    def get_symbols(self) -> dict[str, int]:
        if self._symbols is not None:
            return self._symbols

        # lazy import windows only library
        import pefile

        portable_executable = pefile.PE(self.executable_path)

        # this api is really bad
        if not hasattr(portable_executable, "DIRECTORY_ENTRY_EXPORT"):
            self._symbols = {}
            return {}

        symbols: dict[str, int] = {}

        for export in portable_executable.DIRECTORY_ENTRY_EXPORT.symbols:  # type: ignore
            if export.name:
                symbols[export.name.decode()] = export.address + self.base_address

            else:
                symbols[f"Ordinal {export.ordinal}"] = (
                    export.address + self.base_address
                )

        self._symbols = symbols
        return symbols
