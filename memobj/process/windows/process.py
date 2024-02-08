import ctypes
import ctypes.wintypes
import functools
import typing
from pathlib import Path
from typing import Self, Union

import regex

from memobj.process.windows.utils import (
    CheckWindowsOsError,
    WindowsModuleInfo,
    WindowsMemoryProtection,  # TODO: what was this going to be used for?
    WindowsMemoryBasicInformation,
    LUID,
    LUID_AND_ATTRIBUTES,
    SingleLUIDAndAttributes,
    TOKEN_PRIVILEGES,
    PROCESSENTRY32
)
from memobj.process import Process


class WindowsProcess(Process):
    def __init__(self, process_handle: int):
        self.process_handle = process_handle

    @staticmethod
    def _get_debug_privileges():
        with CheckWindowsOsError():
            # https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocess
            proc = ctypes.windll.kernel32.GetCurrentProcess()
            token_access_flags = 0x1 | 0x2 | 0x4 | 0x8 | 0x10 | 0x20 | 0x40 | 0x80 | 0xF0000
            token_handle = ctypes.wintypes.HANDLE()
            # https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken
            # for some reason OpenProcessToken doesn't work if it's argtypes aren't defined
            ctypes.windll.advapi32.OpenProcessToken.argtypes = (
                ctypes.wintypes.HANDLE,
                ctypes.wintypes.DWORD,
                ctypes.wintypes.PHANDLE,
            )
            open_process_token_success = ctypes.windll.advapi32.OpenProcessToken(
                proc,
                token_access_flags,
                ctypes.byref(token_handle),
            )

            if open_process_token_success == 0:
                raise RuntimeError("OpenProcessToken failed")

        with CheckWindowsOsError():
            wanted_privilege = "SeDebugPrivilege"
            wanted_luid = LUID()
            # https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lookupprivilegevaluew
            lookup_privilege_success = ctypes.windll.advapi32.LookupPrivilegeValueW(
                0,
                wanted_privilege,
                ctypes.byref(wanted_luid),
            )

            if lookup_privilege_success == 0:
                raise RuntimeError("LookupPrivilegeValue failed")

        with CheckWindowsOsError():
            new_privilege = LUID_AND_ATTRIBUTES()
            new_privilege.Luid = wanted_luid
            new_privilege.Attributes = 0x2  # SE_PRIVILEGE_ENABLED

            new_privileges_array = TOKEN_PRIVILEGES()
            new_privileges_array.PrivilegeCount = 1
            new_privileges_array.Privileges = SingleLUIDAndAttributes(new_privilege)

            # https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-adjusttokenprivileges
            adjust_token_success = ctypes.windll.advapi32.AdjustTokenPrivileges(
                token_handle,
                0,
                ctypes.byref(new_privileges_array),
                0,
                0,
                0,
            )

            if adjust_token_success == 0:
                raise RuntimeError("AdjustTokenPrivileges failed")

    @functools.cached_property
    def process_64_bit(self) -> bool:
        # True  = system 64 bit process 32 bit
        # False = system 32 bit process 32 bit
        # False = system ARM    process 32 bit
        # False = system 64 bit process 64 bit
        with CheckWindowsOsError():
            wow_64_process = ctypes.c_bool()
            # https://learn.microsoft.com/en-us/windows/win32/api/wow64apiset/nf-wow64apiset-iswow64process
            success = ctypes.windll.kernel32.IsWow64Process(
                self.process_handle,
                ctypes.byref(wow_64_process),
            )

            if success == 0:
                raise ValueError("IsWow64Process failed")

        # this is the only case where the process is 64 bit
        return self.system_64_bit and wow_64_process.value == 0

    @functools.cached_property
    def executable_path(self) -> Path:
        with CheckWindowsOsError():
            # https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulefilenamea
            file_name = ctypes.create_unicode_buffer(ctypes.wintypes.MAX_PATH)

            ctypes.windll.psapi.GetModuleFileNameExW(
                self.process_handle,
                0,
                ctypes.byref(file_name),
                ctypes.wintypes.MAX_PATH,
            )

        return Path(file_name.value)

    @classmethod
    def from_name(cls, name: str, *, require_debug: bool = True) -> Self:
        with CheckWindowsOsError():
            # https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot
            snapshot = ctypes.windll.kernel32.CreateToolhelp32Snapshot(
                0x2,
                0,
            )

            # https://referencesource.microsoft.com/#mscorlib/microsoft/win32/win32native.cs,1196
            # if that link is dead the content was
            # internal static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
            # INVALID_HANDLE_VALUE is -1
            if snapshot == -1:
                raise RuntimeError("CreateToolhelp32Snapshot failed")

        with CheckWindowsOsError():
            # https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32first
            # this is really quite a silly way to do this
            process_entry = PROCESSENTRY32()
            # see PROCESSENTRY32.dwSize note for why this has to be set
            process_entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
            process_32_success = ctypes.windll.kernel32.Process32First(
                snapshot,
                ctypes.byref(process_entry)
            )

            if process_32_success == 0:
                raise RuntimeError("Process32First failed")

        while process_32_success:
            if process_entry.szExeFile.decode() == name:
                return cls.from_id(process_entry.th32ProcessID, require_debug=require_debug)
            process_32_success = ctypes.windll.kernel32.Process32Next(
                snapshot,
                ctypes.byref(process_entry)
            )

        raise ValueError(f"No processes found named {name}; make sure you included the .exe and any capital letters")

    @classmethod
    def from_id(cls, pid: int, *, require_debug: bool = True) -> Self:
        try:
            cls._get_debug_privileges()
        except OSError as error:
            # 1300 is ERROR_NOT_ALL_ASSIGNED which is raised when the calling process doesn't have the
            # privilege on it's token
            if error.errno == 1300 and require_debug:
                raise RuntimeError("Could not get debug permission; try running as admin or pass require_debug=False")

        # https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
        # https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights
        with CheckWindowsOsError():
            process_handle = ctypes.windll.kernel32.OpenProcess(
                0xF0000 | 0x100000 | 0xFFFF,
                0,
                pid,
            )

            if process_handle == 0:
                raise ValueError(f"OpenProcess returned null for process id {pid}")

        return cls(process_handle)

    def allocate_memory(self, size: int, *, preferred_start: int | None = None) -> int: # type: ignore
        """
        Allocate <size> amount of memory in the process

        Args:
            size: The amount of memory to allocate
            preferred_start: The preferred start address of the allocation

        Returns:
        The start address of the allocated memory
        """
        with CheckWindowsOsError():
            if preferred_start is not None:
                preferred_start: ctypes.c_void_p = ctypes.cast(preferred_start, ctypes.c_void_p)

            else:
                preferred_start = 0  # type: ignore (null pointer)

            ctypes.windll.kernel32.VirtualAllocEx.restype = ctypes.c_size_t

            # https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex
            allocation = ctypes.windll.kernel32.VirtualAllocEx(
                self.process_handle,
                preferred_start,
                size,
                0x1000,  # MEM_COMMIT, I don't see why you'd want any other type
                0x40,  # page_execute_readwrite, I also don't see any reason to have a different protection
            )

            if allocation == 0:
                raise ValueError(f"VirtualAllocEx failed for size {size}")

        return allocation

    # TODO: allow other free types
    def free_memory(self, address: int):
        with CheckWindowsOsError():
            # https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualfreeex
            success = ctypes.windll.kernel32.VirtualFreeEx(
                self.process_handle,
                ctypes.c_void_p(address),
                0,
                0x8000,  # MEM_RELEASE
            )

            if success == 0:
                raise ValueError(f"VirtualFreeEx failed for address {address}")

    def read_memory(self, address: int, size: int) -> bytes:
        with CheckWindowsOsError():
            buffer_type = ctypes.c_char * size
            byte_buffer = buffer_type()
            # https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory
            success = ctypes.windll.kernel32.ReadProcessMemory(
                self.process_handle,
                ctypes.c_void_p(address),
                ctypes.byref(byte_buffer),
                size,
                0,
            )

            if success == 0:
                raise ValueError(f"ReadProcessMemory failed for address {hex(address)} with size {size}")

        return byte_buffer.raw

    def write_memory(self, address: int, value: bytes):
        with CheckWindowsOsError():
            # https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory
            success = ctypes.windll.kernel32.WriteProcessMemory(
                self.process_handle,
                ctypes.c_void_p(address),
                value,
                len(value),
                0,
            )

            if success == 0:
                raise ValueError(f"WriteProcessMemory failed for address {hex(address)}")

    def scan_memory(
            self,
            pattern: regex.Pattern | bytes,
            *,
            module: Union[str, WindowsModuleInfo, bool, None] = None,
    ) -> list[int]:
        """
        Scan memory for a regex pattern

        Args:
            pattern: A regex.Pattern or a byte pattern
            module: Name of a module to exclusively search or a module to search for
            (True is shortcut for base module)

        Returns:
        A list of addresses that matched
        """
        region_start: int = 0

        # Finding information on this is quite the moment
        if self.process_64_bit:
            max_size = 0x7FFFFFFF0000
        else:
            max_size = 0x7FFF0000

        if module is not None:
            if module is True:
                module = self.get_modules(True)

            elif module is False:
                raise ValueError("module can only be True")

            elif isinstance(module, WindowsModuleInfo):
                pass

            else:
                module = self.get_module_named(module)

            region_start = module.lpBaseOfDll
            max_size = region_start + module.SizeOfImage

        matches: list[int] = []
        while region_start < max_size:
            region_info = self.virtual_query(region_start)
            region_start = region_info.BaseAddress + region_info.RegionSize

            # check for MEM_COMMIT
            if region_info.State != 0x1000:
                continue

            # TODO: is this actually faster than checking if the pages can be read
            try:
                region_data = self.read_memory(region_info.BaseAddress, region_info.RegionSize)
            except OSError:
                continue

            for match in regex.finditer(pattern, region_data, regex.DOTALL):
                # noinspection PyUnresolvedReferences
                matches.append(region_info.BaseAddress + match.span()[0])

        return matches

    # note: platform dependent
    def virtual_query(self, address: int = 0) -> WindowsMemoryBasicInformation:
        """
        Get information about a memory region in the process

        see https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualqueryex for
        more information

        Args:
            address: The base address of the page region, passing 0 (the default)
            gives info on the first region.

        Returns:
        A WindowsMemoryBasicInformation about the region
        """
        with CheckWindowsOsError():
            memory_basic_information = WindowsMemoryBasicInformation()

            # https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualqueryex
            returned_bytes = ctypes.windll.kernel32.VirtualQueryEx(
                self.process_handle,
                ctypes.c_void_p(address),
                ctypes.byref(memory_basic_information),
                ctypes.sizeof(memory_basic_information),
            )

            # 0 returned bytes = failure
            if returned_bytes == 0:
                raise ValueError(f"VirtualQueryEx failed for address {address}")

        return memory_basic_information

    @typing.overload
    def get_modules(self, base_only: typing.Literal[False] = False) -> list[WindowsModuleInfo]: ...

    @typing.overload
    def get_modules(self, base_only: typing.Literal[True]) -> WindowsModuleInfo: ...

    # TODO: check if you actually can't get modules on linux
    # note: platform dependent
    def get_modules(self, base_only: bool = False) -> list[WindowsModuleInfo] | WindowsModuleInfo:
        # TODO: for some reason EnumProcessModulesEx always sets LastError?
        # with CheckWindowsOsError():
        # TODO: is it always the psapi dll? check requirments section
        # https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-enumprocessmodulesex
        lpcb_needed = ctypes.wintypes.DWORD()

        success = ctypes.windll.psapi.EnumProcessModulesEx(
            self.process_handle,
            0,
            0,
            ctypes.byref(lpcb_needed),
            0x3,
        )

        if success == 0:
            raise RuntimeError("EnumProcessModulesEx (get size) failed")

        # with CheckWindowsOsError():
        module_handles_type = ctypes.wintypes.HMODULE * (
                lpcb_needed.value // ctypes.sizeof(ctypes.wintypes.HMODULE)
        )
        module_handles = module_handles_type()

        success = ctypes.windll.psapi.EnumProcessModulesEx(
            self.process_handle,
            ctypes.byref(module_handles),
            lpcb_needed,
            ctypes.byref(ctypes.wintypes.DWORD()),
            0x3,
        )

        if success == 0:
            raise RuntimeError("EnumProcessModulesEx failed")

        with CheckWindowsOsError():
            modules = []
            for module_handle in module_handles:
                # https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getmoduleinformation
                module_info = WindowsModuleInfo()

                success = ctypes.windll.psapi.GetModuleInformation(
                    self.process_handle,
                    ctypes.wintypes.HMODULE(module_handle),
                    ctypes.byref(module_info),
                    ctypes.sizeof(module_info),
                )

                if success == 0:
                    raise ValueError(f"GetModuleInformation failed for handle {module_handle}")

                if base_only:
                    return module_info

                modules.append(module_info)

        return modules

    def get_module_name(self, module: WindowsModuleInfo) -> str:
        with CheckWindowsOsError():
            # https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getmodulebasenamew
            # I just assume MAX_PATH is good enough
            name_buffer = ctypes.create_unicode_buffer(ctypes.wintypes.MAX_PATH)

            success = ctypes.windll.psapi.GetModuleBaseNameW(
                self.process_handle,
                ctypes.c_void_p(module.lpBaseOfDll),
                ctypes.byref(name_buffer),
                ctypes.wintypes.MAX_PATH,
            )

            if success == 0:
                raise ValueError(f"GetModuleBaseNameW failed for {module}")

        return name_buffer.value

    def get_module_named(self, name: str) -> WindowsModuleInfo:
        for module in self.get_modules():
            if self.get_module_name(module) == name:
                return module

        raise ValueError(f"No modules named {name}")
