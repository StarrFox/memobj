import ctypes
import sys
from typing import Self


class Process:
    """A connected process"""

    @classmethod
    def from_name(cls, name: str) -> Self:
        raise NotImplementedError()

    @classmethod
    def from_id(cls, pid: int) -> Self:
        raise NotImplementedError()

    def read_memory(self, address: int, size: int) -> bytes:
        """
        Read bytes from memory

        Args:
            address: The address to read from
            size: The number of bytes to read

        Returns:
        The bytes read
        """
        raise NotImplementedError()

    def write_memory(self, address: int, value: bytes):
        """
        Write bytes to memory

        Args:
            address: The address to write to
            value: The bytes to write to that address
        """
        raise NotImplementedError()


class CheckWindowsOsError:
    def __enter__(self):
        # https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-setlasterror
        ctypes.windll.kernel32.SetLastError(0)

    # TODO: use an exceptiongroup here
    def __exit__(self, exc_type, exc_val, exc_tb):
        # https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-getlasterror
        last_error = ctypes.windll.kernel32.GetLastError()

        if last_error != 0:
            raise ctypes.WinError(last_error)


class WindowsProcess(Process):
    def __init__(self, process_handle: int):
        self.process_handle = process_handle

    # noinspection PyPep8Naming
    @staticmethod
    def _get_debug_privileges():
        import ctypes.wintypes

        # https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-luid
        class LUID(ctypes.Structure):
            _fields_ = [
                ("LowPart", ctypes.wintypes.DWORD),
                ("HighPart", ctypes.c_long),
            ]

        # https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-luid_and_attributes
        class LUID_AND_ATTRIBUTES(ctypes.Structure):
            _fields_ = [
                ("Luid", LUID),
                ("Attributes", ctypes.wintypes.DWORD),
            ]

        SingleLUIDAndAttributes = LUID_AND_ATTRIBUTES * 1

        # https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_privileges
        class TOKEN_PRIVILEGES(ctypes.Structure):
            _fields_ = [
                ("PrivilegeCount", ctypes.wintypes.DWORD),
                ("Privileges", SingleLUIDAndAttributes),  # we are only ever specifying one privilege
            ]

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

    @classmethod
    def from_name(cls, name: str, *, require_debug: bool = True) -> Self:
        import ctypes.wintypes

        # https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-processentry32
        class PROCESSENTRY32(ctypes.Structure):
            _fields_ = [
                ("dwSize", ctypes.wintypes.DWORD),
                ("cntUsage", ctypes.wintypes.DWORD),
                ("th32ProcessID", ctypes.wintypes.DWORD),
                ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
                ("th32ModuleID", ctypes.wintypes.DWORD),
                ("cntThreads", ctypes.wintypes.DWORD),
                ("th32ParentProcessID", ctypes.wintypes.DWORD),
                ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", ctypes.wintypes.DWORD),
                ("szExeFile", ctypes.c_char * ctypes.wintypes.MAX_PATH)
            ]

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
                raise ValueError(f"OpenProcess returned null with process id {pid}")

        return cls(process_handle)

    def read_memory(self, address: int, size: int) -> bytes:
        pass

    def write_memory(self, address: int, value: bytes):
        pass


def from_name(name: str) -> Process:
    match sys.platform:
        case "win32":
            return WindowsProcess.from_name(name)
        case "linux":
            raise NotImplementedError()
        case _:
            raise NotImplementedError(f"{sys.platform} has not been implemented")


# TODO: how to handle WindowsProcess's require_debug; *, windows_require_debug?
def from_id(pid: int) -> Process:
    match sys.platform:
        case "win32":
            return WindowsProcess.from_id(pid)
        case "linux":
            raise NotImplementedError()
        case _:
            raise NotImplementedError(f"{sys.platform} has not been implemented")


if __name__ == "__main__":
    process = WindowsProcess.from_name("Notepad.exe", require_debug=False)
