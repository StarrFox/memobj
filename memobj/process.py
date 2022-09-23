import ctypes
from typing import Self


class Process:
    """A connected process"""

    @classmethod
    def from_name(cls) -> Self:
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
            # https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-formatmessage
            buffer = ctypes.create_unicode_buffer(500)
            ctypes.windll.kernel32.FormatMessageW(
                0x1000 | 0x200,
                0,
                last_error,
                0,
                ctypes.byref(buffer),
                500,
            )
            error_message = buffer.value.strip("\r\n")
            raise OSError(last_error, error_message)


class WindowsProcess(Process):
    def __init__(self, process_handle: int):
        self.process_handle = process_handle

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
                raise RuntimeError("LookupPriviledgeValue failed")

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
    def from_name(cls) -> Self:
        pass

    @classmethod
    def from_id(cls, pid: int, *, require_debug: bool = True) -> Self:
        try:
            cls._get_debug_privileges()
        except OSError as error:
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


if __name__ == "__main__":
    process = WindowsProcess.from_id(980, require_debug=True)
