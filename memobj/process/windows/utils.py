import ctypes
import ctypes.wintypes
import enum


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


# https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-memory_basic_information
class WindowsMemoryBasicInformation(ctypes.Structure):
    # TODO: do they mean the debugger should use this type if it's 32 bit or if the process is?
    #  probably process based
    # just some casual trolling by windows
    # see https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-memory_basic_information#remarks
    if ctypes.sizeof(ctypes.c_void_p) == 8:
        _fields_ = [
            ("BaseAddress", ctypes.c_ulonglong),
            ("AllocationBase", ctypes.c_ulonglong),
            ("AllocationProtect", ctypes.wintypes.DWORD),
            ("_alignment1", ctypes.wintypes.DWORD),
            ("RegionSize", ctypes.c_ulonglong),
            ("State", ctypes.wintypes.DWORD),
            ("Protect", ctypes.wintypes.DWORD),
            ("Type", ctypes.wintypes.DWORD),
            ("_alignment2", ctypes.wintypes.DWORD),
        ]
    else:
        _fields_ = [
            ("BaseAddress", ctypes.wintypes.DWORD),
            ("AllocationBase", ctypes.wintypes.DWORD),
            ("AllocationProtect", ctypes.wintypes.DWORD),
            ("RegionSize", ctypes.wintypes.DWORD),
            ("State", ctypes.wintypes.DWORD),
            ("Protect", ctypes.wintypes.DWORD),
            ("Type", ctypes.wintypes.DWORD),
        ]


# TODO: wrap this into a common type for linux and windows
# https://learn.microsoft.com/en-us/windows/win32/api/psapi/ns-psapi-moduleinfo
class WindowsModuleInfo(ctypes.Structure):
    _fields_ = [
        ("lpBaseOfDll", ctypes.wintypes.LPVOID),
        ("SizeOfImage", ctypes.wintypes.DWORD),
        ("EntryPoint", ctypes.wintypes.LPVOID),
    ]


# https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants
class WindowsMemoryProtection(enum.IntFlag):
    # note: can't read
    PAGE_NOACCESS = 0x1
    # note: can't write
    PAGE_READONLY = 0x2
    PAGE_READWRITE = 0x4
    # note: wacky on write
    PAGE_WRITECOPY = 0x8
    # note: can't write, can't read
    PAGE_EXECUTE = 0x10
    # note: can't write
    PAGE_EXECUTE_READ = 0x20
    PAGE_EXECUTE_READWRITE = 0x40
    # note: does wacky stuff on write
    PAGE_EXECUTE_WRITECOPY = 0x80
    # note: can't read
    PAGE_GUARD = 0x100
    # note: what does non-cachable mean
    PAGE_NOCACHE = 0x200
    # note: what is this
    PAGE_WRITECOMBINE = 0x400
    # note: what if CFG info
    PAGE_TARGETS_INVALID = 0x40000000
    PAGE_TARGETS_NO_UPDATE = 0x40000000


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
