from __future__ import annotations

import ctypes
import ctypes.util
import functools
import os
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Self

import regex

from memobj.process.base import Process
from memobj.process.linux.module import LinuxModule

_libc_name = ctypes.util.find_library("c")
_libc = ctypes.CDLL(_libc_name, use_errno=True) if _libc_name else None

_PROT_READ = 0x1
_PROT_WRITE = 0x2
_PROT_EXEC = 0x4
_MAP_PRIVATE = 0x2
_MAP_ANONYMOUS = 0x20
_MAP_FAILED: int = ctypes.c_size_t(-1).value

_PTRACE_PEEKTEXT = 1
_PTRACE_POKETEXT = 4
_PTRACE_CONT = 7
_PTRACE_GETREGS = 12
_PTRACE_SETREGS = 13
_PTRACE_ATTACH = 16
_PTRACE_DETACH = 17

_RTLD_NOW = 2
_MMAP_SYSCALL = 9
_MUNMAP_SYSCALL = 11
_MAP_FIXED_NOREPLACE = 0x100000


class _UserRegsStruct(ctypes.Structure):
    _fields_ = [
        ("r15", ctypes.c_ulonglong),
        ("r14", ctypes.c_ulonglong),
        ("r13", ctypes.c_ulonglong),
        ("r12", ctypes.c_ulonglong),
        ("rbp", ctypes.c_ulonglong),
        ("rbx", ctypes.c_ulonglong),
        ("r11", ctypes.c_ulonglong),
        ("r10", ctypes.c_ulonglong),
        ("r9", ctypes.c_ulonglong),
        ("r8", ctypes.c_ulonglong),
        ("rax", ctypes.c_ulonglong),
        ("rcx", ctypes.c_ulonglong),
        ("rdx", ctypes.c_ulonglong),
        ("rsi", ctypes.c_ulonglong),
        ("rdi", ctypes.c_ulonglong),
        ("orig_rax", ctypes.c_ulonglong),
        ("rip", ctypes.c_ulonglong),
        ("cs", ctypes.c_ulonglong),
        ("eflags", ctypes.c_ulonglong),
        ("rsp", ctypes.c_ulonglong),
        ("ss", ctypes.c_ulonglong),
        ("fs_base", ctypes.c_ulonglong),
        ("gs_base", ctypes.c_ulonglong),
        ("ds", ctypes.c_ulonglong),
        ("es", ctypes.c_ulonglong),
        ("fs", ctypes.c_ulonglong),
        ("gs", ctypes.c_ulonglong),
    ]


@dataclass
class LinuxMemoryRegion:
    """Memory region info from /proc/{pid}/maps (Linux analogue of MEMORY_BASIC_INFORMATION)."""

    base_address: int
    size: int
    permissions: str
    offset: int
    device: str
    inode: int
    pathname: str

    @property
    def readable(self) -> bool:
        return "r" in self.permissions

    @property
    def writable(self) -> bool:
        return "w" in self.permissions

    @property
    def executable(self) -> bool:
        return "x" in self.permissions


def _ptrace(request: int, pid: int, addr: int = 0, data: int = 0) -> int:
    """Low-level ptrace call. Raises OSError on failure (except PEEK which needs special handling)."""
    assert _libc is not None
    _libc.ptrace.restype = ctypes.c_long
    _libc.ptrace.argtypes = [
        ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong
    ]
    result = _libc.ptrace(request, pid, addr, data)
    return int(result)


def _ptrace_peek(pid: int, addr: int) -> int:
    """Peek a word from target process memory. Returns unsigned 64-bit value."""
    assert _libc is not None
    ctypes.set_errno(0)
    _libc.ptrace.restype = ctypes.c_long
    _libc.ptrace.argtypes = [
        ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong
    ]
    result = _libc.ptrace(_PTRACE_PEEKTEXT, pid, addr, 0)
    err = ctypes.get_errno()
    if result == -1 and err:
        raise OSError(err, os.strerror(err), f"PTRACE_PEEKTEXT at {hex(addr)}")
    return result & 0xFFFFFFFF_FFFFFFFF


def _ptrace_poke(pid: int, addr: int, word: int) -> None:
    """Poke a word into target process memory."""
    ret = _ptrace(_PTRACE_POKETEXT, pid, addr, word)
    if ret != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err), f"PTRACE_POKETEXT at {hex(addr)}")


def _peek_bytes(pid: int, addr: int, n_bytes: int) -> bytes:
    n_words = (n_bytes + 7) // 8
    result = bytearray()
    for i in range(n_words):
        result.extend(struct.pack("<Q", _ptrace_peek(pid, addr + i * 8)))
    return bytes(result[:n_bytes])


def _poke_bytes(pid: int, addr: int, data: bytes) -> None:
    n = len(data)
    full_words, remainder = divmod(n, 8)
    for i in range(full_words):
        word = struct.unpack("<Q", data[i * 8:(i + 1) * 8])[0]
        _ptrace_poke(pid, addr + i * 8, word)
    if remainder:
        off = full_words * 8
        existing = _ptrace_peek(pid, addr + off)
        merged = bytearray(struct.pack("<Q", existing))
        for j in range(remainder):
            merged[j] = data[off + j]
        _ptrace_poke(pid, addr + off, struct.unpack("<Q", bytes(merged))[0])


class LinuxProcess(Process):
    def __init__(self, pid: int):
        self._pid = pid
        self._allocations: dict[int, int] = {}  # address -> size

    @functools.cached_property
    def process_id(self) -> int:
        return self._pid

    @functools.cached_property
    def process_64_bit(self) -> bool:
        # ELF header byte 4 (EI_CLASS): 1=ELFCLASS32, 2=ELFCLASS64
        with open(self.executable_path, "rb") as f:
            header = f.read(5)
        if len(header) < 5 or header[:4] != b"\x7fELF":
            raise ValueError(f"Not an ELF binary: {self.executable_path}")
        return header[4] == 2

    @functools.cached_property
    def executable_path(self) -> Path:
        return Path(os.readlink(f"/proc/{self._pid}/exe"))

    @classmethod
    def from_name(cls, name: str, *, ignore_case: bool = True) -> Self:
        """
        Open a process by name, searching ``/proc/<pid>/comm``.

        Args:
            name: The process comm name to search for
            ignore_case: Whether to do case-insensitive matching

        Returns:
            The first matching LinuxProcess
        """
        if ignore_case:
            name = name.lower()

        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            try:
                comm = (entry / "comm").read_text().strip()
                if ignore_case:
                    comm = comm.lower()
                if comm == name:
                    return cls(int(entry.name))
            except (PermissionError, FileNotFoundError, ProcessLookupError):
                continue

        raise ValueError(f"No process found named {name!r}")

    @classmethod
    def from_id(cls, pid: int) -> Self:
        """
        Open a process by PID.

        Args:
            pid: The process ID

        Returns:
            A LinuxProcess for the given PID
        """
        if not Path(f"/proc/{pid}").exists():
            raise ValueError(f"No process with pid {pid}")
        return cls(pid)

    def _ptrace_exec(self, shellcode: bytes, *, stack_data: bytes | None = None) -> int:
        """
        Execute shellcode in the target process via ptrace.

        Attaches to the target, saves CPU state, writes shellcode to an
        executable region (restoring it after), executes until int3, and
        returns the value of RAX. If stack_data is provided it is written
        below the current RSP and its address is passed as the first
        argument (RDI) via the shellcode's built-in setup.

        The caller is responsible for building shellcode that ends with
        ``\\xCC`` (int3).
        """
        # Attach and stop the target
        ret = _ptrace(_PTRACE_ATTACH, self._pid)
        if ret < 0:
            err = ctypes.get_errno()
            raise OSError(err, os.strerror(err), "PTRACE_ATTACH failed")
        os.waitpid(self._pid, 0)

        try:
            regs = _UserRegsStruct()
            _ptrace(_PTRACE_GETREGS, self._pid, 0, ctypes.addressof(regs))

            # Optionally write stack_data below RSP (red zone + buffer)
            if stack_data is not None:
                stack_addr = (regs.rsp - 512 - len(stack_data)) & ~0xF
                _poke_bytes(self._pid, stack_addr, stack_data)

            # Find an executable region large enough for the shellcode
            exec_addr: int | None = None
            for start, end, perms, _off, _dev, _ino, _path in self._iter_maps():
                if "x" in perms and (end - start) >= len(shellcode) + 8:
                    exec_addr = start
                    break

            if exec_addr is None:
                raise RuntimeError("No executable region found in target process")

            # Save the original bytes and install shellcode
            orig_code = _peek_bytes(self._pid, exec_addr, len(shellcode))
            _poke_bytes(self._pid, exec_addr, shellcode)

            # Redirect execution to our shellcode; suppress any pending syscall
            # restart so the kernel honours our new RIP rather than re-entering
            # the interrupted syscall (e.g. nanosleep with ERESTART_RESTARTBLOCK).
            new_regs = _UserRegsStruct.from_buffer_copy(bytearray(regs))
            new_regs.rip = exec_addr
            new_regs.orig_rax = 0xFFFFFFFF_FFFFFFFF
            _ptrace(_PTRACE_SETREGS, self._pid, 0, ctypes.addressof(new_regs))

            # Run until int3 (SIGTRAP / signal 5)
            import signal as _signal
            _ptrace(_PTRACE_CONT, self._pid, 0, 0)
            _, wstatus = os.waitpid(self._pid, 0)

            if not os.WIFSTOPPED(wstatus) or os.WSTOPSIG(wstatus) != _signal.SIGTRAP:
                sig = os.WSTOPSIG(wstatus) if os.WIFSTOPPED(wstatus) else -1
                raise RuntimeError(
                    f"ptrace shellcode did not hit int3 (got signal {sig})"
                )

            # Read result from RAX
            result_regs = _UserRegsStruct()
            _ptrace(_PTRACE_GETREGS, self._pid, 0, ctypes.addressof(result_regs))
            rax = result_regs.rax

        finally:
            # Always restore original code and registers before detaching
            try:
                _poke_bytes(self._pid, exec_addr, orig_code)
                _ptrace(_PTRACE_SETREGS, self._pid, 0, ctypes.addressof(regs))
            except Exception:
                pass
            _ptrace(_PTRACE_DETACH, self._pid, 0, 0)

        return rax

    def _find_remote_dlopen(self) -> int:
        """
        Return the virtual address of ``dlopen`` in the target process.

        Finds libc (or libdl) in the target's maps, then uses ``nm -D`` to
        look up dlopen's load-relative offset in that library file and adds it
        to the library's runtime base address.  This works even when Python
        and the target binary link against different builds of the same library
        (e.g. different Nix store paths for the same glibc version).
        """
        import subprocess
        import time

        # Find libc or libdl in the target's maps.  Prefer libdl.so when present
        # (older glibc keeps dlopen there); otherwise fall back to libc.so.
        # Retry briefly to handle the window between process start and libc load.
        target_lib_path: str | None = None
        target_lib_base: int | None = None

        for _attempt in range(20):
            for start, _end, _perms, file_offset, _dev, _inode, pathname in self._iter_maps():
                if not pathname or pathname.startswith("["):
                    continue
                basename = Path(pathname).name
                if file_offset != 0:
                    continue
                if basename.startswith("libdl.so"):
                    target_lib_path = pathname
                    target_lib_base = start
                    break
                if basename == "libc.so.6" and target_lib_path is None:
                    target_lib_path = pathname
                    target_lib_base = start
            if target_lib_path is not None:
                break
            time.sleep(0.05)

        if target_lib_path is None or target_lib_base is None:
            raise RuntimeError(
                f"Could not find libc/libdl in target process {self._pid} maps"
            )

        # Use nm to get dlopen's load-relative offset from the library file.
        # nm -P format: "name type value size" (value is hex, no "0x" prefix).
        # Symbol names may have version suffixes like "dlopen@GLIBC_2.34".
        result = subprocess.run(
            ["nm", "-D", "--defined-only", "-P", target_lib_path],
            capture_output=True,
            text=True,
            check=False,
        )

        dlopen_offset: int | None = None
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) < 3:
                continue
            sym_name = parts[0].split("@")[0]  # strip version suffix
            if sym_name == "dlopen":
                try:
                    dlopen_offset = int(parts[2], 16)
                    break
                except ValueError:
                    continue

        if dlopen_offset is None:
            raise RuntimeError(
                f"Could not find dlopen symbol in {target_lib_path}. "
                "Is libdl/libc present with exported dynamic symbols?"
            )

        return target_lib_base + dlopen_offset

    def inject_so(self, path: Path) -> bool:
        """
        Inject a shared library into this process via ptrace.

        Uses ptrace to temporarily hijack the target process, writes the
        .so path onto its stack, then calls ``dlopen(path, RTLD_NOW)``.
        Requires the caller to be the parent of the target (or have
        CAP_SYS_PTRACE) and the process to be 64-bit x86.

        Args:
            path: Absolute path to the ``.so`` file to inject

        Returns:
            True if dlopen returned a non-NULL handle
        """
        path_bytes = str(path.resolve()).encode() + b"\x00"
        dlopen_addr = self._find_remote_dlopen()

        # We write path_bytes via stack_data; its address on the stack is
        # (rsp - 512 - len(path_bytes)) & ~0xF — we need it in the shellcode.
        # Instead, we build a two-stage approach: first write path_bytes via
        # PTRACE_POKETEXT, then build a shellcode that knows that address.
        #
        # To keep it simple, we compute the path address inside _ptrace_exec:
        # stack_addr = (rsp - 512 - len(path_bytes)) & ~0xF
        # Since we know rsp after PTRACE_GETREGS, we need a two-pass approach.
        # We use a callback-style helper instead.

        # Do everything inline (cannot use _ptrace_exec directly because we
        # need rsp to compute path_addr before building the shellcode).
        ret = _ptrace(_PTRACE_ATTACH, self._pid)
        if ret < 0:
            err = ctypes.get_errno()
            raise OSError(err, os.strerror(err), "PTRACE_ATTACH failed")
        os.waitpid(self._pid, 0)

        exec_addr: int | None = None
        orig_code: bytes = b""
        regs = _UserRegsStruct()

        try:
            _ptrace(_PTRACE_GETREGS, self._pid, 0, ctypes.addressof(regs))

            # Write path string well below the current stack pointer.
            # dlopen's implementation chains many functions and can consume several
            # KB of stack — we need the path string to survive the entire call.
            # 4096 bytes of clearance is enough for any glibc version in practice.
            path_addr = (regs.rsp - 4096 - len(path_bytes)) & ~0xF
            _poke_bytes(self._pid, path_addr, path_bytes)

            # Build shellcode: align stack, call dlopen(path_addr, RTLD_NOW), int3.
            # x86-64 ABI requires RSP % 16 == 0 at the point of a CALL instruction
            # (before CALL pushes the 8-byte return address). We use AND to mask the
            # lower 4 bits without using a scratch register.
            shellcode = (
                b"\x48\x83\xE4\xF0" +                          # and rsp, ~15
                b"\x48\xBF" + struct.pack("<Q", path_addr) +   # mov rdi, path_addr
                b"\x48\xBE" + struct.pack("<Q", _RTLD_NOW) +   # mov rsi, RTLD_NOW
                b"\x48\xB8" + struct.pack("<Q", dlopen_addr) + # mov rax, dlopen_addr
                b"\xFF\xD0" +                                   # call rax
                b"\xCC"                                         # int3
            )

            # Find an executable region
            for start, end, perms, _off, _dev, _ino, _path in self._iter_maps():
                if "x" in perms and (end - start) >= len(shellcode) + 8:
                    exec_addr = start
                    break

            if exec_addr is None:
                raise RuntimeError("No executable region found in target process")

            orig_code = _peek_bytes(self._pid, exec_addr, len(shellcode))
            _poke_bytes(self._pid, exec_addr, shellcode)

            new_regs = _UserRegsStruct.from_buffer_copy(bytearray(regs))
            new_regs.rip = exec_addr
            # Prevent the kernel from restarting a pending syscall (e.g. nanosleep).
            # If orig_rax != -1 the kernel would restart the interrupted syscall
            # instead of jumping to our RIP when we call PTRACE_CONT.
            new_regs.orig_rax = 0xFFFFFFFF_FFFFFFFF
            _ptrace(_PTRACE_SETREGS, self._pid, 0, ctypes.addressof(new_regs))

            import signal as _signal
            _ptrace(_PTRACE_CONT, self._pid, 0, 0)
            _, wstatus = os.waitpid(self._pid, 0)

            if not os.WIFSTOPPED(wstatus) or os.WSTOPSIG(wstatus) != _signal.SIGTRAP:
                sig = os.WSTOPSIG(wstatus) if os.WIFSTOPPED(wstatus) else -1
                raise RuntimeError(
                    f"inject_so shellcode did not hit int3 (got signal {sig}); "
                    "dlopen likely crashed — check RSP alignment or .so path"
                )

            result_regs = _UserRegsStruct()
            _ptrace(_PTRACE_GETREGS, self._pid, 0, ctypes.addressof(result_regs))
            success = result_regs.rax != 0

        finally:
            if exec_addr is not None and orig_code:
                try:
                    _poke_bytes(self._pid, exec_addr, orig_code)
                except Exception:
                    pass
            try:
                _ptrace(_PTRACE_SETREGS, self._pid, 0, ctypes.addressof(regs))
            except Exception:
                pass
            _ptrace(_PTRACE_DETACH, self._pid, 0, 0)

        return success

    def _remote_mmap(self, size: int, *, preferred_start: int | None = None) -> int:
        """Allocate memory in the remote process by injecting a mmap syscall."""
        addr_arg = preferred_start if preferred_start is not None else 0
        flags = _MAP_PRIVATE | _MAP_ANONYMOUS
        prot = _PROT_READ | _PROT_WRITE | _PROT_EXEC

        # syscall calling convention: rax=num, rdi, rsi, rdx, r10, r8, r9
        # (4th syscall arg uses r10, not rcx)
        shellcode = (
            b"\x48\x83\xE4\xF0" +                                    # and rsp, ~15
            b"\x48\xBF" + struct.pack("<Q", addr_arg) +              # mov rdi, addr
            b"\x48\xBE" + struct.pack("<Q", size) +                  # mov rsi, size
            b"\x48\xBA" + struct.pack("<Q", prot) +                  # mov rdx, prot
            b"\x49\xBA" + struct.pack("<Q", flags) +                 # mov r10, flags
            b"\x49\xB8" + struct.pack("<Q", 0xFFFFFFFF_FFFFFFFF) +  # mov r8, -1 (fd)
            b"\x49\xB9" + struct.pack("<Q", 0) +                    # mov r9, 0 (offset)
            b"\x48\xC7\xC0" + struct.pack("<I", _MMAP_SYSCALL) +    # mov eax, 9
            b"\x0F\x05" +                                           # syscall
            b"\xCC"                                                  # int3
        )

        result = self._ptrace_exec(shellcode)
        if result == 0xFFFFFFFF_FFFFFFFF:
            raise OSError(f"remote mmap failed for size {size}")

        self._allocations[result] = size
        return result

    def _remote_mmap_near(self, size: int, near_addr: int) -> int:
        """Allocate rwx memory within ±2GB of near_addr using MAP_FIXED_NOREPLACE."""
        page_size = 0x1000
        aligned_size = (size + page_size - 1) & ~(page_size - 1)
        two_gb = 0x80000000

        lo = max(page_size, near_addr - two_gb)
        hi = min(0xFFFF_FFFF_FFFF_F000, near_addr + two_gb)

        # Collect sorted list of [start, end) occupied regions
        occupied: list[tuple[int, int]] = []
        with open(f"/proc/{self._pid}/maps") as f:
            for line in f:
                parts = line.split()
                if not parts:
                    continue
                start_s, end_s = parts[0].split("-")
                occupied.append((int(start_s, 16), int(end_s, 16)))
        occupied.sort()

        # Walk candidate addresses from near_addr outward, try gaps
        def _gaps():
            prev_end = 0
            for start, end in occupied:
                if prev_end < start:
                    gap_lo = max(prev_end, lo)
                    gap_hi = min(start, hi)
                    if gap_hi - gap_lo >= aligned_size:
                        yield gap_lo, gap_hi
                prev_end = max(prev_end, end)
            # After last region
            tail_lo = max(prev_end, lo)
            if hi - tail_lo >= aligned_size:
                yield tail_lo, hi

        # Sort gaps by distance from near_addr
        gaps = sorted(_gaps(), key=lambda g: min(abs(g[0] - near_addr), abs(g[1] - near_addr)))

        prot = _PROT_READ | _PROT_WRITE | _PROT_EXEC
        flags = _MAP_PRIVATE | _MAP_ANONYMOUS | _MAP_FIXED_NOREPLACE

        for gap_lo, gap_hi in gaps:
            # Try at the end of the gap closest to near_addr
            candidates = [gap_lo, gap_hi - aligned_size]
            for candidate in candidates:
                candidate = candidate & ~(page_size - 1)
                if candidate < gap_lo or candidate + aligned_size > gap_hi:
                    continue
                if not (lo <= candidate and candidate + aligned_size <= hi):
                    continue
                shellcode = (
                    b"\x48\x83\xE4\xF0" +
                    b"\x48\xBF" + struct.pack("<Q", candidate) +
                    b"\x48\xBE" + struct.pack("<Q", aligned_size) +
                    b"\x48\xBA" + struct.pack("<Q", prot) +
                    b"\x49\xBA" + struct.pack("<Q", flags) +
                    b"\x49\xB8" + struct.pack("<Q", 0xFFFFFFFF_FFFFFFFF) +
                    b"\x49\xB9" + struct.pack("<Q", 0) +
                    b"\x48\xC7\xC0" + struct.pack("<I", _MMAP_SYSCALL) +
                    b"\x0F\x05" +
                    b"\xCC"
                )
                result = self._ptrace_exec(shellcode)
                if result == candidate:
                    self._allocations[result] = aligned_size
                    return result
                if result != 0xFFFFFFFF_FFFFFFFF:
                    # Got an unexpected address — munmap and try next candidate
                    self._remote_munmap(result, aligned_size)

        raise OSError(f"Could not allocate {size} bytes within 2GB of {hex(near_addr)}")

    def _remote_munmap(self, address: int, size: int) -> None:
        """Free memory in the remote process by injecting a munmap syscall."""
        shellcode = (
            b"\x48\xBF" + struct.pack("<Q", address) +         # mov rdi, addr
            b"\x48\xBE" + struct.pack("<Q", size) +             # mov rsi, size
            b"\x48\xC7\xC0" + struct.pack("<I", _MUNMAP_SYSCALL) +  # mov eax, 11
            b"\x0F\x05" +                                       # syscall
            b"\xCC"                                             # int3
        )
        result = self._ptrace_exec(shellcode)
        if result != 0:
            raise OSError(f"remote munmap failed for {hex(address)}: returned {result}")

    def allocate_memory(self, size: int, *, preferred_start: int | None = None) -> int:
        if self._pid != os.getpid():
            if preferred_start is not None:
                return self._remote_mmap_near(size, preferred_start)
            return self._remote_mmap(size)

        assert _libc is not None
        _libc.mmap.restype = ctypes.c_size_t
        _libc.mmap.argtypes = [
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_long,
        ]
        addr = _libc.mmap(
            ctypes.c_void_p(preferred_start),
            size,
            _PROT_READ | _PROT_WRITE | _PROT_EXEC,
            _MAP_PRIVATE | _MAP_ANONYMOUS,
            -1,
            0,
        )
        if addr == _MAP_FAILED:
            errno_val = ctypes.get_errno()
            raise OSError(errno_val, os.strerror(errno_val), f"mmap failed for size {size}")
        self._allocations[addr] = size
        return addr

    def free_memory(self, address: int):
        size = self._allocations.pop(address, None)
        if size is None:
            raise ValueError(f"No tracked allocation at {hex(address)}")

        if self._pid != os.getpid():
            self._remote_munmap(address, size)
            return

        assert _libc is not None
        _libc.munmap.restype = ctypes.c_int
        _libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        result = _libc.munmap(ctypes.c_void_p(address), size)
        if result != 0:
            errno_val = ctypes.get_errno()
            raise OSError(errno_val, os.strerror(errno_val), f"munmap failed for {hex(address)}")

    def read_memory(self, address: int, size: int) -> bytes:
        fd = os.open(f"/proc/{self._pid}/mem", os.O_RDONLY)
        try:
            data = os.pread(fd, size, address)
        finally:
            os.close(fd)

        if len(data) != size:
            raise OSError(
                f"Short read at {hex(address)}: expected {size} bytes, got {len(data)}"
            )
        return data

    def write_memory(self, address: int, value: bytes):
        if self._pid == os.getpid():
            ctypes.memmove(address, value, len(value))
            return

        # Write by running shellcode inside the target process itself.
        # PTRACE_POKETEXT from the outside can be silently swallowed by
        # container runtimes (e.g. gVisor) for r-xp code pages; having the
        # process write to its own memory via mprotect+store always works.
        page_size = 0x1000
        page_addr = address & ~(page_size - 1)
        # Cover all pages touched by the write (handle page-crossing writes).
        last_page = (address + len(value) - 1) & ~(page_size - 1)
        mprotect_len = last_page - page_addr + page_size
        prot_rwx = _PROT_READ | _PROT_WRITE | _PROT_EXEC
        _MPROTECT_SYSCALL = 10

        shellcode = bytearray()
        shellcode += b"\x48\x83\xE4\xF0"                                      # and rsp, ~15
        # mprotect(page_addr, mprotect_len, PROT_READ|PROT_WRITE|PROT_EXEC)
        shellcode += b"\x48\xBF" + struct.pack("<Q", page_addr)               # mov rdi, page_addr
        shellcode += b"\x48\xBE" + struct.pack("<Q", mprotect_len)            # mov rsi, len
        shellcode += b"\x48\xBA" + struct.pack("<Q", prot_rwx)                # mov rdx, prot
        shellcode += b"\x48\xC7\xC0" + struct.pack("<I", _MPROTECT_SYSCALL)  # mov eax, 10
        shellcode += b"\x0F\x05"                                               # syscall
        # Write each byte: keep target address in RDI, increment as we go
        shellcode += b"\x48\xBF" + struct.pack("<Q", address)                 # mov rdi, address
        for i, byte in enumerate(value):
            if i == 0:
                shellcode += b"\xC6\x07" + bytes([byte])                      # mov byte [rdi], imm8
            else:
                shellcode += b"\x48\xFF\xC7"                                  # inc rdi
                shellcode += b"\xC6\x07" + bytes([byte])                      # mov byte [rdi], imm8
        shellcode += b"\xCC"                                                   # int3

        self._ptrace_exec(bytes(shellcode))

    def scan_memory(
        self,
        pattern: regex.Pattern[bytes] | bytes,
        *,
        module: str | LinuxModule | None = None,
    ) -> list[int]:
        if isinstance(pattern, bytes):
            compiled = regex.compile(regex.escape(pattern), regex.DOTALL)
        else:
            compiled = pattern

        module_name: str | None = None
        if module is not None:
            module_name = module if isinstance(module, str) else module.name

        matches: list[int] = []
        for start, end, perms, _, _, _, pathname in self._iter_maps():
            if "r" not in perms:
                continue

            if module_name is not None:
                region_basename = Path(pathname).name if pathname else ""
                if region_basename.lower() != module_name.lower():
                    continue

            try:
                data = self.read_memory(start, end - start)
            except OSError:
                continue

            for match in regex.finditer(compiled, data):
                matches.append(start + match.span()[0])

        return matches

    def _iter_maps(self):
        """Parse /proc/{pid}/maps, yielding (start, end, perms, offset, device, inode, pathname)."""
        with open(f"/proc/{self._pid}/maps") as f:
            for line in f:
                parts = line.split()
                if not parts:
                    continue
                addr_range = parts[0]
                perms = parts[1] if len(parts) > 1 else "----"
                offset = int(parts[2], 16) if len(parts) > 2 else 0
                device = parts[3] if len(parts) > 3 else "00:00"
                inode = int(parts[4]) if len(parts) > 4 else 0
                pathname = parts[5] if len(parts) > 5 else ""

                start_str, end_str = addr_range.split("-")
                yield int(start_str, 16), int(end_str, 16), perms, offset, device, inode, pathname

    # note: platform dependent
    def virtual_query(self, address: int = 0) -> LinuxMemoryRegion:
        """
        Get information about the memory region containing address.
        Linux equivalent of VirtualQueryEx on Windows.

        Args:
            address: An address within the region to query (default 0 gives the first region)

        Returns:
            LinuxMemoryRegion describing the region
        """
        for start, end, perms, offset, device, inode, pathname in self._iter_maps():
            if start <= address < end:
                return LinuxMemoryRegion(
                    base_address=start,
                    size=end - start,
                    permissions=perms,
                    offset=offset,
                    device=device,
                    inode=inode,
                    pathname=pathname,
                )
        raise ValueError(f"No memory region found at address {hex(address)}")

    # note: platform dependent
    def get_modules(self, base_only: bool = False) -> list[LinuxModule] | LinuxModule:
        """
        Get loaded modules from /proc/{pid}/maps.

        Args:
            base_only: If True, return only the main executable module

        Returns:
            List of LinuxModule, or a single LinuxModule if base_only=True
        """
        all_modules = LinuxModule.get_all_modules(self)

        if not base_only:
            return all_modules

        exe_path = str(self.executable_path)
        for module in all_modules:
            if module.executable_path == exe_path:
                return module

        raise ValueError(f"Base module not found for {exe_path}")

    # note: platform dependent
    def get_module_named(self, name: str, *, ignore_case: bool = True) -> LinuxModule:
        """
        Find a loaded module by filename.

        Args:
            name: The module filename (basename) to search for
            ignore_case: Whether to do case-insensitive matching

        Returns:
            The matching LinuxModule
        """
        return LinuxModule.from_name(self, name, ignore_case=ignore_case)
