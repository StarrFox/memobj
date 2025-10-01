import ctypes
import functools
import platform
import struct
from pathlib import Path
from typing import Any, Self, assert_never

import regex

from memobj.utils import ProcessEndianness, Type


class Process:
    """A connected process"""

    @functools.cached_property
    def process_id(self) -> int:
        """
        The process id
        """
        raise NotImplementedError()

    @functools.cached_property
    def process_64_bit(self) -> bool:
        """
        If this process is 64 bit
        """
        raise NotImplementedError()

    @functools.cached_property
    def python_64_bit(self) -> bool:
        """
        If the current python is 64 bit
        """
        # we can just check the pointer size; 4 = 32, 8 = 64
        return ctypes.sizeof(ctypes.c_void_p) == 8

    @functools.cached_property
    def system_64_bit(self) -> bool:
        """
        If the system is 64 bit
        """
        return platform.architecture()[0] == "64bit"

    @functools.cached_property
    def executable_path(self) -> Path:
        """
        Path to the process's executable
        """
        raise NotImplementedError()

    @functools.cached_property
    def pointer_format_string(self) -> str:
        if self.process_64_bit:
            return "Q"
        else:
            return "I"

    @functools.cached_property
    def pointer_size(self) -> int:
        if self.process_64_bit:
            return 8
        else:
            return 4

    @classmethod
    def from_name(cls, name: str) -> Self:
        """
        Open a process by name

        Args:
            name: The name of the process to open

        Returns:
        The opened process
        """
        raise NotImplementedError()

    @classmethod
    def from_id(cls, pid: int) -> Self:
        """
        Open a process by id

        Args:
            pid: The id of the process to open

        Returns:
        The opened process
        """
        raise NotImplementedError()

    # TODO
    # def itererate_modules(self): ...

    def allocate_memory(self, size: int) -> int:
        """
        Allocate <size> amount of memory in the process

        Args:
            size: The amount of memory to allocate

        Returns:
        The start address of the allocated memory
        """
        raise NotImplementedError()

    def free_memory(self, address: int):
        """
        Free some memory in the process

        Args:
            address: The start address of the area to free
        """
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

    def scan_memory(
        self, pattern: regex.Pattern[bytes] | bytes, *, module: str | None = None
    ) -> list[int]:
        """
        Scan memory for a regex pattern

        Args:
            pattern: A regex.Pattern[bytes] or a byte pattern
            module: Name of a module to exclusively search

        Returns:
        A list of addresses that matched
        """
        raise NotImplementedError()

    def scan_one(
        self, pattern: regex.Pattern[bytes] | bytes, *, module: str | None = None
    ) -> int:
        """
        Scan memory for a regex pattern and error if one address was not found

        Args:
            pattern: A regex.Pattern[bytes] or a byte pattern
            module: Name of a module to exclusively search

        Returns:
        Address found
        """
        results = self.scan_memory(pattern, module=module)

        if result_len := len(results) == 0:
            raise ValueError(f"No matches found for pattern {pattern!r}")

        elif result_len > 1:
            raise ValueError(f"Multiple matches found for pattern {pattern!r}")

        return results[0]

    def read_formatted(self, address: int, format_string: str) -> tuple[Any] | Any:
        """
        Read formatted bytes from memory, format_string is passed directly to struct.unpack

        Args:
            address: The address to read from
            format_string: The format string to pass to struct.unpack

        Returns:
        The formatted data (the corresponding python type/tuple of)
        """
        raw_data = self.read_memory(address, struct.calcsize(format_string))

        # struct.unpack is actually faster than int.from_data for some reason
        formatted = struct.unpack(format_string, raw_data)

        if len(formatted) == 1:
            return formatted[0]

        return formatted

    def read_typed(
        self,
        address: int,
        read_type: Type,
        *,
        endianness: ProcessEndianness = ProcessEndianness.native,
    ) -> Any:
        """
        Read a single typed value from memory using utils.Type and optional endianness

        Args:
            address: The address to read from
            read_type: The Type enumeration indicating the value to read (e.g., Type.s4)
            endianness: The endianness to use when reading (defaults to native "=")

        Returns:
            The formatted value as the corresponding Python type
        """
        match endianness:
            case ProcessEndianness.native:
                endianness_string = "="
            case ProcessEndianness.little:
                endianness_string = "<"
            case ProcessEndianness.big:
                endianness_string = ">"
            case _:
                assert_never(endianness)

        combined_format = endianness_string + read_type.value  # type: ignore (it doesn't believe me about exhaustiveness)

        return self.read_formatted(address, combined_format)

    def write_formatted(
        self, address: int, format_string: str, value: tuple[Any] | Any
    ):
        """
        Write formatted bytes to memory, format_string is passed directly to struct.pack

        Args:
            address: The address to write to
            format_string: The format string to pass to struct.pack
            value: The data to pass to struct.pack
        """
        packed_data = struct.pack(format_string, value)
        self.write_memory(address, packed_data)

    def write_typed(
        self,
        address: int,
        write_type: Type,
        value: Any,
        *,
        endianness: ProcessEndianness = ProcessEndianness.native,
    ) -> None:
        match endianness:
            case ProcessEndianness.native:
                endianness_string = "="
            case ProcessEndianness.little:
                endianness_string = "<"
            case ProcessEndianness.big:
                endianness_string = ">"
            case _:
                assert_never(endianness)

        combined_format = endianness_string + write_type.value

        return self.write_formatted(address, combined_format, value)

    # TODO: scan_formatted? scan_formatted(format_string, value)
