import ctypes
import functools
import platform
import struct
import typing
from pathlib import Path
from typing import Any, Self, Literal, TypeAlias

import regex

from memobj.utils import ProcessEndianess, TypeFormat


# TODO: switch to type statements when we drop 3.11 (TypeAlias is depreciated)
FormatStringInt: TypeAlias = Literal["b", "B", "h", "H", "i", "I", "l", "L", "q", "Q", "n", "N", "P"]
FormatStringFloat: TypeAlias = Literal["e", "f", "d"]
FormatStringBool: TypeAlias = Literal["?"]
FormatStringBytes: TypeAlias = Literal["c", "s", "p"]


# TODO: add non-keyword to args where needed (/)
class Process:
    """A connected process"""

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

    def scan_memory(self, pattern: regex.Pattern | bytes, *, module: str | None = None) -> list[int]:
        """
        Scan memory for a regex pattern

        Args:
            pattern: A regex.Pattern or a byte pattern
            module: Name of a module to exclusively search

        Returns:
        A list of addresses that matched
        """
        raise NotImplementedError()

    def scan_one(self, pattern: regex.Pattern | bytes, *, module: str | None = None) -> int:
        """
        Scan memory for a regex pattern and error if one address was not found

        Args:
            pattern: A regex.Pattern or a byte pattern
            module: Name of a module to exclusively search

        Returns:
        Address found
        """
        results = self.scan_memory(pattern, module=module)
        
        if result_len := len(results) == 0:
            raise ValueError(F"No matches found for pattern {pattern!r}")
        
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

    @typing.overload
    def read_formatted_single(
        self,
        address: int,
        format_string: FormatStringInt,
        *,
        endianess: ProcessEndianess = ProcessEndianess.native
    ) -> int: ...

    @typing.overload
    def read_formatted_single(
        self,
        address: int,
        format_string: FormatStringBool,
        *,
        endianess: ProcessEndianess = ProcessEndianess.native
    ) -> bool: ...

    @typing.overload
    def read_formatted_single(
        self,
        address: int,
        format_string: FormatStringBytes,
        *,
        endianess: ProcessEndianess = ProcessEndianess.native
    ) -> bytes: ...

    @typing.overload
    def read_formatted_single(
        self,
        address: int,
        format_string: FormatStringFloat,
        *,
        endianess: ProcessEndianess = ProcessEndianess.native
    ) -> float: ...

    # NOTE: the order of these matters (the any default needs to be last)
    @typing.overload
    def read_formatted_single(
        self,
        address: int,
        format_string: str,
        *,
        endianess: ProcessEndianess = ProcessEndianess.native
    ) -> Any: ...

    def read_formatted_single(
        self,
        address: int,
        format_string: str,
        *,
        # TODO: should the default be native?
        endianess: ProcessEndianess = ProcessEndianess.native
    ) -> Any:
        if len(format_string) != 1:
            raise ValueError(f"format_string should be a single character not {format_string}")

        # we don't just include endianess in the format string to make typing easier
        match endianess:
            case ProcessEndianess.native:
                endianess_string = "="
            case ProcessEndianess.little:
                endianess_string = "<"
            case ProcessEndianess.big:
                endianess_string = ">"

        combined_format = endianess_string + format_string
        
        return self.read_formatted(address, combined_format)

    def write_formatted(self, address: int, format_string: str, value: tuple[Any] | Any):
        """
        Write formatted bytes to memory, format_string is passed directly to struct.pack

        Args:
            address: The address to write to
            format_string: The format string to pass to struct.pack
            value: The data to pass to struct.pack
        """
        packed_data = struct.pack(format_string, value)
        self.write_memory(address, packed_data)

    @typing.overload
    def write_formatted_single(
        self,
        address: int,
        format_string: FormatStringInt,
        value: int,
        *,
        endianess: ProcessEndianess = ProcessEndianess.native,
    ) -> None: ...

    @typing.overload
    def write_formatted_single(
        self,
        address: int,
        format_string: FormatStringBool,
        value: bool,
        *,
        endianess: ProcessEndianess = ProcessEndianess.native,
    ) -> None: ...

    @typing.overload
    def write_formatted_single(
        self,
        address: int,
        format_string: FormatStringFloat,
        value: float,
        *,
        endianess: ProcessEndianess = ProcessEndianess.native,
    ) -> None: ...
    
    @typing.overload
    def write_formatted_single(
        self,
        address: int,
        format_string: FormatStringBytes,
        value: bytes,
        *,
        endianess: ProcessEndianess = ProcessEndianess.native,
    ) -> None: ...

    # TODO: this overrides the other impls into making value Any when we'd like it to error
    #  i.e. write_formatted_single(1, "?", 100) would be valid when it shouldn't be
    @typing.overload
    def write_formatted_single(
        self,
        address: int,
        format_string: str,
        value: Any,
        *,
        endianess: ProcessEndianess = ProcessEndianess.native,
    ) -> None: ...

    def write_formatted_single(
        self,
        address: int,
        format_string: str,
        value: Any,
        *,
        endianess: ProcessEndianess = ProcessEndianess.native,
    ) -> None:
        if len(format_string) != 1:
            raise ValueError(f"format_string should be a single character not {format_string}")

        # we don't just include endianess in the format string to make typing easier
        match endianess:
            case ProcessEndianess.native:
                endianess_string = "="
            case ProcessEndianess.little:
                endianess_string = "<"
            case ProcessEndianess.big:
                endianess_string = ">"

        combined_format = endianess_string + format_string

        return self.write_formatted(address, combined_format, value)

    # TODO: scan_formatted? scan_formatted(format_string, value)
