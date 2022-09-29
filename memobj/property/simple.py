import struct
from typing import Any

from . import MemoryProperty


class SimpleData(MemoryProperty):
    format_string: str = None

    def __init__(self, offset: int | None = None, format_string: str = None):
        super().__init__(offset)
        if format_string is not None:
            self.format_string = format_string

    def from_memory(self) -> Any:
        return self.read_formatted_from_offset(self.format_string)

    def to_memory(self, value: Any):
        self.write_formatted_to_offset(self.format_string, value)

    def memory_size(self) -> int:
        return struct.calcsize(self.format_string)


class Bool(SimpleData):
    format_string = "?"


class Float(SimpleData):
    format_string = "f"


class Double(SimpleData):
    format_string = "d"


class Signed1(SimpleData):
    format_string = "b"


class Unsigned1(SimpleData):
    format_string = "B"


class Signed2(SimpleData):
    format_string = "h"


class Unsigned2(SimpleData):
    format_string = "H"


class Signed4(SimpleData):
    format_string = "i"


class Unsigned4(SimpleData):
    format_string = "I"


class Signed8(SimpleData):
    format_string = "q"


class Unsigned8(SimpleData):
    format_string = "Q"
