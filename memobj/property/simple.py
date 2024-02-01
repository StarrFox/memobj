import struct
from typing import Any, Union

from . import MemoryProperty


class SimpleData(MemoryProperty):
    format_string: Union[str, None] = None

    def __init__(self, offset: int | None = None, format_string: Union[str, None] = None):
        super().__init__(offset)
        if format_string is not None:
            self.format_string = format_string

    def _get_format(self) -> str:
        if self.format_string is None:
            raise ValueError(f"None format_string for {self.__class__.__name__}")
        
        return self.format_string

    def from_memory(self) -> Any:
        return self.read_formatted_from_offset(self._get_format())

    def to_memory(self, value: Any):
        self.write_formatted_to_offset(self._get_format(), value)

    def memory_size(self) -> int:
        return struct.calcsize(self._get_format())


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
