from typing import TYPE_CHECKING, Optional, Any


if TYPE_CHECKING:
    from memobj.object import MemoryObject


class MemoryProperty:
    def __init__(self, offset: int | None):
        self.offset: int | None = offset
        self.memory_object: Optional["MemoryObject"] = None

    def read_formatted_from_offset(self, format_string: str) -> tuple[Any] | Any:
        offset_address = self.memory_object.base_address + self.offset
        return self.memory_object.memobj_process.read_formatted(offset_address, format_string)

    def write_formatted_to_offset(self, format_string: str, value: tuple[Any] | Any):
        offset_address = self.memory_object.base_address + self.offset
        self.memory_object.memobj_process.write_formatted(offset_address, format_string, value)

    def from_memory(self) -> Any:
        raise NotImplementedError()

    def to_memory(self, value: Any):
        raise NotImplementedError()


class ObjectPointer(MemoryProperty):
    def __init__(
            self,
            offset: int | None,
            object_type: Optional[type["MemoryObject"]] = None,
            *,
            endianness: str = "little",
    ):
        super().__init__(offset)
        self.object_type = object_type
        self._endianness = endianness

    @property
    def endianness(self) -> str:
        if self._endianness == "little":
            return "<"

        return ">"

    def from_memory(self) -> Any:
        if self.memory_object.memobj_process.process_64_bit:
            format_string = "Q"
        else:
            format_string = "I"

        pointer = self.read_formatted_from_offset(self.endianness + format_string)

        if pointer == 0:
            return None

        if self.object_type is None:
            return type(self.memory_object)(pointer, self.memory_object.memobj_process)

        return self.object_type(pointer, self.memory_object.memobj_process)

    def to_memory(self, value: Any):
        raise NotImplementedError()


class SimpleDataProperty(MemoryProperty):
    format_string: str = None

    def __init__(self, offset: int | None, *, endianness: str = "little"):
        super().__init__(offset)
        self._endianness = endianness

    @property
    def endianness(self) -> str:
        if self._endianness == "little":
            return "<"

        return ">"

    def from_memory(self) -> Any:
        return self.read_formatted_from_offset(self.endianness + self.format_string)

    def to_memory(self, value: Any):
        self.write_formatted_to_offset(self.endianness + self.format_string, value)


class Bool(SimpleDataProperty):
    format_string = "?"


class Float(SimpleDataProperty):
    format_string = "f"


class Double(SimpleDataProperty):
    format_string = "d"


class Signed1(SimpleDataProperty):
    format_string = "b"


class Unsigned1(SimpleDataProperty):
    format_string = "B"


class Signed2(SimpleDataProperty):
    format_string = "h"


class Unsigned2(SimpleDataProperty):
    format_string = "H"


class Signed4(SimpleDataProperty):
    format_string = "i"


class Unsigned4(SimpleDataProperty):
    format_string = "I"


class Signed8(SimpleDataProperty):
    format_string = "q"


class Unsigned8(SimpleDataProperty):
    format_string = "Q"
