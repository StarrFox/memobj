import inspect
from typing import TYPE_CHECKING, Optional, Any, Union


if TYPE_CHECKING:
    from memobj.object import MemoryObject
    from memobj.process import Process, WindowsProcess


class MemoryProperty(property):
    def __init__(self, offset: int | None):
        super().__init__(self._get_prelude, self._set_prelude)
        self.offset: int | None = offset
        self.memory_object: Optional["MemoryObject"] = None

    @property
    def process(self) -> Union["Process", "WindowsProcess"]:
        return self.memory_object.memobj_process

    def read_formatted_from_offset(self, format_string: str) -> tuple[Any] | Any:
        offset_address = self.memory_object.base_address + self.offset
        return self.memory_object.memobj_process.read_formatted(offset_address, format_string)

    def write_formatted_to_offset(self, format_string: str, value: tuple[Any] | Any):
        offset_address = self.memory_object.base_address + self.offset
        self.memory_object.memobj_process.write_formatted(offset_address, format_string, value)

    def _get_prelude(self, memory_object):
        self.memory_object = memory_object
        return self.from_memory()

    def _set_prelude(self, memory_object, value):
        self.memory_object = memory_object
        self.to_memory(value)

    def from_memory(self) -> Any:
        raise NotImplementedError()

    def to_memory(self, value: Any):
        raise NotImplementedError()


class ObjectPointer(MemoryProperty):
    def __init__(
            self,
            offset: int | None,
            object_type: Optional[Union[type["MemoryObject"], str]] = None,
            *,
            endianness: str = "little",
    ):
        super().__init__(offset)
        self.object_type = object_type
        self._endianness = endianness

    def _get_prelude(self, memory_object):
        self.memory_object = memory_object

        if isinstance(self.object_type, str):
            module = memory_object.__module__

            if __name__ == module:
                globals_ = globals()

            elif module == "__main__":
                globals_ = inspect.stack()[-1].frame.f_globals

            else:
                for frame_info in inspect.stack():
                    if frame_info.filename == module:
                        globals_ = frame_info.frame.f_globals
                        break
                else:
                    raise ValueError(f"Couldn't find frame for type {self.object_type}")

            typed_object_type = globals_.get(self.object_type)

            if typed_object_type is None:
                raise ValueError(f"{self.object_type} not found in scope of object")

            self.object_type = typed_object_type

        return self.from_memory()

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
