import inspect
import importlib
import struct
from functools import cached_property
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

    @cached_property
    def pointer_format_string(self) -> str:
        if self.memory_object.memobj_process.process_64_bit:
            return "Q"
        else:
            return "I"

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

            globals_ = None
            if __name__ == module:
                globals_ = globals()

            elif module == "__main__":
                globals_ = inspect.stack()[-1].frame.f_globals

            else:
                module_import = importlib.import_module(module)
                try:
                    typed_object_type = getattr(module_import, self.object_type)
                except AttributeError:
                    raise ValueError(f"{self.object_type} not found in scope of object")

            if globals_ is not None:
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
        pointer = self.read_formatted_from_offset(self.endianness + self.pointer_format_string)

        if pointer == 0:
            return None

        if self.object_type is None:
            return type(self.memory_object)(pointer, self.memory_object.memobj_process)

        return self.object_type(pointer, self.memory_object.memobj_process)

    def to_memory(self, value: "MemoryObject"):
        self.write_formatted_to_offset(self.pointer_format_string, value.base_address)


class NullTerminatedString(MemoryProperty):
    def __init__(self, offset: int | None, max_size: int = 20, encoding: str = "utf-8", pointer: bool = False):
        super().__init__(offset)
        self.max_size = max_size
        self.encoding = encoding
        self.pointer = pointer

    def from_memory(self) -> Any:
        # TODO: add Pointer property i.e. name: str = Pointer(0x0, NullTerminatedString(...))
        if self.pointer:
            pointer = self.read_formatted_from_offset(self.pointer_format_string)
            string_bytes = self.memory_object.memobj_process.read_memory(
                pointer,
                self.max_size
            )
        else:
            string_bytes = self.memory_object.memobj_process.read_memory(
                self.memory_object.base_address + self.offset,
                self.max_size,
            )

        end = string_bytes.find(b"\x00")

        if end == 0:
            return ""

        if end == -1:
            raise ValueError("No null end")

        return string_bytes[:end].decode(self.encoding)

    def to_memory(self, value: str):
        value = value.encode(self.encoding) + b"\x00"

        if (value_len := len(value)) > self.max_size:
            raise ValueError(f"Value was {value_len} while the max size is {self.max_size}")

        if self.pointer:
            allocation = self.memory_object.memobj_process.allocate_memory(value_len)
            self.memory_object.memobj_process.write_memory(allocation, value)

            self.write_formatted_to_offset(self.pointer_format_string, allocation)

        else:
            self.memory_object.memobj_process.write_memory(
                self.memory_object.base_address + self.offset,
                value,
            )


class SimpleDataProperty(MemoryProperty):
    format_string: str = None

    def __init__(self, offset: int | None, *, endianness: str = "little", ignore_alignment: bool = False):
        if not ignore_alignment:
            size = struct.calcsize(self.format_string)
            if offset % size:
                raise ValueError(f"{offset} is not aligned with data size {size}")

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
