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

    def _get_prelude(self, preluder: MemoryObject):
        self.memory_object = preluder
        return self.from_memory()

    def _set_prelude(self, preluder: MemoryObject, value):
        self.memory_object = preluder
        self.to_memory(value)

    def from_memory(self) -> Any:
        raise NotImplementedError()

    def to_memory(self, value: Any):
        raise NotImplementedError()

    def memory_size(self) -> int:
        raise NotImplementedError()


class Pointer(MemoryProperty):
    """
    name = Pointer(0x20, String(...))
    other_type = Pointer(0x20, "NameOfType")
    other_type2 = Pointer(0x20, OtherType())
    position = Pointer(0x30, SimpleData(format_string="fff"))
    """
    def __init__(self, offset: int | None, pointed_type: str | MemoryProperty | MemoryObject):
        super().__init__(offset)
        self.pointed_type = pointed_type

    def from_memory(self) -> Any:
        pointer = self.read_formatted_from_offset(self.pointer_format_string)

        if isinstance(self.pointed_type, MemoryObject):
            self.pointed_type._base_address = pointer
            self.pointed_type.memobj_process = self.memory_object.memobj_process
            return self.pointed_type

        elif isinstance(self.pointed_type, str):
            module = self.memory_object.__module__

            globals_ = None
            if __name__ == module:
                globals_ = globals()

            elif module == "__main__":
                globals_ = inspect.stack()[-1].frame.f_globals

            else:
                module_import = importlib.import_module(module)
                try:
                    typed_object_type = getattr(module_import, self.pointed_type)
                except AttributeError:
                    raise ValueError(f"{self.pointed_type} not found in scope of object")

            if globals_ is not None:
                typed_object_type = globals_.get(self.pointed_type)

                if typed_object_type is None:
                    raise ValueError(f"{self.pointed_type} not found in scope of object")

            # noinspection PyUnboundLocalVariable
            self.pointed_type = typed_object_type()

            self.pointed_type._base_address = pointer
            self.pointed_type.memobj_process = self.memory_object.memobj_process
            return self.pointed_type

        # MemoryProperty
        elif isinstance(self.pointed_type, MemoryProperty):
            # create a mock object at the address
            self.pointed_type.memory_object = MemoryObject(
                address=pointer,
                process=self.memory_object.memobj_process,
            )
            return self.pointed_type.from_memory()

    def to_memory(self, value: Any):
        pass

    def memory_size(self) -> int:
        return 8 if self.memory_object.memobj_process.process_64_bit else 4


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

    def memory_size(self) -> int:
        if self.pointer:
            return 8 if self.memory_object.memobj_process.process_64_bit else 4
        else:
            return self.max_size


class SimpleData(MemoryProperty):
    format_string: str = None

    def __init__(self, offset: int | None, format_string: str = None):
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
