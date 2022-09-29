from functools import cached_property
from typing import TYPE_CHECKING, Optional, Any, Union

from . import MemoryProperty

if TYPE_CHECKING:
    from memobj.object import MemoryObject


class Void(MemoryProperty):
    def from_memory(self) -> Any:
        raise TypeError("cannot read void from memory")

    def to_memory(self, _: Any):
        raise TypeError("cannot write void to memory")

    def memory_size(self) -> int:
        return 0


class Pointer(MemoryProperty):
    def __init__(self, offset: int | None, pointed_type: Union[str, MemoryProperty, "MemoryObject"]):
        super().__init__(offset)

        self._pointed_type = pointed_type

    @staticmethod
    def is_null(addr: int) -> bool:
        return addr == 0

    def cast(self, new_type: Union[MemoryProperty, "MemoryObject"]) -> "Pointer":
        # New pointer to same address but with changed type.
        return Pointer(self.offset, new_type)

    def from_memory(self) -> Any:
        return self.read_formatted_from_offset(self.pointer_format_string)

    def from_memory_deref(self) -> Any:
        addr = self.from_memory()
        if Pointer.is_null(addr):
            raise ValueError("null pointer cannot be dereferenced")

        if isinstance(self._pointed_type, MemoryObject):
            self._pointed_type._base_address = addr
            self._pointed_type.memobj_process = self.memory_object.memobj_process

            return self._pointed_type

        elif isinstance(self._pointed_type, MemoryProperty):
            # create a mock object at the address
            self._pointed_type.memory_object = MemoryObject(
                address=addr,
                process=self.memory_object.memobj_process,
            )
            self._pointed_type.offset = 0

            return self._pointed_type.from_memory()

        else:
            raise TypeError("pointed-to type is neither MemoryObject nor MemoryProperty")

    def to_memory(self, value: Any):
        if not isinstance(value, int):
            raise TypeError("expected an integer address to write")

        self.write_formatted_to_offset(self.pointer_format_string, value)

    def to_memory_deref(self, value: Any):
        addr = self.from_memory()
        if Pointer.is_null(addr):
            raise ValueError("null pointer cannot be dereferenced")

        if isinstance(self._pointed_type, MemoryObject):
            if not isinstance(value, type(self._pointed_type)):
                raise TypeError(f"{value!r} incompatible with {self._pointed_type!r}")

            self._pointed_type._base_address = addr
            self._pointed_type.memobj_process = self.memory_object.memobj_process

            for (dest, source) in zip(
                self._pointed_type.__memory_properties__.values(),
                value.__memory_properties__.values()
            ):
                dest = source

        elif isinstance(self._pointed_type, MemoryProperty):
            self._pointed_type.memory_object = MemoryObject(
                address=addr,
                process=self.memory_object.memobj_process,
            )
            self._pointed_type.offset = 0

            self._pointed_type.to_memory(value)

        else:
            raise TypeError("pointed-to type is neither MemoryObject nor MemoryProperty")

    def memory_size(self) -> int:
        return 8 if self.memory_object.memobj_process.process_64_bit else 4
