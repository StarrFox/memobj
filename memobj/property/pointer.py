from __future__ import annotations
from typing import TYPE_CHECKING, Any

from . import MemoryProperty

if TYPE_CHECKING:
    from memobj.object import MemoryObject


class Pointer(MemoryProperty):
    def __init__(
        self,
        offset: int | None,
        pointed_type: str | MemoryProperty | type[MemoryObject],
        *,
        detached: bool = True,
    ):
        super().__init__(offset)

        self._pointed_type = pointed_type
        self._detached = detached

    def _get_prelude(self, preluder: "MemoryObject"):
        self.memory_object = preluder
        return self

    def _set_prelude(self, preluder: "MemoryObject", value):
        self.memory_object = preluder
        self.to_memory(value)

    @staticmethod
    def is_null(addr: int) -> bool:
        return addr == 0

    def handle_null(self) -> Any:
        raise ValueError("null pointer cannot be dereferenced")

    def from_memory(self) -> Any:
        value = self.read_typed_from_offset(self.process.pointer_type)
        if self.is_null(value):
            return self.handle_null()
        
        return value

    def from_memory_deref(self) -> Any:
        # circular import bs
        from memobj import MemoryObject
        from memobj.object import MemoryObjectMeta

        if self._detached:
            address = self.from_memory()
            address_source = lambda: address
        else:
            address_source = self.from_memory

        if type(self._pointed_type) is MemoryObjectMeta:
            return self._pointed_type(address_source=address_source, process=self.process)

        elif isinstance(self._pointed_type, str):
            typed_object_type = MemoryObject._resolve_string_class_lookup(
                self._pointed_type
            )

            return typed_object_type(address_source=address_source, process=self.process)

        elif isinstance(self._pointed_type, Pointer):
            self._pointed_type.memory_object = MemoryObject(
                address_source=address_source,
                process=self.process,
            )
            return self._pointed_type

        elif isinstance(self._pointed_type, MemoryProperty):
            # create a mock object at the address
            self._pointed_type.memory_object = MemoryObject(
                address_source=address_source,
                process=self.process,
            )
            self._pointed_type.offset = 0

            return self._pointed_type.from_memory()

        else:
            raise TypeError(
                "pointed-to type is neither MemoryObject nor MemoryProperty"
            )

    def to_memory(self, value: Any):
        if not isinstance(value, int):
            raise TypeError("expected an integer address to write")

        self.write_formatted_to_offset(self.pointer_format_string, value)

    def memory_size(self) -> int:
        return self.pointer_size


class DereffedPointer(Pointer):
    def _get_prelude(self, preluder: "MemoryObject"):
        self.memory_object = preluder
        return self.from_memory_deref()

    def handle_null(self):
        return None
