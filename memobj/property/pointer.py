from copy import copy
from typing import TYPE_CHECKING, Any, Union

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
    def __init__(
            self,
            offset: int | None,
            pointed_type: Union[str, MemoryProperty, "MemoryObject", type["MemoryObject"]]
    ):
        super().__init__(offset)

        self._pointed_type = pointed_type

    def _get_prelude(self, preluder: "MemoryObject"):
        self.memory_object = preluder
        return self

    def _set_prelude(self, preluder: "MemoryObject", value):
        self.memory_object = preluder
        self.to_memory_deref(value)

    @staticmethod
    def is_null(addr: int) -> bool:
        return addr == 0

    def handle_null(self):
        raise ValueError("null pointer cannot be dereferenced")

    def cast(self, new_type: Union[MemoryProperty, "MemoryObject"]) -> "Pointer":
        # New pointer to same address but with changed type.
        return Pointer(self.offset, new_type)

    def from_memory(self) -> Any:
        return self.read_formatted_from_offset(self.pointer_format_string)

    def from_memory_deref(self) -> Any:
        addr = self.from_memory()
        if self.is_null(addr):
            return self.handle_null()

        # circular import bs
        from memobj import MemoryObject
        from memobj.object import MemoryObjectMeta

        if isinstance(self._pointed_type, MemoryObject):
            # this is so returned instance isn't overwritten
            instance = copy(self._pointed_type)
            instance._base_address = addr
            instance.memobj_process = self.process

            return instance

        elif type(self._pointed_type) is MemoryObjectMeta:
            return self._pointed_type(address=addr, process=self.process)

        elif isinstance(self._pointed_type, str):
            # noinspection PyProtectedMember
            typed_object_type = MemoryObject._resolve_string_class_lookup(self._pointed_type)

            self._pointed_type = typed_object_type()

            self._pointed_type._base_address = addr
            self._pointed_type.memobj_process = self.process

            return self._pointed_type

        elif isinstance(self._pointed_type, Pointer):
            self._pointed_type.memory_object = MemoryObject(
                address=addr,
                process=self.process,
            )
            return self._pointed_type

        elif isinstance(self._pointed_type, MemoryProperty):
            # create a mock object at the address
            self._pointed_type.memory_object = MemoryObject(
                address=addr,
                process=self.process,
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
        if self.is_null(addr):
            raise ValueError("null pointer cannot be dereferenced")

        # circular import bs
        from memobj import MemoryObject
        from memobj.object import MemoryObjectMeta

        if isinstance(self._pointed_type, MemoryObject):
            if not isinstance(value, type(self._pointed_type)):
                raise TypeError(f"{value!r} incompatible with {self._pointed_type!r}")

            self._pointed_type._base_address = addr
            self._pointed_type.memobj_process = self.process

            for attribute_name in self._pointed_type.__memory_properties__.keys():
                setattr(self._pointed_type, attribute_name, getattr(value, attribute_name))

        # TODO: is there a better way to check for this
        elif type(self._pointed_type) is MemoryObjectMeta:
            instance = self._pointed_type(address=addr, process=self.process)

            for attribute_name in self._pointed_type.__memory_properties__.keys():
                setattr(self._pointed_type, attribute_name, getattr(value, attribute_name))

        elif isinstance(self._pointed_type, str):
            # noinspection PyProtectedMember
            typed_object_type = MemoryObject._resolve_string_class_lookup(self._pointed_type)

            self._pointed_type = typed_object_type

            instance = self._pointed_type(address=addr, process=self.process)

            for attribute_name in self._pointed_type.__memory_properties__.keys():
                setattr(instance, attribute_name, getattr(value, attribute_name))

        elif isinstance(self._pointed_type, MemoryProperty):
            self._pointed_type.memory_object = MemoryObject(
                address=addr,
                process=self.process,
            )
            self._pointed_type.offset = 0

            self._pointed_type.to_memory(value)

        else:
            raise TypeError("pointed-to type is neither MemoryObject nor MemoryProperty")

    def memory_size(self) -> int:
        return self.pointer_size


class DereffedPointer(Pointer):
    def _get_prelude(self, preluder: "MemoryObject"):
        self.memory_object = preluder
        return self.from_memory_deref()

    def _set_prelude(self, preluder: "MemoryObject", value):
        self.memory_object = preluder
        self.to_memory_deref(value)

    def handle_null(self):
        return None
