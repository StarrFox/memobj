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

    @property
    def pointer_format_string(self) -> str:
        return self.memory_object.memobj_process.pointer_format_string

    @property
    def pointer_size(self) -> int:
        return self.memory_object.memobj_process.pointer_size

    def read_formatted_from_offset(self, format_string: str) -> tuple[Any] | Any:
        offset_address = self.memory_object.base_address + self.offset
        return self.memory_object.memobj_process.read_formatted(offset_address, format_string)

    def write_formatted_to_offset(self, format_string: str, value: tuple[Any] | Any):
        offset_address = self.memory_object.base_address + self.offset
        self.memory_object.memobj_process.write_formatted(offset_address, format_string, value)

    def _get_prelude(self, preluder: "MemoryObject"):
        self.memory_object = preluder
        return self.from_memory()

    def _set_prelude(self, preluder: "MemoryObject", value):
        self.memory_object = preluder
        self.to_memory(value)

    def from_memory(self) -> Any:
        raise NotImplementedError()

    def to_memory(self, value: Any):
        raise NotImplementedError()

    def memory_size(self) -> int:
        raise NotImplementedError()
