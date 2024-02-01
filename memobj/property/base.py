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
        assert self.memory_object is not None
        assert self.memory_object.memobj_process is not None
        return self.memory_object.memobj_process

    @property
    def offset_address(self) -> int:
        if self.offset is None:
            raise ValueError("Offset cannot be None")
        
        assert self.memory_object is not None
        return self.memory_object.base_address + self.offset

    @property
    def pointer_format_string(self) -> str:
        return self.process.pointer_format_string

    @property
    def pointer_size(self) -> int:
        return self.process.pointer_size

    def read_formatted_from_offset(self, format_string: str) -> tuple[Any] | Any:
        return self.process.read_formatted(self.offset_address, format_string)

    def write_formatted_to_offset(self, format_string: str, value: tuple[Any] | Any):
        self.process.write_formatted(self.offset_address, format_string, value)

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
