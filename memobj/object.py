from typing import TYPE_CHECKING, Union

from .property import MemoryProperty

if TYPE_CHECKING:
    from .process import Process, WindowsProcess


class MemoryObject:
    def __init__(self, base_address: int | None, process: Union["Process", "WindowsProcess"]):
        self._base_address = base_address
        self.memobj_process = process

    # TODO: should this be named something else to prevent collisions with properties
    @property
    def base_address(self):
        return self._base_address

    def __getattribute__(self, name: str):
        attr = super().__getattribute__(name)

        if not isinstance(attr, MemoryProperty):
            return attr

        attr.memory_object = self
        return attr.from_memory()

    def __setattr__(self, name, value):
        try:
            attr = super().__getattribute__(name)
        except AttributeError:
            attr = None

        if not isinstance(attr, MemoryProperty):
            super().__setattr__(name, value)

        else:
            attr.to_memory(value)
