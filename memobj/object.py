from typing import TYPE_CHECKING, Union


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
