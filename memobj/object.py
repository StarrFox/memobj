from typing import TYPE_CHECKING, Union


if TYPE_CHECKING:
    from .process import Process, WindowsProcess


class MemoryObject:
    def __init__(
            self,
            offset: int = None,
            *,
            address: int = None,
            process: Union["Process", "WindowsProcess"] = None,
    ):
        self._offset = offset
        self._base_address = address
        self.memobj_process = process

    # TODO: should this be named something else to prevent collisions with properties
    @property
    def base_address(self):
        return self._base_address

    def __getattribute__(self, name):
        attr = super().__getattribute__(name)

        if not isinstance(attr, MemoryObject):
            return attr

        attr._base_address = self.base_address + attr._offset
        attr.memobj_process = self.memobj_process

        return attr
