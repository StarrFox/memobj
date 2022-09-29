import inspect
from typing import TYPE_CHECKING, Union

from memobj.property import MemoryProperty, Pointer

if TYPE_CHECKING:
    from .process import Process, WindowsProcess


class MemoryObjectMeta(type):
    # noinspection PyMethodParameters
    def __new__(cls, class_name: str, superclasses: tuple[type], attributed_dict: dict, *args, **kwargs):
        if not superclasses:
            return super().__new__(cls, class_name, superclasses, attributed_dict)

        print(f"{superclasses[-1]=}")

        memory_object = superclasses[-1]

        if memory_object.__memory_object_instances__.get(class_name):
            raise NameError(f"You can only have one MemoryObject named {class_name}")

        new_instance = super().__new__(cls, class_name, superclasses, attributed_dict)

        memory_object.__memory_object_instances__[class_name] = new_instance

        __memory_objects__ = {}
        __memory_properties__ = {}
        for name, _type in attributed_dict.items():
            if isinstance(_type, MemoryObject):
                __memory_objects__[name] = _type
            elif isinstance(_type, MemoryProperty):
                __memory_properties__[name] = _type

        new_instance.__memory_objects__ = __memory_objects__
        new_instance.__memory_properties__ = __memory_properties__

        return new_instance


class MemoryObject(metaclass=MemoryObjectMeta):
    __memory_object_instances__ = {}

    __memory_objects__ = {}
    __memory_properties__ = {}

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

        if isinstance(self.__memory_properties__[name], Pointer):
            return attr

        attr._base_address = self.base_address + attr._offset
        attr.memobj_process = self.memobj_process

        return attr
