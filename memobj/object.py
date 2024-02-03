import typing
from typing import TYPE_CHECKING, Union, Callable

from memobj.property import MemoryProperty, Pointer

if TYPE_CHECKING:
    from .process import Process, WindowsProcess


class MemoryObjectMeta(type):
    # TODO: move to __init_subclass__?
    # noinspection PyMethodParameters
    def __new__(cls, class_name: str, superclasses: tuple[type], attributed_dict: dict, *args, **kwargs):
        if not superclasses:
            return super().__new__(cls, class_name, superclasses, attributed_dict)

        new_instance = super().__new__(cls, class_name, superclasses, attributed_dict)
        memory_object = superclasses[-1]

        replace = kwargs.pop("replace", False)

        memory_object._register_string_class_lookup(new_instance, replace)  # type: ignore

        __memory_objects__ = {}
        __memory_properties__ = {}
        for name, _type in attributed_dict.items():
            if isinstance(_type, MemoryObject):
                __memory_objects__[name] = _type
            elif isinstance(_type, MemoryProperty):
                __memory_properties__[name] = _type

        new_instance.__memory_objects__ = __memory_objects__  # type: ignore
        new_instance.__memory_properties__ = __memory_properties__  # type: ignore

        return new_instance


class MemoryObject(metaclass=MemoryObjectMeta):
    __memory_object_instances__ = {}

    __memory_objects__ = {}
    __memory_properties__ = {}

    def __init__(
            self,
            offset: Union[int, None] = None,
            *,
            address: Union[int, None] = None,
            address_provider: Union[Callable[[], int], None] = None,
            process: Union["Process", "WindowsProcess", None] = None,
    ):
        if address is not None and address_provider is not None:
            raise ValueError("both address and address_provider cannot be provided")

        self._offset = offset
        self._base_address = address
        self._address_provider = address_provider
        self.memobj_process = process

    # TODO: should this be named something else to prevent collisions with properties?
    @property
    def base_address(self) -> int:
        if self._address_provider is not None:
            return self._address_provider()

        # the property-like usage
        if self._base_address is None:
            raise ValueError("Uninitialized memoryobject did not receieve an address")

        return self._base_address

    @staticmethod
    def _resolve_string_class_lookup(class_name: str) -> type["MemoryObject"]:
        try:
            return MemoryObject.__memory_object_instances__[class_name]
        except KeyError:
            raise ValueError(f"No registered MemoryObject named {class_name}")

    @staticmethod
    def _register_string_class_lookup(type_instance: type["MemoryObject"], replace: bool = False):
        class_name = type_instance.__name__
        if MemoryObject.__memory_object_instances__.get(class_name) and not replace:
            raise NameError(f"You can only have one MemoryObject named {type_instance.__name__}")

        MemoryObject.__memory_object_instances__[class_name] = type_instance

    if not TYPE_CHECKING:
        def __getattribute__(self, name):
            attr = super().__getattribute__(name)

            if not isinstance(attr, MemoryObject):
                return attr

            if isinstance(self.__memory_properties__[name], Pointer):
                return attr

            if attr._offset is None:
                raise ValueError("Offset not set")

            attr._base_address = self.base_address + attr._offset
            attr.memobj_process = self.memobj_process

            return attr
