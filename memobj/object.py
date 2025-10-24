from __future__ import annotations
from typing import TYPE_CHECKING, Callable

from memobj.property import MemoryProperty, Pointer
from memobj.utils import AddressSource

if TYPE_CHECKING:
    from .process import Process, WindowsProcess


class MemoryObjectMeta(type):
    # TODO: move to __init_subclass__?
    # noinspection PyMethodParameters
    def __new__(
        cls,
        class_name: str,
        superclasses: tuple[type],
        attributed_dict: dict,
        *args,
        **kwargs,
    ):
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
    __memory_object_instances__: dict[str, type["MemoryObject"]] = {}

    __memory_properties__: dict[str, MemoryProperty] = {}

    def __init__(
        self,
        address_source: AddressSource,
        process: Process,
    ):
        self._address_source = address_source
        self._memobj_process = process

    # TODO: should this be named something else to prevent collisions with properties?
    @property
    def base_address(self) -> int:
        return self._address_source()

    @staticmethod
    def _resolve_string_class_lookup(class_name: str) -> type["MemoryObject"]:
        try:
            return MemoryObject.__memory_object_instances__[class_name]
        except KeyError:
            raise ValueError(f"No registered MemoryObject named {class_name}")

    @staticmethod
    def _register_string_class_lookup(
        type_instance: type["MemoryObject"], replace: bool = False
    ):
        class_name = type_instance.__name__
        if MemoryObject.__memory_object_instances__.get(class_name) and not replace:
            raise NameError(
                f"You can only have one MemoryObject named {type_instance.__name__}"
            )

        MemoryObject.__memory_object_instances__[class_name] = type_instance
