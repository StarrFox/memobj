from typing import Any
from copy import copy

from . import MemoryProperty
from .. import MemoryObject


class Array(MemoryProperty):
    def __init__(
        self,
        offset: int | None,
        element_type: MemoryProperty, *,
        count: int | MemoryProperty | None = None
    ):
        super().__init__(offset)

        self._element_type = element_type
        self._count = count

    def element_size(self) -> int:
        return self._element_type.memory_size()

    def element_count(self) -> int:
        if isinstance(self._count, MemoryProperty):
            return self._count.from_memory()

        elif isinstance(self._count, int):
            return self._count

        else:
            raise NotImplementedError("missing count requires overriden .element_count() impl")

    def from_memory(self) -> Any:
        elements = []

        self._element_type.memory_object = MemoryObject(
            address=self.offset_address,
            process=self.process,
        )

        for idx in range(self.element_count()):
            self._element_type.offset = idx * self.element_size()
            elements.append(self._element_type.from_memory())

        return elements

    def to_memory(self, value: Any):
        self._element_type.memory_object = MemoryObject(
            address=self.offset_address,
            process=self.process,
        )

        for idx, element in enumerate(value):
            self._element_type.offset = idx * self.element_size()
            self._element_type.to_memory(element)

    def memory_size(self) -> int:
        return self.element_size() * self.element_count()
