from __future__ import annotations
import struct
from typing import Any, Generic, TypeVar, ClassVar

from memobj.utils import Type
from . import MemoryProperty


T = TypeVar("T")


class SimpleData(MemoryProperty, Generic[T]):
    #format_string: ClassVar[str | None] = None
    data_type: Type | None = None

    def __init__(
        self, offset: int | None = None, data_type: Type | None = None
    ):
        super().__init__(offset)
        if data_type is not None:
            self.data_type = data_type

    def _get_format(self) -> Type:
        if self.data_type is None:
            raise ValueError(f"None data_type for {self.__class__.__name__}")

        return self.data_type

    def from_memory(self) -> T:
        return self.read_typed_from_offset(self._get_format())

    def to_memory(self, value: Any):
        self.write_typed_from_offset(self._get_format(), value)

    def memory_size(self) -> int:
        return struct.calcsize(self._get_format().value)


class Bool(SimpleData):
    data_type = Type.bool


class Float(SimpleData):
    data_type = Type.float


class Double(SimpleData):
    data_type = Type.double


class Signed1(SimpleData):
    data_type = Type.signed1


class Unsigned1(SimpleData):
    data_type = data_type = Type.unsigned1


class Signed2(SimpleData):
    data_type = Type.signed2


class Unsigned2(SimpleData):
    data_type = data_type = Type.unsigned2


class Signed4(SimpleData):
    data_type = Type.signed4


class Unsigned4(SimpleData):
    data_type = Type.unsigned4


class Signed8(SimpleData):
    data_type = Type.signed8


class Unsigned8(SimpleData):
    data_type = Type.unsigned8
