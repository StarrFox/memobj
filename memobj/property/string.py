from typing import Any

from . import MemoryProperty


class NullTerminatedString(MemoryProperty):
    def __init__(
            self,
            offset: int | None = None,
            search_size: int = 20,
            *,
            encoding: str = "utf-8",
            ignore_errors: bool = False,
    ):
        super().__init__(offset)
        self.search_size = search_size
        self.encoding = encoding
        self.ignore_errors = ignore_errors

    def from_memory(self) -> Any:
        data = self.process.read_memory(
            self.offset_address,
            self.search_size,
        )

        end = data.find(b"\x00")

        if end == 0:
            return ""

        if end == -1:
            if self.ignore_errors:
                return ""

            raise ValueError("No null end found")

        return data[:end].decode(self.encoding)

    def to_memory(self, value: Any):
        value = value.encode(self.encoding) + b"\x00"

        if (value_len := len(value)) > self.search_size:
            raise ValueError(f"Value was {value_len} while the search_size size is {self.search_size}")

        self.process.write_memory(
            self.offset_address,
            value,
        )

    def memory_size(self) -> int:
        return self.search_size
