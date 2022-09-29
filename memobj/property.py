
class NullTerminatedString(MemoryProperty):
    def __init__(self, offset: int | None, max_size: int = 20, encoding: str = "utf-8", pointer: bool = False):
        super().__init__(offset)
        self.max_size = max_size
        self.encoding = encoding
        self.pointer = pointer

    def from_memory(self) -> Any:
        # TODO: add Pointer property i.e. name: str = Pointer(0x0, NullTerminatedString(...))
        if self.pointer:
            pointer = self.read_formatted_from_offset(self.pointer_format_string)
            string_bytes = self.memory_object.memobj_process.read_memory(
                pointer,
                self.max_size
            )
        else:
            string_bytes = self.memory_object.memobj_process.read_memory(
                self.memory_object.base_address + self.offset,
                self.max_size,
            )

        end = string_bytes.find(b"\x00")

        if end == 0:
            return ""

        if end == -1:
            raise ValueError("No null end")

        return string_bytes[:end].decode(self.encoding)

    def to_memory(self, value: str):
        value = value.encode(self.encoding) + b"\x00"

        if (value_len := len(value)) > self.max_size:
            raise ValueError(f"Value was {value_len} while the max size is {self.max_size}")

        if self.pointer:
            allocation = self.memory_object.memobj_process.allocate_memory(value_len)
            self.memory_object.memobj_process.write_memory(allocation, value)

            self.write_formatted_to_offset(self.pointer_format_string, allocation)

        else:
            self.memory_object.memobj_process.write_memory(
                self.memory_object.base_address + self.offset,
                value,
            )

    def memory_size(self) -> int:
        if self.pointer:
            return 8 if self.memory_object.memobj_process.process_64_bit else 4
        else:
            return self.max_size
