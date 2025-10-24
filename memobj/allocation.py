from typing import TYPE_CHECKING, Any, Self

from memobj.utils import Type, get_type_size

if TYPE_CHECKING:
    from memobj.process import Process


class Allocation:
    def __init__(self, address: int, process: "Process", size: int):
        self.address = address
        self.process = process
        self.size = size

        self._is_closed: bool = False

    def __repr__(self) -> str:
        return f"<Allocation at {hex(self.address)}>"

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_):
        self.free()

    @property
    def closed(self) -> bool:
        return self._is_closed

    def free(self):
        if self._is_closed:
            raise ValueError("Cannot free an already freed allocation")

        self.process.free_memory(self.address)
        self._is_closed = True

    def read_typed(self, read_type: Type) -> Any:
        if (type_size := get_type_size(read_type)) != self.size:
            raise ValueError(
                f"{read_type} size ({type_size}) does not match allocation size ({self.size})"
            )

        return self.process.read_typed(self.address, read_type)

    def write_typed(self, write_type: Type, value: Any) -> None:
        if (type_size := get_type_size(write_type)) != self.size:
            raise ValueError(
                f"Write type ({type_size}) does not match allocation size ({self.size})"
            )

        return self.process.write_typed(self.address, write_type, value)


class Allocator:
    """
    with Allocator(process) as allocator:
        with allocator.allocate() as allocation:
            # do something with allocation

        allocation = allocator.allocate()
    """

    def __init__(self, process: "Process"):
        self.process = process
        self.allocations: list[Allocation] = []

        self._is_closed: bool = False

    def __enter__(self) -> Self:
        if self._is_closed:
            raise ValueError("Cannot reuse a closed allocator")
        return self

    def __exit__(self, *_):
        self.close()

    @property
    def closed(self) -> bool:
        return self._is_closed

    def allocate(self, size: int, *, preferred_start: int | None = None) -> Allocation:
        """
        Allocates a block of memory for the process.

        Allocates a specified block of memory for the associated process, keeping
        track of the allocation for management purposes. The allocated memory
        is represented as an `Allocation` object and is appended to the list of
        current allocations.

        Args:
            size (int): The size of the memory block to allocate in bytes.
            preferred_start: The preferred start address of the allocation

        Returns:
            Allocation: An object representing the allocated memory block.
        """
        address = self.process.allocate_memory(size, preferred_start=preferred_start)
        allocation = Allocation(address, self.process, size)
        self.allocations.append(allocation)
        return allocation

    def close(self):
        """
        Closes the allocator, ensuring all current allocations are properly freed and the allocator
        is set to a closed state. This method prevents further use of the allocator by marking it
        as closed. If the allocator is already closed, an error will be raised.

        Raises:
            ValueError: If the allocator is already closed before the invocation of this method.
        """
        if self._is_closed:
            raise ValueError("Cannot close an already closed allocator")

        for allocation in self.allocations:
            if not allocation.closed:
                allocation.free()

        self.allocations = []
        self._is_closed = True
