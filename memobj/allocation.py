from typing import TYPE_CHECKING, Self


if TYPE_CHECKING:
    from memobj.process import Process


class Allocation:
    def __init__(self, address: int, process: "Process"):
        self.address = address
        self.process = process
        
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

    def allocate(self, size: int) -> Allocation:
        address = self.process.allocate_memory(size)
        allocation = Allocation(address, self.process)
        self.allocations.append(allocation)
        return allocation

    def close(self):
        if self._is_closed:
            raise ValueError("Cannot close an already closed allocator")
        
        for allocation in self.allocations:
            if not allocation.closed:
                allocation.free()

        self.allocations = []
        self._is_closed = True
