import ctypes


class Process:
    """A connected process"""

    # TODO: 3.11 replace with typing.Self
    @classmethod
    def from_name(cls) -> "Process":
        raise NotImplementedError()

    @classmethod
    def from_id(cls) -> "Process":
        raise NotImplementedError()

    def read_memory(self, address: int, size: int) -> bytes:
        """
        Read bytes from memory

        Args:
            address: The address to read from
            size: The number of bytes to read

        Returns:
        The bytes read
        """
        raise NotImplementedError()

    def write_memory(self, address: int, value: bytes):
        """
        Write bytes to memory

        Args:
            address: The address to write to
            value: The bytes to write to that address
        """
        raise NotImplementedError()


class WindowsProcess(Process):
    user32 = ctypes.windll.user32

    @classmethod
    def from_name(cls) -> "WindowsProcess":
        pass

    @classmethod
    def from_id(cls) -> "WindowsProcess":
        pass

    def read_memory(self, address: int, size: int) -> bytes:
        pass

    def write_memory(self, address: int, value: bytes):
        pass
