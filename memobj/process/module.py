from dataclasses import dataclass

from .base import Process


@dataclass
class Module:
    name: str
    base_address: int
    executable_path: str
    size: int
    process: Process

    def get_symbols(self) -> dict[str, int]:
        """Get the module's symbols

        Returns:
            dict[str, int]: A mapping of module symbol to address
        """
        raise NotImplemented()
