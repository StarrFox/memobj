from __future__ import annotations

import subprocess
from pathlib import Path
from typing import TYPE_CHECKING, Self

from memobj.process.module import Module

if TYPE_CHECKING:
    from .process import LinuxProcess


class LinuxModule(Module):
    _symbols: dict[str, int] | None = None

    @classmethod
    def from_name(
        cls, process: LinuxProcess, name: str, *, ignore_case: bool = True
    ) -> Self:
        if ignore_case:
            name = name.lower()

        for module in cls.get_all_modules(process):
            compare = module.name.lower() if ignore_case else module.name
            if compare == name:
                return module

        raise ValueError(f"No module named {name!r}")

    @classmethod
    def get_all_modules(cls, process: LinuxProcess) -> list[Self]:
        """Build module list from /proc/{pid}/maps, merging segments of the same file."""
        seen: dict[str, tuple[int, int]] = {}  # path -> (min_base, max_end)

        with open(f"/proc/{process.process_id}/maps") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 6:
                    continue

                pathname = parts[5]
                if not pathname or pathname.startswith("["):
                    continue

                start_str, end_str = parts[0].split("-")
                start = int(start_str, 16)
                end = int(end_str, 16)

                if pathname in seen:
                    existing_base, existing_end = seen[pathname]
                    seen[pathname] = (min(existing_base, start), max(existing_end, end))
                else:
                    seen[pathname] = (start, end)

        return [
            cls(
                name=Path(path).name,
                base_address=base,
                executable_path=path,
                size=end - base,
                process=process,
            )
            for path, (base, end) in seen.items()
        ]

    def _is_position_independent(self) -> bool:
        """Return True for PIE executables and shared libraries (ELF type ET_DYN)."""
        try:
            with open(self.executable_path, "rb") as f:
                header = f.read(18)
            if len(header) < 18 or header[:4] != b"\x7fELF":
                return False
            endian = "little" if header[5] == 1 else "big"
            e_type = int.from_bytes(header[16:18], endian)
            return e_type == 3  # ET_DYN
        except OSError:
            return False

    def get_symbols(self) -> dict[str, int]:
        if self._symbols is not None:
            return self._symbols

        is_pie = self._is_position_independent()
        symbols: dict[str, int] = {}

        # Try both dynamic (-D) and static symbol tables; merge, with static
        # taking precedence for address accuracy on plain executables.
        for nm_args in (
            ["nm", "--defined-only", "-P", self.executable_path],
            ["nm", "-D", "--defined-only", "-P", self.executable_path],
        ):
            try:
                result = subprocess.run(
                    nm_args,
                    capture_output=True,
                    text=True,
                    check=False,
                )
            except FileNotFoundError:
                break

            for line in result.stdout.splitlines():
                # nm -P format: name type value size
                parts = line.split()
                if len(parts) < 3:
                    continue
                sym_name = parts[0].split("@")[0]  # strip GLIBC version suffixes
                sym_type = parts[1]
                if sym_type in ("U", "w", "v"):
                    continue
                try:
                    offset = int(parts[2], 16)
                    # For PIE binaries and shared libs, nm gives load-relative offsets
                    addr = self.base_address + offset if is_pie else offset
                    if sym_name not in symbols:
                        symbols[sym_name] = addr
                except ValueError:
                    continue

        self._symbols = symbols
        return symbols

    def get_symbol_with_name(self, name: str) -> int:
        try:
            return self.get_symbols()[name]
        except KeyError:
            raise ValueError(f"No symbol named {name!r}")
