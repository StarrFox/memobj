import os
import sys
from pathlib import Path

import pytest

from memobj import Process, WindowsProcess


@pytest.fixture(scope="session")
def process() -> Process:
    """
    Get a Process for the current interpreter
    """
    match sys.platform:
        case "win32":
            return WindowsProcess.from_id(os.getpid())
        case _:
            raise RuntimeError("Unsupported platform")


@pytest.fixture(scope="session")
def test_binaries() -> tuple[Path, Path]:
    library_root = Path(__file__).parent.parent

    assert library_root.name == "memobj"
    assert (library_root / "README.md").exists() is True

    release_dir = library_root / "target" / "release"

    exe_path = (release_dir / "inject_target.exe").resolve()
    dll_path = (release_dir / "test_inject.dll").resolve()

    if not exe_path.exists() or not dll_path.exists():
        pytest.skip("Test binaries not found")

    return exe_path, dll_path
