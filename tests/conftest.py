import os
import sys

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
