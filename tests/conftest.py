import sys
import os

import pytest

from memobj import Process, WindowsProcess


def pytest_addoption(parser):
    parser.addoption("--run-manual", action="store_true", default=False, help="run manual tests")


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
