# memobj

A Python library for defining and reading structured objects directly from another process's memory.

## Installation

- Using pip:
  - pip install memobj
- Using uv:
  - uv add memobj  

## Quickstart

```python
import os
from memobj import WindowsProcess, MemoryObject
from memobj.property import Signed4

class PythonIntObject(MemoryObject):
    # note: this offset might be different in future python versions
    value: int = Signed4(24)

process = WindowsProcess.from_id(os.getpid())

# id(x) gives the address of the object in cpython
my_int = PythonIntObject(address=id(1), process=process)

# prints 1
print(my_int.value)
```

See tests for more examples (pointer properties, process/module utilities, etc.).

## Development setup

This project uses uv as the build backend and package manager.

- Sync dependencies (including the tests group):
  - uv sync --all-groups
- Run tests:
  - uv run pytest
- Format code:
  - isort . && black .

Optional: A Nix flake provides a dev shell with Python 3.11, just, black, isort, and more:

- nix develop

## Support

discord: <https://discord.gg/wcftyYm6qe>
