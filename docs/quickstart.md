# Quickstart

## Installation

Using pip:
```
pip install memobj
```

Using uv:
```
uv add memobj
```

## Basic usage

Define a `MemoryObject` subclass with typed properties at fixed offsets, attach it to a live
process, and read/write values as plain Python attributes.

```python
import os
from memobj import WindowsProcess, MemoryObject
from memobj.property import Signed4

class PythonIntObject(MemoryObject):
    # offset of ob_ival in CPython's PyLongObject (may differ across Python versions)
    value: int = Signed4(24)

process = WindowsProcess.from_id(os.getpid())

# id(x) returns the address of the object in CPython
my_int = PythonIntObject(address=id(1), process=process)

print(my_int.value)  # 1
```

## Pointer properties

Use `Pointer` to follow a pointer chain:

```python
from memobj.property import Pointer

class Inner(MemoryObject):
    x: int = Signed4(0)

class Outer(MemoryObject):
    inner: Inner = Pointer(0, Inner)
```

## Allocations

`Allocator` manages a pool of allocations that are freed together:

```python
from memobj import Allocator
from memobj.utils import Type

with Allocator(process) as allocator:
    with allocator.allocate(4) as alloc:
        alloc.write_typed(Type.signed4, 42)
        print(alloc.read_typed(Type.signed4))  # 42
```

See the `tests/` directory for more complete examples.
