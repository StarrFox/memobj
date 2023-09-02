# memobj

A library for defining objects in memory

## installing

`pip install memobj`

## example

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

## support

discord: <https://discord.gg/7hBStdXkyR>
