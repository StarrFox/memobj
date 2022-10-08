# memobj
A library for defining objects in memory

## installing
python 3.11+ only!
`pip install memobj`

## usage
```python
import os

from memobj import WindowsProcess, MemoryObject
from memobj.property import Signed4


class PythonIntObject(MemoryObject):
    value: int = Signed4(24)


process = WindowsProcess.from_id(os.getpid())

# id(x) gives the address of the object in cpython
my_int = PythonIntObject(address=id(1), process=process)

# prints 1
print(my_int.value)
```

## support
discord
https://discord.gg/7hBStdXkyR
