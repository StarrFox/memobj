import os

from memobj import WindowsProcess, MemoryObject
from memobj.property import Signed4


def test_readme():
    class PythonIntObject(MemoryObject):
        value: int = Signed4(24)

    process = WindowsProcess.from_id(os.getpid())

    # id(x) gives the address of the object in cpython
    my_int = PythonIntObject(address=id(1), process=process)

    # prints 1
    print(my_int.value)
