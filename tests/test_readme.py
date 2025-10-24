from memobj import MemoryObject
from memobj.property import Signed4


def test_readme(process):
    class PythonIntObject(MemoryObject):
        value = Signed4(24)

    # id(x) gives the address of the object in cpython
    my_int = PythonIntObject(address_source=lambda: id(1), process=process)

    # prints 1
    assert my_int.value == 1
