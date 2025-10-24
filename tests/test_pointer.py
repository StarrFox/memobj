import ctypes

from memobj import MemoryObject
from memobj.property import Pointer, Unsigned4


class ExampleObject(ctypes.Structure):
    _fields_ = [
        ("data", ctypes.c_int32),
    ]


class ReferenceObject(ctypes.Structure):
    _fields_ = [
        ("vtable", ctypes.c_void_p),
        ("weak", ctypes.c_int32),
        ("hard", ctypes.c_int32),
        ("obj", ctypes.POINTER(ExampleObject)),
    ]


class SharedPointer(ctypes.Structure):
    _fields_ = [
        ("obj", ctypes.POINTER(ExampleObject)),
        ("reference", ctypes.POINTER(ReferenceObject)),
    ]


def create_shared_pointer(data: int = 0):
    obj = ExampleObject(data=data)
    obj_p = ctypes.pointer(obj)

    ref = ReferenceObject(obj=obj_p)
    shared = SharedPointer(obj=obj_p, reference=ctypes.pointer(ref))

    return shared


def test_read_shared_pointer(process):
    class MemExampleObject(MemoryObject, replace=True):
        data = Unsigned4(0x0)

    class MemReferenceObject(MemoryObject, replace=True):
        object = Pointer(16, MemExampleObject)

    class MemSharedPointer(MemoryObject, replace=True):
        reference = Pointer(8, MemReferenceObject)

    shared = create_shared_pointer(200)

    mem_obj = MemSharedPointer(address_source=lambda: ctypes.addressof(shared), process=process)

    assert mem_obj.reference.from_memory_deref().object.from_memory_deref().data == 200


def test_read_double_pointer(process):
    class MemExampleObject(MemoryObject, replace=True):
        data = Unsigned4(0x0)

    class MemSharedPointer(MemoryObject, replace=True):
        reference: Pointer = Pointer(8, Pointer(16, MemExampleObject))

    shared = create_shared_pointer(200)

    mem_obj = MemSharedPointer(address_source=lambda: ctypes.addressof(shared), process=process)

    x: Pointer = mem_obj.reference

    x.from_memory_deref()

    assert mem_obj.reference.from_memory_deref().from_memory_deref().data == 200
