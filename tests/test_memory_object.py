import ctypes

from memobj.property import *
from memobj import MemoryObject


# TODO: why do I use this instead of ctypes.addressof?
def get_address_of_ctypes_obj(obj, pointer_format):
    return struct.unpack(pointer_format, bytes(ctypes.pointer(obj)))[0]


def test_simple_data(process):
    test_value = ctypes.c_int32(23)

    test_value_address = get_address_of_ctypes_obj(test_value, process.pointer_format_string)

    class Test(MemoryObject):
        other = SimpleData(0x0, format_string="i")

    test_instance = Test(address=test_value_address, process=process)

    assert test_instance.other == 23


def test_simple_data_pointer(process):
    test_value = ctypes.c_int32(23)
    pointer_to_test_value = ctypes.pointer(test_value)

    test_value_address = get_address_of_ctypes_obj(pointer_to_test_value, process.pointer_format_string)

    class Test(MemoryObject, replace=True):
        other = Pointer(0x0, SimpleData(format_string="i"))

    test_instance = Test(address=test_value_address, process=process)

    assert test_instance.other.from_memory_deref() == 23


def test_simple_data_dereffed_pointer(process):
    test_value = ctypes.c_int32(23)
    pointer_to_test_value = ctypes.pointer(test_value)

    test_value_address = get_address_of_ctypes_obj(pointer_to_test_value, process.pointer_format_string)

    class Test(MemoryObject, replace=True):
        other = DereffedPointer(0x0, SimpleData(format_string="i"))

    test_instance = Test(address=test_value_address, process=process)

    assert test_instance.other == 23


def test_nested_object(process):
    test_value = ctypes.c_int32(23)
    pointer_to_test_value = ctypes.pointer(test_value)

    # gets the address of the pointer
    test_value_address = get_address_of_ctypes_obj(pointer_to_test_value, process.pointer_format_string)

    class OtherTest(MemoryObject, replace=True):
        value = SimpleData(0x0, format_string="i")

    class Test(MemoryObject, replace=True):
        other: Pointer = Pointer(0x0, OtherTest)

    test_instance = Test(address=test_value_address, process=process)

    assert test_instance.other.from_memory_deref().value == 23


def test_nested_object_forward_ref(process):
    test_value = ctypes.c_int32(23)
    pointer_to_test_value = ctypes.pointer(test_value)

    # gets the address of the pointer
    test_value_address = get_address_of_ctypes_obj(pointer_to_test_value, process.pointer_format_string)

    class Test(MemoryObject, replace=True):
        other: Pointer = Pointer(0x0, "OtherTest")

    class OtherTest(MemoryObject, replace=True):
        value = SimpleData(0x0, format_string="i")

    test_instance = Test(address=test_value_address, process=process)

    assert test_instance.other.from_memory_deref().value == 23
