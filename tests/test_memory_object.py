import ctypes

from memobj.property import *
from memobj import MemoryObject, WindowsProcess


# helper method for tests, it returns a Process attached to the python interpreter
def get_current_process() -> WindowsProcess:
    self_pid = ctypes.windll.kernel32.GetCurrentProcessId()
    return WindowsProcess.from_id(self_pid)


def get_address_of_ctypes_obj(obj, pointer_format):
    return struct.unpack(pointer_format, bytes(ctypes.pointer(obj)))[0]


def test_simple_data():
    process = get_current_process()

    test_value = ctypes.c_int32(23)

    test_value_address = get_address_of_ctypes_obj(test_value, process.pointer_format_string)

    class Test(MemoryObject):
        other = SimpleData(0x0, format_string="i")

    test_instance = Test(address=test_value_address, process=process)

    assert test_instance.other == 23


def test_simple_data_pointer():
    process = get_current_process()

    test_value = ctypes.c_int32(23)
    pointer_to_test_value = ctypes.pointer(test_value)

    test_value_address = get_address_of_ctypes_obj(pointer_to_test_value, process.pointer_format_string)

    class Test(MemoryObject):
        other = Pointer(0x0, SimpleData(format_string="i"))

    test_instance = Test(address=test_value_address, process=process)

    assert test_instance.other == 23


def test_nested_object():
    process = get_current_process()

    test_value = ctypes.c_int32(23)
    pointer_to_test_value = ctypes.pointer(test_value)

    # gets the address of the pointer
    test_value_address = get_address_of_ctypes_obj(pointer_to_test_value, process.pointer_format_string)

    class OtherTest(MemoryObject):
        value = SimpleData(0x0, format_string="i")

    class Test(MemoryObject):
        other: OtherTest = Pointer(0x0, OtherTest())

    test_instance = Test(address=test_value_address, process=process)

    assert test_instance.other.value == 23


def test_nested_object_forward_ref():
    process = get_current_process()

    test_value = ctypes.c_int32(23)
    pointer_to_test_value = ctypes.pointer(test_value)

    # gets the address of the pointer
    test_value_address = get_address_of_ctypes_obj(pointer_to_test_value, process.pointer_format_string)

    class Test(MemoryObject):
        other: "OtherTest" = Pointer(0x0, "OtherTest")

    class OtherTest(MemoryObject):
        value = SimpleData(0x0, format_string="i")

    test_instance = Test(address=test_value_address, process=process)

    assert test_instance.other.value == 23
