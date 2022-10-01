# memobj
A library for defining objects in memory

## installing
python 3.11+ only!
`pip install memobj`

## usage
```python
from memobj import WindowsProcess, MemoryObject
from memobj.property import *


# you can define custom property readers like this
class FloatVec3(MemoryProperty):
    def from_memory(self) -> tuple[float]:
        # read 3 floats
        return self.read_formatted_from_offset("fff")
    
    def to_memory(self, value: tuple[float]):
        self.write_formatted_to_offset("fff", value)


class MyObject(MemoryObject):
    # you can forward reference classes by putting them in a string
    my_other_object: "MyOtherObject" = Pointer(0x20, "MyOtherObject")


class MyOtherObject(MemoryObject):
    my_float_vec: tuple[float] = FloatVec3(0x30)


process = WindowsProcess.from_name("my_process.exe")

my_object = MyObject(address=0xFFFFFFFF, process=process)
print(my_object.my_other_object.my_float_vec)
```

## support
discord
https://discord.gg/7hBStdXkyR
