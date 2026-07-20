# Hooks

Hooks let you inject assembly into a running process at a pattern-matched address, execute custom
code, and optionally capture values back to Python. All hook classes require a Windows process.

## JmpHook

`JmpHook` patches a small trampoline at a byte pattern in the target process. You subclass it,
set `PATTERN` and `MODULE`, and implement `get_code()` to return the instructions that run
inside the trampoline. The hook head/tail (the jump in, original displaced instructions, and
jump back) are generated automatically.

### Capturing a register value

A common use-case is capturing the value of a register at a specific point in the target's code.
`allocate_variable` reserves memory in the target process and `wait_variable_non_zero` blocks
until the target writes a non-zero value there.

```python
import regex
from iced_x86 import Code, Instruction, MemoryOperand, Register

from memobj import WindowsProcess
from memobj.hook import JmpHook


class PlayerPtrHook(JmpHook):
    # Unique byte sequence that identifies the instruction site to hook.
    # Use regex.escape() for literal bytes or a regex.Pattern for wildcards.
    PATTERN = regex.escape(bytes.fromhex("48 8B 81 E0 01 00 00 48 85 C0"))
    MODULE = "game.exe"

    def get_code(self) -> list[Instruction]:
        # Allocate 8 bytes in the target process to hold the captured pointer.
        player_ptr = self.allocate_variable("player_ptr", 8)

        return [
            # mov [player_ptr_addr], rcx
            Instruction.create_mem_reg(
                Code.MOV_MOFFS64_RAX,
                MemoryOperand(displ=player_ptr.address, displ_size=8),
                Register.RCX,
            )
        ]


process = WindowsProcess.from_name("game.exe")

with PlayerPtrHook(process) as hook:
    # Block until the game writes a non-zero value (i.e. the hooked code runs).
    player_address = hook.wait_variable_non_zero("player_ptr")
    print(f"player object at: {hex(player_address)}")
```

### Reading the captured value later

If you need to poll the captured value across multiple frames rather than waiting once, keep the
hook active and call `read_typed` on the allocation directly:

```python
from memobj.utils import Type

hook = PlayerPtrHook(process)
hook.activate()

# ... later, in a game loop:
alloc = hook.get_variable("player_ptr")
player_address = alloc.read_typed(Type.unsigned8)

hook.deactivate()
```

### Modifying a value in-place

`get_code()` can also write back to the target process. Here the hook doubles a counter each
time the target reaches the pattern:

```python
from iced_x86 import Code, Instruction, Register

from memobj.hook import JmpHook
import regex


class DoubleCounterHook(JmpHook):
    PATTERN = regex.escape(bytes.fromhex("8B 05 AA BB CC DD"))
    MODULE = "app.exe"

    def get_code(self) -> list[Instruction]:
        return [
            # add eax, eax  — doubles whatever EAX holds at this point
            Instruction.create_reg_reg(Code.ADD_RM32_R32, Register.EAX, Register.EAX),
        ]
```

---

## create_capture_hook

`create_capture_hook` is a factory that builds a `JmpHook` subclass which captures one or more
registers at a pattern address. It handles the `get_code()` implementation for you.

### Basic register capture

```python
import regex
from iced_x86 import Register

from memobj import WindowsProcess
from memobj.hook import create_capture_hook, RegisterCaptureSettings


# Build a hook class that captures RCX and RDX at the matched address.
EntityHook = create_capture_hook(
    pattern=regex.escape(bytes.fromhex("48 83 EC 28 F3 0F 10 41 04")),
    module="game.exe",
    bitness=64,
    register_captures=[
        RegisterCaptureSettings(Register.RCX),   # raw register value
        RegisterCaptureSettings(Register.RDX),
    ],
)

process = WindowsProcess.from_name("game.exe")
hook = EntityHook(process)
hook.activate()

rcx_alloc = hook.get_variable("RCX_capture")
rdx_alloc = hook.get_variable("RDX_capture")

rcx_value = hook.wait_variable_non_zero("RCX_capture")
print(f"RCX = {hex(rcx_value)}")

hook.deactivate()
```

Variable names follow the pattern `<REGISTER_NAME>_capture` (e.g. `RCX_capture`, `RDX_capture`).

### Dereferencing a register

Set `derefference=True` (and optionally `offset`) on `RegisterCaptureSettings` to capture the
value *pointed to* by the register rather than the register itself:

```python
from iced_x86 import Register
from memobj.hook import create_capture_hook, RegisterCaptureSettings
import regex

# Capture *(RCX + 0x10) instead of RCX.
ValueHook = create_capture_hook(
    pattern=regex.escape(bytes.fromhex("48 89 4C 24 08")),
    module="app.exe",
    bitness=64,
    register_captures=[
        RegisterCaptureSettings(Register.RCX, derefference=True, offset=0x10),
    ],
)
```

### Using the hook as a context manager

All hook classes support the context manager protocol, which calls `activate()` on entry and
`deactivate()` on exit:

```python
with EntityHook(process) as hook:
    address = hook.wait_variable_non_zero("RCX_capture")
    print(f"entity at {hex(address)}")
# hook is automatically deactivated here
```
