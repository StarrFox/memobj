import time
from dataclasses import dataclass
from functools import cached_property
from logging import getLogger
from typing import TYPE_CHECKING, Any, Literal, Self, ClassVar
from collections.abc import Callable

import regex
from iced_x86 import (
    BlockEncoder,
    Code,
    Decoder,
    FlowControl,
    Instruction,
    MemoryOperand,
    Register,
)
from iced_x86._iced_x86_py import Register as RegisterType

from memobj.allocation import Allocation, Allocator

if TYPE_CHECKING:
    from memobj.process import Process


logger = getLogger(__name__)


def _debug_print_disassembly(
    code: bytes,
    instruction_pointer: int,
    *,
    name: str | None = None,
    callback: Callable[[str], Any] = print,
    bitness: Literal[64] | Literal[32] = 64,
):
    decoder = Decoder(bitness, code, ip=instruction_pointer)

    if name:
        callback(f"{name}:")

    callback("bytes=" + " ".join(map(hex, code)))

    for instruction in decoder:
        callback(
            f"{instruction.ip:016X} {instruction}; {instruction.code=} | ({instruction.op_code()})"
        )


# def _add_instruction_label(label_id: int, instruction: Instruction) -> Instruction:
#     instruction.ip = label_id
#     return instruction


def instructions_to_code(
    instructions: list[Instruction],
    instruction_pointer: int,
    *,
    bitness: Literal[64] | Literal[32] = 64,
):
    encoder = BlockEncoder(bitness)
    encoder.add_many(instructions)
    return encoder.encode(instruction_pointer)


def get_register_name(register: RegisterType) -> str:
    for name, value in Register.__dict__.items():
        if register == value:
            return name

    raise ValueError(f"{register} name could not be found")


class Hook:
    def __init__(self, process: "Process"):
        self.process = process
        self.allocator = Allocator(self.process)

        self._variables: dict[str, Allocation] = {}
        self._active: bool = False

    def __enter__(self) -> Self:
        self.activate()
        return self

    def __exit__(self, *_):
        self.deactivate()

    def pre_hook(self):
        """Called before the hook is activated"""
        pass

    def post_hook(self):
        """Called after the hook is activated"""
        pass

    def hook(self) -> Any:
        """Called when the hook is activated"""
        raise NotImplementedError()

    def unhook(self):
        """Called when the hook is deactivated"""
        pass

    @property
    def active(self) -> bool:
        """Whether the hook is active"""
        return self._active

    def get_code(
        self,
    ) -> list[Instruction]:
        """Called when the hook is activated to get the code to put in the hook"""
        raise NotImplementedError()

    def allocate_variable(self, name: str, size: int, *, preferred_start: int | None = None) -> Allocation:
        """
        Allocate a variable of the specified size for use in the hook, retrievable with get_variable.

        Args:
            name: str
                The name of the variable to allocate.
            size: int
                The size of the memory block to allocate.
            preferred_start: The preferred start address of the allocation

        Returns:
            Allocation
                An Allocation object representing the allocated memory block.

        Raises:
            ValueError
                If a variable with the specified name has already been allocated.
        """
        if self._variables.get("name") is not None:
            raise ValueError(f"Variable {name} is already allocated")

        allocation = self.allocator.allocate(size, preferred_start=preferred_start)
        self._variables[name] = allocation
        return allocation

    def get_variable(self, name: str) -> Allocation:
        """
        Retrieves the allocated variable by its name.

        This method attempts to fetch the variable associated with the provided
        name from the internal allocation storage. If the requested variable
        does not exist, an error is raised to indicate that it has not been
        allocated.

        Args:
            name (str): The name of the variable to retrieve.

        Returns:
        Allocation
            The allocated variable corresponding to the given name.

        Raises:
        ValueError
            If the variable with the specified name does not exist in the
            allocation storage.
        """
        try:
            return self._variables[name]
        except KeyError:
            raise ValueError(f"Variable {name} has not been allocated")

    def activate(self) -> dict[str, Allocation]:
        """Activate the hook"""
        if self.active:
            raise ValueError(f"Cannot activate active hook {self.__class__.__name__}")

        if self.allocator.closed:
            self.allocator = Allocator(self.process)

        self.pre_hook()
        self.hook()
        self.post_hook()
        self._active = True

        return self._variables

    def deactivate(self, *, close_allocator: bool = True):
        """Deactivate the hook"""
        self.unhook()

        if close_allocator:
            self.allocator.close()

        self._variables = {}
        self._active = False


class JmpHook(Hook):
    PATTERN: ClassVar[regex.Pattern[bytes] | bytes | None] = None
    MODULE: ClassVar[str | None] = None
    PRESERVE_RAX: ClassVar[bool] = True

    def __init__(
        self,
        process: "Process",
        *,
        special_deallocate: bool = True,
        delayed_close_allocator_seconds: float | None = 0.5,
    ):
        """
        Initializes an instance of the specified class with provided parameters.

        Args:
            process (Process): The process to hook.
            special_deallocate (bool): If we should remove the entry jump before deallocating. Default is True.
            delayed_close_allocator_seconds (float | None): How many seconds to delay the deallocating. Default is 0.5.
        """
        # TODO: make this better
        if not process.process_64_bit:
            self.__class__.PRESERVE_RAX = False

        super().__init__(process)
        # (address, code)
        self._original_code: tuple[int, bytes] | None = None

        self.close_allocator = special_deallocate
        self.delayed_close_allocator_seconds = delayed_close_allocator_seconds

    def activate(self) -> dict[str, Allocation]:
        if self.PATTERN is None:
            raise ValueError(f"PATTERN not set on {self.__class__.__name__}")

        if self.MODULE is None:
            logger.warning(
                f"MODULE not set for {self.__class__.__name__} scanning entire memory space"
            )

        return super().activate()

    # TODO: move the delayed dealloc stuff to Hook class?
    def deactivate(self, *, close_allocator: bool = True):
        """Deactivates the hook"""
        if (
            self.close_allocator is False
            and self.delayed_close_allocator_seconds is not None
        ):
            raise ValueError(
                "close_allocator cannot be False with a delayed number of seconds"
            )

        if (
            self.close_allocator is True
            and self.delayed_close_allocator_seconds is not None
        ):
            # this will write over the outside jmp so the body is no longer entered
            super().deactivate(close_allocator=False)
            # this wait gives the process time to exit the hook body code, should only need ~1 second
            time.sleep(self.delayed_close_allocator_seconds)
            # finally deallocate the body
            self.allocator.close()
            return None
        else:
            return super().deactivate(close_allocator=close_allocator)

    def hook(self):
        assert self.PATTERN is not None
        target_address = self.process.scan_one(self.PATTERN, module=self.MODULE)

        head = self.get_hook_head()
        tail, noops = self.get_hook_tail(target_address)
        hook_instructions = self.get_code()
        hook_instructions = head + hook_instructions + tail

        bitness = 64 if self.process.process_64_bit else 32

        allocation_size = sum(map(len, hook_instructions))
        hook_allocation = self.allocate_variable("hook_site", allocation_size)
        hook_code = instructions_to_code(
            hook_instructions, hook_allocation.address, bitness=bitness
        )
        self.process.write_memory(hook_allocation.address, hook_code)

        jump_instructions = self.get_jump_code(hook_allocation.address, noops)
        jump_code = instructions_to_code(
            jump_instructions, target_address, bitness=bitness
        )
        self.process.write_memory(target_address, jump_code)

    def unhook(self):
        if self._original_code is not None:
            address, code = self._original_code
            self.process.write_memory(address, code)

    @cached_property
    def _jump_needed(self) -> int:
        if not self.PRESERVE_RAX:
            if self.process.process_64_bit:
                # mov rax,0x1122334455667788
                # jmp rax
                return 12
            else:
                # jmp 0xFFFF_FFFF (E9 FF FF FF FF)
                return 5
        else:
            if not self.process.process_64_bit:
                raise RuntimeError(
                    "somehow in preserve rax code for non-64 bit process hook"
                )
            # NOTE: these movs are 10 each which is quite bad
            # push rax
            # mov rax,0x1122334455667788
            # jmp rax
            # pop rax
            return 14

    def get_hook_head(self) -> list[Instruction]:
        if self.PRESERVE_RAX:
            if not self.process.process_64_bit:
                raise RuntimeError(
                    "somehow in preserve rax code for non-64 bit process hook"
                )

            head = [
                Instruction.create_reg(
                    Code.POP_R64,
                    Register.RAX,
                )
            ]
        else:
            head = []

        return head

    def get_hook_tail(self, jump_address: int) -> tuple[list[Instruction], int]:
        position = 0
        original_instructions = []

        # TODO: what does this 10 mean? is it just a general guess and what else we might need?
        search_bytes = self.process.read_memory(jump_address, self._jump_needed + 10)

        if self.process.process_64_bit:
            bitness = 64
        else:
            bitness = 32

        decoder = Decoder(bitness, search_bytes, ip=0)

        for instruction in decoder:
            # NOTE: this is not a None check, Instruction has special bool() handling
            if not instruction:
                raise RuntimeError(
                    f"Got unknown instruction in bytes {position=} {search_bytes=}"
                )

            control_flow = instruction.flow_control

            match control_flow:
                case FlowControl.NEXT:
                    pass
                case (
                    FlowControl.UNCONDITIONAL_BRANCH
                    | FlowControl.INDIRECT_BRANCH
                    | FlowControl.CONDITIONAL_BRANCH
                ):
                    near_target = instruction.near_branch_target

                    if near_target == 0:
                        raise ValueError(
                            f"Original code contains a far branch: {instruction}"
                        )

                    # TODO: try and fix the jump instead
                    if not near_target < self._jump_needed - position:
                        raise ValueError(
                            f"Original code contains a near jump outside of captured code: {instruction}"
                        )

                # TODO: figure out how xbegin works
                case FlowControl.XBEGIN_XABORT_XEND:
                    pass

                case FlowControl.EXCEPTION:
                    raise ValueError(
                        f"Could not decode flow control of instruction: {instruction}"
                    )

            original_instructions.append(instruction)
            position += len(instruction)

            if position >= self._jump_needed:
                if self.process.process_64_bit:
                    # - 1 on position is so the `pop rax` is run, - (position - needed) is for the no ops
                    jump_back_instructions = [
                        # mov rax,jump_back_addr
                        Instruction.create_reg_i64(
                            Code.MOV_R64_IMM64,
                            Register.RAX,
                            jump_address
                            + position
                            - (position - self._jump_needed)
                            - (1 if self.PRESERVE_RAX else 0),
                        ),
                        # jmp rax
                        Instruction.create_reg(Code.JMP_RM64, Register.RAX),
                    ]

                else:
                    # - (position - needed) is for the no ops
                    jump_back_instructions = [
                        Instruction.create_branch(
                            Code.JMP_REL32_32,
                            jump_address + position - (position - self._jump_needed),
                        )
                    ]

                if self.PRESERVE_RAX:
                    jump_back_instructions = [
                        Instruction.create_reg(
                            Code.PUSH_R64,
                            Register.RAX,
                        )
                    ] + jump_back_instructions

                noops = 0
                if position > self._jump_needed:
                    noops = position - self._jump_needed

                original_instructions += jump_back_instructions
                self._original_code = (jump_address, search_bytes[:position])

                return original_instructions, noops

        raise RuntimeError("Couldn't find enough bytes for jump")

    def get_jump_code(self, hook_address: int, noops_needed: int) -> list[Instruction]:
        if self.PRESERVE_RAX:
            if not self.process.process_64_bit:
                raise RuntimeError(
                    "somehow in preserve rax code for non-64 bit process hook"
                )

            jump_instructions = [
                Instruction.create_reg(Code.PUSH_R64, Register.RAX),
                Instruction.create_reg_u64(
                    Code.MOV_R64_IMM64,
                    Register.RAX,
                    hook_address,
                ),
                Instruction.create_reg(Code.JMP_RM64, Register.RAX),
                Instruction.create_reg(Code.POP_R64, Register.RAX),
            ]
        else:
            if self.process.process_64_bit:
                jump_instructions = [
                    Instruction.create_reg_u64(
                        Code.MOV_R64_IMM64,
                        Register.RAX,
                        hook_address,
                    ),
                    Instruction.create_reg(Code.JMP_RM64, Register.RAX),
                ]
            else:
                jump_instructions = [
                    Instruction.create_branch(Code.JMP_REL32_32, hook_address)
                ]

        for _ in range(noops_needed):
            jump_instructions.append(Instruction.create(Code.NOPD))

        return jump_instructions

    def get_code(self) -> list[Instruction]:
        raise NotImplementedError()


"""
123: <block>
u32 entries
u32 entry_size
entry
entry
entry


push rax
push r8
push r9
mov rax,[rcx]
mov r8, [123]
mov r9, [123+4]
cmp r8,<max_entry_number>
jz reset
mov [123+r8*r9+8],rax
inc r8
mov [123],r8
jmp pop_off
reset:
mov [123],0x00000000
pop_off:
pop rax
pop r8
pop r9
"""
# class ListMulticapture(JmpHook):
#     ...


@dataclass
class RegisterCaptureSettings:
    register: RegisterType
    derefference: bool = False
    offset: int = 0


# NOTE: this registertype is kinda mid, we may need to provide our own
def create_capture_hook(
    pattern: regex.Pattern[bytes] | bytes,
    module: str,
    bitness: Literal[32] | Literal[64],
    *,
    register_captures: list[RegisterCaptureSettings],
) -> type[JmpHook]:
    """Create a capture hook class

    Args:
        pattern (regex.Pattern[bytes] | bytes): Pattern to hook at
        module (str): Module to search in
        bitness (int): What bitness of hook to create
        register_captures (list[RegisterCaptureSettings]): Registers to capture

    Returns:
        type[JmpHook]: The created capture hook
    """

    if bitness == 64:
        return _create_capture_hook_64bit(pattern, module, register_captures)
    else:
        return _create_capture_hook_32bit(pattern, module, register_captures)


def _create_capture_hook_32bit(
    pattern: regex.Pattern[bytes] | bytes,
    module: str,
    register_captures: list[RegisterCaptureSettings],
):
    class CaptureHook(JmpHook):
        PATTERN = pattern
        MODULE = module

        def get_code(self) -> list[Instruction]:
            instructions: list[Instruction] = []

            for register_setting in register_captures:
                name = get_register_name(register_setting.register)
                capture = self.allocate_variable(f"{name}_capture", 4)

                if register_setting.derefference is True:
                    instructions += [
                        # push <reg>
                        Instruction.create_reg(
                            Code.PUSH_R32, register_setting.register
                        ),
                        # mov <reg>,[<reg>+<offset>]
                        Instruction.create_reg_mem(
                            Code.MOV_R32_RM32,
                            register_setting.register,
                            MemoryOperand(
                                register_setting.register,
                                displ=register_setting.offset,
                                displ_size=4,
                            ),
                        ),
                        # mov [<capture_addr>],<reg>
                        Instruction.create_mem_reg(
                            Code.MOV_RM32_R32,
                            MemoryOperand(displ=capture.address, displ_size=4),
                            register_setting.register,
                        ),
                        # pop <reg>
                        Instruction.create_reg(Code.POP_R32, register_setting.register),
                    ]

                else:
                    # mov rax,<reg>
                    instructions.append(
                        Instruction.create_mem_reg(
                            Code.MOV_RM32_R32,
                            MemoryOperand(displ=capture.address, displ_size=4),
                            register_setting.register,
                        )
                    )

            return instructions

    return CaptureHook


def _create_capture_hook_64bit(
    pattern: regex.Pattern[bytes] | bytes,
    module: str,
    register_captures: list[RegisterCaptureSettings],
):
    for register_setting in register_captures:
        if register_setting.register == Register.RAX:
            rax_register = register_setting
            break
    else:
        rax_register = None

    if rax_register is not None:
        register_captures.remove(rax_register)

    class CaptureHook(JmpHook):
        PATTERN = pattern
        MODULE = module

        def get_code(self) -> list[Instruction]:
            instructions: list[Instruction] = [
                Instruction.create_reg(Code.PUSH_R64, Register.RAX)
            ]

            # we need to get rax first since it's used to mov the rest
            if rax_register is not None:
                rax_capture = self.allocate_variable("RAX_capture", 8)
                if rax_register.derefference is True:
                    # mov rax,[rax+<offset>]
                    instructions.append(
                        Instruction.create_reg_mem(
                            Code.MOV_R64_RM64,
                            Register.RAX,
                            MemoryOperand(
                                Register.RAX, displ=rax_register.offset, displ_size=8
                            ),
                        )
                    )

                # mov [<addr>],rax
                instructions.append(
                    Instruction.create_mem_reg(
                        Code.MOV_MOFFS64_RAX,
                        MemoryOperand(displ=rax_capture.address, displ_size=8),
                        Register.RAX,
                    )
                )

            for register_setting in register_captures:
                name = get_register_name(register_setting.register)
                capture = self.allocate_variable(f"{name}_capture", 8)

                if register_setting.derefference is True:
                    # NOTE: this doesn't work for RSP
                    # mov rax,[<reg>+<offset>]
                    instructions.append(
                        Instruction.create_reg_mem(
                            Code.MOV_R64_RM64,
                            Register.RAX,
                            MemoryOperand(
                                register_setting.register,
                                displ=register_setting.offset,
                                displ_size=8,
                            ),
                        )
                    )

                else:
                    # mov rax,<reg>
                    instructions.append(
                        Instruction.create_reg_reg(
                            Code.MOV_R64_RM64,
                            Register.RAX,
                            register_setting.register,
                        )
                    )

                instructions.append(
                    Instruction.create_mem_reg(
                        Code.MOV_MOFFS64_RAX,
                        MemoryOperand(displ=capture.address, displ_size=8),
                        Register.RAX,
                    )
                )

            instructions.append(Instruction.create_reg(Code.POP_R64, Register.RAX))

            return instructions

    return CaptureHook
