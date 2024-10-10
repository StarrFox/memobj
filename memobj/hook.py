import time
from typing import TYPE_CHECKING, Callable, Any, Self
from logging import getLogger
from functools import cached_property

import regex
from iced_x86 import Instruction, Decoder, Code, MemoryOperand, Register, BlockEncoder, FlowControl
from iced_x86._iced_x86_py import Register as RegisterType

from memobj.allocation import Allocator, Allocation


if TYPE_CHECKING:
    from memobj.process import Process


logger = getLogger(__name__)


def _debug_print_disassembly(
    code: bytes,
    instruction_pointer: int,
    *,
    name: str | None = None,
    callback: Callable[[str], Any] = print,
    bitness: int = 64
):
    decoder = Decoder(bitness, code, ip=instruction_pointer)

    if name:
        callback(f"{name}:")

    callback("bytes=" + " ".join(map(hex, code)))

    for instruction in decoder:
        callback(f"{instruction.ip:016X} {instruction}; {instruction.code=}")


def _add_instruction_label(label_id: int, instruction: Instruction) -> Instruction:
    instruction.ip = label_id
    return instruction


def instructions_to_code(
    instructions: list[Instruction],
    instruction_pointer: int,
    *,
    bitness: int = 64
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
        pass

    def post_hook(self):
        pass

    def hook(self) -> Any:
        raise NotImplemented()

    def unhook(self):
        pass

    @property
    def active(self) -> bool:
        return self._active

    def get_code(
        self,
    ) -> list[Instruction]:
        raise NotImplemented()

    def allocate_variable(self, name: str, size: int) -> Allocation:
        if self._variables.get("name") is not None:
            raise ValueError(f"Variable {name} is already allocated")

        allocation = self.allocator.allocate(size)
        self._variables[name] = allocation
        return allocation

    def get_variable(self, name: str) -> Allocation:
        try:
            return self._variables[name]
        except KeyError:
            raise ValueError(f"Variable {name} has not been allocated")

    def activate(self) -> dict[str, Allocation]:
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
        self.unhook()

        if close_allocator:
            self.allocator.close()

        self._variables = {}
        self._active = False


# TODO: add 32-bit support
class JmpHook(Hook):
    PATTERN: regex.Pattern | bytes | None = None
    MODULE: str | None = None
    PRESERVE_RAX: bool = True

    def __init__(self, process: "Process"):
        super().__init__(process)
        # (address, code)
        self._original_code: tuple[int, bytes] | None = None

    def activate(self) -> dict[str, Allocation]:
        if self.PATTERN is None:
            raise ValueError(f"PATTERN not set on {self.__class__.__name__}")

        if self.MODULE is None:
            logger.warning(f"MODULE not set for {self.__class__.__name__} scanning entire memory space")

        return super().activate()

    # TODO: move the delayed dealloc stuff to Hook class?
    def deactivate(self, *, close_allocator: bool = True, delayed_close_allocator_seconds: float | None = None):
        """Deactivates the hook

        Args:
            close_allocator (bool, optional): If the body allocator should be closed. Defaults to True.
            delayed_close_allocator_seconds (float | None, optional): how many second to delay body deallocation. Defaults to None.
        """
        if close_allocator is False and delayed_close_allocator_seconds is not None:
            raise ValueError("close_allocator cannot be False with a delayed number of seconds")
        
        if close_allocator is True and delayed_close_allocator_seconds is not None:
            # this will write over the outside jmp so the body is no longer entered
            super().deactivate(close_allocator=False)
            # this wait gives the process time to exit the hook body code, should only need ~1 second
            time.sleep(delayed_close_allocator_seconds)
            # finally deallocate the body
            self.allocator.close()
        else:
            return super().deactivate(close_allocator=close_allocator)

    def hook(self):
        assert self.PATTERN is not None
        target_address = self.process.scan_one(self.PATTERN, module=self.MODULE)

        head = self.get_hook_head()
        tail, noops = self.get_hook_tail(target_address)
        hook_instructions = self.get_code()
        hook_instructions = head + hook_instructions + tail

        allocation_size = sum(map(len, hook_instructions))
        hook_allocation = self.allocate_variable("hook_site", allocation_size)
        hook_code = instructions_to_code(hook_instructions, hook_allocation.address)
        self.process.write_memory(hook_allocation.address, hook_code)

        jump_instructions = self.get_jump_code(hook_allocation.address, noops)
        jump_code = instructions_to_code(jump_instructions, target_address)
        self.process.write_memory(target_address, jump_code)

    def unhook(self):
        if self._original_code is not None:
            address, code = self._original_code
            self.process.write_memory(address, code)

    @cached_property
    def _jump_needed(self) -> int:
        if not self.PRESERVE_RAX:
            # mov rax,0x1122334455667788
            # jmp rax
            return 12
        else:
            # NOTE: these movs are 10 each which is quite bad
            # push rax
            # mov rax,0x1122334455667788
            # jmp rax
            # pop rax
            return 14

    def get_hook_head(self) -> list[Instruction]:
        if self.PRESERVE_RAX:
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

        search_bytes = self.process.read_memory(jump_address, self._jump_needed + 10)

        #logger.debug(f"{search_bytes=}")

        decoder = Decoder(64, search_bytes, ip=jump_address)

        for instruction in decoder:
            # NOTE: this is not a None check, Instruction has special bool() handling
            if not instruction:
                raise RuntimeError(f"Got unknown instruction in bytes {position=} {search_bytes=}")

            control_flow = instruction.flow_control

            match control_flow:
                case FlowControl.NEXT:
                    pass
                case FlowControl.UNCONDITIONAL_BRANCH | FlowControl.INDIRECT_BRANCH | FlowControl.CONDITIONAL_BRANCH:
                    near_target = instruction.near_branch_target

                    if near_target == 0:
                        raise ValueError(f"Original code contains a far branch: {instruction}")

                    # TODO: try and fix the jump instead
                    if not near_target < self._jump_needed - position:
                        raise ValueError(f"Original code contains a near jump outside of captured code: {instruction}")

                # TODO: figure out how xbegin works
                case FlowControl.XBEGIN_XABORT_XEND:
                    pass

                case FlowControl.EXCEPTION:
                    raise ValueError(f"Could not decode flow control of instruction: {instruction}")

            original_instructions.append(instruction)
            position += len(instruction)

            if position >= self._jump_needed:
                # - 1 on position is so the `pop rax` is run, - (position - needed) is for the no ops
                jump_back_instructions = [
                    Instruction.create_reg_i64(
                        Code.MOV_R64_IMM64,
                        Register.RAX,
                        jump_address + position - (position - self._jump_needed) - (1 if self.PRESERVE_RAX else 0)
                    ),
                    Instruction.create_reg(Code.JMP_RM64, Register.RAX),
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
            rax_preserve_allocation = self.allocate_variable("rax_preserve", 8)

            jump_instructions = [
                Instruction.create_reg(
                    Code.PUSH_R64,
                    Register.RAX
                ),
                Instruction.create_reg_u64(
                    Code.MOV_R64_IMM64,
                    Register.RAX,
                    hook_address,
                ),
                Instruction.create_reg(Code.JMP_RM64, Register.RAX),
                Instruction.create_reg(Code.POP_R64, Register.RAX),
            ]
        else:
            jump_instructions = [
                Instruction.create_reg_u64(
                    Code.MOV_R64_IMM64,
                    Register.RAX,
                    hook_address,
                ),
                Instruction.create_reg(Code.JMP_RM64, Register.RAX),
            ]

        for _ in range(noops_needed):
            jump_instructions.append(Instruction.create(Code.NOPD))

        return jump_instructions

    def get_code(self) -> list[Instruction]:
        raise NotImplemented()


# NOTE: this registertype is kinda mid, we may need to provide our own
def create_capture_hook(
    pattern: regex.Pattern | bytes,
    module: str,
    *,
    registers: set[tuple[RegisterType, int | None]]
) -> type[JmpHook]:
    """Create a capture hook class
    
    registers is a set of tuples with the register to capture and
    the offset to or None for the register value itself
    
    123 -> [rcx+123]
    0 -> [rcx]
    None -> rcx

    Args:
        pattern (regex.Pattern | bytes): Pattern to hook at
        module (str): Module to search in
        registers (set[tuple[RegisterType, int | None]]): Registers to capture

    Returns:
        type[JmpHook]: The created capture hook
    """

    rax_offset = 0

    for register_set in registers:
        if register_set[0] == Register.RAX:
            rax_register = True
            rax_offset = register_set[1]
            break
    else:
        rax_register = False

    if rax_register:
        registers.remove((Register.RAX, rax_offset))

    class CaptureHook(JmpHook):
        PATTERN = pattern
        MODULE = module

        def get_code(self) -> list[Instruction]:
            instructions: list[Instruction] = [Instruction.create_reg(Code.PUSH_R64, Register.RAX)]

            # we need to get rax first since it's used to mov the rest
            if rax_register:
                rax_capture = self.allocate_variable("RAX_capture", 8)    
                if rax_offset == 0:
                    # mov rax,[rax]
                    instructions.append(
                        Instruction.create_reg_mem(
                        Code.MOV_R64_RM64,
                        Register.RAX,
                        MemoryOperand(Register.RAX, displ_size=8)
                        )
                    )
                elif rax_offset is None:
                    # mov rax,rax
                    instructions.append(Instruction.create_mem_reg(
                        Code.MOV_MOFFS64_RAX,
                        MemoryOperand(displ=rax_capture.address, displ_size=8),
                        Register.RAX,
                    ))
                else:
                    # mov rax,[rax+<offset>]
                    instructions.append(
                        Instruction.create_reg_mem(
                            Code.MOV_R64_RM64,
                            Register.RAX,
                            MemoryOperand(Register.RAX, displ=rax_offset, displ_size=8),
                        ))
                
                # mov [<addr>],rax
                instructions.append(Instruction.create_mem_reg(
                            Code.MOV_MOFFS64_RAX,
                            MemoryOperand(displ=rax_capture.address, displ_size=8),
                            Register.RAX,
                        ))

            for register, offset in registers:
                name = get_register_name(register)
                capture = self.allocate_variable(f"{name}_capture", 8)

                if offset == 0:
                    # mov rax,[<reg>]
                    instructions.append(
                        Instruction.create_reg_mem(
                        Code.MOV_R64_RM64,
                        Register.RAX,
                        MemoryOperand(register, displ_size=8)
                        )
                    )

                elif offset is None:
                    # mov rax,<reg>
                    instructions.append(
                        Instruction.create_reg_reg(
                            Code.MOV_R64_RM64,
                            Register.RAX,
                            register,
                        )
                    )
                else:
                    # TODO: make sure to account for 32 bit here if support is added
                    if register == Register.RSP:
                        offset += 8 # push rax before moves

                    # mov rax,[<reg>+<offset>]
                    instructions.append(
                        Instruction.create_reg_mem(
                            Code.MOV_R64_RM64,
                            Register.RAX,
                            MemoryOperand(base=register, displ=offset, displ_size=8),
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
