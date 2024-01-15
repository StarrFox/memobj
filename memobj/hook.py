from typing import TYPE_CHECKING, Callable, Any
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

    def pre_hook(self):
        pass

    def post_hook(self):
        pass

    def hook(self):
        raise NotImplemented()

    def unhook(self):
        pass

    @property
    def active(self) -> bool:
        return self._active

    def get_code(
        self,
        tail: list[Instruction]
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
    FUNCTION_TOP: bool = True

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

    def hook(self):
        assert self.PATTERN is not None
        target_address = self.process.scan_one(self.PATTERN, module=self.MODULE)

        tail, noops = self._get_hook_tail(target_address)
        hook_instructions = self.get_code(tail)
        allocation_size = sum(map(len, hook_instructions))
        hook_allocation = self.allocate_variable("hook_site", allocation_size)
        hook_code = instructions_to_code(hook_instructions, hook_allocation.address)
        self.process.write_memory(hook_allocation.address, hook_code)

        if not self.FUNCTION_TOP:
            jump_instructions = [
                Instruction.create_reg(Code.PUSH_R64, Register.RAX),
                Instruction.create_reg_u64(
                    Code.MOV_R64_IMM64,
                    Register.RAX,
                    hook_allocation.address,
                ),
                Instruction.create_reg(Code.JMP_RM64, Register.RAX),
                Instruction.create_reg(Code.POP_R64, Register.RAX),
            ]
        else:
            jump_instructions = [
                Instruction.create_reg_u64(
                    Code.MOV_R64_IMM64,
                    Register.RAX,
                    hook_allocation.address,
                ),
                Instruction.create_reg(Code.JMP_RM64, Register.RAX),
            ]

        for _ in range(noops):
            jump_instructions.append(Instruction.create(Code.NOPD))

        jump_code = instructions_to_code(jump_instructions, target_address)
        self.process.write_memory(target_address, jump_code)

    def unhook(self):
        if self._original_code is not None:
            address, code = self._original_code
            self.process.write_memory(address, code)

    @cached_property
    def _jump_needed(self) -> int:
        if self.FUNCTION_TOP:
            # mov rax,0x1122334455667788
            # jmp rax
            return 12
        
        else:
            # push rax
            # mov rax,0x1122334455667788
            # jmp rax
            # pop rax
            return 14

    def _get_hook_tail(self, jump_address: int) -> tuple[list[Instruction], int]:
        position = 0
        original_instructions = []

        search_bytes = self.process.read_memory(jump_address, self._jump_needed + 10)

        logger.debug(f"{search_bytes=}")

        decoder = Decoder(64, search_bytes, ip=jump_address)

        for instruction in decoder:
            # NOTE: this is not a None check, Instruction has special bool() handling
            if not instruction:
                raise RuntimeError(f"Got unknown instruction in bytes {position=} {search_bytes=}")

            control_flow = instruction.flow_control
            
            match control_flow:
                case FlowControl.NEXT:
                    pass
                case FlowControl.RETURN:
                    if not self.FUNCTION_TOP:
                        raise ValueError("Original code contains a return and we've pushed rax onto stack")
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
                # - 1 on position is so the pop rax is run, - (position - needed) is for the no ops
                jump_back_instructions = [
                    Instruction.create_reg_i64(
                        Code.MOV_R64_IMM64,
                        Register.RAX,
                        jump_address + position - 1 - (position - self._jump_needed)
                    ),
                    Instruction.create_reg(Code.JMP_RM64, Register.RAX),
                ]

                noops = 0
                if position > self._jump_needed:
                    noops = position - self._jump_needed

                original_instructions += jump_back_instructions
                self._original_code = (jump_address, search_bytes[:position])

                return original_instructions, noops

        raise RuntimeError("Couldn't find enough bytes for jump")

    def get_code(self, tail: list[Instruction]) -> list[Instruction]:
        raise NotImplemented()


# NOTE: this registertype is kinda mid, we may need to provide our own
def create_capture_hook(
    pattern: regex.Pattern | bytes,
    module: str,
    *,
    registers: set[RegisterType]
) -> type[JmpHook]:
    
    for register in registers:
        if register == Register.RAX:
            rax_register = True
            break
    else:
        rax_register = False

    if rax_register:
        registers.remove(Register.RAX)

    class CaptureHook(JmpHook):
        PATTERN = pattern
        MODULE = module

        def get_code(self, tail: list[Instruction]) -> list[Instruction]:
            instructions: list[Instruction] = [Instruction.create_reg(Code.PUSH_R64, Register.RAX)]

            # we need to get rax first since it's used to mov the rest
            if rax_register:
                rax_capture = self.allocate_variable("RAX_capture", 8)
                instructions.append(
                    Instruction.create_mem_reg(
                        Code.MOV_MOFFS64_RAX,
                        MemoryOperand(displ=rax_capture.address, displ_size=8),
                        Register.RAX,
                    )
                )
            
            for register in registers:
                name = get_register_name(register)
                capture = self.allocate_variable(f"{name}_capture", 8)
                instructions += [
                    Instruction.create_reg_reg(
                        Code.MOV_R64_RM64,
                        Register.RAX,
                        register,
                    ),
                    Instruction.create_mem_reg(
                        Code.MOV_MOFFS64_RAX,
                        MemoryOperand(displ=capture.address, displ_size=8),
                        Register.RAX,
                    ),
                ]

            instructions.append(Instruction.create_reg(Code.POP_R64, Register.RAX))

            return instructions + tail

    return CaptureHook
