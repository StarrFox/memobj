from typing import TYPE_CHECKING, Callable, Any
from logging import getLogger
from functools import cached_property

from iced_x86 import Instruction, Decoder, Code, Register, BlockEncoder, FlowControl
import regex

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
    ALLOCATION_SIZE: int = 1_000
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
        matched_addresses = self.process.scan_memory(self.PATTERN, module=self.MODULE)
        
        # TODO: add this repetitive code to Process
        if matched_len := len(matched_addresses) == 0:
            raise ValueError(f"No matches found for pattern of {self.__class__.__name__}")

        elif matched_len > 1:
            raise ValueError(f"Multiple results ({matched_len}) for pattern of {self.__class__.__name__}")

        target_address = matched_addresses[0]

        tail, noops = self._get_hook_tail(target_address)

        hook_allocation = self.allocate_variable("hook_site", self.ALLOCATION_SIZE)
        hook_instructions = self.get_code(tail)
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

        # TODO: add sanity checks for instructions like ret and jmp
        for instruction in decoder:
            # NOTE: this is not a None check, Instruction has special bool() handling
            if not instruction:
                raise RuntimeError(f"Got unknown instruction in bytes {position=} {search_bytes=}")

            original_instructions.append(instruction)
            position += instruction.len

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
                    # for _ in range(position - _HOOK_JUMP_NEEDED):
                    #     jump_back_instructions.append(Instruction.create(Code.NOPD))

                original_instructions += jump_back_instructions

                self._original_code = (jump_address, search_bytes[:position])

                return original_instructions, noops

        raise RuntimeError("Couldn't find enough bytes for jump")

    def get_code(self, tail: list[Instruction]) -> list[Instruction]:
        raise NotImplemented()


if __name__ == "__main__":
    from iced_x86 import MemoryOperand
    from memobj import WindowsProcess
    
    class TestHook(JmpHook):
        PATTERN = rb"\x8D\x04\x11\xC3"
        MODULE = "testapp.exe"
        
        def get_code(self, tail: list[Instruction]) -> list[Instruction]:
            rcx_cache = self.allocate_variable("rcx_cache", 8)
            instructions = [
                Instruction.create_reg(Code.PUSH_R64, Register.RAX),
                Instruction.create_reg_reg(
                    Code.MOV_R64_RM64,
                    Register.RAX,
                    Register.RCX,
                ), 
                Instruction.create_mem_reg(
                    Code.MOV_MOFFS64_RAX,
                    MemoryOperand(displ=rcx_cache.address, displ_size=8),
                    Register.RAX,
                ),
                Instruction.create_reg(Code.POP_R64, Register.RAX),
            ]

            return instructions + tail

    process = WindowsProcess.from_name("testapp.exe")
    hook = TestHook(process)
    variables = hook.activate()
    
    rcx_cache = variables["rcx_cache"]
    
    old = 0
    
    import time
    
    while True:
        new = process.read_formatted(rcx_cache.address, "<i")
        if new != old:
            old = new
            print(f"{new=}")
            break
        
        time.sleep(0.5)

    input("enter to exit")

    hook.deactivate()
    
    #_debug_print_disassembly(b"\x48\xA3\x00\x00\xDC\x04\xD6\x02\x00\x00", 0)
    
    #process.write_memory(0x7FF6BA341070, b"\x8D\x04\x11\xC3\x90")
    
    # alloc = process.allocate_memory(1000)
    # print(f"{hex(alloc)=}")
