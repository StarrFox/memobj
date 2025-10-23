import operator
import struct
import time
from enum import Enum
from typing import Generic, TypeVar
from collections.abc import Callable

# TODO: remove when dropping 3.11 support
T = TypeVar("T")


class ValueWaiter(Generic[T]):
    """A utility class to wait for changes from a callable

    Args:
        callback (Callable[[], T]): the callable to wait for changes from
    """

    def __init__(self, callback: Callable[[], T]):
        self.callback = callback

    def wait_for_value(
        self,
        value: T,
        *,
        timeout: float | None = None,
        sleep_time: float = 0.5,
        inverse: bool = False,
    ) -> tuple[T, float]:
        """Wait for callback to return a value

        Args:
            value (T): the value to wait for
            timeout (float | None, optional): optional timeout. Defaults to None.
            sleep_time (float, optional): how long to wait between calls. Defaults to 0.5.
            inverse (bool, optional): wait for the result to NOT be value instead

        Raises:
            TimeoutError: if we passed the timeout

        Returns:
            returns the value and how long we waited for it
        """
        elapsed: float = 0.0
        current = self.callback()

        if inverse:
            comparison = operator.eq
        else:
            comparison = operator.ne

        while comparison(current, value):
            time.sleep(sleep_time)
            elapsed += sleep_time
            if timeout and elapsed > timeout:
                raise TimeoutError(f"ran out of time waiting for value {value}")

            current = self.callback()

        return current, elapsed

    def yield_changes(
        self,
        *,
        amount: int | None = None,
        timeout: float | None = None,
        sleep_time: float = 0.5,
    ):
        """Yield values from the callback as they change

        Args:
            amount (int | None, optional): the amount of values to yield. Defaults to None.
            timeout (float | None, optional): optional timeout. Defaults to None.
            sleep_time (float, optional): how long to wait between calls. Defaults to 0.5.

        Yields:
            T: the values as they change
        """
        value = self.callback()
        yield value
        results = 1
        elapsed: float = 0.0

        while True:
            if amount and results >= amount:
                break

            value, per_elapsed = self.wait_for_value(
                value,
                timeout=(timeout - elapsed) if timeout else None,
                sleep_time=sleep_time,
                inverse=True,
            )
            yield value

            elapsed += per_elapsed
            results += 1


class ProcessEndianness(Enum):
    native = 0
    little = 1
    big = 2


class Type(Enum):
    """
    Byte sized based types
    """

    # struct calls this char but they're trolling
    byte = "c"
    bool = "?"
    signed1 = "b"
    unsigned1 = "B"
    signed2 = "h"
    unsigned2 = "H"
    signed4 = "i"
    unsigned4 = "I"
    signed8 = "l"
    unsigned8 = "L"
    signed_size = "n"
    unsigned_size = "N"
    float = "f"
    double = "d"


def get_type_size(type_: Type) -> int:
    return struct.calcsize(type_.value)


def align_up(value: int, align: int) -> int:
    return align_down(value + (align - 1), align)


def align_down(value: int, align: int) -> int:
    return value & -align


def is_aligned(value: int, align: int) -> bool:
    return (value & (align - 1)) == 0


def get_alignment(size: int) -> int:
    return size & -size


def get_padding(offset: int, align: int) -> int:
    return -offset & (align - 1)


def pad_format(format_string: str) -> str:
    stripped_endian = ""

    if format_string.startswith(("@", "=", "<", ">", "!")):
        stripped_endian = format_string[0]
        format_string = format_string[1:]

    largest = max(struct.calcsize(c) for c in format_string)

    aligned_format = ""
    offset = 0
    for format_char in format_string:
        align = struct.calcsize(format_char)

        padding = get_padding(offset, align)
        offset += align + padding
        aligned_format += ("x" * padding) + format_char

    aligned_format += "x" * get_padding(offset, largest)

    return stripped_endian + aligned_format
